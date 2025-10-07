package io.calif.keycloak.recaptchapassworddefense;

import com.google.api.gax.core.FixedCredentialsProvider;
import com.google.api.gax.retrying.RetrySettings;
import com.google.auth.oauth2.ServiceAccountCredentials;
import com.google.cloud.recaptcha.passwordcheck.PasswordCheckResult;
import com.google.cloud.recaptcha.passwordcheck.PasswordCheckVerification;
import com.google.cloud.recaptcha.passwordcheck.PasswordCheckVerifier;
import com.google.cloud.recaptchaenterprise.v1.RecaptchaEnterpriseServiceClient;
import com.google.cloud.recaptchaenterprise.v1.RecaptchaEnterpriseServiceSettings;
import com.google.protobuf.ByteString;
import com.google.recaptchaenterprise.v1.Assessment;
import com.google.recaptchaenterprise.v1.CreateAssessmentRequest;
import com.google.recaptchaenterprise.v1.PrivatePasswordLeakVerification;
import org.threeten.bp.Duration;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Small helper around reCAPTCHA Enterprise "Password Defense" (https://cloud.google.com/recaptcha/docs/check-passwords).
 * This class performs the full request/verify handshake as recommended by Google.
 */
public class RecaptchaPasswordDefenseClient {
    private final String projectId;
    private final com.google.auth.Credentials serviceAccount;
    private final int timeoutMs; // applies to RPC and local async steps

    public RecaptchaPasswordDefenseClient(String projectId, InputStream serviceAccount, int timeoutMs) throws IOException {
        if (projectId == null || projectId.isBlank()) {
            throw new IllegalArgumentException("Invalid config: projectId is required");
        }
        if (serviceAccount == null) {
            throw new IllegalArgumentException("Invalid config: serviceAccount is required");
        }
        this.projectId = projectId;
        this.serviceAccount = ServiceAccountCredentials.fromStream(serviceAccount);
        this.timeoutMs = timeoutMs > 0 ? timeoutMs : RecaptchaPasswordDefenseSettings.DEFAULT_TIMEOUT_MS;
    }

    /**
     * Create a reCAPTCHA Enterprise assessment with RPC timeout.
     * Returns: PrivatePasswordLeakVerification containing reencryptedUserCredentialsHash and
     * the credential breach DB whose prefix matches the lookupHashPrefix.
     */
    private PrivatePasswordLeakVerification createPasswordLeakAssessment(
            byte[] lookupHashPrefix,
            byte[] encryptedUserCredentialsHash)
            throws IOException {

        // Build service settings with per-RPC timeout (and no backoff growth).
        RecaptchaEnterpriseServiceSettings.Builder settingsBuilder =
                RecaptchaEnterpriseServiceSettings.newBuilder()
                        .setCredentialsProvider(FixedCredentialsProvider.create(serviceAccount));

        RetrySettings baseRetry = settingsBuilder
                .createAssessmentSettings()
                .getRetrySettings();

        RetrySettings tunedRetry = baseRetry.toBuilder()
                .setTotalTimeout(Duration.ofMillis(timeoutMs))          // overall deadline for the call
                .setInitialRpcTimeout(Duration.ofMillis(timeoutMs))     // per-attempt
                .setMaxRpcTimeout(Duration.ofMillis(timeoutMs))         // cap per-attempt
                .setRpcTimeoutMultiplier(1.0)                           // don't grow timeouts
                .build();

        settingsBuilder.createAssessmentSettings().setRetrySettings(tunedRetry);

        try (RecaptchaEnterpriseServiceClient client =
                     RecaptchaEnterpriseServiceClient.create(settingsBuilder.build())) {

            // Set the hashprefix and credentials hash (triggers Password Leak Protection).
            PrivatePasswordLeakVerification passwordLeakVerification =
                    PrivatePasswordLeakVerification.newBuilder()
                            .setLookupHashPrefix(ByteString.copyFrom(lookupHashPrefix))
                            .setEncryptedUserCredentialsHash(ByteString.copyFrom(encryptedUserCredentialsHash))
                            .build();

            // Build the assessment request.
            CreateAssessmentRequest createAssessmentRequest =
                    CreateAssessmentRequest.newBuilder()
                            .setParent(String.format("projects/%s", this.projectId))
                            .setAssessment(
                                    Assessment.newBuilder()
                                            .setPrivatePasswordLeakVerification(passwordLeakVerification)
                                            .build())
                            .build();

            // Send the create assessment request and return the result.
            return client.createAssessment(createAssessmentRequest).getPrivatePasswordLeakVerification();
        }
    }

    /**
     * Checks if given username/password pair was found in known breaches.
     *
     * @return true if leaked, false otherwise
     * @throws RecaptchaPasswordDefenseException when verification cannot be completed
     */
    public boolean isLeaked(String username, String password) {
        try {
            // Instantiate helper to perform cryptographic functions.
            PasswordCheckVerifier passwordLeak = new PasswordCheckVerifier();

            // Local async computation; bound via timeout as well.
            PasswordCheckVerification verification =
                    passwordLeak.createVerification(username, password)
                            .get(timeoutMs, TimeUnit.MILLISECONDS);

            byte[] lookupHashPrefix = verification.getLookupHashPrefix();
            byte[] encryptedUserCredentialsHash = verification.getEncryptedUserCredentialsHash();

            // Get the matching database entry for the hash prefix (RPC with timeout).
            PrivatePasswordLeakVerification credentials = createPasswordLeakAssessment(
                    lookupHashPrefix,
                    encryptedUserCredentialsHash);

            // Convert to appropriate input format.
            List<byte[]> leakMatchPrefixes = new ArrayList<>(credentials.getEncryptedLeakMatchPrefixesCount());
            credentials.getEncryptedLeakMatchPrefixesList().forEach(x -> leakMatchPrefixes.add(x.toByteArray()));

            // Verify if the encrypted credentials are present in the obtained match list.
            PasswordCheckResult result = passwordLeak
                    .verify(
                            verification,
                            credentials.getReencryptedUserCredentialsHash().toByteArray(),
                            leakMatchPrefixes
                    )
                    .get(timeoutMs, TimeUnit.MILLISECONDS); // bound verification step too

            // Check if the credential is leaked.
            return result.areCredentialsLeaked();
        } catch (TimeoutException e) {
            throw new RecaptchaPasswordDefenseException(
                    String.format("Password leak verification timed out after %d ms", timeoutMs),
                    e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RecaptchaPasswordDefenseException("Password leak verification was interrupted", e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause() == null ? e : e.getCause();
            throw new RecaptchaPasswordDefenseException("Password leak verification failed", cause);
        } catch (Exception e) {
            throw new RecaptchaPasswordDefenseException("Error while performing password leak verification", e);
        }
    }
}
