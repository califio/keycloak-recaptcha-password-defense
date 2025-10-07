package io.calif.keycloak.recaptchapassworddefense;

import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

record RecaptchaPasswordDefenseSettings(
        String projectId,
        String serviceAccountJson,
        int timeoutMs,
        List<String> notificationEmails,
        boolean failClosed,
        boolean doNotDisable,
        boolean notifyUser,
        boolean includeCredentialsInUserEmail
) {

    static final String CFG_GCP_PROJECT_ID = "gcpProjectId";
    static final String CFG_GCP_SERVICE_ACCOUNT = "gcpServiceAccount";
    static final String CFG_TIMEOUT_MS = "assessmentTimeoutMs";
    static final String CFG_NOTIFICATION_EMAILS = "notificationEmails";
    static final String CFG_FAIL_CLOSED = "failClosed";
    static final String CFG_DO_NOT_DISABLE = "doNotDisable";
    static final String CFG_NOTIFY_USER = "notifyUser";
    static final String CFG_INCLUDE_CREDENTIALS = "includeCredentialsInUserEmail";

    static final String NOTE_ACCOUNT_BREACHED = "ACCOUNT_BREACHED";

    static final Set<String> STRONG_TYPES = Collections.unmodifiableSet(resolveStrongCredentialTypes());

    static List<ProviderConfigProperty> configProperties(boolean isLoginForm) {
        List<ProviderConfigProperty> properties = new ArrayList<>();

        properties.add(requiredProperty(
                CFG_GCP_PROJECT_ID,
                "Google Cloud Project ID",
                "The ID of the Google Cloud project.",
                ProviderConfigProperty.STRING_TYPE));

        ProviderConfigProperty serviceAccount = requiredProperty(
                CFG_GCP_SERVICE_ACCOUNT,
                "Google Cloud Service Account",
                "A service account with access to reCAPTCHA Enterprise API on Google Cloud.",
                ProviderConfigProperty.FILE_TYPE);
        setSecret(serviceAccount, true);
        properties.add(serviceAccount);

        ProviderConfigProperty timeout = property(
                CFG_TIMEOUT_MS,
                "Assessment Timeout (ms)",
                "Timeout value for credentials assessment. Defaults to 2500 ms.",
                ProviderConfigProperty.STRING_TYPE,
                String.valueOf(RecaptchaPasswordDefenseSettings.DEFAULT_TIMEOUT_MS));
        properties.add(timeout);

        if (isLoginForm) {
            properties.add(property(
                    CFG_NOTIFICATION_EMAILS,
                    "Notification Emails",
                    "List of email addresses to notify on each breach detection.",
                    ProviderConfigProperty.MULTIVALUED_STRING_TYPE,
                    null));
        }

        properties.add(property(
                CFG_FAIL_CLOSED,
                "Fail closed on API errors",
                "If true, the action fails when the password defense API call fails. Default is false (fail-open).",
                ProviderConfigProperty.BOOLEAN_TYPE,
                "false"));

        if (isLoginForm) {
            properties.add(property(
                    CFG_DO_NOT_DISABLE,
                    "Unsafe mode - Do not disable account",
                    "If true, breached account will not be disabled. Default is false (safe mode).",
                    ProviderConfigProperty.BOOLEAN_TYPE,
                    "false"));

            properties.add(property(
                    CFG_NOTIFY_USER,
                    "Notify account owner",
                    "If true, send an email to the affected account when a breach is detected (requires verified email).",
                    ProviderConfigProperty.BOOLEAN_TYPE,
                    "true"));

            properties.add(property(
                    CFG_INCLUDE_CREDENTIALS,
                    "Include masked credentials in emails",
                    "If true, the email notification contains the username and a masked copy of the breached password.",
                    ProviderConfigProperty.BOOLEAN_TYPE,
                    "true"));
        }

        return properties;
    }

    static final int DEFAULT_TIMEOUT_MS = 2500;

    static RecaptchaPasswordDefenseSettings fromConfig(Map<String, String> config) {
        if (config == null) {
            config = Collections.emptyMap();
        }

        String projectId = config.getOrDefault(CFG_GCP_PROJECT_ID, null);
        String serviceAccount = config.getOrDefault(CFG_GCP_SERVICE_ACCOUNT, null);
        int timeoutMs = parseInt(config.getOrDefault(CFG_TIMEOUT_MS, String.valueOf(DEFAULT_TIMEOUT_MS)), DEFAULT_TIMEOUT_MS);
        boolean failClosed = Boolean.parseBoolean(config.getOrDefault(CFG_FAIL_CLOSED, "false"));
        boolean doNotDisable = Boolean.parseBoolean(config.getOrDefault(CFG_DO_NOT_DISABLE, "false"));
        boolean notifyUser = Boolean.parseBoolean(config.getOrDefault(CFG_NOTIFY_USER, "true"));
        boolean includeCredentials = Boolean.parseBoolean(config.getOrDefault(CFG_INCLUDE_CREDENTIALS, "true"));
        List<String> notificationEmails = parseEmails(config.getOrDefault(CFG_NOTIFICATION_EMAILS, ""));

        return new RecaptchaPasswordDefenseSettings(projectId, serviceAccount, timeoutMs, notificationEmails, failClosed, doNotDisable, notifyUser, includeCredentials);
    }

    boolean hasNotConfigured() {
        return projectId == null || projectId.isBlank()
                || serviceAccountJson == null || serviceAccountJson.isBlank();
    }

    private static ProviderConfigProperty property(String name,
                                                   String label,
                                                   String helpText,
                                                   String type,
                                                   Object defaultValue) {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName(name);
        property.setLabel(label);
        property.setHelpText(helpText);
        property.setType(type);
        property.setDefaultValue(defaultValue);
        return property;
    }

    private static ProviderConfigProperty requiredProperty(String name,
                                                           String label,
                                                           String helpText,
                                                           String type) {
        ProviderConfigProperty property = property(name, label, helpText, type, null);
        setRequired(property, true);
        return property;
    }

    private static void setSecret(ProviderConfigProperty property, boolean secret) {
        try {
            property.getClass().getMethod("setSecret", boolean.class).invoke(property, secret);
        } catch (NoSuchMethodException ex) {
            // Older Keycloak versions do not expose this setter; ignore.
        } catch (Exception ex) {
            // Keep compatibility: log at debug level when available.
        }
    }

    private static void setRequired(ProviderConfigProperty property, boolean required) {
        try {
            property.getClass().getMethod("setRequired", boolean.class).invoke(property, required);
        } catch (NoSuchMethodException ex) {
            // Keycloak < 23 lacked the setter; leave at default.
        } catch (Exception ex) {
            // Ignore unexpected reflection issues; default remains false.
        }
    }

    private static int parseInt(String value, int def) {
        try {
            return Integer.parseInt(value);
        } catch (Exception ex) {
            return def;
        }
    }

    private static List<String> parseEmails(String raw) {
        if (raw == null || raw.isBlank()) {
            return List.of();
        }
        return Arrays.stream(raw.split("##"))
                .map(String::trim)
                .filter(v -> !v.isBlank())
                .distinct()
                .toList();
    }

    private static Set<String> resolveStrongCredentialTypes() {
        Set<String> types = new HashSet<>();
        types.add(OTPCredentialModel.TYPE);

        // WebAuthn constants have been renamed/added over time; resolve them defensively to support older Keycloak releases.
        try {
            types.add(WebAuthnCredentialModel.TYPE_TWOFACTOR);
        } catch (NoSuchFieldError ex) {
            // Older Keycloak versions used a single WebAuthn type; ignore when missing.
        }

        try {
            types.add(WebAuthnCredentialModel.TYPE_PASSWORDLESS);
        } catch (NoSuchFieldError ex) {
            // Passkeys not yet available; skip.
        }

        return types;
    }
}
