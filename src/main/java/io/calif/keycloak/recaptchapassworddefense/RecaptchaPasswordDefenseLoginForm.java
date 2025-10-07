package io.calif.keycloak.recaptchapassworddefense;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Collections;
import java.util.List;

/**
 * Custom UsernamePasswordForm that, after validating credentials, calls reCAPTCHA password defense
 * to check if the supplied credentials are breached.
 *
 * Default behavior on breach:
 * - If user has another strong factor (OTP/WebAuthn/Passkey): mark a note to force step-up and require UPDATE_PASSWORD
 * - Otherwise: disable the account and show an error page instructing to contact administrators
 * If configurated, admins and the user are notified by email.
 */
public class RecaptchaPasswordDefenseLoginForm extends UsernamePasswordForm {

    private static final Logger LOG = Logger.getLogger(RecaptchaPasswordDefenseLoginForm.class);

    private static final String MSG_LOGIN_BREACHED = "recaptchaPasswordDefense.login.breached";
    private static final String MSG_LOGIN_DISABLED = "recaptchaPasswordDefense.login.disabled";
    private static final String MSG_LOGIN_UNAVAILABLE = "recaptchaPasswordDefense.login.unavailable";
    private static final EventType CUSTOM_REQUIRED_ACTION_EVENT = Utils.resolveEventType("CUSTOM_REQUIRED_ACTION", EventType.LOGIN);

    @Override
    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        // Extract the password early, so we still have access to it after super.validateForm()
        String password = formData.getFirst("password");

        if (!super.validateForm(context, formData)) {
            return false;
        }

        UserModel user = context.getUser();
        RealmModel realm = context.getRealm();
        KeycloakSession session = context.getSession();
        EventBuilder baseEvent = context.getEvent();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        // If no password is present (e.g., login by passkey), skip
        if (password == null || password.isEmpty() || user == null) {
            return true;
        }

        RecaptchaPasswordDefenseSettings settings = RecaptchaPasswordDefenseSettings.fromConfig(
                context.getAuthenticatorConfig() == null
                        ? Collections.emptyMap()
                        : context.getAuthenticatorConfig().getConfig());

        if (settings.hasNotConfigured()) {
            LOG.warn("reCAPTCHA service account is not configured; skipping password defense check.");
            return true;
        }

        try {
            RecaptchaPasswordDefenseClient client = Utils.buildClient(settings);
            boolean leaked = client.isLeaked(user.getUsername(), password);

            if (!leaked) {
                return true;
            }

            Utils.emitEvent(baseEvent, EventType.LOGIN_ERROR, "breached", user,
                    event -> event.error("Breached credentials"));

            boolean hasStrongFactor = RecaptchaPasswordDefenseSettings.STRONG_TYPES
                    .stream()
                    .anyMatch(type -> user.credentialManager().isConfiguredFor(type));

            Utils.sendNotificationEmails(
                    session,
                    realm,
                    user,
                    settings,
                    hasStrongFactor,
                    hasStrongFactor ? "step-up enforced + required password change" : "account disabled",
                    password,
                    LOG);

            context.form().setError(MSG_LOGIN_BREACHED);

            if (hasStrongFactor) {
                if (authSession != null) {
                    authSession.setAuthNote(RecaptchaPasswordDefenseSettings.NOTE_ACCOUNT_BREACHED, "true");
                }
                // Force step-up and password change
                user.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
                Utils.emitEvent(baseEvent, CUSTOM_REQUIRED_ACTION_EVENT, "breached_stepup", user, EventBuilder::success);
                // Continue the flow; the conditional sub-flow will execute 2FA
                return true;
            } else {
                if (settings.doNotDisable()) {
                    // Unsafe mode
                    Utils.emitEvent(baseEvent, EventType.LOGIN_ERROR, "breached_account_allow_unsafe", user,
                            event -> event.error("Breached account was allowed to log in because of the config."));
                    return true;
                }
                // Disable account and stop the flow
                user.setEnabled(false);
                Utils.emitEvent(baseEvent, EventType.LOGIN_ERROR, "breached_account_disabled", user,
                        event -> event.error("Breached account was disabled because there was no strong authentication method for a step-up."));
                Response challenge = context.form()
                        .setErrors(List.of(new FormMessage(null, MSG_LOGIN_DISABLED)))
                        .createErrorPage(Response.Status.FORBIDDEN);
                context.challenge(challenge);
                return false;
            }
        } catch (Exception e) {
            LOG.warn("Password defense check failed", e);
            if (settings.failClosed()) {
                Response challenge = context.form()
                        .setErrors(List.of(new FormMessage(null, MSG_LOGIN_UNAVAILABLE)))
                        .createErrorPage(Response.Status.SERVICE_UNAVAILABLE);
                context.challenge(challenge);
                return false;
            }
            return true; // fail-open
        }
    }

}
