package io.calif.keycloak.recaptchapassworddefense;

import jakarta.ws.rs.core.MultivaluedMap;

import org.jboss.logging.Logger;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.authentication.forms.RegistrationPage;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;

import java.util.Collections;
import java.util.List;

/**
 * Registration form action that verifies the provided password with reCAPTCHA Password Defense.
 */
public class RecaptchaPasswordDefenseRegistrationAction implements FormAction {

    private static final Logger LOG = Logger.getLogger(RecaptchaPasswordDefenseRegistrationAction.class);

    private static final String MSG_REGISTRATION_BREACHED = "recaptchaPasswordDefense.registration.breached";
    private static final String MSG_REGISTRATION_UNAVAILABLE = "recaptchaPasswordDefense.registration.unavailable";

    @Override
    public void validate(ValidationContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String password = formData.getFirst(RegistrationPage.FIELD_PASSWORD);

        if (password == null || password.isBlank()) {
            context.success();
            return;
        }

        RecaptchaPasswordDefenseSettings settings = RecaptchaPasswordDefenseSettings.fromConfig(
                context.getAuthenticatorConfig() == null
                        ? Collections.emptyMap()
                        : context.getAuthenticatorConfig().getConfig());

        if (settings.hasNotConfigured()) {
            LOG.warn("reCAPTCHA service account is not configured for registration; skipping password defense check.");
            context.success();
            return;
        }

        String username = resolveUsername(context, formData);

        try {
            RecaptchaPasswordDefenseClient client = Utils.buildClient(settings);
            boolean leaked = client.isLeaked(username, password);

            if (!leaked) {
                context.success();
                return;
            }

            Utils.emitEvent(context.getEvent(), EventType.REGISTER_ERROR, "breached_registration", null,
                    event -> event.error("Breached credentials"));

            formData.remove(RegistrationPage.FIELD_PASSWORD);
            formData.remove(RegistrationPage.FIELD_PASSWORD_CONFIRM);

            context.error(Errors.INVALID_REGISTRATION);
            context.validationError(formData, List.of(new FormMessage(RegistrationPage.FIELD_PASSWORD, MSG_REGISTRATION_BREACHED)));
            return;
        } catch (Exception ex) {
            LOG.warn("Password defense check failed during registration", ex);
            if (settings.failClosed()) {
                formData.remove(RegistrationPage.FIELD_PASSWORD);
                formData.remove(RegistrationPage.FIELD_PASSWORD_CONFIRM);
                context.error(Errors.INVALID_REGISTRATION);
                context.validationError(formData, List.of(new FormMessage(null, MSG_REGISTRATION_UNAVAILABLE)));
                return;
            }
            context.success();
            return;
        }
    }

    @Override
    public void success(FormContext context) {
        // no-op
    }

    @Override
    public void buildPage(FormContext context, LoginFormsProvider form) {
        // no additional attributes
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }

    private static String resolveUsername(ValidationContext context, MultivaluedMap<String, String> formData) {
        if (context.getRealm().isRegistrationEmailAsUsername()) {
            return nullSafe(formData.getFirst(RegistrationPage.FIELD_EMAIL));
        }
        return nullSafe(formData.getFirst(RegistrationPage.FIELD_USERNAME));
    }

    private static String nullSafe(String value) {
        return value == null ? "" : value;
    }
}
