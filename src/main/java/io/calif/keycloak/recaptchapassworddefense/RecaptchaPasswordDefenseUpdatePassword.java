package io.calif.keycloak.recaptchapassworddefense;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticatorUtil;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.authentication.requiredactions.UpdatePassword;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelException;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.ArrayList;
import java.util.List;

/**
 * Override of Keycloak's UpdatePassword required action that calls reCAPTCHA Password Defense before accepting
 * a new password (used for both password updates and reset flows).
 */
public class RecaptchaPasswordDefenseUpdatePassword extends UpdatePassword {

    private static final Logger LOG = Logger.getLogger(RecaptchaPasswordDefenseUpdatePassword.class);

    private static final String MSG_UPDATE_PASSWORD_BREACHED = "recaptchaPasswordDefense.updatePassword.breached";
    private static final String MSG_UPDATE_PASSWORD_UNAVAILABLE = "recaptchaPasswordDefense.updatePassword.unavailable";

    private static final EventType UPDATE_CREDENTIAL_EVENT = Utils.resolveEventType("UPDATE_CREDENTIAL", EventType.UPDATE_PASSWORD);
    private static final EventType UPDATE_CREDENTIAL_ERROR_EVENT = Utils.resolveEventType("UPDATE_CREDENTIAL_ERROR", EventType.UPDATE_PASSWORD_ERROR);

    @Override
    public void processAction(RequiredActionContext context) {
        EventBuilder event = context.getEvent();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        UserModel user = context.getUser();
        if (user == null) {
            LOG.warn("Update password required action invoked without an authenticated user; skipping password defense check.");
            context.success();
            return;
        }

        ClientModel client = authSession != null ? authSession.getClient() : null;
        String username = user.getUsername();
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        event.user(user);
        event.client(client);
        event.event(UPDATE_CREDENTIAL_EVENT);
        event.detail(Details.CREDENTIAL_TYPE, PasswordCredentialModel.PASSWORD);

        boolean emitLegacyEvents = UPDATE_CREDENTIAL_EVENT != EventType.UPDATE_PASSWORD
                || UPDATE_CREDENTIAL_ERROR_EVENT != EventType.UPDATE_PASSWORD_ERROR;

        String passwordNew = formData.getFirst("password-new");
        String passwordConfirm = formData.getFirst("password-confirm");

        if (Validation.isBlank(passwordNew)) {
            Response challenge = context.form()
                    .setAttribute("username", username)
                    .addError(new FormMessage(Validation.FIELD_PASSWORD, Messages.MISSING_PASSWORD))
                    .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
            context.challenge(challenge);
            Utils.emitEvent(event, UPDATE_CREDENTIAL_ERROR_EVENT, null, user, client,
                    builder -> builder.error(Errors.PASSWORD_MISSING));
            if (emitLegacyEvents) {
                Utils.emitEvent(event, EventType.UPDATE_PASSWORD_ERROR, null, user, client,
                        builder -> builder.error(Errors.PASSWORD_MISSING));
            }
            return;
        } else if (!passwordNew.equals(passwordConfirm)) {
            Response challenge = context.form()
                    .setAttribute("username", username)
                    .addError(new FormMessage(Validation.FIELD_PASSWORD_CONFIRM, Messages.NOTMATCH_PASSWORD))
                    .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
            context.challenge(challenge);
            Utils.emitEvent(event, UPDATE_CREDENTIAL_ERROR_EVENT, null, user, client,
                    builder -> builder.error(Errors.PASSWORD_CONFIRM_ERROR));
            if (emitLegacyEvents) {
                Utils.emitEvent(event, EventType.UPDATE_PASSWORD_ERROR, null, user, client,
                        builder -> builder.error(Errors.PASSWORD_CONFIRM_ERROR));
            }
            return;
        }

        boolean logoutRequested = "on".equals(formData.getFirst("logout-sessions"));

        RecaptchaPasswordDefenseSettings settings = RecaptchaPasswordDefenseSettings.fromConfig(
                RequiredActionConfigCompat.resolve(context));

        if (settings.hasNotConfigured()) {
            LOG.warn("reCAPTCHA service account is not configured for password updates; skipping password defense check.");
        } else {
            try {
                RecaptchaPasswordDefenseClient defenseClient = Utils.buildClient(settings);
                if (defenseClient.isLeaked(username, passwordNew)) {
                    Utils.emitEvent(event, UPDATE_CREDENTIAL_ERROR_EVENT, "breached_update_password", user, client,
                            builder -> builder.error(Errors.PASSWORD_REJECTED));
                    if (emitLegacyEvents) {
                        Utils.emitEvent(event, EventType.UPDATE_PASSWORD_ERROR, "breached_update_password", user, client,
                                builder -> builder.error(Errors.PASSWORD_REJECTED));
                    }

                    Response challenge = context.form()
                            .setAttribute("username", username)
                            .addError(new FormMessage(Validation.FIELD_PASSWORD, MSG_UPDATE_PASSWORD_BREACHED))
                            .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
                    context.challenge(challenge);

                    return;
                }
            } catch (Exception ex) {
                LOG.warn("Password defense check failed during password update", ex);
                if (settings.failClosed()) {
                    Utils.emitEvent(event, UPDATE_CREDENTIAL_ERROR_EVENT, "update_password_api_failure", user, client,
                            builder -> builder.error(Errors.PASSWORD_REJECTED));
                    if (emitLegacyEvents) {
                        Utils.emitEvent(event, EventType.UPDATE_PASSWORD_ERROR, "update_password_api_failure", user, client,
                                builder -> builder.error(Errors.PASSWORD_REJECTED));
                    }
                    Response challenge = context.form()
                            .setAttribute("username", username)
                            .setError(MSG_UPDATE_PASSWORD_UNAVAILABLE)
                            .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
                    context.challenge(challenge);
                    return;
                }
            }
        }

        if (logoutRequested) {
            AuthenticatorUtil.logoutOtherSessions(context);
        }

        try {
            user.credentialManager().updateCredential(UserCredentialModel.password(passwordNew, false));
            context.success();
            if (emitLegacyEvents) {
                event.success();
            }
        } catch (ModelException me) {
            Utils.emitEvent(event, UPDATE_CREDENTIAL_ERROR_EVENT, null, user, client,
                    builder -> builder.detail(Details.REASON, me.getMessage()).error(Errors.PASSWORD_REJECTED));
            if (emitLegacyEvents) {
                Utils.emitEvent(event, EventType.UPDATE_PASSWORD_ERROR, null, user, client,
                        builder -> builder.detail(Details.REASON, me.getMessage()).error(Errors.PASSWORD_REJECTED));
            }
            Response challenge = context.form()
                    .setAttribute("username", username)
                    .setError(me.getMessage(), me.getParameters())
                    .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
            context.challenge(challenge);
        } catch (Exception ape) {
            Utils.emitEvent(event, UPDATE_CREDENTIAL_ERROR_EVENT, null, user, client,
                    builder -> builder.detail(Details.REASON, ape.getMessage()).error(Errors.PASSWORD_REJECTED));
            if (emitLegacyEvents) {
                Utils.emitEvent(event, EventType.UPDATE_PASSWORD_ERROR, null, user, client,
                        builder -> builder.detail(Details.REASON, ape.getMessage()).error(Errors.PASSWORD_REJECTED));
            }
            Response challenge = context.form()
                    .setAttribute("username", username)
                    .setError(ape.getMessage())
                    .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
            context.challenge(challenge);
        }
    }

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return new RecaptchaPasswordDefenseUpdatePassword();
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        List<ProviderConfigProperty> properties = new ArrayList<>(RecaptchaPasswordDefenseSettings.configProperties(false));
        properties.addAll(super.getConfigMetadata());
        return properties;
    }

}
