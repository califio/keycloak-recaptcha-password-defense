package io.calif.keycloak.recaptchapassworddefense;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class BreachConditionalStepUp implements ConditionalAuthenticator {

    public static final BreachConditionalStepUp SINGLETON = new BreachConditionalStepUp();

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        if (context.getAuthenticationSession() == null) {
            return false;
        }
        String breachedNote = context.getAuthenticationSession()
                .getAuthNote(RecaptchaPasswordDefenseSettings.NOTE_ACCOUNT_BREACHED);
        return breachedNote != null && breachedNote.equalsIgnoreCase("true");
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // no-op
    }

    @Override
    public boolean requiresUser() {
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
}
