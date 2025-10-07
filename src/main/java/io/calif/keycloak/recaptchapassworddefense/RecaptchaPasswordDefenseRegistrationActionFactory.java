package io.calif.keycloak.recaptchapassworddefense;

import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class RecaptchaPasswordDefenseRegistrationActionFactory implements FormActionFactory {

    public static final String PROVIDER_ID = "recaptcha-password-defense-register";

    private static final List<ProviderConfigProperty> CONFIG =
            List.copyOf(RecaptchaPasswordDefenseSettings.configProperties(false));

    @Override
    public String getHelpText() {
        return "Checks the registration password against Google reCAPTCHA Password Defense and blocks breached passwords.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG;
    }

    @Override
    public FormAction create(KeycloakSession session) {
        return new RecaptchaPasswordDefenseRegistrationAction();
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Checking Password with reCAPTCHA Password Defense";
    }

    @Override
    public String getReferenceCategory() {
        return PasswordCredentialModel.TYPE;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[]{
                AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }
}
