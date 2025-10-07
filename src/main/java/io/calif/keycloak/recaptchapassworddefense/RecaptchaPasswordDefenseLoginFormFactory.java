package io.calif.keycloak.recaptchapassworddefense;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class RecaptchaPasswordDefenseLoginFormFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {

    public static final String PROVIDER_ID = "recaptcha-password-defense-login";

    private static final List<ProviderConfigProperty> CONFIG =
            List.copyOf(RecaptchaPasswordDefenseSettings.configProperties(true));

    @Override
    public String getDisplayType() {
        return "Username Password Form with reCAPTCHA Password Defense";
    }

    @Override
    public String getReferenceCategory() {
        return "Password Verification";
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

    @Override
    public String getHelpText() {
        return "Validates username/password and checks against Google reCAPTCHA Password Defense. " +
               "If breached, either enforces step-up + password change or disables the account.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new RecaptchaPasswordDefenseLoginForm();
    }

    @Override
    public void init(Config.Scope config) { }

    @Override
    public void postInit(KeycloakSessionFactory factory) { }

    @Override
    public void close() { }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
