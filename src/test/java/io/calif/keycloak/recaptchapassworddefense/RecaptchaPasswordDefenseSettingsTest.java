package io.calif.keycloak.recaptchapassworddefense;

import org.junit.jupiter.api.Test;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class RecaptchaPasswordDefenseSettingsTest {

    @Test
    void fromConfigDefaultsWhenNull() {
        RecaptchaPasswordDefenseSettings settings = RecaptchaPasswordDefenseSettings.fromConfig(null);

        assertNull(settings.projectId());
        assertNull(settings.serviceAccountJson());
        assertEquals(RecaptchaPasswordDefenseSettings.DEFAULT_TIMEOUT_MS, settings.timeoutMs());
        assertEquals(List.of(), settings.notificationEmails());
        assertFalse(settings.failClosed());
        assertFalse(settings.doNotDisable());
        assertTrue(settings.notifyUser());
        assertTrue(settings.includeCredentialsInUserEmail());
    }

    @Test
    void fromConfigParsesValuesAndEmails() {
        Map<String, String> config = new HashMap<>();
        config.put(RecaptchaPasswordDefenseSettings.CFG_GCP_PROJECT_ID, "project-123");
        config.put(RecaptchaPasswordDefenseSettings.CFG_GCP_SERVICE_ACCOUNT, "{json}");
        config.put(RecaptchaPasswordDefenseSettings.CFG_TIMEOUT_MS, "5000");
        config.put(RecaptchaPasswordDefenseSettings.CFG_NOTIFICATION_EMAILS, " admin@example.com ##user@example.com##admin@example.com  ## ");
        config.put(RecaptchaPasswordDefenseSettings.CFG_FAIL_CLOSED, "true");
        config.put(RecaptchaPasswordDefenseSettings.CFG_DO_NOT_DISABLE, "true");
        config.put(RecaptchaPasswordDefenseSettings.CFG_NOTIFY_USER, "false");
        config.put(RecaptchaPasswordDefenseSettings.CFG_INCLUDE_CREDENTIALS, "false");

        RecaptchaPasswordDefenseSettings settings = RecaptchaPasswordDefenseSettings.fromConfig(config);

        assertEquals("project-123", settings.projectId());
        assertEquals("{json}", settings.serviceAccountJson());
        assertEquals(5000, settings.timeoutMs());
        assertEquals(List.of("admin@example.com", "user@example.com"), settings.notificationEmails());
        assertTrue(settings.failClosed());
        assertTrue(settings.doNotDisable());
        assertFalse(settings.notifyUser());
        assertFalse(settings.includeCredentialsInUserEmail());
    }

    @Test
    void fromConfigFallsBackWhenTimeoutInvalid() {
        Map<String, String> config = Map.of(
                RecaptchaPasswordDefenseSettings.CFG_GCP_PROJECT_ID, "project", 
                RecaptchaPasswordDefenseSettings.CFG_GCP_SERVICE_ACCOUNT, "json",
                RecaptchaPasswordDefenseSettings.CFG_TIMEOUT_MS, "not-a-number"
        );

        RecaptchaPasswordDefenseSettings settings = RecaptchaPasswordDefenseSettings.fromConfig(config);

        assertEquals(RecaptchaPasswordDefenseSettings.DEFAULT_TIMEOUT_MS, settings.timeoutMs());
    }

    @Test
    void hasNotConfiguredDetectsMissingOrBlankValues() {
        RecaptchaPasswordDefenseSettings missing = new RecaptchaPasswordDefenseSettings(null, null, 100, List.of(), false, false, true, true);
        assertTrue(missing.hasNotConfigured());

        RecaptchaPasswordDefenseSettings blank = new RecaptchaPasswordDefenseSettings("   ", "   ", 100, List.of(), false, false, true, true);
        assertTrue(blank.hasNotConfigured());

        RecaptchaPasswordDefenseSettings configured = new RecaptchaPasswordDefenseSettings("project", "json", 100, List.of(), false, false, true, true);
        assertFalse(configured.hasNotConfigured());
    }

    @Test
    void configPropertiesIncludeLoginSpecificFieldsWhenRequested() {
        List<ProviderConfigProperty> loginProperties = RecaptchaPasswordDefenseSettings.configProperties(true);
        List<String> names = loginProperties.stream().map(ProviderConfigProperty::getName).toList();

        assertTrue(names.contains(RecaptchaPasswordDefenseSettings.CFG_NOTIFICATION_EMAILS));
        assertTrue(names.contains(RecaptchaPasswordDefenseSettings.CFG_DO_NOT_DISABLE));
        assertTrue(names.contains(RecaptchaPasswordDefenseSettings.CFG_NOTIFY_USER));
        assertTrue(names.contains(RecaptchaPasswordDefenseSettings.CFG_INCLUDE_CREDENTIALS));
    }

    @Test
    void configPropertiesExcludeLoginSpecificFieldsWhenNotRequested() {
        List<ProviderConfigProperty> properties = RecaptchaPasswordDefenseSettings.configProperties(false);
        List<String> names = properties.stream().map(ProviderConfigProperty::getName).toList();

        assertFalse(names.contains(RecaptchaPasswordDefenseSettings.CFG_NOTIFICATION_EMAILS));
        assertFalse(names.contains(RecaptchaPasswordDefenseSettings.CFG_DO_NOT_DISABLE));
        assertFalse(names.contains(RecaptchaPasswordDefenseSettings.CFG_NOTIFY_USER));
        assertFalse(names.contains(RecaptchaPasswordDefenseSettings.CFG_INCLUDE_CREDENTIALS));
    }
}
