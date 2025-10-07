package io.calif.keycloak.recaptchapassworddefense;

import org.jboss.logging.Logger;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionConfigModel;
import org.keycloak.models.RequiredActionProviderModel;
import org.keycloak.models.UserModel;

import java.util.Collections;
import java.util.Map;

/**
 * Resolves required action configuration across Keycloak versions. Older releases did not expose
 * {@link RequiredActionContext#getConfig()}, so we fall back to reading the realm configuration directly.
 */
final class RequiredActionConfigCompat {

    private static final Logger LOG = Logger.getLogger(RequiredActionConfigCompat.class);

    private RequiredActionConfigCompat() {
    }

    static Map<String, String> resolve(RequiredActionContext context) {
        if (context == null) {
            return Collections.emptyMap();
        }

        Map<String, String> config = resolveFromContext(context);
        if (!config.isEmpty()) {
            return config;
        }

        return resolveFromRealm(context);
    }

    private static Map<String, String> resolveFromContext(RequiredActionContext context) {
        try {
            RequiredActionConfigModel model = context.getConfig();
            if (model == null) {
                return Collections.emptyMap();
            }
            Map<String, String> config = model.getConfig();
            return config == null ? Collections.emptyMap() : config;
        } catch (NoSuchMethodError ex) {
            // Older Keycloak versions lack RequiredActionContext#getConfig().
            return Collections.emptyMap();
        }
    }

    private static Map<String, String> resolveFromRealm(RequiredActionContext context) {
        RealmModel realm = null;
        try {
            realm = context.getRealm();
        } catch (RuntimeException ex) {
            LOG.debug("Unable to access realm when resolving required action config", ex);
            return Collections.emptyMap();
        }

        if (realm == null) {
            return Collections.emptyMap();
        }

        String actionAlias = resolveActionAlias(context);

        Map<String, String> config = tryProviderModel(realm, actionAlias);
        if (config != null && !config.isEmpty()) {
            return config;
        }

        Map<String, String> legacyConfig = tryConfigModel(realm, actionAlias);
        return legacyConfig == null ? Collections.emptyMap() : legacyConfig;
    }

    private static Map<String, String> tryProviderModel(RealmModel realm, String actionAlias) {
        try {
            RequiredActionProviderModel model = realm.getRequiredActionProviderByAlias(actionAlias);
            if (model != null && model.getConfig() != null) {
                return model.getConfig();
            }
        } catch (NoSuchMethodError ex) {
            // Method added in newer Keycloak; ignore when absent.
        } catch (RuntimeException ex) {
            LOG.debug("Failed reading RequiredActionProviderModel config", ex);
        }
        return null;
    }

    private static Map<String, String> tryConfigModel(RealmModel realm, String actionAlias) {
        try {
            RequiredActionConfigModel model = realm.getRequiredActionConfigByAlias(actionAlias);
            if (model != null && model.getConfig() != null) {
                return model.getConfig();
            }
        } catch (NoSuchMethodError ex) {
            // Older releases may not support this lookup; ignore.
        } catch (RuntimeException ex) {
            LOG.debug("Failed reading RequiredActionConfigModel config", ex);
        }
        return null;
    }

    private static String resolveActionAlias(RequiredActionContext context) {
        try {
            String action = context.getAction();
            if (action != null && !action.isBlank()) {
                return action;
            }
        } catch (NoSuchMethodError ex) {
            // getAction() was introduced in newer Keycloak versions.
        } catch (RuntimeException ex) {
            LOG.debug("Failed to obtain required action alias from context", ex);
        }

        // Our provider overrides the built-in UpdatePassword required action.
        return UserModel.RequiredAction.UPDATE_PASSWORD.name();
    }
}
