package io.calif.keycloak.recaptchapassworddefense;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.models.RealmModel;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;

class UtilsTest {

    private static Method maskPassword;
    private static Method resolveRealmDisplayName;

    @BeforeAll
    static void setUpReflection() throws Exception {
        maskPassword = Utils.class.getDeclaredMethod("maskPasswordForEmail", String.class);
        maskPassword.setAccessible(true);

        resolveRealmDisplayName = Utils.class.getDeclaredMethod("resolveRealmDisplayName", RealmModel.class);
        resolveRealmDisplayName.setAccessible(true);
    }

    @Test
    void maskPasswordForEmailReturnsEmptyWhenInputMissing() throws Exception {
        assertEquals("", invokeMask(null));
        assertEquals("", invokeMask("   "));
    }

    @Test
    void maskPasswordForEmailPrefixOnlyWhenShort() throws Exception {
        assertEquals("a******", invokeMask("a"));
        assertEquals("ab******", invokeMask("ab"));
    }

    @Test
    void maskPasswordForEmailMasksPrefixAndSuffix() throws Exception {
        assertEquals("pa******d1", invokeMask("  password1  "));
        assertEquals("12******89", invokeMask("123456789"));
    }

    @Test
    void resolveRealmDisplayNamePrefersDisplayName() throws Exception {
        RealmModel realm = realm("realm-id", "Realm Display");
        assertEquals("Realm Display", invokeResolve(realm));
    }

    @Test
    void resolveRealmDisplayNameFallsBackToName() throws Exception {
        RealmModel realm = realm("realm-id", "   ");
        assertEquals("realm-id", invokeResolve(realm));
    }

    @Test
    void resolveRealmDisplayNameReturnsEmptyWhenRealmNull() throws Exception {
        assertEquals("", invokeResolve(null));
    }

    private String invokeMask(String password) throws Exception {
        return (String) maskPassword.invoke(null, password);
    }

    private String invokeResolve(RealmModel realm) throws Exception {
        return (String) resolveRealmDisplayName.invoke(null, realm);
    }

    private RealmModel realm(String name, String displayName) {
        return (RealmModel) Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class[]{RealmModel.class},
                (proxy, method, args) -> {
                    String methodName = method.getName();
                    if ("getDisplayName".equals(methodName)) {
                        return displayName;
                    }
                    if ("getName".equals(methodName)) {
                        return name;
                    }
                    Class<?> returnType = method.getReturnType();
                    if (returnType.isPrimitive()) {
                        if (returnType == boolean.class) {
                            return false;
                        }
                        return 0;
                    }
                    return null;
                });
    }
}
