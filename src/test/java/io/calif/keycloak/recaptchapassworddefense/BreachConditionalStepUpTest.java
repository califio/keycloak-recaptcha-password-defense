package io.calif.keycloak.recaptchapassworddefense;

import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BreachConditionalStepUpTest {

    @Test
    void matchConditionReturnsFalseWhenAuthenticationSessionMissing() {
        AuthenticationFlowContext context = flowContextWithSession(null);
        assertFalse(BreachConditionalStepUp.SINGLETON.matchCondition(context));
    }

    @Test
    void matchConditionReturnsTrueWhenNoteIsTrueIgnoringCase() {
        AuthenticationFlowContext context = flowContextWithSession(sessionWithNote("TrUe"));
        assertTrue(BreachConditionalStepUp.SINGLETON.matchCondition(context));
    }

    @Test
    void matchConditionReturnsFalseWhenNoteIsAbsentOrFalse() {
        AuthenticationFlowContext contextWithoutNote = flowContextWithSession(sessionWithNote(null));
        assertFalse(BreachConditionalStepUp.SINGLETON.matchCondition(contextWithoutNote));

        AuthenticationFlowContext contextWithFalseNote = flowContextWithSession(sessionWithNote("false"));
        assertFalse(BreachConditionalStepUp.SINGLETON.matchCondition(contextWithFalseNote));
    }
    @Test
    void requiresUserIsTrue() {
        assertTrue(BreachConditionalStepUp.SINGLETON.requiresUser());
    }

    private AuthenticationFlowContext flowContextWithSession(AuthenticationSessionModel session) {
        InvocationHandler handler = (proxy, method, args) -> {
            if ("getAuthenticationSession".equals(method.getName())) {
                return session;
            }
            return defaultValue(method.getReturnType());
        };
        return (AuthenticationFlowContext) Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class[]{AuthenticationFlowContext.class},
                handler);
    }

    private AuthenticationSessionModel sessionWithNote(String note) {
        InvocationHandler handler = new AuthenticationSessionHandler(note);
        return (AuthenticationSessionModel) Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class[]{AuthenticationSessionModel.class},
                handler);
    }

    private Object defaultValue(Class<?> returnType) {
        if (returnType == boolean.class) {
            return false;
        }
        if (returnType == byte.class || returnType == short.class || returnType == int.class || returnType == long.class) {
            return 0;
        }
        if (returnType == float.class) {
            return 0f;
        }
        if (returnType == double.class) {
            return 0d;
        }
        if (returnType == char.class) {
            return '\0';
        }
        return null;
    }

    private static final class AuthenticationSessionHandler implements InvocationHandler {
        private String note;

        AuthenticationSessionHandler(String note) {
            this.note = note;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            String name = method.getName();
            if ("getAuthNote".equals(name) && args != null && args.length == 1) {
                return note;
            }
            if ("setAuthNote".equals(name) && args != null && args.length == 2) {
                if (RecaptchaPasswordDefenseSettings.NOTE_ACCOUNT_BREACHED.equals(args[0])) {
                    this.note = (String) args[1];
                }
                return null;
            }
            if ("getAuthNotes".equals(name)) {
                return note == null ? Map.of() : Map.of(RecaptchaPasswordDefenseSettings.NOTE_ACCOUNT_BREACHED, note);
            }
            Class<?> returnType = method.getReturnType();
            if (returnType == boolean.class) {
                return false;
            }
            if (returnType == byte.class || returnType == short.class || returnType == int.class || returnType == long.class) {
                return 0;
            }
            if (returnType == float.class) {
                return 0f;
            }
            if (returnType == double.class) {
                return 0d;
            }
            if (returnType == char.class) {
                return '\0';
            }
            return null;
        }
    }
}
