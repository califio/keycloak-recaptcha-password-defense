package io.calif.keycloak.recaptchapassworddefense;

/**
 * Signals that the reCAPTCHA Password Defense API could not complete successfully.
 */
class RecaptchaPasswordDefenseException extends RuntimeException {

    RecaptchaPasswordDefenseException(String message) {
        super(message);
    }

    RecaptchaPasswordDefenseException(String message, Throwable cause) {
        super(message, cause);
    }
}
