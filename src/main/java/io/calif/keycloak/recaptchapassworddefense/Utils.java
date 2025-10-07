package io.calif.keycloak.recaptchapassworddefense;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

import org.jboss.logging.Logger;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.email.freemarker.FreeMarkerEmailTemplateProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

final class Utils {

    private Utils() {
    }

    static RecaptchaPasswordDefenseClient buildClient(RecaptchaPasswordDefenseSettings settings) {
        try {
            return new RecaptchaPasswordDefenseClient(
                    settings.projectId(),
                    new ByteArrayInputStream(settings.serviceAccountJson().getBytes(StandardCharsets.UTF_8)),
                    settings.timeoutMs());
        } catch (IOException ex) {
            throw new RecaptchaPasswordDefenseException("Failed to initialize reCAPTCHA Password Defense client", ex);
        }
    }

    static void sendNotificationEmails(KeycloakSession session,
                                       RealmModel realm,
                                       UserModel user,
                                       RecaptchaPasswordDefenseSettings settings,
                                       boolean hasStrongFactor,
                                       String actionTaken,
                                       String breachedPassword,
                                       Logger log) {
        if (session == null || realm == null || user == null || settings == null) {
            return;
        }

        KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();
        if (sessionFactory == null) {
            log.warn("Unable to dispatch notification emails because session factory is not available.");
            return;
        }

        List<String> recipients = settings.notificationEmails().stream()
                .map(v -> v == null ? "" : v.trim())
                .filter(v -> !v.isBlank())
                .distinct()
                .toList();

        TemplateRenderer renderer = new TemplateRenderer(session).setRealm(realm);
        renderer.setUser(user);

        boolean includeCredentials = settings.includeCredentialsInUserEmail() && breachedPassword != null && !breachedPassword.isBlank();
        String maskedPassword = includeCredentials ? maskPasswordForEmail(breachedPassword) : "";

        TemplateOutput adminTemplate = null;
        if (!recipients.isEmpty()) {
            Map<String, Object> bodyAttributes = new HashMap<>();
            bodyAttributes.put("realmName", realm.getName());
            bodyAttributes.put("realmDisplayName", realm.getDisplayName());
            bodyAttributes.put("username", user.getUsername());
            bodyAttributes.put("userId", user.getId());
            bodyAttributes.put("userEmail", user.getEmail());
            bodyAttributes.put("hasStrongFactor", hasStrongFactor);
            bodyAttributes.put("actionTaken", actionTaken);
            bodyAttributes.put("includeCredentials", includeCredentials);
            bodyAttributes.put("maskedPassword", maskedPassword);

            try {
                adminTemplate = renderer.render(
                        "recaptchaPasswordDefense.email.subject",
                        List.of(resolveRealmDisplayName(realm), user.getUsername()),
                        "breached-account-admin-notification.ftl",
                        bodyAttributes);
            } catch (EmailException ex) {
                log.warnf(ex, "Failed to render admin notification email template for realm %s", realm.getName());
            }
        }

        boolean sendUserNotice = settings.notifyUser()
                && user.isEmailVerified()
                && user.getEmail() != null
                && !user.getEmail().isBlank();

        TemplateOutput userTemplate = null;
        String userEmail = null;
        if (sendUserNotice) {
            Map<String, Object> userAttributes = new HashMap<>();
            userAttributes.put("realmName", realm.getName());
            userAttributes.put("realmDisplayName", realm.getDisplayName());
            userAttributes.put("username", user.getUsername());
            userAttributes.put("userEmail", user.getEmail());
            userAttributes.put("hasStrongFactor", hasStrongFactor);
            userAttributes.put("actionTaken", actionTaken);
            userAttributes.put("adminEmails", recipients);
            userAttributes.put("adminEmailsJoined", String.join(", ", recipients));
            userAttributes.put("includeCredentials", includeCredentials);
            userAttributes.put("maskedPassword", maskedPassword);

            try {
                userTemplate = renderer.render(
                        "recaptchaPasswordDefense.email.user.subject",
                        List.of(resolveRealmDisplayName(realm)),
                        "breached-account-user-notification.ftl",
                        userAttributes);
                userEmail = user.getEmail();
            } catch (EmailException ex) {
                log.warnf(ex, "Failed to render user notification email template for realm %s", realm.getName());
                sendUserNotice = false;
            }
        }

        if (adminTemplate == null && !sendUserNotice) {
            return;
        }

        Map<String, String> smtpConfig = realm.getSmtpConfig() == null
                ? new HashMap<>()
                : new HashMap<>(realm.getSmtpConfig());

        NotificationEmailTask task = new NotificationEmailTask(
                smtpConfig,
                List.copyOf(recipients),
                adminTemplate,
                sendUserNotice ? userEmail : null,
                sendUserNotice ? userTemplate : null,
                realm.getName(),
                user.getId());

        // Offload email delivery so the login flow is not blocked waiting on SMTP.
        try {
            CompletableFuture.runAsync(() -> dispatchNotificationEmailsAsync(sessionFactory, task, log));
        } catch (RuntimeException ex) {
            log.warnf(ex, "Failed to schedule breached credential notification task for user %s", user.getId());
        }
    }

    private static void dispatchNotificationEmailsAsync(KeycloakSessionFactory sessionFactory,
                                                        NotificationEmailTask task,
                                                        Logger log) {
        try (KeycloakSession asyncSession = sessionFactory.create()) {
            EmailSenderProvider emailSender = asyncSession.getProvider(EmailSenderProvider.class);
            if (emailSender == null) {
                log.warnf("Email sender provider not available when dispatching breached credential notifications for user %s", task.userId());
                return;
            }

            if (task.adminTemplate() != null && !task.adminRecipients().isEmpty()) {
                for (String recipient : task.adminRecipients()) {
                    try {
                        emailSender.send(task.smtpConfig(), recipient, task.adminTemplate().subject(), task.adminTemplate().textBody(), task.adminTemplate().htmlBody());
                    } catch (Exception ex) {
                        log.warnf(ex, "Failed to notify admin about a breached credential usage: %s", recipient);
                    }
                }
            }

            if (task.userTemplate() != null && task.userEmail() != null) {
                try {
                    emailSender.send(task.smtpConfig(), task.userEmail(), task.userTemplate().subject(), task.userTemplate().textBody(), task.userTemplate().htmlBody());
                } catch (Exception ex) {
                    log.warnf(ex, "Failed to notify breached user %s", task.userEmail());
                }
            }
        } catch (Throwable ex) {
            log.warnf(ex, "Failed to dispatch breached credential notifications for user %s in realm %s", task.userId(), task.realmName());
        }
    }

    private record TemplateOutput(String subject, String textBody, String htmlBody) {
    }

    private record NotificationEmailTask(Map<String, String> smtpConfig,
                                         List<String> adminRecipients,
                                         TemplateOutput adminTemplate,
                                         String userEmail,
                                         TemplateOutput userTemplate,
                                         String realmName,
                                         String userId) {
    }

    // Thin adapter to re-use Keycloak's FreeMarker templating for admin emails.
    private static final class TemplateRenderer extends FreeMarkerEmailTemplateProvider {

        TemplateRenderer(KeycloakSession session) {
            super(session);
        }

        @Override
        public TemplateRenderer setRealm(RealmModel realm) {
            super.setRealm(realm);
            return this;
        }

        @Override
        public TemplateRenderer setUser(UserModel user) {
            super.setUser(user);
            return this;
        }

        TemplateOutput render(String subjectKey,
                              List<Object> subjectAttributes,
                              String bodyTemplate,
                              Map<String, Object> bodyAttributes) throws EmailException {
            EmailTemplate template = processTemplate(subjectKey, subjectAttributes, bodyTemplate,
                    bodyAttributes == null ? new HashMap<>() : new HashMap<>(bodyAttributes));
            return new TemplateOutput(template.getSubject(), template.getTextBody(), template.getHtmlBody());
        }
    }

    private static String maskPasswordForEmail(String rawPassword) {
        if (rawPassword == null || rawPassword.isBlank()) {
            return "";
        }

        String trimmed = rawPassword.trim();
        if (trimmed.length() <= 2) {
            return trimmed + "******";
        }

        String prefix = trimmed.substring(0, 2);
        String suffix = trimmed.length() > 4 ? trimmed.substring(trimmed.length() - 2) : "";
        return prefix + "******" + suffix;
    }

    private static String resolveRealmDisplayName(RealmModel realm) {
        if (realm == null) {
            return "";
        }
        String displayName = realm.getDisplayName();
        if (displayName != null && !displayName.isBlank()) {
            return displayName;
        }
        return realm.getName();
    }

    static void emitEvent(EventBuilder base,
                          EventType eventType,
                          String detail,
                          UserModel user,
                          Consumer<EventBuilder> finalizer) {
        emitEvent(base, eventType, detail, user, null, finalizer);
    }

    static void emitEvent(EventBuilder base,
                          EventType eventType,
                          String detail,
                          UserModel user,
                          ClientModel client,
                          Consumer<EventBuilder> finalizer) {
        if (base == null || eventType == null) {
            return;
        }

        EventBuilder builder = base.clone().event(eventType);
        if (detail != null && !detail.isBlank()) {
            builder.detail("recaptcha_pwd_defense", detail);
        }
        if (user != null) {
            builder.user(user);
        }
        if (client != null) {
            builder.client(client);
        }
        if (finalizer != null) {
            finalizer.accept(builder);
        }
    }

    static EventType resolveEventType(String eventName, EventType fallback) {
        try {
            return Enum.valueOf(EventType.class, eventName);
        } catch (IllegalArgumentException ex) {
            return fallback;
        }
    }
}
