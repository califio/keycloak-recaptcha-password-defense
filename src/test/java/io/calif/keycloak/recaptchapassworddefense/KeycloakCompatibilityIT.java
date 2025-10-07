package io.calif.keycloak.recaptchapassworddefense;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.io.IOException;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class KeycloakCompatibilityIT {

    private static final String ADMIN_USER = "admin";
    private static final String ADMIN_PASSWORD = "admin";
    private static final String ADMIN_CLIENT_ID = "admin-cli";
    private static final int KEYCLOAK_HTTP_PORT = 8080;
    private static final String UPDATE_PASSWORD_ALIAS = "UPDATE_PASSWORD";
    private static final String TEST_PROJECT_ID = "compatibility-tests";
    private static final String TEST_SERVICE_ACCOUNT = "{\"type\":\"service_account\",\"client_email\":\"compat@test\"}";
    private static final String BROKEN_SERVICE_ACCOUNT = "{\"type\":\"service_account\",\"project_id\":\"broken\"}";
    private static final String ACCOUNT_CLIENT_ID = "account-console";
    private static final String ACCOUNT_REDIRECT_PATH = "/realms/master/account/";
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HttpClient HTTP = newHttpClientBuilder().build();
    private static final SecureRandom RNG = new SecureRandom();

    private static String propertyOrEnv(String propertyKey, String envKey) {
        String value = System.getProperty(propertyKey);
        if (value == null || value.isBlank()) {
            value = System.getenv(envKey);
        }
        return (value == null || value.isBlank()) ? null : value;
    }

    private static HttpClient.Builder newHttpClientBuilder() {
        HttpClient.Builder builder = HttpClient.newBuilder();
        resolveProxySelector().ifPresent(builder::proxy);
        return builder;
    }

    private static Optional<ProxySelector> resolveProxySelector() {
        String value = propertyOrEnv("compatibility.http.proxy", "COMPATIBILITY_HTTP_PROXY");
        if (value == null) {
            return Optional.empty();
        }

        String normalized = value.contains("://") ? value : "http://" + value;
        try {
            URI uri = URI.create(normalized);
            String host = uri.getHost();
            int port = uri.getPort();
            if (host == null || host.isBlank() || port == -1) {
                throw new IllegalArgumentException("Proxy must include host and port");
            }
            return Optional.of(ProxySelector.of(new InetSocketAddress(host, port)));
        } catch (IllegalArgumentException ex) {
            throw new IllegalStateException("Invalid compatibility.http.proxy value: " + value, ex);
        }
    }

    @BeforeAll
    static void requireDocker() {
        Assumptions.assumeTrue(isDockerAvailable(), "Docker is required for Keycloak compatibility tests");
    }

    static Stream<String> keycloakVersions() {
        return resolveVersions().stream();
    }

    private static void withKeycloak(String version, KeycloakScenario scenario) throws Exception {
        Path providerJar = resolveProviderJar();
        DockerImageName image = DockerImageName.parse("quay.io/keycloak/keycloak").withTag(version);

        try (GenericContainer<?> keycloak = new GenericContainer<>(image)
                .withEnv("KEYCLOAK_ADMIN", ADMIN_USER)
                .withEnv("KEYCLOAK_ADMIN_PASSWORD", ADMIN_PASSWORD)
                .withCommand("start-dev")
                .withExposedPorts(KEYCLOAK_HTTP_PORT)
                .withCopyFileToContainer(MountableFile.forHostPath(providerJar),
                        "/opt/keycloak/providers/" + providerJar.getFileName())
                .waitingFor(Wait.forHttp("/realms/master/.well-known/openid-configuration").forStatusCode(200))
                .withStartupTimeout(Duration.ofMinutes(2))) {

            keycloak.start();

            String baseUrl = "http://" + keycloak.getHost() + ":" + keycloak.getMappedPort(KEYCLOAK_HTTP_PORT);
            String token = fetchAdminToken(baseUrl);
            scenario.run(baseUrl, token);
        }
    }

    @ParameterizedTest(name = "Keycloak {0} registers providers")
    @MethodSource("keycloakVersions")
    void providersRegisterWithKeycloak(String version) throws Exception {
        withKeycloak(version, (baseUrl, token) -> {
            assertTrue(containsProvider(
                            fetchProviderMap(baseUrl, token, "/admin/realms/master/authentication/authenticator-providers"),
                            RecaptchaPasswordDefenseLoginFormFactory.PROVIDER_ID),
                    "Login form provider not registered for Keycloak " + version);

            assertTrue(containsProvider(
                            fetchProviderMap(baseUrl, token, "/admin/realms/master/authentication/form-action-providers"),
                            RecaptchaPasswordDefenseRegistrationActionFactory.PROVIDER_ID),
                    "Registration form action not registered for Keycloak " + version);
        });
    }

    @ParameterizedTest(name = "Keycloak {0} update password flow failClosed=true")
    @MethodSource("keycloakVersions")
    void updatePasswordApiFailureFailClosed(String version) throws Exception {
        withKeycloak(version, (baseUrl, token) -> runUpdatePasswordApiFailureScenario(baseUrl, token, true));
    }

    @ParameterizedTest(name = "Keycloak {0} update password flow failClosed=false")
    @MethodSource("keycloakVersions")
    void updatePasswordApiFailureFailOpen(String version) throws Exception {
        withKeycloak(version, (baseUrl, token) -> runUpdatePasswordApiFailureScenario(baseUrl, token, false));
    }

    @ParameterizedTest(name = "Keycloak {0} login flow failClosed=false")
    @MethodSource("keycloakVersions")
    void loginFlowApiFailureFailOpen(String version) throws Exception {
        withKeycloak(version, (baseUrl, token) -> runLoginFormApiFailureScenario(baseUrl, token, false));
    }

    @ParameterizedTest(name = "Keycloak {0} login flow failClosed=true")
    @MethodSource("keycloakVersions")
    void loginFlowApiFailureFailClosed(String version) throws Exception {
        withKeycloak(version, (baseUrl, token) -> runLoginFormApiFailureScenario(baseUrl, token, true));
    }

    @ParameterizedTest(name = "Keycloak {0} real configuration end-to-end")
    @MethodSource("keycloakVersions")
    void realConfigurationScenarios(String version) throws Exception {
        Optional<RealScenarioConfig> config = resolveRealScenarioConfig();
        Assumptions.assumeTrue(config.isPresent(), "Real scenario configuration not provided");
        withKeycloak(version, (baseUrl, token) -> runRealConfigScenario(baseUrl, token, config.get()));
    }

    private static boolean isDockerAvailable() {
        try {
            DockerClientFactory.instance().client();
            return true;
        } catch (Throwable ex) {
            return false;
        }
    }

    private static List<String> resolveVersions() {
        String override = propertyOrEnv("compatibility.keycloak.versions", "COMPATIBILITY_KEYCLOAK_VERSIONS");
        if (override != null && !override.isBlank()) {
            List<String> versions = Arrays.stream(override.split(","))
                    .map(String::trim)
                    .filter(entry -> !entry.isEmpty())
                    .toList();
            if (!versions.isEmpty()) {
                return versions;
            }
        }
        return List.of("22.0.5", "23.0.7", "24.0.5", "25.0.6", "26.4.0");
    }

    private static Path resolveProviderJar() {
        String buildDir = System.getProperty("project.build.directory", "target");
        try (Stream<Path> files = Files.list(Path.of(buildDir))) {
            return files
                    .filter(Files::isRegularFile)
                    .filter(path -> path.getFileName().toString().endsWith("-shaded.jar"))
                    .findFirst()
                    .map(Path::toAbsolutePath)
                    .orElseThrow(() -> new IllegalStateException("Could not find shaded provider jar in " + buildDir));
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to locate shaded provider jar", ex);
        }
    }

    private static String fetchAdminToken(String baseUrl) throws IOException, InterruptedException {
        String body = "grant_type=password&client_id=" + ADMIN_CLIENT_ID
                + "&username=" + ADMIN_USER
                + "&password=" + ADMIN_PASSWORD;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/realms/master/protocol/openid-connect/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();

        HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() >= 400) {
            throw new IllegalStateException("Failed to obtain admin token: HTTP " + response.statusCode() + " - " + response.body());
        }

        JsonNode json = MAPPER.readTree(response.body());
        JsonNode token = json.get("access_token");
        if (token == null || token.asText().isBlank()) {
            throw new IllegalStateException("Keycloak token response missing access_token: " + response.body());
        }
        return token.asText();
    }

    private static JsonNode fetchProviderMap(String baseUrl, String token, String path) throws IOException, InterruptedException {
        HttpResponse<String> response = sendGet(baseUrl + path, token);
        return MAPPER.readTree(response.body());
    }

    private static boolean containsProvider(JsonNode node, String providerId) {
        if (node == null || node.isNull()) {
            return false;
        }
        if (node.isObject()) {
            return node.has(providerId);
        }
        if (node.isArray()) {
            for (JsonNode item : node) {
                if (item == null || item.isNull()) {
                    continue;
                }
                if (item.isTextual() && providerId.equals(item.asText())) {
                    return true;
                }
                if (item.isObject()) {
                    JsonNode id = item.get("id");
                    if (id != null && providerId.equals(id.asText())) {
                        return true;
                    }
                    JsonNode provider = item.get("providerId");
                    if (provider != null && providerId.equals(provider.asText())) {
                        return true;
                    }
                    JsonNode alias = item.get("alias");
                    if (alias != null && providerId.equals(alias.asText())) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static void runUpdatePasswordApiFailureScenario(String baseUrl, String token, boolean failClosed)
            throws IOException, InterruptedException {
        String failClosedValue = Boolean.toString(failClosed);
        configureUpdatePasswordAction(baseUrl, token, TEST_PROJECT_ID, TEST_SERVICE_ACCOUNT, "4000", failClosedValue);
        assertUpdatePasswordConfig(baseUrl, token, TEST_PROJECT_ID, TEST_SERVICE_ACCOUNT, "4000", failClosedValue);

        String suffix = randomSuffix();
        String username = "dummy." + suffix;
        String email = username + "@example.com";
        String initialPassword = "Init-" + suffix + "!1";
        String newPassword = "New-" + suffix + "!2";

        String userId = createUser(baseUrl, token, username, email);
        try {
            setUserPassword(baseUrl, token, userId, initialPassword, true);

            PasswordUpdateResult result = attemptPasswordUpdate(baseUrl, username, initialPassword, newPassword);
            if (failClosed) {
                assertTrue(!result.success(), "failClosed=true should block password update when assessment fails");
                assertTrue(result.statusCode() == 200,
                        "Expected HTTP 200 with form error when failClosed=true, got " + result.statusCode());
                assertTrue(result.body().contains("We are unable to update your password"),
                        "Expected unavailable message in response body when failClosed=true");
            } else {
                assertTrue(result.success(), "failClosed=false should allow password update on assessment failure");
                assertTrue(canLoginWithoutRequiredAction(baseUrl, username, newPassword),
                        "User should be able to login with the new password when failClosed=false");
            }
        } finally {
            deleteUser(baseUrl, token, userId);
        }
    }

    private static Optional<RealScenarioConfig> resolveRealScenarioConfig() {
        if (!Boolean.parseBoolean(propertyOrEnv("compatibility.real.verifyBreach",
                "COMPATIBILITY_REAL_VERIFY_BREACH"))) {
            return Optional.empty();
        }

        String projectId = propertyOrEnv("compatibility.real.projectId",
                "COMPATIBILITY_REAL_PROJECT_ID");
        String serviceAccount = propertyOrEnv("compatibility.real.serviceAccount",
                "COMPATIBILITY_REAL_SERVICE_ACCOUNT");
        String timeoutMs = Optional.ofNullable(propertyOrEnv("compatibility.real.timeoutMs",
                "COMPATIBILITY_REAL_TIMEOUT_MS")).orElse("4000");
        String breachedPassword = Optional.ofNullable(propertyOrEnv("compatibility.real.breachedPassword",
                "COMPATIBILITY_REAL_BREACHED_PASSWORD")).orElse("qwerty123");
        String safePassword = Optional.ofNullable(propertyOrEnv("compatibility.real.safePassword",
                "COMPATIBILITY_REAL_SAFE_PASSWORD")).orElse("Safe-" + randomSuffix() + "!3");
        String username = Optional.ofNullable(propertyOrEnv("compatibility.real.username",
                "COMPATIBILITY_REAL_USERNAME")).orElse("user");
        String userEmail = Optional.ofNullable(propertyOrEnv("compatibility.real.email",
                "COMPATIBILITY_REAL_EMAIL")).orElse("user@example.com");

        if (projectId == null || serviceAccount == null) {
            throw new IllegalStateException(
                    "Real config verification requires projectId and serviceAccount via property or environment variable");
        }

        return Optional.of(new RealScenarioConfig(projectId, serviceAccount, timeoutMs, breachedPassword,
                safePassword, username, userEmail));
    }

    private static void runRealConfigScenario(String baseUrl,
                                              String token,
                                              RealScenarioConfig config)
            throws IOException, InterruptedException {
        configureUpdatePasswordAction(baseUrl, token, config.projectId(), config.serviceAccount(), config.timeoutMs(), "true");
        assertUpdatePasswordConfig(baseUrl, token, config.projectId(), config.serviceAccount(), config.timeoutMs(), "true");

        String suffix = randomSuffix();
        String username = config.username();
        String email = config.userEmail();
        String initialPassword = "Init-" + suffix + "!4";

        String userId = createUser(baseUrl, token, username, email);
        try {
            setUserPassword(baseUrl, token, userId, initialPassword, true);

            PasswordUpdateResult breachedAttempt = attemptPasswordUpdate(baseUrl, username, initialPassword, config.breachedPassword());
            assertTrue(!breachedAttempt.success(), "Breached password should be rejected when real config is active");
            assertTrue(breachedAttempt.body().contains("Your new password was found in a data breach"),
                    "Expected breached password warning in response body");

            PasswordUpdateResult safeAttempt = attemptPasswordUpdate(baseUrl, username, initialPassword, config.safePassword());
            assertTrue(safeAttempt.success(), "User should be able to select a safe password after breach rejection");
            assertTrue(canLoginWithoutRequiredAction(baseUrl, username, config.safePassword()),
                    "User should login without required action after setting a safe password");
        } finally {
            deleteUser(baseUrl, token, userId);
        }

        runRealConfigLoginScenario(baseUrl, token, config);
    }

    private static void runRealConfigLoginScenario(String baseUrl,
                                                   String token,
                                                   RealScenarioConfig config)
            throws IOException, InterruptedException {
        RecaptchaLoginConfig loginConfig = new RecaptchaLoginConfig(config.projectId(), config.serviceAccount(),
                config.timeoutMs(), true, false);
        LoginFlowContext flowContext = configureRecaptchaLoginFlow(baseUrl, token, loginConfig);

        String userId = null;
        String email = config.userEmail();
        try {
            userId = createUser(baseUrl, token, config.username(), email, false);
            setUserPassword(baseUrl, token, userId, config.breachedPassword(), false);

            LoginAttemptResult breachedAttempt = attemptBrowserLogin(baseUrl, config.username(),
                    config.breachedPassword());
            assertTrue(breachedAttempt.statusCode() == 403,
                    "Breached login should return HTTP 403 when password defense disables the account; got "
                            + breachedAttempt.statusCode());
            assertTrue(breachedAttempt.body().contains("temporarily disabled"),
                    "Expected disabled account message when breached login is detected");

            setUserEnabled(baseUrl, token, userId, true);
            setUserPassword(baseUrl, token, userId, config.safePassword(), false);

            LoginAttemptResult safeAttempt = attemptBrowserLogin(baseUrl, config.username(), config.safePassword());
            boolean redirected = safeAttempt.statusCode() == 302
                    && safeAttempt.location() != null
                    && safeAttempt.location().contains(ACCOUNT_REDIRECT_PATH);
            assertTrue(redirected,
                    "User should be able to login with a safe password after remediation; response was HTTP "
                            + safeAttempt.statusCode() + " -> " + safeAttempt.location());
        } finally {
            if (userId != null) {
                deleteUser(baseUrl, token, userId);
            }
            cleanupRecaptchaLoginFlow(baseUrl, token, flowContext);
        }
    }

    private static void runLoginFormApiFailureScenario(String baseUrl, String token, boolean failClosed)
            throws IOException, InterruptedException {
        LoginFlowContext flowContext = configureRecaptchaLoginFlow(baseUrl, token, failClosed);
        String suffix = randomSuffix();
        String username = "login." + suffix;
        String email = username + "@example.com";
        String password = "Login-" + suffix + "!1";

        String userId = null;
        try {
            userId = createUser(baseUrl, token, username, email, false);
            setUserPassword(baseUrl, token, userId, password, false);

            LoginAttemptResult attempt = attemptBrowserLogin(baseUrl, username, password);
            if (failClosed) {
                assertTrue(attempt.statusCode() == 503,
                        "failClosed=true should surface the login form failure as HTTP 503, got " + attempt.statusCode());
                assertTrue(attempt.body().contains("We are unable to complete your login at this time"),
                        "Expected unavailable login message when failClosed=true and password defense fails");
            } else {
                boolean redirected = attempt.statusCode() == 302
                        && attempt.location() != null
                        && attempt.location().contains(ACCOUNT_REDIRECT_PATH);
                assertTrue(redirected,
                        "failClosed=false should allow login when password defense fails; response was HTTP "
                                + attempt.statusCode() + " -> " + attempt.location());
            }
        } finally {
            if (userId != null) {
                deleteUser(baseUrl, token, userId);
            }
            cleanupRecaptchaLoginFlow(baseUrl, token, flowContext);
        }
    }

    private static void configureUpdatePasswordAction(String baseUrl,
                                                      String token,
                                                      String projectId,
                                                      String serviceAccount,
                                                      String timeoutMs,
                                                      String failClosed)
            throws IOException, InterruptedException {
        JsonNode requiredActions = fetchRequiredActions(baseUrl, token);
        JsonNode updatePassword = findRequiredAction(requiredActions, UPDATE_PASSWORD_ALIAS);
        if (updatePassword == null) {
            throw new IllegalStateException("Update Password required action not found");
        }

        ObjectNode payload = (ObjectNode) updatePassword.deepCopy();
        payload.put("enabled", true);
        payload.put("defaultAction", true);

        ObjectNode config = MAPPER.createObjectNode();
        config.put(RecaptchaPasswordDefenseSettings.CFG_GCP_PROJECT_ID, projectId);
        config.put(RecaptchaPasswordDefenseSettings.CFG_GCP_SERVICE_ACCOUNT, serviceAccount);
        config.put(RecaptchaPasswordDefenseSettings.CFG_TIMEOUT_MS, timeoutMs);
        config.put(RecaptchaPasswordDefenseSettings.CFG_FAIL_CLOSED, failClosed);
        payload.set("config", config);

        sendPut(baseUrl + "/admin/realms/master/authentication/required-actions/" + UPDATE_PASSWORD_ALIAS, token,
                payload.toString());
    }

    private static void assertUpdatePasswordConfig(String baseUrl,
                                                   String token,
                                                   String projectId,
                                                   String serviceAccount,
                                                   String timeoutMs,
                                                   String failClosed)
            throws IOException, InterruptedException {
        JsonNode refreshed = fetchRequiredActions(baseUrl, token);
        JsonNode updated = findRequiredAction(refreshed, UPDATE_PASSWORD_ALIAS);
        if (updated == null) {
            throw new IllegalStateException("Update Password required action disappeared after configuration");
        }

        JsonNode refreshedConfig = updated.get("config");
        if (refreshedConfig == null) {
            throw new IllegalStateException("Update Password config not present after update");
        }

        assertTrue(projectId.equals(refreshedConfig.path(RecaptchaPasswordDefenseSettings.CFG_GCP_PROJECT_ID).asText()),
                "Configured gcpProjectId not persisted");
        assertTrue(serviceAccount.equals(refreshedConfig.path(RecaptchaPasswordDefenseSettings.CFG_GCP_SERVICE_ACCOUNT).asText()),
                "Configured gcpServiceAccount not persisted");
        assertTrue(timeoutMs.equals(refreshedConfig.path(RecaptchaPasswordDefenseSettings.CFG_TIMEOUT_MS).asText()),
                "Configured timeoutMs not persisted");
        assertTrue(failClosed.equals(refreshedConfig.path(RecaptchaPasswordDefenseSettings.CFG_FAIL_CLOSED).asText()),
                "Configured failClosed not persisted");
    }

    private static String createUser(String baseUrl, String token, String username, String email)
            throws IOException, InterruptedException {
        return createUser(baseUrl, token, username, email, true);
    }

    private static String createUser(String baseUrl,
                                     String token,
                                     String username,
                                     String email,
                                     boolean requireUpdatePassword)
            throws IOException, InterruptedException {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("username", username);
        payload.put("email", email);
        payload.put("enabled", true);
        payload.put("emailVerified", true);
        if (requireUpdatePassword) {
            payload.putArray("requiredActions").add(UPDATE_PASSWORD_ALIAS);
        }

        HttpResponse<String> response = sendPost(baseUrl + "/admin/realms/master/users", token, payload.toString());
        if (response.statusCode() != 201) {
            throw new IllegalStateException("Failed to create test user: HTTP " + response.statusCode() + " - " + response.body());
        }

        Optional<String> location = response.headers().firstValue("Location");
        if (location.isPresent()) {
            String path = location.get();
            return path.substring(path.lastIndexOf('/') + 1);
        }

        HttpResponse<String> lookup = sendGet(baseUrl + "/admin/realms/master/users?username=" + urlEncode(username), token);
        JsonNode array = MAPPER.readTree(lookup.body());
        for (JsonNode node : array) {
            if (username.equalsIgnoreCase(node.path("username").asText())) {
                return node.path("id").asText();
            }
        }
        throw new IllegalStateException("Unable to determine user ID for " + username);
    }

    private static void deleteUser(String baseUrl, String token, String userId) throws IOException, InterruptedException {
        sendDelete(baseUrl + "/admin/realms/master/users/" + userId, token);
    }

    private static void setUserPassword(String baseUrl,
                                        String token,
                                        String userId,
                                        String password,
                                        boolean temporary)
            throws IOException, InterruptedException {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("type", "password");
        payload.put("value", password);
        payload.put("temporary", temporary);

        sendPut(baseUrl + "/admin/realms/master/users/" + userId + "/reset-password", token, payload.toString());
    }

    private static void setUserEnabled(String baseUrl,
                                       String token,
                                       String userId,
                                       boolean enabled)
            throws IOException, InterruptedException {
        HttpResponse<String> read = sendGet(baseUrl + "/admin/realms/master/users/" + userId, token);
        ObjectNode payload = (ObjectNode) MAPPER.readTree(read.body());
        payload.put("enabled", enabled);
        sendPut(baseUrl + "/admin/realms/master/users/" + userId, token, payload.toString());
    }

    // Keycloak >= 26 remove `_LEGACY` cookies, which make our test requests over HTTP protocol fail
    // https://www.keycloak.org/2024/10/keycloak-2600-released
    // This utility removes secure flags of all cookies for the sake of convenience
    private static void removeCookieSecureFlag(CookieManager cookies) {
        for (HttpCookie cookie : cookies.getCookieStore().getCookies()) {
            cookie.setSecure(false);
        }
    }

    private static PasswordUpdateResult attemptPasswordUpdate(String baseUrl,
                                                              String username,
                                                              String currentPassword,
                                                              String newPassword)
            throws IOException, InterruptedException {
        CookieManager cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        HttpClient browser = newHttpClientBuilder()
                .cookieHandler(cookies)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        String redirectUri = baseUrl + ACCOUNT_REDIRECT_PATH;
        Pkce pkce = generatePkce();
        String state = randomSuffix();
        URI authUri = buildAuthUri(baseUrl, redirectUri, pkce, state);

        HttpResponse<String> loginPage = browser.send(HttpRequest.newBuilder(authUri).GET().build(), HttpResponse.BodyHandlers.ofString());
        FormInfo loginForm = extractForm(loginPage.body(), "kc-form-login");
        URI loginUri = resolveToAbsolute(baseUrl, loginForm.action());

        Map<String, String> loginParams = new LinkedHashMap<>(loginForm.hidden());
        loginParams.put("username", username);
        loginParams.put("password", currentPassword);

        removeCookieSecureFlag(cookies);
        HttpResponse<String> loginResponse = browser.send(HttpRequest.newBuilder(loginUri)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(buildFormBody(loginParams), StandardCharsets.UTF_8))
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        if (loginResponse.statusCode() != 302) {
            throw new IllegalStateException("Unexpected login response: HTTP " + loginResponse.statusCode() + " - " + loginResponse.body());
        }

        URI requiredActionUri = resolveToAbsolute(baseUrl, loginResponse.headers().firstValue("Location")
                .orElseThrow(() -> new IllegalStateException("Missing required action redirect")));

        removeCookieSecureFlag(cookies);
        HttpResponse<String> updatePage = browser.send(HttpRequest.newBuilder(requiredActionUri).GET().build(), HttpResponse.BodyHandlers.ofString());
        FormInfo updateForm = extractForm(updatePage.body(), "kc-passwd-update-form");
        URI updateUri = resolveToAbsolute(baseUrl, updateForm.action());

        Map<String, String> updateParams = new LinkedHashMap<>(updateForm.hidden());
        updateParams.put("password-new", newPassword);
        updateParams.put("password-confirm", newPassword);

        removeCookieSecureFlag(cookies);
        HttpResponse<String> updateResponse = browser.send(HttpRequest.newBuilder(updateUri)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(buildFormBody(updateParams), StandardCharsets.UTF_8))
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        int status = updateResponse.statusCode();
        String location = updateResponse.headers().firstValue("Location").orElse(null);
        boolean success = (status == 302 || status == 303) && location != null && location.contains(ACCOUNT_REDIRECT_PATH);
        return new PasswordUpdateResult(success, status, updateResponse.body(), location);
    }

    private static LoginAttemptResult attemptBrowserLogin(String baseUrl,
                                                          String username,
                                                          String password)
            throws IOException, InterruptedException {
        CookieManager cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        HttpClient browser = newHttpClientBuilder()
                .cookieHandler(cookies)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        String redirectUri = baseUrl + ACCOUNT_REDIRECT_PATH;
        Pkce pkce = generatePkce();
        String state = randomSuffix();
        URI authUri = buildAuthUri(baseUrl, redirectUri, pkce, state);

        HttpResponse<String> loginPage = browser.send(HttpRequest.newBuilder(authUri).GET().build(), HttpResponse.BodyHandlers.ofString());
        FormInfo loginForm = extractForm(loginPage.body(), "kc-form-login");
        URI loginUri = resolveToAbsolute(baseUrl, loginForm.action());

        Map<String, String> loginParams = new LinkedHashMap<>(loginForm.hidden());
        loginParams.put("username", username);
        loginParams.put("password", password);

        removeCookieSecureFlag(cookies);
        HttpResponse<String> loginResponse = browser.send(HttpRequest.newBuilder(loginUri)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(buildFormBody(loginParams), StandardCharsets.UTF_8))
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        return new LoginAttemptResult(
                loginResponse.statusCode(),
                loginResponse.headers().firstValue("Location").orElse(null),
                loginResponse.body());
    }

    private static boolean canLoginWithoutRequiredAction(String baseUrl, String username, String password)
            throws IOException, InterruptedException {
        CookieManager cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        HttpClient browser = HttpClient.newBuilder()
                .cookieHandler(cookies)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        String redirectUri = baseUrl + ACCOUNT_REDIRECT_PATH;
        Pkce pkce = generatePkce();
        String state = randomSuffix();
        URI authUri = buildAuthUri(baseUrl, redirectUri, pkce, state);

        HttpResponse<String> loginPage = browser.send(HttpRequest.newBuilder(authUri).GET().build(), HttpResponse.BodyHandlers.ofString());
        FormInfo loginForm = extractForm(loginPage.body(), "kc-form-login");
        URI loginUri = resolveToAbsolute(baseUrl, loginForm.action());

        Map<String, String> loginParams = new LinkedHashMap<>(loginForm.hidden());
        loginParams.put("username", username);
        loginParams.put("password", password);

        removeCookieSecureFlag(cookies);
        HttpResponse<String> loginResponse = browser.send(HttpRequest.newBuilder(loginUri)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(buildFormBody(loginParams), StandardCharsets.UTF_8))
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        if (loginResponse.statusCode() != 302) {
            return false;
        }
        String location = loginResponse.headers().firstValue("Location").orElse("");
        if (location.isEmpty()) {
            return false;
        }
        return location.contains(ACCOUNT_REDIRECT_PATH);
    }

    private static URI resolveToAbsolute(String baseUrl, String action) {
        String decoded = htmlDecode(action);
        if (decoded.startsWith("http")) {
            return URI.create(decoded);
        }
        if (decoded.startsWith("/")) {
            return URI.create(baseUrl + decoded);
        }
        return URI.create(baseUrl + "/" + decoded);
    }

    private static FormInfo extractForm(String html, String formId) {
        Pattern pattern = Pattern.compile("(?is)<form[^>]*id\\s*=\\s*\"" + Pattern.quote(formId)
                + "\"[^>]*>(.*?)</form>");
        Matcher matcher = pattern.matcher(html);
        if (!matcher.find()) {
            throw new IllegalStateException("Unable to locate form with id=" + formId);
        }
        String formBlock = matcher.group(0);
        String action = Optional.ofNullable(extractAttribute(formBlock, "action"))
                .orElseThrow(() -> new IllegalStateException("Form " + formId + " is missing action attribute"));
        Map<String, String> hidden = extractHiddenInputs(matcher.group(1));
        return new FormInfo(action, hidden);
    }

    private static Map<String, String> extractHiddenInputs(String html) {
        Map<String, String> result = new LinkedHashMap<>();
        Pattern inputPattern = Pattern.compile("(?is)<input[^>]*>");
        Matcher matcher = inputPattern.matcher(html);
        while (matcher.find()) {
            String tag = matcher.group();
            String type = extractAttribute(tag, "type");
            if (type != null && !"hidden".equalsIgnoreCase(type.trim())) {
                continue;
            }
            String name = extractAttribute(tag, "name");
            if (name == null || name.isBlank()) {
                continue;
            }
            String value = Optional.ofNullable(extractAttribute(tag, "value")).orElse("");
            result.put(name, value);
        }
        return result;
    }

    private static String extractAttribute(String tag, String attribute) {
        Pattern pattern = Pattern.compile("(?i)" + attribute + "\\s*=\\s*\"([^\"]*)\"");
        Matcher matcher = pattern.matcher(tag);
        if (matcher.find()) {
            return htmlDecode(matcher.group(1));
        }
        return null;
    }

    private static String buildFormBody(Map<String, String> params) {
        StringBuilder body = new StringBuilder();
        boolean first = true;
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (!first) {
                body.append('&');
            }
            first = false;
            body.append(urlEncode(entry.getKey()))
                    .append('=')
                    .append(urlEncode(entry.getValue()));
        }
        return body.toString();
    }

    private static URI buildAuthUri(String baseUrl, String redirectUri, Pkce pkce, String state) {
        return URI.create(baseUrl + "/realms/master/protocol/openid-connect/auth?client_id=" + ACCOUNT_CLIENT_ID
                + "&redirect_uri=" + urlEncode(redirectUri)
                + "&response_type=code&scope=openid"
                + "&state=" + state
                + "&code_challenge_method=S256&code_challenge=" + pkce.challenge());
    }

    private static Pkce generatePkce() {
        String verifier = generateCodeVerifier();
        String challenge = generateCodeChallenge(verifier);
        return new Pkce(verifier, challenge);
    }

    private static String generateCodeVerifier() {
        byte[] bytes = new byte[64];
        RNG.nextBytes(bytes);
        return base64Url(bytes);
    }

    private static String generateCodeChallenge(String verifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return base64Url(hash);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 algorithm unavailable", ex);
        }
    }

    private static String base64Url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private static String htmlDecode(String value) {
        return value.replace("&amp;", "&");
    }

    private static String urlEncode(String value) {
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8)
                .replace("+", "%20");
    }

    private static String randomSuffix() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    private static LoginFlowContext configureRecaptchaLoginFlow(String baseUrl,
                                                                String token,
                                                                boolean failClosed)
            throws IOException, InterruptedException {
        return configureRecaptchaLoginFlow(baseUrl, token,
                new RecaptchaLoginConfig(TEST_PROJECT_ID, BROKEN_SERVICE_ACCOUNT, "500", failClosed, true));
    }

    private static LoginFlowContext configureRecaptchaLoginFlow(String baseUrl,
                                                                String token,
                                                                RecaptchaLoginConfig config)
            throws IOException, InterruptedException {
        String newAlias = "recaptcha-browser-" + randomSuffix();
        copyAuthenticationFlow(baseUrl, token, "browser", newAlias);

        JsonNode flows = fetchAuthenticationFlows(baseUrl, token);
        JsonNode copiedFlow = findFlowByAlias(flows, newAlias);
        if (copiedFlow == null) {
            throw new IllegalStateException("Copied browser flow not found: " + newAlias);
        }

        String flowId = copiedFlow.path("id").asText();
        if (flowId == null || flowId.isBlank()) {
            throw new IllegalStateException("Copied browser flow missing id for " + newAlias);
        }

        JsonNode formsExecutions = findFormsSubflow(baseUrl, token, newAlias);
        if (formsExecutions == null) {
            throw new IllegalStateException("forms subflow not present in flow " + newAlias);
        }

        String formsAlias = formsExecutions.path("alias").asText();
        if (formsAlias == null || formsAlias.isBlank()) {
            throw new IllegalStateException("Unable to resolve forms subflow alias for flow " + newAlias);
        }

        addExecutionToFlow(baseUrl, token, formsAlias, RecaptchaPasswordDefenseLoginFormFactory.PROVIDER_ID);

        formsExecutions = fetchFlowExecutions(baseUrl, token, newAlias);

        JsonNode usernamePassword = findExecutionByProvider(formsExecutions, "auth-username-password-form");
        if (usernamePassword != null) {
            deleteExecution(baseUrl, token, usernamePassword.path("id").asText());
        }
        JsonNode recaptchaExecution = findExecutionByProvider(formsExecutions, RecaptchaPasswordDefenseLoginFormFactory.PROVIDER_ID);
        if (recaptchaExecution == null) {
            throw new IllegalStateException("Recaptcha login execution not found in forms subflow " + formsAlias);
        }

        String recaptchaExecutionId = recaptchaExecution.path("id").asText();
        if (recaptchaExecutionId == null || recaptchaExecutionId.isBlank()) {
            throw new IllegalStateException("Recaptcha login execution missing id in subflow " + formsAlias);
        }

        updateExecutionRequirement(baseUrl, token, formsAlias, recaptchaExecutionId, "REQUIRED");
        raiseExecutionPriority(baseUrl, token, recaptchaExecutionId);
        configureRecaptchaLoginExecution(baseUrl, token, recaptchaExecutionId, config);

        selectBrowserFlow(baseUrl, token, "master", newAlias);
        return new LoginFlowContext(newAlias, flowId, recaptchaExecutionId);
    }

    private static void cleanupRecaptchaLoginFlow(String baseUrl,
                                                  String token,
                                                  LoginFlowContext context)
            throws IOException, InterruptedException {
        try {
            JsonNode flows = fetchAuthenticationFlows(baseUrl, token);
            JsonNode defaultBrowser = findFlowByAlias(flows, "browser");
            if (defaultBrowser != null) {
                String defaultId = defaultBrowser.path("id").asText();
                String defaultAlias = defaultBrowser.path("alias").asText("browser");
                if (defaultId != null && !defaultId.isBlank()) {
                    selectBrowserFlow(baseUrl, token, "master", defaultAlias);
                }
            }
        } finally {
            if (context != null && context.flowId() != null && !context.flowId().isBlank()) {
                try {
                    sendDelete(baseUrl + "/admin/realms/master/authentication/flows/" + context.flowId(), token);
                } catch (Exception ignored) {
                    // best-effort cleanup; ignore errors so the main assertion outcome is preserved
                }
            }
        }
    }

    private static void copyAuthenticationFlow(String baseUrl,
                                               String token,
                                               String sourceAlias,
                                               String newAlias)
            throws IOException, InterruptedException {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("newName", newAlias);
        sendPost(baseUrl + "/admin/realms/master/authentication/flows/" + urlEncode(sourceAlias) + "/copy",
                token, payload.toString());
    }

    private static JsonNode fetchAuthenticationFlows(String baseUrl, String token)
            throws IOException, InterruptedException {
        HttpResponse<String> response = sendGet(baseUrl + "/admin/realms/master/authentication/flows", token);
        return MAPPER.readTree(response.body());
    }

    private static JsonNode findFlowByAlias(JsonNode flows, String alias) {
        if (flows == null || !flows.isArray()) {
            return null;
        }
        for (JsonNode flow : flows) {
            if (flow != null && alias.equals(flow.path("alias").asText())) {
                return flow;
            }
        }
        return null;
    }

    private static JsonNode fetchRealm(String baseUrl, String token, String realm)
            throws IOException, InterruptedException {
        HttpResponse<String> response = sendGet(baseUrl + "/admin/realms/"
                + urlEncode(realm), token);
        return MAPPER.readTree(response.body());
    }

    private static JsonNode fetchFlowExecutions(String baseUrl, String token, String flowAlias)
            throws IOException, InterruptedException {
        HttpResponse<String> response = sendGet(baseUrl + "/admin/realms/master/authentication/flows/"
                + urlEncode(flowAlias) + "/executions", token);
        return MAPPER.readTree(response.body());
    }

    private static JsonNode fetchFlow(String baseUrl, String token, String flowId)
            throws IOException, InterruptedException {
        HttpResponse<String> response = sendGet(baseUrl + "/admin/realms/master/authentication/flows/"
                + urlEncode(flowId), token);
        return MAPPER.readTree(response.body());
    }

    private static JsonNode findExecutionByProvider(JsonNode executions, String providerId) {
        if (executions == null || !executions.isArray()) {
            return null;
        }
        for (JsonNode node : executions) {
            if (node != null && providerId.equals(node.path("providerId").asText())) {
                return node;
            }
        }
        return null;
    }

    private static JsonNode findFormsSubflow(String baseUrl, String token, String parentAlias)
            throws IOException, InterruptedException {
        JsonNode executions = fetchFlowExecutions(baseUrl, token, parentAlias);
        if (executions == null || !executions.isArray()) {
            return null;
        }
        String subflowId = "";
        for (JsonNode node : executions) {
            if (node == null) {
                continue;
            }
            boolean isFlow = node.path("authenticationFlow").asBoolean(false);
            if (isFlow && node.path("displayName").asText().contains("forms")) {
                subflowId = node.path("flowId").asText();
            }
        }

        JsonNode flow = fetchFlow(baseUrl, token, subflowId);
        if (flow == null || flow.isArray()) {
            return null;
        }

        return flow;
    }

    private static void raiseExecutionPriority(String baseUrl, String token, String executionId)
            throws IOException, InterruptedException {
        if (executionId == null || executionId.isBlank()) {
            return;
        }

        sendPost(baseUrl + "/admin/realms/master/authentication/executions/" + urlEncode(executionId) + "/raise-priority", token, "");
    }

    private static void deleteExecution(String baseUrl, String token, String executionId)
            throws IOException, InterruptedException {
        if (executionId == null || executionId.isBlank()) {
            return;
        }
        sendDelete(baseUrl + "/admin/realms/master/authentication/executions/" + urlEncode(executionId), token);
    }

    private static void updateExecutionRequirement(String baseUrl,
                                                   String token,
                                                   String flowAlias,
                                                   String executionId,
                                                   String requirement)
            throws IOException, InterruptedException {
        if (executionId == null || executionId.isBlank()) {
            return;
        }
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("id", executionId);
        payload.put("requirement", requirement);
        sendPut(baseUrl + "/admin/realms/master/authentication/flows/" + urlEncode(flowAlias) + "/executions",
                token, payload.toString());
    }

    private static void addExecutionToFlow(String baseUrl,
                                           String token,
                                           String flowAlias,
                                           String providerId)
            throws IOException, InterruptedException {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("provider", providerId);
        sendPost(baseUrl + "/admin/realms/master/authentication/flows/" + urlEncode(flowAlias) + "/executions/execution",
                token, payload.toString());
    }

    private static void configureRecaptchaLoginExecution(String baseUrl,
                                                         String token,
                                                         String executionId,
                                                         RecaptchaLoginConfig config)
            throws IOException, InterruptedException {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("alias", "recaptcha-login-config-" + randomSuffix());
        ObjectNode executionConfig = payload.putObject("config");
        executionConfig.put(RecaptchaPasswordDefenseSettings.CFG_GCP_PROJECT_ID, config.projectId());
        executionConfig.put(RecaptchaPasswordDefenseSettings.CFG_GCP_SERVICE_ACCOUNT, config.serviceAccount());
        executionConfig.put(RecaptchaPasswordDefenseSettings.CFG_TIMEOUT_MS, config.timeoutMs());
        executionConfig.put(RecaptchaPasswordDefenseSettings.CFG_FAIL_CLOSED, Boolean.toString(config.failClosed()));
        executionConfig.put(RecaptchaPasswordDefenseSettings.CFG_DO_NOT_DISABLE, Boolean.toString(config.doNotDisable()));

        sendPost(baseUrl + "/admin/realms/master/authentication/executions/" + executionId + "/config",
                token, payload.toString());
    }

    private static void selectBrowserFlow(String baseUrl,
                                          String token,
                                          String realm,
                                          String flowAlias)
            throws IOException, InterruptedException {
        if (flowAlias == null || flowAlias.isBlank()) {
            return;
        }

        JsonNode realmConfig = fetchRealm(baseUrl, token, realm);
        ObjectNode payload = ((ObjectNode) realmConfig).put("browserFlow", flowAlias);

        sendPut(baseUrl + "/admin/realms/" + realm, token, payload.toString());
    }

    private record FormInfo(String action, Map<String, String> hidden) {
    }

    private record PasswordUpdateResult(boolean success, int statusCode, String body, String location) {
    }

    private record Pkce(String verifier, String challenge) {
    }

    private record LoginAttemptResult(int statusCode, String location, String body) {
    }

    private record LoginFlowContext(String alias, String flowId, String executionId) {
    }

    @FunctionalInterface
    private interface KeycloakScenario {
        void run(String baseUrl, String token) throws Exception;
    }

    private record RecaptchaLoginConfig(String projectId,
                                        String serviceAccount,
                                        String timeoutMs,
                                        boolean failClosed,
                                        boolean doNotDisable) {
    }

    private record RealScenarioConfig(String projectId,
                                      String serviceAccount,
                                      String timeoutMs,
                                      String breachedPassword,
                                      String safePassword,
                                      String username,
                                      String userEmail) {
    }

    private static JsonNode fetchRequiredActions(String baseUrl, String token) throws IOException, InterruptedException {
        HttpResponse<String> response = sendGet(baseUrl + "/admin/realms/master/authentication/required-actions", token);
        return MAPPER.readTree(response.body());
    }

    private static JsonNode findRequiredAction(JsonNode source, String alias) {
        if (source == null || !source.isArray()) {
            return null;
        }
        for (JsonNode node : source) {
            if (node != null && alias.equals(node.path("alias").asText())) {
                return node;
            }
        }
        return null;
    }

    private static HttpResponse<String> sendGet(String url, String token) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Authorization", "Bearer " + token)
                .build();

        HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() >= 400) {
            throw new IllegalStateException("GET " + url + " failed: HTTP " + response.statusCode() + " - " + response.body());
        }
        return response;
    }

    private static HttpResponse<String> sendPost(String url, String token, String payload)
            throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_8))
                .build();

        HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() >= 400) {
            throw new IllegalStateException("POST " + url + " failed: HTTP " + response.statusCode() + " - " + response.body());
        }
        return response;
    }

    private static void sendPut(String url, String token, String payload) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_8))
                .build();

        HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() >= 400) {
            throw new IllegalStateException("PUT " + url + " failed: HTTP " + response.statusCode() + " - " + response.body());
        }
    }

    private static void sendDelete(String url, String token) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Authorization", "Bearer " + token)
                .DELETE()
                .build();

        HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() >= 400) {
            throw new IllegalStateException("DELETE " + url + " failed: HTTP " + response.statusCode() + " - " + response.body());
        }
    }
}
