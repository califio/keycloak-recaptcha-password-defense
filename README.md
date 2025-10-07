# Keycloak reCAPTCHA Password Defense

Drop-in provider for Keycloak 22+ that checks username/password submissions with
Google [reCAPTCHA Enterprise – Password Defense](https://cloud.google.com/recaptcha/docs/check-passwords).
Tested with Keycloak 22.0.5 through 26.4.0.

When users log in, if reCAPTCHA flags the credentials as breached, the extension applies an adaptive policy:

* **User has another strong factor (OTP / WebAuthn / Passkey)** → challenge with that factor, then require a password change.
* **User has no strong factor** → disable the account and show a contact-admin message (unless you enable *Unsafe mode – Do not disable account*).

For password updates and registration, the extension blocks the use of breached credentials.

> Implementation follows Google’s documented **Private Password Leak Verification** flow and uses the official helper library to perform the cryptographic handshake locally so plaintext credentials are never sent to Google. See: [Detect password leaks and breached credentials](https://cloud.google.com/recaptcha/docs/check-passwords) and the Java helper lib [recaptcha-password-check-helpers](https://github.com/GoogleCloudPlatform/java-recaptcha-password-check-helpers).

---

## What’s included

This module provides four components you can add to your authentication flows:

1. **Authenticator**: `Username Password Form with reCAPTCHA Password Defense`
   Extends Keycloak’s username/password form; on successful password validation, it checks whether the credentials are breached and applies the policy described above.

2. **Conditional**: `If breached then execute (step-up)`
   A conditional execution that **only matches if a breach was detected earlier** in the flow. Nest your 2FA executions (OTP, WebAuthn, etc.) under a conditional sub-flow using this provider to implement the “challenge the user” branch.

3. **Registration form action**: `Checking Password with reCAPTCHA Password Defense`
   Validates passwords during self-registration and blocks leaked passwords before the account is created.

4. **Required action**: `Update Password`
   Replaces Keycloak’s default *Update Password* required action so password resets and account password changes are verified against the reCAPTCHA Password Defense service as well.

---

## Build and install

Build the shaded JAR:

```bash
mvn -DskipTests package
```

Copy it into Keycloak and rebuild the server image/cache:

```bash
cp target/recaptchapassworddefense-<version>-shaded.jar "$KEYCLOAK_HOME/providers/"
"$KEYCLOAK_HOME/bin/kc.sh" build
"$KEYCLOAK_HOME/bin/kc.sh" start
```

---

## Google Cloud setup

1. Enable the **reCAPTCHA Enterprise API** in your Google Cloud project.
2. Create (or reuse) a service account with the `roles/recaptchaenterprise.agent` role.
3. Download the service account JSON key; Keycloak will use it to call the API.

---

## Configure Keycloak (Admin Console)

1. **Add to flow (Browser flow)**
   - Go to **Authentication → Flows**.
   - Copy the **Browser** flow to a new flow (e.g., *Browser + Password Defense*).
   - Under the *Forms* sub-flow, **delete** the default *Username Password Form*.
   - **Add execution** → choose **Username Password Form with reCAPTCHA Password Defense** → set **REQUIRED**.
   - **Add sub-flow** → name it *If breached then step-up* → set **Conditional** and **ALTERNATIVE** (or **REQUIRED** if you always want to gate).
   - Under that sub-flow, **add execution**: **If breached then execute (step-up)** → set **REQUIRED**.
   - **Under the same sub-flow**, add your step-up methods, e.g.:
     - **OTP Form** (TOTP/HOTP)
     - **WebAuthn Authenticator** (2FA)
     - (**Optional**) “Reset Stolen Credentials” flows you already use
   - Ensure each step-up method is **REQUIRED** (or set according to your policy).

2. **Add to Registration flow**
   - Staying under **Authentication → Flows**, switch to the **Registration** flow (or your copy).
   - Add execution → choose **Checking Password with reCAPTCHA Password Defense** → set **REQUIRED**.
   - Keep the default *Password Validation* execution too; this action only adds the breach check.

3. **Enable password-update required action**
   - Go to **Realm Settings → Required Actions**.
   - Configure the **Update Password** action (you should see the reCAPTCHA section because this extension replaces the stock provider).

4. **Provider config (click the cog on each execution/required action)**
   - **Shared settings** (browser form, registration action, and required action):
     - **Google Cloud Project ID** – your GCP project (e.g., `my-gcp-project`).
     - **Google Cloud Service Account** – upload the JSON for a service account that can call reCAPTCHA Enterprise.
     - **Assessment Timeout (ms)** – request timeout, default `2500`.
     - **Fail closed on API errors** – if `true`, the execution fails when the password-defense API call fails (default `false`).
   - **Login form only**:
     - **Notification Emails** – add one address per row to notify security teams on each breach detection.
     - **Notify account owner** – when enabled (default), email the affected user if their address is verified in Keycloak.
     - **Include masked credentials in emails** – include the username and masked password (`******` in the middle) in admin and user notifications.
     - **Unsafe mode - Do not disable account** – if `true`, breached accounts are allowed to continue (default `false`, safe mode).

5. **SMTP**
   - Make sure **Realm Settings → Email** is configured; the extension uses Keycloak’s `EmailSenderProvider` to notify admins.

---

## Security notes & recommendations

- **How the conditional sub-flow is triggered**: The password form writes a note `ACCOUNT_BREACHED=true` to the auth session when a breach is detected. The conditional provider reads that note and **activates the nested sub‑flow** only in that case.

- **Registration & password changes**:
  - Registration passwords are checked before user creation; breached passwords are rejected and the user must pick another one.
  - The custom required action blocks password updates/resets that reuse breached passwords while keeping the account enabled.

- **Password-less logins**: If no password is submitted (for example, passkey-only logins), the authenticator skips the password-defense check because there are no credentials to verify.

- **Fail-open vs. fail-closed**: Default is fail‑open to avoid accidental lockouts if the reCAPTCHA API is briefly unavailable. You can flip to fail‑closed in regulated environments.
- **Safe mode vs. unsafe mode**: Default is safe mode to avoid breached credentials being used by malicious actors. Turn on unsafe mode only when timely user access is critical.
- **Privacy**: The cryptographic helper ensures that Google receives only blinded/encrypted values. Plaintext passwords **never leave Keycloak**.
- **Least privilege**: Use a dedicated service account with `roles/recaptchaenterprise.agent` only. Rotate keys regularly.
- **Auditing**: Store all Keycloak events, especially `LOGIN` and `LOGIN_ERROR`. Consider adding SIEM alerts via Keycloak events if needed.

---

## Troubleshooting

- **“Project ID not configured” / “service account not configured”** – set both values on each execution or required action (cog icon → config).
- **“No email sent”** – verify SMTP config on the realm.
- **“Flow doesn’t step-up”** – ensure the conditional sub-flow contains **“If breached then execute (step-up)”** as **REQUIRED**, and that your OTP/WebAuthn executions are **REQUIRED** under that sub-flow.
- **Build errors for Google libs** – make sure you’re online when building; the POM imports the Google **libraries‑bom** so you don’t need to pin versions manually.

---

## Customize user-facing messages

The extension ships an English message bundle (`theme-resources/messages/messages_en.properties`) so all UI strings can be overridden per realm using Keycloak’s localization feature.

1. In the Admin Console go to **Realm Settings → Localization**.
2. In tab **Realms overrides** → pick the locale you want to override (e.g. `English`).
3. Click **Add translation** and add entries for any of the keys below with your preferred wording:
   * `recaptchaPasswordDefense.login.breached`
   * `recaptchaPasswordDefense.login.disabled`
   * `recaptchaPasswordDefense.login.unavailable`
   * `recaptchaPasswordDefense.updatePassword.breached`
   * `recaptchaPasswordDefense.updatePassword.unavailable`
   * `recaptchaPasswordDefense.registration.breached`
   * `recaptchaPasswordDefense.registration.unavailable`
   * Email subjects and labels (optional):
     * `recaptchaPasswordDefense.email.subject`
     * `recaptchaPasswordDefense.email.user.subject`
     * `recaptchaPasswordDefense.email.credentialsHeading`
     * `recaptchaPasswordDefense.email.user.withStrong`
     * `recaptchaPasswordDefense.email.user.withoutStrong`
     * `recaptchaPasswordDefense.email.user.contactAdmins`
     * `recaptchaPasswordDefense.email.user.contactAdmins.disabled`
     * `recaptchaPasswordDefense.email.user.contactAdmins.none`
4. Users will see the customized text immediately after the realm cache refreshes.

If you maintain a custom theme, you can also add these keys to your theme’s `messages/<locale>.properties` files. Realm overrides always take precedence over bundled defaults.

---

## Customize email notifications

When the login authenticator flags a breach, it sends notifications through Keycloak’s standard email templating. Every message key and FreeMarker template ships in `src/main/resources/theme-resources`, so you can copy them into your realm’s active email theme. (Admin alerts require at least one address under **Notification Emails**; user notices require **Notify account owner** to be enabled and a verified email on the account.)

1. **Copy templates/messages into your theme**
   - Admin notification text: `theme-resources/templates/text/breached-account-admin-notification.ftl`
   - Admin notification HTML: `theme-resources/templates/html/breached-account-admin-notification.ftl`
   - User notification text: `theme-resources/templates/text/breached-account-user-notification.ftl`
   - User notification HTML: `theme-resources/templates/html/breached-account-user-notification.ftl`
   - Message bundle: `theme-resources/messages/messages_en.properties` (contains both subject keys and content strings)
   Drop these into your theme under `email/text/`, `email/html/`, and `email/messages/` (or merge the content into existing files).

2. **Adjust wording or layout**
   - Subjects automatically include the realm’s display name (`Realm Settings → General → Display name`). Override the message bundle (`recaptchaPasswordDefense.email.subject`, `recaptchaPasswordDefense.email.user.subject`) if you want different phrasing.
   - Update the FreeMarker templates to change structure, add branding, or include more context. All values injected by the provider are listed below:
     * `realmName`, `realmDisplayName`
     * `username`, `userId`, `userEmail`
     * `hasStrongFactor` (boolean)
     * `actionTaken`
     * `adminEmails` (list) / `adminEmailsJoined` (comma separated string)
     * `includeCredentials` (boolean)
     * `maskedPassword`

3. **Realm-level overrides (optional)**
   - Instead of shipping a custom theme, use **Realm Settings → Localization** to override the message keys (subject labels, intro text, etc.).

4. **Preview changes**
   - Trigger a breached-login scenario or use Keycloak’s “Send test email” after copying your templates to confirm formatting.

> 📝 After editing theme assets on disk, run `kc.sh build` (or rebuild the container image) so Keycloak picks up the updates.

---

## Compatibility

- **Keycloak**: 22+
- **Java**: JDK 17+

### Automated compatibility tests

- Requires Docker; if the daemon is unavailable, the suite is skipped (`Assumptions.assumeTrue`).
- Run `mvn verify` to build the shaded JAR and execute the integration tests.
- Tested Keycloak versions: override with `-Dcompatibility.keycloak.versions=...` or `COMPATIBILITY_KEYCLOAK_VERSIONS=...`; default matrix: `22.0.5`, `23.0.7`, `24.0.5`, `25.0.6`, `26.4.0`.
- Each test container installs the provider JAR, replaces the login form, and exercises the custom `Update Password` required action in both fail-open and fail-closed modes using stub Google Cloud credentials (no external API calls).
- Optional real reCAPTCHA password checks: set `-Dcompatibility.real.verifyBreach=true` or `COMPATIBILITY_REAL_VERIFY_BREACH=true`,
  then provide `compatibility.real.projectId` / `COMPATIBILITY_REAL_PROJECT_ID`, `compatibility.real.serviceAccount` /
  `COMPATIBILITY_REAL_SERVICE_ACCOUNT`, and `compatibility.real.breachedPassword` /
  `COMPATIBILITY_REAL_BREACHED_PASSWORD` (defaults to `qwerty123`); override the timeout with
  `compatibility.real.timeoutMs` / `COMPATIBILITY_REAL_TIMEOUT_MS` and optionally seed a safe control password via
  `compatibility.real.safePassword` / `COMPATIBILITY_REAL_SAFE_PASSWORD`.
  Override the test account email with `compatibility.real.email` / `COMPATIBILITY_REAL_EMAIL`
  (defaults to `user@example.com`), and the test account username with
  `compatibility.real.username` / `COMPATIBILITY_REAL_USERNAME` (defaults to `user`).
- HTTP proxy support: set `-Dcompatibility.http.proxy=host:port` or `COMPATIBILITY_HTTP_PROXY` when container traffic must go through a proxy.

---

## License

Apache-2.0
