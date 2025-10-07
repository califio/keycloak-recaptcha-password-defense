<#ftl output_format="HTML">
<p>${msg("recaptchaPasswordDefense.email.intro")}</p>
<ul>
  <li>${msg("recaptchaPasswordDefense.realm")}: ${realmName}</li>
  <li>${msg("recaptchaPasswordDefense.username")}: ${username} (ID: ${userId})</li>
  <li>${msg("recaptchaPasswordDefense.email.strongFactorPresent")}: <#if hasStrongFactor?? && hasStrongFactor>${msg("recaptchaPasswordDefense.labelYes")}<#else>${msg("recaptchaPasswordDefense.labelNo")}</#if></li>
  <li>${msg("recaptchaPasswordDefense.email.actionTaken")}: ${actionTaken}</li>
</ul>

<#if includeCredentials?? && includeCredentials>
  <p><strong>${msg("recaptchaPasswordDefense.email.credentialsHeading")}</strong></p>
  <ul>
    <li>${msg("recaptchaPasswordDefense.username")}: ${username}</li>
    <li>${msg("recaptchaPasswordDefense.password")}: ${maskedPassword}</li>
  </ul>
</#if>
