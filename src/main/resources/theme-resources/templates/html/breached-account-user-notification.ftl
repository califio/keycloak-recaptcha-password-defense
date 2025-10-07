<#ftl output_format="HTML">
<p>${msg("recaptchaPasswordDefense.email.user.intro")}</p>
<#if hasStrongFactor?? && hasStrongFactor>
  <p>${msg("recaptchaPasswordDefense.email.user.withStrong")}</p>

  <#if adminEmailsJoined?has_content>
    <p>${msg("recaptchaPasswordDefense.email.user.contactAdmins", adminEmailsJoined)}</p>
  <#else>
    <p>${msg("recaptchaPasswordDefense.email.user.contactAdmins.none")}</p>
  </#if>
<#else>
  <p>${msg("recaptchaPasswordDefense.email.user.withoutStrong")}</p>

  <#if adminEmailsJoined?has_content>
    <p>${msg("recaptchaPasswordDefense.email.user.contactAdmins.disabled", adminEmailsJoined)}</p>
  <#else>
    <p>${msg("recaptchaPasswordDefense.email.user.contactAdmins.none")}</p>
  </#if>
</#if>

<#if includeCredentials?? && includeCredentials>
  <p><strong>${msg("recaptchaPasswordDefense.email.user.credentialsHeading")}</strong></p>
  <ul>
    <li>${msg("recaptchaPasswordDefense.username")}: ${username}</li>
    <li>${msg("recaptchaPasswordDefense.password")}: ${maskedPassword}</li>
  </ul>
<#else>
  <p>${msg("recaptchaPasswordDefense.email.user.credentialsOmitted")}</p>
</#if>
