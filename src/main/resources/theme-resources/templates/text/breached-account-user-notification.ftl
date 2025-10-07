<#ftl output_format="plainText">
${msg("recaptchaPasswordDefense.email.user.intro")}

<#if hasStrongFactor?? && hasStrongFactor>
${msg("recaptchaPasswordDefense.email.user.withStrong")}

<#if adminEmailsJoined?has_content>
${msg("recaptchaPasswordDefense.email.user.contactAdmins", adminEmailsJoined)}
<#else>
${msg("recaptchaPasswordDefense.email.user.contactAdmins.none")}
</#if>
<#else>
${msg("recaptchaPasswordDefense.email.user.withoutStrong")}

<#if adminEmailsJoined?has_content>
${msg("recaptchaPasswordDefense.email.user.contactAdmins.disabled", adminEmailsJoined)}
<#else>
${msg("recaptchaPasswordDefense.email.user.contactAdmins.none")}
</#if>
</#if>

<#if includeCredentials?? && includeCredentials>
${msg("recaptchaPasswordDefense.email.user.credentialsHeading")}:
${msg("recaptchaPasswordDefense.username")}: ${username}
${msg("recaptchaPasswordDefense.password")}: ${maskedPassword}
<#else>
${msg("recaptchaPasswordDefense.email.user.credentialsOmitted")}
</#if>
