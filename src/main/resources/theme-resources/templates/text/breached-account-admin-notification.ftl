<#ftl output_format="plainText">
${msg("recaptchaPasswordDefense.email.intro")}

${msg("recaptchaPasswordDefense.realm")}: ${realmName}
${msg("recaptchaPasswordDefense.username")}: ${username} (ID: ${userId})
${msg("recaptchaPasswordDefense.email.strongFactorPresent")}: <#if hasStrongFactor?? && hasStrongFactor>${msg("recaptchaPasswordDefense.labelYes")}<#else>${msg("recaptchaPasswordDefense.labelNo")}</#if>
${msg("recaptchaPasswordDefense.email.actionTaken")}: ${actionTaken}

<#if includeCredentials?? && includeCredentials>
${msg("recaptchaPasswordDefense.email.credentialsHeading")}:
${msg("recaptchaPasswordDefense.username")}: ${username}
${msg("recaptchaPasswordDefense.password")}: ${maskedPassword}
</#if>
