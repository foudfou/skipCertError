// https://developer.mozilla.org/en/Localizing_extension_descriptions
pref("extensions.skipcerterror@foudil.fr.description", "chrome://sce/locale/overlay.properties");

// Extension prefs
pref("extensions.sce.enabled", true);
pref("extensions.sce.add_temporary_exceptions", true);
pref("extensions.sce.notify", true);
pref("extensions.sce.bypass_domains", '[]');
pref("extensions.sce.bypass_issuer_not_trusted", true);
pref("extensions.sce.bypass_issuer_unknown", true);
pref("extensions.sce.bypass_self_signed", true);
pref("extensions.sce.bypass_domain_mismatch", false);
pref("extensions.sce.single_click_skip", false);

// Set the environment settings
pref("browser.ssl_override_behavior", 2);
pref("browser.xul.error_pages.expert_bad_cert", true);
