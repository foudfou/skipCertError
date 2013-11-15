/* -*- Mode: js2; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

const Cc = Components.classes;
const Ci = Components.interfaces;

Components.utils.import("resource://sce/commons.js");


var sceUIOptions = {

  onLoad: function() {
    this.fillBypassDomains();
    this.toggleDisable_All(sce.Utils.prefService.getBoolPref('enabled'));
    this.toggleCheck_BypassIssuerNotTrusted(
      document.getElementById('ui_bypass_self_signed').checked);

    window.sizeToContent();
  },

  toggleDisable_All: function(enabledIsChecked) {
    document.getElementById('ui_add_temporary_exceptions').disabled = !enabledIsChecked;
    document.getElementById('ui_notify').disabled = !enabledIsChecked;
    document.getElementById('ui_bypass_domains').disabled = !enabledIsChecked;
    this.toggleDisable_BypassErrors(enabledIsChecked);
   },

  toggleDisable_BypassErrors: function(checked) {
    var certErrorCondChildren = document.getElementById('ui_bypass_errors')
      .childNodes;
    for (var i = 0; i < certErrorCondChildren.length; i++) {
      var node = certErrorCondChildren[i];
      node.disabled = !checked;
     }

    if (checked)
      this.toggleCheck_BypassIssuerNotTrusted(
        document.getElementById('ui_bypass_self_signed').checked);
  },

  toggleCheck_BypassIssuerNotTrusted: function(selfSignedIsChecked) {
    if (selfSignedIsChecked) {
      document.getElementById('ui_bypass_issuer_not_trusted').checked  = true;
      sce.Utils.prefService.setBoolPref("bypass_issuer_not_trusted", true);
    }
    document.getElementById('ui_bypass_issuer_not_trusted').disabled =
      selfSignedIsChecked;
  },

  fillBypassDomains: function() {
    var domains = sce.Utils.getArrayPref("bypass_domains");
    var domainsStr = domains.join("\n");
    document.getElementById('ui_bypass_domains').value = domainsStr;
  },

  parseBypassDomains: function(text) {
    var domains = text.replace(/\r\n/g, "\n").split("\n");
    domains = domains.filter(function(e){return (/^\s*$/.test(e)) ? false : true;});
    sce.Utils.setArrayPref("bypass_domains", domains);
  }

};
