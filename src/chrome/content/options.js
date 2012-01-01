/* -*- Mode: js2; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

const Cc = Components.classes;
const Ci = Components.interfaces;

Components.utils.import("resource://sce/commons.js");


var sceUIOptions = {

  onLoad: function() {
    this.toggleDisable_All(sce.Utils.prefService.getBoolPref('enabled'));
    this.toggleCheck_BypassIssuerNotTrusted(
      document.getElementById('ui_bypass_self_signed').checked);
  },

  toggleDisable_All: function(enabledIsChecked) {
    document.getElementById('ui_add_temporary_exceptions').disabled = !enabledIsChecked;
    document.getElementById('ui_notify').disabled = !enabledIsChecked;
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
      document.getElementById('ui_bypass_issuer_not_trusted').checked = selfSignedIsChecked;
      document.getElementById('ui_bypass_issuer_not_trusted').disabled = true;
    } else {
      document.getElementById('ui_bypass_issuer_not_trusted').disabled = false;
    }
  },

};
