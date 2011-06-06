/* -*- Mode: js2; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

Components.utils.import("resource://sce/commons.js");

const Cc = Components.classes;
const Ci = Components.interfaces;

sce.UIOptions = {

  onLoad: function() {
    this.toggleDisable_All(sce.Utils.prefService.getBoolPref('enabled'));
  },

  toggleDisable_All: function(enabledChecked) {
    document.getElementById('ui_add_temporary_exceptions').disabled = !enabledChecked;
    document.getElementById('ui_silent_mode').disabled = !enabledChecked;
    if (enabledChecked) {
      this.toggleDisable_BypassErrors(document.getElementById('ui_silent_mode').checked);
      this.toggleCheck_BypassIssuerUnknown(
        document.getElementById('ui_bypass_self_signed').checked);
    } else
      this.toggleDisable_BypassErrors(false);
   },

  toggleDisable_BypassErrors: function(silentChecked) {
    var certErrorCondChildren = document.getElementById('ui_bypass_errors')
      .childNodes;
    for (var i = 0; i < certErrorCondChildren.length; i++) {
      var node = certErrorCondChildren[i];
      sce.Debug.dump(node.nodeName);
      node.disabled = !silentChecked;
     }

    if (silentChecked)
      this.toggleCheck_BypassIssuerUnknown(
        document.getElementById('ui_bypass_self_signed').checked);
  },

  toggleCheck_BypassIssuerUnknown: function(selfSignedChecked) {
    if (selfSignedChecked) {
      document.getElementById('ui_bypass_issuer_unknown').checked = selfSignedChecked;
      document.getElementById('ui_bypass_issuer_unknown').disabled = true;
    } else {
      document.getElementById('ui_bypass_issuer_unknown').disabled = false;
    }
  },

};
