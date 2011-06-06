/* -*- Mode: js2; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

Components.utils.import("resource://sce/commons.js");

const Cc = Components.classes;
const Ci = Components.interfaces;

sce.UIOptions = {

  onLoad: function() {
    this.toggleAll(!sce.Utils.prefService.getBoolPref('enabled'));
    this.toggleCertErrorConditions(!sce.Utils.prefService.getBoolPref('silent_mode'));
  },

  toggleAll: function(wasChecked) {
    document.getElementById('ui_add_temporary_exceptions').disabled = wasChecked;
    document.getElementById('ui_silent_mode').disabled = wasChecked;
    if (wasChecked)
      this.toggleCertErrorConditions(wasChecked);
    else
      this.toggleCertErrorConditions(true);
   },

  toggleCertErrorConditions: function(wasChecked) {
    var certErrorCondChildren = document.getElementById('ui_cert_error_conditions').childNodes;
    for (var i = 0; i < certErrorCondChildren.length; i++) {
      var node = certErrorCondChildren[i];
      sce.Debug.dump(node.nodeName);
      node.disabled = wasChecked;
     }
  },

};
