/* -*- Mode: js2; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

Components.utils.import("resource://mitmme/commons.js");

const Cc = Components.classes;
const Ci = Components.interfaces;

mitmme.UIOptions = {

  onLoad: function() {
    this.toggleOthers(!mitmme.Utils.prefService.getBoolPref('enabled'));
  },

  toggleOthers: function(wasChecked) {
    document.getElementById('ui_add_temporary_exceptions').disabled = wasChecked;
    document.getElementById('ui_silent_mode').disabled = wasChecked;
  },

};
