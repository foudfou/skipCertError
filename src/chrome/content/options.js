/* -*- Mode: js2; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

Components.utils.import("resource://sce/commons.js");

const Cc = Components.classes;
const Ci = Components.interfaces;

sce.UIOptions = {

  onLoad: function() {
    this.toggleOthers(!sce.Utils.prefService.getBoolPref('enabled'));
  },

  toggleOthers: function(wasChecked) {
    document.getElementById('ui_add_temporary_exceptions').disabled = wasChecked;
    document.getElementById('ui_silent_mode').disabled = wasChecked;
  },

};
