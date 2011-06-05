/* -*- Mode: js2; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/*
 * should contain our business logic in JSM, available through service objects,
 * and keep chrome scripts limited to handle presentation logic.
 * http://developer.mozilla.org/en/XUL_School/JavaScript_Object_Management.html
 */

var EXPORTED_SYMBOLS = [ "sce" ];

const Cc = Components.classes;
const Ci = Components.interfaces;

/**
 * sce namespace.
 */
if ("undefined" == typeof(sce)) {
  var sce = {
    DEBUG_MODE: true,
  };
};

sce.Debug = {

  _initialized: false,

  _consoleService: null,

  /**
   * Object constructor.
   */
  init: function() {
    if (this._initialized) return;
    this._consoleService = Cc['@mozilla.org/consoleservice;1'].getService(Ci.nsIConsoleService);
    this.dump("SkipErrorCert Debug initialized");
    this._initialized = true;
  },

  /* Console logging functions */
  /* NOTE: Web Console inappropriates: doesn't catch all messages */
  dump: function(message) { // Debuging function -- prints to javascript console
    if(!sce.DEBUG_MODE) return;
    this._consoleService.logStringMessage(message);
  },

  dumpObj: function(obj) {
    if(!sce.DEBUG_MODE) return;
    var str = "";
    for(i in obj) {
      try {
        str += "obj["+i+"]: " + obj[i] + "\n";
      } catch(e) {
        str += "obj["+i+"]: Unavailable\n";
      }
    }
    this.dump(str);
  },

};
// build it !
sce.Debug.init();


sce.Utils = {

  prefService: Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService)
    .getBranch("extensions.sce."),

  safeGetName: function(request) {
    return request ? request.name : null;
  },

};
