/* -*- Mode: js2; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/*
 * should contain our business logic in JSM, available through service objects,
 * and keep chrome scripts limited to handle presentation logic.
 * http://developer.mozilla.org/en/XUL_School/JavaScript_Object_Management.html
 */

var EXPORTED_SYMBOLS = [ "sce", "SCE_CERT_SELF_SIGNED",
  "SCE_SSL_DOMAIN_MISMATCH", "SCE_SSL_NOT_VALID" ];

const Cc = Components.classes;
const Ci = Components.interfaces;

/* SCE Constants */
// custom const to keep track of cert errors
const SCE_CERT_SELF_SIGNED     = 1 << 8;
const SCE_SSL_DOMAIN_MISMATCH  = 1 << 9;
const SCE_SSL_NOT_VALID        = 1 << 10;

/**
 * sce namespace.
 */
if ("undefined" == typeof(sce)) {
  var sce = {};
};

sce.Debug = {
  DEBUG_MODE: true,

  initialized: false,

  /**
   * Object constructor.
   */
  init: function() {
    if (this.initialized) return;
    this.consoleService = Cc['@mozilla.org/consoleservice;1'].getService(Ci.nsIConsoleService);
    this.dump("SkipCertError Debug initialized");
    this.initialized = true;
  },

  /* Console logging functions */
  /* NOTE: Web Console inappropriates: doesn't catch all messages */
  /*
   * CAUTION: dump() dumpObj() may be stripped from .js files during xpi build.
   * IT'S IMPORTANT THAT DEBUG CALLS ARE WRITTEN ON A SINGLE LINE !
   */
  dump: function(message) { // Debuging function -- prints to javascript console
    if(!this.DEBUG_MODE) return;
    this.consoleService.logStringMessage(message);
  },

  dumpObj: function(obj) {
    if(!this.DEBUG_MODE) return;
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
(function() { this.init(); }).
  apply(sce.Debug);


sce.Utils = {

  prefService: Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService)
    .getBranch("extensions.sce."),

  safeGetName: function(request) {
    return request ? request.name : null;
  }

};
