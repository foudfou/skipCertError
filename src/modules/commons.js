/* -*- Mode: js2; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/*
 * should contain our business logic in JSM, available through service objects,
 * and keep chrome scripts limited to handle presentation logic.
 * http://developer.mozilla.org/en/XUL_School/JavaScript_Object_Management.html
 */

var EXPORTED_SYMBOLS = [ "sce", "SCE_X509CertInterface" ];

var Cc = Components.classes;
var Ci = Components.interfaces;

// FIXME: SCE_COMPAT_nsIX509Cert ?
var SCE_X509CertInterface = ("nsIX509Cert3" in Ci) ? Ci.nsIX509Cert3 : Ci.nsIX509Cert;

Components.utils.import("resource://sce/logging.jsm");

/**
 * sce namespace.
 */
if ("undefined" == typeof(sce)) {
  var sce = {};
};

var log = sce.Logging.getLogger("sce.commons");

sce.Utils = {

  prefService: Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService)
    .getBranch("extensions.sce."),

  safeGetName: function(request) {
    return request ? request.name : null;
  },

  getObjPref: function(prefStr) {
    log.debug(prefStr);
    try {
      var objPref = JSON.parse(
        sce.Utils.prefService.getCharPref(prefStr));
    } catch (x) {
      log.error(x);
    }
    return objPref;
  },
  setObjPref: function(prefStr, obj) {
    log.debug(obj);
    try {
      sce.Utils.prefService.setCharPref(prefStr, JSON.stringify(obj));
    } catch (x) {
      log.error(x);
    }
  },

  getArrayPref: function(prefStr) {
    let arrayPref = this.getObjPref(prefStr);
    if (!sce.js.isArray(arrayPref)) throw new TypeError();
    return arrayPref;
  },
  setArrayPref: function(prefStr, aArray) {
    if (!sce.js.isArray(aArray)) throw new TypeError();
    this.setObjPref(prefStr, aArray);
  }

};


sce.js = {
  // http://stackoverflow.com/questions/767486/how-do-you-check-if-a-variable-is-an-array-in-javascript
  isArray: function(o) {
    return this.getType(o) === '[object Array]';
  },
  getType: function(thing) {
    if(thing === null) return "[object Null]"; // special case
    return Object.prototype.toString.call(thing);
  }
}
