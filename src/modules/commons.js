// should contain our business logic in JSM, available through service objects,
// and keep chrome scripts are limited to handle presentation logic.
// http://developer.mozilla.org/en/XUL_School/JavaScript_Object_Management.html

var EXPORTED_SYMBOLS = [ "mitmme" ];

const Cc = Components.classes;
const Ci = Components.interfaces;

/**
 * mitmme namespace.
 */
if ("undefined" == typeof(mitmme)) {
  var mitmme = {};
};

mitmme.Debug = {

  DEBUG_MODE: true,

  _consoleService: null,

  /**
   * Object constructor.
   */
  _init: function() {
    this._consoleService = Cc['@mozilla.org/consoleservice;1'].getService(Ci.nsIConsoleService);
    this.dump("INIT console service");
  },

  /* Console logging functions */
  /* NOTE: Web Console inappropriates: doesn't catch all messages */
  dump: function(message) { // Debuging function -- prints to javascript console
    if(!this.DEBUG_MODE) return;
    this._consoleService.logStringMessage(message);
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

// Construct one !
(function() { this._init(); }).apply(mitmme.Debug); // apply = by-copy
