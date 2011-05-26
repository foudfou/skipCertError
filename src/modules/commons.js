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
  var mitmme = {
    DEBUG_MODE: true,
  };
};

mitmme.Debug = {

  _initialized: false,

  _consoleService: null,
  
  /**
   * Object constructor.
   */
  init: function() {
    if (this._initialized) return;
    this._consoleService = Cc['@mozilla.org/consoleservice;1'].getService(Ci.nsIConsoleService);
    this.dump("MITTME Debug initialized");
    this._initialized = true;
  },

  /* Console logging functions */
  /* NOTE: Web Console inappropriates: doesn't catch all messages */
  dump: function(message) { // Debuging function -- prints to javascript console
    if(!mitmme.DEBUG_MODE) return;
    this._consoleService.logStringMessage(message);
  },

  dumpObj: function(obj) {
    if(!mitmme.DEBUG_MODE) return;
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
mitmme.Debug.init();
