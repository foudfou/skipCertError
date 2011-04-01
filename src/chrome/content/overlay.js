var mitm_me = {
  DEBUG_MODE: true,

  onLoad: function() {
    // initialization code
    this.initialized = true;
    this.strings = document.getElementById("mitm-me-strings");

    // Set up preference change observer
    this._prefService =
      Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService)
      .getBranch("extensions.mitm-me.");
    this._prefService.QueryInterface(Components.interfaces.nsIPrefBranch2);
    this._prefService.addObserver("", this, false);
  },

  onQuit: function() {

    // Remove observer
    this._prefService.QueryInterface(Ci.nsIPrefBranch2);
    this._prefService.removeObserver("", this);
  },

  observe: function(subject, topic, data) {
    // Observer for pref changes
    if (topic != "nsPref:changed") return;
    this.dump('Pref changed: '+data);

    // switch(data) {
    // case 'context':
    // case 'replace_builtin':
    //   this.updateUIFromPrefs();
    //   break;
    // }
  },

  onMenuItemCommand: function(e) {
    var promptService = Components.classes["@mozilla.org/embedcomp/prompt-service;1"]
                                  .getService(Components.interfaces.nsIPromptService);
    promptService.alert(window, this.strings.getString("helloMessageTitle"),
                                this.strings.getString("helloMessage"));
  },

  onToolbarButtonCommand: function(e) {
    // just reuse the function above.  you can change this, obviously!
    mitm_me.onMenuItemCommand(e);
  },

  /* Console logging functions */
  dump: function(message) { // Debuging function -- prints to javascript console
    if(!this.DEBUG_MODE) return;
    var ConsoleService = Cc['@mozilla.org/consoleservice;1'].getService(Ci.nsIConsoleService);
    ConsoleService.logStringMessage(message);
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

window.addEventListener("load", function () { mitm_me.onLoad(); }, false);
