/* -*- Mode: javascript; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

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

  //   window.setTimeout(this.delayedStartup, 1000); // 1s
  // },
  // delayedStartup: function() {

    // Add click handler in place of browser's
    // if (typeof BrowserOnCommand != "undefined")
    //   gBrowser.removeEventListener("command", BrowserOnCommand, false);
    gBrowser.removeEventListener("click", BrowserOnClick, false);
    // TODO: harder to replace BrowserOnClick which is attached through a TabsProgressListener...
    gBrowser.addEventListener("click", this.onClick, false);

    gBrowser.addEventListener("command", this.onCommand, false);
    var silent = this._prefService.getBoolPref("silent_mode");
    this.dump('silent_mode: '+silent);
    if (silent)
      document.getElementById("content")
      .addEventListener("DOMLinkAdded", this.onCommand, false);
  },

  onClick: function(event) {
    Components.utils.reportError(event);
    mitm_me.dump("onClick");
    mitm_me.dumpObj(event);
  },

  onCommand: function(event) {
    // Don't trust synthetic events
    if (!event.isTrusted)
      return;

    var ot = event.originalTarget;
    var errorDoc = ot.ownerDocument;
    var uri = gBrowser.currentURI;

    // If the event came from an ssl error page
    // optional semi-automatic "Add Exception" button event...
    // FF3.5 support: about:certerror
    if (/^about:neterror\?e=nssBadCert/.test(errorDoc.documentURI)
     || /^about:certerror/.test(errorDoc.documentURI)) {

      if (ot == errorDoc.getElementById('exceptionDialogButton')
          || mitm_me._prefService.getBoolPref("silent_mode")) {

        // Get the cert
        var recentCertsSvc = Components.classes["@mozilla.org/security/recentbadcerts;1"]
                            .getService(Components.interfaces.nsIRecentBadCertsService);

        var hostWithPort = uri.host + ":" + uri.port;
        gSSLStatus = gBrowser.securityUI
          .QueryInterface(Components.interfaces.nsISSLStatusProvider)
          .SSLStatus;
        if(!gSSLStatus) {
          try {
            var recentCertsSvc = Components.classes["@mozilla.org/security/recentbadcerts;1"]
              .getService(Components.interfaces.nsIRecentBadCertsService);
            if (!recentCertsSvc)
              return;

            var hostWithPort = uri.host + ":" + uri.port;
            gSSLStatus = recentCertsSvc.getRecentBadCert(hostWithPort);
          }
          catch (e) {
            Components.utils.reportError(e);
            return;
          }
        }

        if(!gSSLStatus)
          mitm_me.getCert(uri);

        if(!gSSLStatus) {
          Components.utils.reportError("MITMME - No gSSLStatus on attempt to add exception")
          return;
        }

        gCert = gSSLStatus.QueryInterface(Components.interfaces.nsISSLStatus).serverCert;
        if(!gCert){
          Components.utils.reportError("MITMME - No gCert on attempt to add exception")
          return;
        }
        // Add the exception
        var overrideService = Components.classes["@mozilla.org/security/certoverride;1"]
                                        .getService(Components.interfaces.nsICertOverrideService);
        var flags = 0;
        if(gSSLStatus.isUntrusted)
          flags |= overrideService.ERROR_UNTRUSTED;
        if(gSSLStatus.isDomainMismatch)
          flags |= overrideService.ERROR_MISMATCH;
        if(gSSLStatus.isNotValidAtThisTime)
          flags |= overrideService.ERROR_TIME;

        overrideService.rememberValidityOverride(
          uri.asciiHost, uri.port,
          gCert,
          flags,
          mitm_me._prefService.getBoolPref("add_temporary_exceptions"));

        // Eat the event
        event.stopPropagation();

        // Reload the page
        if(errorDoc && errorDoc.location)
          errorDoc.location.reload();
      } else {
        BrowserOnClick(event);
      }
    } else {
      BrowserOnClick(event);
    }

  },

  // Lifted from exceptionDialog.js in PSM
  getCert: function(uri) {
    var req = new XMLHttpRequest();
    try {
      if(uri) {
        req.open('GET', uri.prePath, false);
        req.channel.notificationCallbacks = new badCertListener();
        req.send(null);
      }
    } catch (e) {
      // We *expect* exceptions if there are problems with the certificate
      // presented by the site. Log it, just in case, but we can proceed here,
      // with appropriate sanity checks
      Components.utils.reportError("MITMME: Attempted to connect to a site with a bad certificate. " +
                                   "This results in a (mostly harmless) exception being thrown. " +
                                   "Logged for information purposes only: " + e);
    } finally {
      gChecking = false;
    }

    if(req.channel && req.channel.securityInfo) {
      const Ci = Components.interfaces;
      gSSLStatus = req.channel.securityInfo
                      .QueryInterface(Ci.nsISSLStatusProvider).SSLStatus;
      gCert = gSSLStatus.QueryInterface(Ci.nsISSLStatus).serverCert;
    }
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

  /* Console logging functions */
  // TODO: use Web console (C-S-k)
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

// Simple badcertlistener lifted from exceptionDialog.js in PSM
function badCertListener() {}
badCertListener.prototype = {
  getInterface: function (aIID) {
    return this.QueryInterface(aIID);
  },
  QueryInterface: function(aIID) {
    if (aIID.equals(Components.interfaces.nsIBadCertListener2) ||
        aIID.equals(Components.interfaces.nsIInterfaceRequestor) ||
        aIID.equals(Components.interfaces.nsISupports))
      return this;

    throw Components.results.NS_ERROR_NO_INTERFACE;
  },
  handle_test_result: function () {
    if (gSSLStatus)
      gCert = gSSLStatus.QueryInterface(Components.interfaces.nsISSLStatus).serverCert;
  },
  notifyCertProblem: function MSR_notifyCertProblem(socketInfo, sslStatus, targetHost) {
    gBroken = true;
    gSSLStatus = sslStatus;
    this.handle_test_result();
    return true; // suppress error UI
  }
}

window.addEventListener("load", function () { mitm_me.onLoad(); }, false);
