/* -*- Mode: javascript; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/* ***** BEGIN LICENSE BLOCK *****
*   Version: MPL 1.1/GPL 2.0/LGPL 2.1
*
* The contents of this file are subject to the Mozilla Public License Version
* 1.1 (the "License"); you may not use this file except in compliance with
* the License. You may obtain a copy of the License at
* http://www.mozilla.org/MPL/
*
* Software distributed under the License is distributed on an "AS IS" basis,
* WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
* for the specific language governing rights and limitations under the
* License.
*
* The Original Code is MitM Me.
*
* The Initial Developer of the Original Code is
* Johnathan Nightingale.
* Portions created by the Initial Developer are Copyright (C) 2008
* the Initial Developer. All Rights Reserved.
*
* Contributor(s):
* Andras TIM - the new developer @ 2010
* andras.tim@gmail.com, andras.tim@balabit.hu
* Foudil Brétel <foudil.newbie@bigfoot.com>
*
* Alternatively, the contents of this file may be used under the terms of
* either the GNU General Public License Version 2 or later (the "GPL"), or
* the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
* in which case the provisions of the GPL or the LGPL are applicable instead
* of those above. If you wish to allow use of your version of this file only
* under the terms of either the GPL or the LGPL, and not to allow others to
* use your version of this file under the terms of the MPL, indicate your
* decision by deleting the provisions above and replace them with the notice
* and other provisions required by the GPL or the LGPL. If you do not delete
* the provisions above, a recipient may use your version of this file under
* the terms of any one of the MPL, the GPL or the LGPL.
*
* ***** END LICENSE BLOCK ***** */

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
    this._prefService.QueryInterface(Ci.nsIPrefBranch2);
    this._prefService.addObserver("", this, false);

    // Get cert services
    this._overrideService =
      Cc["@mozilla.org/security/certoverride;1"]
      .getService(Components.interfaces.nsICertOverrideService);

    try {
      gBrowser.addTabsProgressListener(mitm_me.TabsProgressListener);
    } catch (ex) {
      Components.utils.reportError(ex);
    }

    this.dump('MITMME LOADED !');
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
    // preform actions here: switch(data) { ...
  },

  /* Console logging functions */
  /* NOTE: Web Console inappropriates: doesn't catch all messages */
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
  },

  TabsProgressListener: {

    // This method will be called on security transitions (eg HTTP -> HTTPS,
    // HTTPS -> HTTP, FOO -> HTTPS) and *after document load* completion. It
    // might also be called if an error occurs during network loading.
    onSecurityChange: function (aBrowser, aWebProgress, aRequest, aState) {
      mitm_me.dump("onSecurityChange");
      var uri = aBrowser.currentURI;

      if (!uri.schemeIs("https")) return;

      // NOTE: the documentation says "after document load" (assuming
      // aBrowser.currentURI), so we *should* know already about the badcert,
      // and could be using nsIRecentBadCertsService. BUT, for some reason...
      // ...at this stage, the bad cert is unknown, so we need to:
      mitm_me.getCert(uri); // sets gSSLStatus using badCertListener()
                            // TODO: don't use a global

      if (!gSSLStatus) {
        Components.utils.reportError("MITMME: couldn't get gSSLStatus");
        return;
      }

			var cert = gSSLStatus.serverCert;
      mitm_me.dump("gSSLStatus");
      mitm_me.dumpObj(gSSLStatus);
      mitm_me.dump("cert");
      mitm_me.dumpObj(cert);

      // we're only interested in self-signed certs
      cert.QueryInterface(Components.interfaces.nsIX509Cert3);
      mitm_me.dump("isSelfSigned:" + cert.isSelfSigned);
      // ...or maybe also by unknown issuer
			var verificationResult = cert.verifyForUsage(Ci.nsIX509Cert.CERT_USAGE_SSLServer);
			switch (verificationResult) {
			case Ci.nsIX509Cert.ISSUER_NOT_TRUSTED: // including self-signed
				mitm_me.dump("issuer not trusted");
			case Ci.nsIX509Cert.ISSUER_UNKNOWN:
				mitm_me.dump("issuer unknown");
			default:
				mitm_me.dump("verificationResult: " + verificationResult);
				break;
			}

    }, // END TabsProgressListener

    onStateChange: function (aBrowser, aWebProgress, aRequest, aStateFlags, aStatus) {
      if (aStateFlags & Ci.nsIWebProgressListener.STATE_STOP &&
          /^about:certerror/.test(aWebProgress.DOMWindow.document.documentURI)) {
        mitm_me.dump("onStateChange: certerror: "
                     + aWebProgress.DOMWindow.document.documentURI);
      }
    },

  }, // END TabsProgressListener

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

// is this sufficient for a delayed Startup ?
// https://developer.mozilla.org/en/Extensions/Performance_best_practices_in_extensions
window.addEventListener("load", function () { mitm_me.onLoad(); }, false);
