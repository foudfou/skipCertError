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

  TabsProgressListener: {

    onSecurityChange: function (aWebProgress, aRequest, aState) {
      mitm_me.dump("onSecurityChange");
      var uri = gBrowser.currentURI;

      if (uri.schemeIs("https")) {

        mitm_me.dumpObj(this);

        // get SSLStatus from nsISSLStatusProvider
        gSSLStatus = gBrowser.securityUI
          .QueryInterface(Components.interfaces.nsISSLStatusProvider)
          .SSLStatus;

        // otherwise get SSLStatus from recentBadCertsService
        if(!gSSLStatus) {
          mitm_me.dump("onSecurityChange: no SSLStatus from nsISSLStatusProvider, trying recentBadCertsService");
          try {
            if (!mitm_me._recentBadCertsService) {
              Components.utils.reportError("MITME: no recentBadCertService ?!");
              return;
            }
            var hostWithPort = uri.host + ":" + uri.port;
            mitm_me.dump("onSecurityChange: "+hostWithPort+" gSSLStatus="+gSSLStatus);
            gSSLStatus = mitm_me._recentBadCertsService.getRecentBadCert(hostWithPort);
            if(gSSLStatus)
              mitm_me.dump("gSSLStatus defined !")
            else
              mitm_me.dump("gSSLStatus undefined !")
          }
          catch (e) {
            Components.utils.reportError(e);
            return;
          }
        }

        // Get the cert (XHR)
        mitm_me.getCert(uri);
				mitm_me.dumpObj(gSSLStatus);

        // Ultimate check for SSLStatus
        if(!gSSLStatus) {
          Components.utils.reportError("MITMME - No gSSLStatus on attempt to add exception")
          return;
        }
        if(!gCert){
          Components.utils.reportError("MITMME - No gCert on attempt to add exception")
          return;
        }

        // Add the exception
        // TODO: useful ? right place ?
        // if (!mitm_me._overrideService) {
        //   Components.utils.reportError("MITME: no overrideService ?!");
        //   return;
        // }
        var flags = 0;
        if(gSSLStatus.isUntrusted)
          flags |= mitm_me._overrideService.ERROR_UNTRUSTED;
        if(gSSLStatus.isDomainMismatch)
          flags |= mitm_me._overrideService.ERROR_MISMATCH;
        if(gSSLStatus.isNotValidAtThisTime)
          flags |= mitm_me._overrideService.ERROR_TIME;

        mitm_me._overrideService.rememberValidityOverride(
          uri.asciiHost, uri.port,
          gCert,
          flags,
          mitm_me._prefService.getBoolPref("add_temporary_exceptions"));

        // // Reload the page
        // gBrowser.reloadTab(gBrowser.mCurrentTab);
        // mitm_me.dump("page reloaded");
        // mitm_me.dumpObj(aWebProgress);
        aWebProgress.reload();

      }
    },

    onStateChange: function (aBrowser, aWebProgress, aRequest, aStateFlags, aStatus) {
      // Attach a listener to watch for "click" events bubbling up from error
      // pages and other similar page.
      // We can't look for this during onLocationChange since at that point the
      // document URI is not yet the about:-uri of the error page.

      if (aStateFlags & Ci.nsIWebProgressListener.STATE_STOP &&
          /^about:certerror/.test(aWebProgress.DOMWindow.document.documentURI)) {
        mitm_me.dump("onStateChange: certerror !");

        aBrowser.addEventListener("click", mitm_me.onClick, false);
        aBrowser.addEventListener("pagehide", function () {
          aBrowser.removeEventListener("click", mitm_me.onClick, false);
          aBrowser.removeEventListener("pagehide", arguments.callee, true);
        }, true);

      }
    },

  },

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

    // Get the cert
    this._recentBadCertsService =
      Cc["@mozilla.org/security/recentbadcerts;1"]
      .getService(Components.interfaces.nsIRecentBadCertsService);

    this._overrideService =
      Cc["@mozilla.org/security/certoverride;1"]
      .getService(Components.interfaces.nsICertOverrideService);

  //   window.setTimeout(this.delayedStartup, 1000); // 1s
  // },
  // delayedStartup: function() {

    try {
      // gBrowser.removeTabsProgressListener(window.TabsProgressListener);
      gBrowser.addTabsProgressListener(mitm_me.TabsProgressListener);
    } catch (ex) {
      Components.utils.reportError(ex);
    }

    this.dump('MITME LOADED !');
  },

  // TODO: this is where we're going to handle the 'silent' option
  onClick: function(event) {
    // Components.utils.reportError(event);
    mitm_me.dump("onClick");
  },

  onCommand: function(event) {
    // Don't trust synthetic events
    if (!event.isTrusted)
      return;

    var ot = event.originalTarget;
    var errorDoc = ot.ownerDocument;
    var uri = gBrowser.currentURI;

    mitm_me.dump("originalTarget:");
    // mitm_me.dumpObj(ot.ownerDocument);

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

    if (req.channel)
      mitm_me.dump("req.channel defined");
    else
      mitm_me.dump("req.channel undef");

    // WHERE GETS gSSLStatus CREATED ?!

    if(req.channel && req.channel.securityInfo) {
      var secInfo = req.channel.securityInfo;

			mitm_me.dump("req.channel.securityInfo OK");

      gSSLStatus = secInfo.QueryInterface(Ci.nsISSLStatusProvider).SSLStatus;
      gCert = gSSLStatus.QueryInterface(Ci.nsISSLStatus).serverCert;

		  if (secInfo instanceof Ci.nsISSLStatusProvider) {

			  var cert = secInfo.QueryInterface(Ci.nsISSLStatusProvider).
			    SSLStatus.QueryInterface(Ci.nsISSLStatus).serverCert;
			  var verificationResult = cert.verifyForUsage(Ci.nsIX509Cert.CERT_USAGE_SSLServer);

			  switch (verificationResult) {
				case Ci.nsIX509Cert.VERIFIED_OK:
					mitm_me.dump("OK");
					break;
				case Ci.nsIX509Cert.NOT_VERIFIED_UNKNOWN:
					mitm_me.dump("not verfied/unknown");
					break;
				case Ci.nsIX509Cert.CERT_REVOKED:
					mitm_me.dump("revoked");
					break;
				case Ci.nsIX509Cert.CERT_EXPIRED:
					mitm_me.dump("expired");
					break;
				case Ci.nsIX509Cert.CERT_NOT_TRUSTED:
					mitm_me.dump("not trusted");
					break;
				case Ci.nsIX509Cert.ISSUER_NOT_TRUSTED:
					mitm_me.dump("issuer not trusted");
					break;
				case Ci.nsIX509Cert.ISSUER_UNKNOWN:
					mitm_me.dump("issuer unknown");
					break;
				case Ci.nsIX509Cert.INVALID_CA:
					mitm_me.dump("invalid CA");
					break;
				default:
					mitm_me.dump("unexpected failure");
					break;
			  }
			}
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
