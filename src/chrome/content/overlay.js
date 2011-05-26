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

Components.utils.import("resource://mitmme/commons.js");

mitmme.Main = {

  onLoad: function() {
    // initialization code
    this.initialized = true;
    this.strings = document.getElementById("mitmme-strings");

    try {
      // Set up preference change observer
      this._prefService =
        Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService)
        .getBranch("extensions.mitmme.");
      this._prefService.QueryInterface(Ci.nsIPrefBranch2);
      this._prefService.addObserver("", this, false);

      // Get cert services
      this._overrideService =
        Cc["@mozilla.org/security/certoverride;1"]
        .getService(Components.interfaces.nsICertOverrideService);
      this._recentCertsSvc = Cc["@mozilla.org/security/recentbadcerts;1"]
        .getService(Ci.nsIRecentBadCertsService);
    }
    catch (ex) {
      Components.utils.reportError(ex);
      return false;
    }

    try {
      gBrowser.addTabsProgressListener(mitmme.Main.TabsProgressListener);
    } catch (ex) {
      Components.utils.reportError(ex);
      return false;
    }

    mitmme.Debug.dump('MITMME LOADED !');
    return true;
  },

  onQuit: function() {
    // Remove observer
    this._prefService.QueryInterface(Ci.nsIPrefBranch2);
    this._prefService.removeObserver("", this);
  },

  observe: function(subject, topic, data) {
    // Observer for pref changes
    if (topic != "nsPref:changed") return;
    mitmme.Debug.dump('Pref changed: '+data);
    // preform actions here: switch(data) { ...
  },

  TabsProgressListener: {

    // This method will be called on security transitions (eg HTTP -> HTTPS,
    // HTTPS -> HTTP, FOO -> HTTPS) and *after document load* completion. It
    // might also be called if an error occurs during network loading.
    onSecurityChange: function (aBrowser, aWebProgress, aRequest, aState) {
      var uri = aBrowser.currentURI;
      mitmme.Debug.dump("onSecurityChange: uri=" + uri.prePath);

      if (!uri.schemeIs("https")) return;

      // retrieve bad cert from nsIRecentBadCertsService
      var port = uri.port;
      if (port == -1) port = 443; // thx http://gitorious.org/perspectives-notary-server/
      var hostWithPort = uri.host + ":" + port;
      var SSLStatus = mitmme.Main._recentCertsSvc.getRecentBadCert(hostWithPort);
      if (!SSLStatus) {
        Components.utils.reportError("MITMME: couldn't get SSLStatus for: " + hostWithPort);
        return;
      }
			var cert = SSLStatus.serverCert;
      mitmme.Debug.dump("SSLStatus");
      mitmme.Debug.dumpObj(SSLStatus);
      mitmme.Debug.dump("cert");
      mitmme.Debug.dumpObj(cert);

      // we're only interested in self-signed certs
      cert.QueryInterface(Components.interfaces.nsIX509Cert3);
      mitmme.Debug.dump("isSelfSigned:" + cert.isSelfSigned);
      // ...or maybe also by unknown issuer
			var verificationResult = cert.verifyForUsage(Ci.nsIX509Cert.CERT_USAGE_SSLServer);
			switch (verificationResult) {
			case Ci.nsIX509Cert.ISSUER_NOT_TRUSTED: // including self-signed
				mitmme.Debug.dump("issuer not trusted");
			case Ci.nsIX509Cert.ISSUER_UNKNOWN:
				mitmme.Debug.dump("issuer unknown");
			default:
				mitmme.Debug.dump("verificationResult: " + verificationResult);
				break;
			}

    }, // END TabsProgressListener

    onStateChange: function (aBrowser, aWebProgress, aRequest, aStateFlags, aStatus) {
      if (aStateFlags & Ci.nsIWebProgressListener.STATE_STOP &&
          /^about:certerror/.test(aWebProgress.DOMWindow.document.documentURI)) {
        mitmme.Debug.dump("onStateChange: certerror: "
                     + aWebProgress.DOMWindow.document.documentURI);
      }
    },

  }, // END TabsProgressListener

};


// should be sufficient for a delayed Startup (no need for window.setTimeout())
// https://developer.mozilla.org/en/Extensions/Performance_best_practices_in_extensions
// https://developer.mozilla.org/en/XUL_School/JavaScript_Object_Management.html
window.addEventListener("load", function () { mitmme.Main.onLoad(); }, false);
