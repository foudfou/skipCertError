/* -*- Mode: js2; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/*
 * GLOBAL APPROACH:
 *
 * since we can't avoid the about:certerr page (1), and can't shortcut the
 * internal request to about:certerr gracefully (2), we:
 *
 * - add the cert exception
 * - wait for the about:certerr page
 * - load the initially requested URL
 *
 * (1) certerror is hardly avoidable since it may be displayed whenever a
 * newsocket is created, see: nsNSSIOLayer.cpp: dialogs->ShowCertError,
 * nsNSSBadCertHandler, nsSSLIOLayerNewSocket,
 * ./netwerk/base/src/nsSocketTransport2.cpp
 *
 * (2) reloading the requested https page works, but is not very clean since it
 * shortcuts the internal request to about:certerr, and produces a (not too
 * noticeable) error
 */

Components.utils.import("resource://mitmme/commons.js");

mitmme.Main = {

  onLoad: function() {
    // initialization code
    this.initialized = null;
    this.strings = document.getElementById("mitmme-strings");

    try {
      // Set up preference change observer
      mitmme.Utils.prefService.QueryInterface(Ci.nsIPrefBranch2);
      // must stay out of _toggle()
      mitmme.Utils.prefService.addObserver("", this, false);

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

    var enabled = mitmme.Utils.prefService.getBoolPref('enabled');
    mitmme.Debug.dump('enabled: '+enabled);
    if (enabled)
      this._toggle(true);

    mitmme.Debug.dump('MITMME LOADED !');
    this.initialized = true;
    return true;
  },

  // since we are using a TabsProgressListener, it seems we do not need to keep
  // track of WebProgressListeners as indicated on
  // https://developer.mozilla.org/en/XUL_School/Intercepting_Page_Loads#WebProgressListeners
  _toggle: function (enable) {
    mitmme.Debug.dump('toggle: '+enable);
    try {
      if (enable) {
        gBrowser.addTabsProgressListener(this.TabsProgressListener);
      } else {
        gBrowser.removeTabsProgressListener(this.TabsProgressListener);
      }
    } catch (ex) {
      Components.utils.reportError(ex);
      return false;
    }
  },

  onQuit: function() {
    // Remove observer
    mitmme.Utils.prefService.removeObserver("", this);

    this._toogle(false);

    mitmme.Debug.dump('MITMME UNLOADED !');
    this.initialized = false;
  },

  observe: function(subject, topic, data) {
    // Observer for pref changes
    if (topic != "nsPref:changed") return;
    mitmme.Debug.dump('Pref changed: '+data);

    switch(data) {
    case 'enabled':
      var enable = mitmme.Utils.prefService.getBoolPref('enabled');
      this._toggle(enable);
      break;
    }
  },

  // a TabProgressListner seem more appropriate than an Observer, which only
  // gets notified for document requests (not internal requests)
  TabsProgressListener: {
    // can't see the necessity of having QueryInterface(aIID) implemented...

    _certExceptionJustAdded: null, // used for communication btw
                                   // onSecurityChange, onStateChange, ...

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

      // Add cert exception
      var knownCert = this._getCertException(uri, cert);
      if (!knownCert)
        this._addCertException(SSLStatus, uri, cert);

      this._goto = uri.spec;    // never reset
    }, // END onSecurityChange

    _getCertException: function(uri, cert) {
      // if (uri.asciiHost != cert.commonName)
      //   flags |= mitmme.Main._overrideService.ERROR_MISMATCH;
      // flags |= mitmme.Main._overrideService.ERROR_UNTRUSTED;
      // mitmme.Debug.dump("known cert flags: " + flags);
      var outFlags = {};
      var outTempException = {};
      var knownCert = mitmme.Main._overrideService.hasMatchingOverride(
        uri.asciiHost,
        uri.port,
        cert,
        outFlags,
        outTempException);
      mitmme.Debug.dump("known cert: " + knownCert);
      return knownCert;
    },

    _addCertException: function(SSLStatus, uri, cert) {
      var flags = 0;
      if(SSLStatus.isUntrusted)
        flags |= mitmme.Main._overrideService.ERROR_UNTRUSTED;
      if(SSLStatus.isDomainMismatch)
        flags |= mitmme.Main._overrideService.ERROR_MISMATCH;
      if(SSLStatus.isNotValidAtThisTime)
        flags |= mitmme.Main._overrideService.ERROR_TIME;
      mitmme.Main._overrideService.rememberValidityOverride(
        uri.asciiHost, uri.port,
        cert,
        flags,
        mitmme.Utils.prefService.getBoolPref("add_temporary_exceptions"));
      mitmme.Debug.dump("CertEx added");
      this._certExceptionJustAdded = true;
      mitmme.Debug.dump("certEx changed: " + this._certExceptionJustAdded);
    },

    // We can't look for this during onLocationChange since at that point the
    // document URI is not yet the about:-uri of the error page. (browser.js)
    // it *seems* that the scenario is as follows: badcert (onSecurityChange)
    // leading to about:blank, which triggers request of
    // about:document-onload-blocker, leading to prevURI=about:certerror
    onStateChange: function (aBrowser, aWebProgress, aRequest, aStateFlags, aStatus) {

      // aProgress.DOMWindow is the tab/window which triggered the change.
      var originDoc = aWebProgress.DOMWindow.document;
      var originURI = originDoc.documentURI;
      mitmme.Debug.dump("onStateChange: originURI=" + originURI);
      var safeRequestName = mitmme.Utils.safeGetName(aRequest);
      mitmme.Debug.dump("safeRequestName: " + safeRequestName);

      // WE JUST CAN'T CANCEL THE REQUEST FOR
      // about:certerr|about:document-onload-blocker
      // ...SO WE WAIT FOR IT !
      if (aStateFlags & (Ci.nsIWebProgressListener.STATE_STOP
                         |Ci.nsIWebProgressListener.STATE_IS_REQUEST)) {

        if (/^about:certerr/.test(originURI) && this._certExceptionJustAdded) {
          this._certExceptionJustAdded = false; // reset
          mitmme.Debug.dump("certEx changed: " + this._certExceptionJustAdded);
          aRequest.cancel(Components.results.NS_BINDING_ABORTED);
          aBrowser.loadURI(this._goto, null, null);
        }

      }

    }, // END onStateChange

    onLocationChange: function(aBrowser, aWebProgress, aRequest, aLocation) { },
    onProgressChange: function() { },
    onStatusChange: function() { },

  }, // END TabsProgressListener

};


// should be sufficient for a delayed Startup (no need for window.setTimeout())
// https://developer.mozilla.org/en/Extensions/Performance_best_practices_in_extensions
// https://developer.mozilla.org/en/XUL_School/JavaScript_Object_Management.html
window.addEventListener("load", function () { mitmme.Main.onLoad(); }, false);
window.addEventListener("unload", function(e) { mitmme.Main.onQuit(); }, false);
