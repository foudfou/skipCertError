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
 * (2) a raw reload of the requested https page works, but is not very clean
 * since it shortcuts the internal request to about:certerr, and produces a
 * (not too noticeable) error
 */

Components.utils.import("resource://sce/commons.js");

sce.Main = {

  onLoad: function() {
    // initialization code
    this.initialized = null;
    this.strings = document.getElementById("sce-strings");
    this.notification = {};
    this.stash = {};

    try {
      // Set up preference change observer
      sce.Utils.prefService.QueryInterface(Ci.nsIPrefBranch2);
      // must stay out of _toggle()
      sce.Utils.prefService.addObserver("", this, false);

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

    var enabled = sce.Utils.prefService.getBoolPref('enabled');
    sce.Debug.dump('enabled: '+enabled);
    if (enabled)
      this._toggle(true);

    sce.Debug.dump('SkipCertError LOADED !');
    this.initialized = true;
    return true;
  },

  onQuit: function() {
    // Remove observer
    sce.Utils.prefService.removeObserver("", this);

    this._toogle(false);

    sce.Debug.dump('SkipCertError UNLOADED !');
    this.initialized = false;
  },

  // since we are using a TabsProgressListener, it seems we do not need to keep
  // track of WebProgressListeners as indicated on
  // https://developer.mozilla.org/en/XUL_School/Intercepting_Page_Loads#WebProgressListeners
  _toggle: function (enable) {
    sce.Debug.dump('toggle: '+enable);
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

  observe: function(subject, topic, data) {
    // Observer for pref changes
    if (topic != "nsPref:changed") return;
    sce.Debug.dump('Pref changed: '+data);

    switch(data) {
    case 'enabled':
      var enable = sce.Utils.prefService.getBoolPref('enabled');
      this._toggle(enable);
      break;
    }
  },

  _getCertException: function(uri, cert) {
    var outFlags = {};
    var outTempException = {};
    var knownCert = sce.Main._overrideService.hasMatchingOverride(
      uri.asciiHost,
      uri.port,
      cert,
      outFlags,
      outTempException);
    sce.Debug.dump("known cert: " + knownCert);
    return knownCert;
  },

  _addCertException: function(SSLStatus, uri, cert) {
    var flags = 0;
    if(SSLStatus.isUntrusted)
      flags |= sce.Main._overrideService.ERROR_UNTRUSTED;
    if(SSLStatus.isDomainMismatch)
      flags |= sce.Main._overrideService.ERROR_MISMATCH;
    if(SSLStatus.isNotValidAtThisTime)
      flags |= sce.Main._overrideService.ERROR_TIME;
    sce.Main._overrideService.rememberValidityOverride(
      uri.asciiHost, uri.port,
      cert,
      flags,
      sce.Utils.prefService.getBoolPref('add_temporary_exceptions'));
    sce.Debug.dump("CertEx added");
    sce.Main.TabsProgressListener._certExceptionJustAdded = true;
    sce.Debug.dump("certEx changed: " + sce.Main.TabsProgressListener._certExceptionJustAdded);

    sce.Main.TabsProgressListener._goto = uri.spec;    // never reset
  },

  _parseBadCertFlags: function(flags) {
    var tag = '';
    var ns = Ci.nsIX509Cert;

    if (flags & ns.NOT_VERIFIED_UNKNOWN)
      tag += ', ' + sce.Main.strings.getString('NOT_VERIFIED_UNKNOWN');
    if (flags & ns.CERT_REVOKED)
      tag += ', ' + sce.Main.strings.getString('CERT_REVOKED');
    if (flags & ns.CERT_EXPIRED)
      tag += ', ' + sce.Main.strings.getString('CERT_EXPIRED');
    if (flags & ns.CERT_NOT_TRUSTED)
      tag += ', ' + sce.Main.strings.getString('CERT_NOT_TRUSTED');
    if (flags & ns.ISSUER_NOT_TRUSTED)
      tag += ', ' + sce.Main.strings.getString('ISSUER_NOT_TRUSTED');
    if (flags & ns.ISSUER_UNKNOWN)
      tag += ', ' + sce.Main.strings.getString('ISSUER_UNKNOWN');
    if (flags & ns.INVALID_CA)
      tag += ', ' + sce.Main.strings.getString('INVALID_CA');
    if (flags & ns.USAGE_NOT_ALLOWED)
      tag += ', ' + sce.Main.strings.getString('USAGE_NOT_ALLOWED');
    if (flags & SCE_CERT_SELF_SIGNED)
      tag += ', ' + sce.Main.strings.getString('CERT_SELF_SIGNED');

    if (tag != "") tag = tag.substr(2);

    return tag;
  },

  notify: function(abrowser) {

    // find the correct tab to display notification on
		var mainWindow = window
      .QueryInterface(Ci.nsIInterfaceRequestor).getInterface(Ci.nsIWebNavigation)
      .QueryInterface(Ci.nsIDocShellTreeItem).rootTreeItem
      .QueryInterface(Ci.nsIInterfaceRequestor).getInterface(Ci.nsIDOMWindow);
    var notificationBox = mainWindow.gBrowser.getNotificationBox(abrowser);
    sce.Main.stash.notificationBox = notificationBox; // stash for later use

    // check notification not already here
    if (notificationBox.getNotificationWithValue('SkipCertError')) {
      sce.Debug.dump("notificationBox already here");
      return;
    }

    // build notification
    var priority = 'PRIORITY_INFO_LOW'; // notificationBox.PRIORITY_INFO_LOW not working ??
    var temporaryException = sce.Utils.prefService.getBoolPref('add_temporary_exceptions') ?
      sce.Main.strings.getString('temporaryException') : sce.Main.strings.getString('permanentException');
    var msgArgs = [];
    switch (sce.Main.notification.type) {
    case 'exceptionAdded':
      msgArgs = [temporaryException, sce.Main.notification.host];
      break;
    case 'exceptionNotAdded':
      msgArgs = [sce.Main.notification.dontBypassFlags];
      break;
    default:
      break;
    }
		var message = sce.Main.strings.getFormattedString(
      sce.Main.notification.type, msgArgs);

    // appendNotification( label , value , image , priority , buttons )
    var notification = notificationBox.appendNotification(
      message, 'SkipCertError', null, notificationBox[priority], null);

    // close notificatioBox if needed (will close automatically if reload)
    var exceptionDialogButton = abrowser.webProgress.DOMWindow
      .document.getElementById('exceptionDialogButton');
    exceptionDialogButton.addEventListener(
      "click", sce.Main.exceptionDialogButtonOnClick, false);

    sce.Main.notification = {}; // reset
  },

  exceptionDialogButtonOnClick: function(event) {
    sce.Main._closeNotificationMaybe();
    event.originalTarget.removeEventListener(
      "click", sce.Main.exceptionDialogButtonOnClick, false);
  },

  _closeNotificationMaybe: function() {
    if (!sce.Main.stash.notificationBox)
      return;
    sce.Main.stash.notificationBox.currentNotification.close();
    sce.Main.stash.notificationBox = null;
  },

  // a TabProgressListner seems more appropriate than an Observer, which only
  // gets notified for document requests (not internal requests)
  TabsProgressListener: {
    // can't see the necessity of having QueryInterface(aIID) implemented...

    _certExceptionJustAdded: null, // used for communication btw
                                   // onSecurityChange, onStateChange, ...
    _certerrorCount: 0,            // certerr seems called more than once...

    // This method will be called on security transitions (eg HTTP -> HTTPS,
    // HTTPS -> HTTP, FOO -> HTTPS) and *after document load* completion. It
    // might also be called if an error occurs during network loading.
    onSecurityChange: function (aBrowser, aWebProgress, aRequest, aState) {
      var uri = aBrowser.currentURI;
      sce.Debug.dump("onSecurityChange: uri=" + uri.prePath);

      if (!uri.schemeIs("https")) return;

      this._certerrorCount = 0; // reset

      // retrieve bad cert from nsIRecentBadCertsService
      var port = uri.port;
      if (port == -1) port = 443; // thx http://gitorious.org/perspectives-notary-server/
      var hostWithPort = uri.host + ":" + port;
      sce.Main.notification.host = uri.host;
      var SSLStatus = sce.Main._recentCertsSvc.getRecentBadCert(hostWithPort);
      if (!SSLStatus) {
        Components.utils.reportError("SkipCertError: couldn't get SSLStatus for: " + hostWithPort);
        return;
      }
      var cert = SSLStatus.serverCert;
      sce.Debug.dump("SSLStatus");
      sce.Debug.dumpObj(SSLStatus);
      sce.Debug.dump("cert");
      sce.Debug.dumpObj(cert);

      // check if cert already known/added
      var knownCert = sce.Main._getCertException(uri, cert);
      if (knownCert) return;

      // Determine cert problems
      var dontBypassFlags = 0;

      // we're only interested in certs with characteristics
      // defined in options (self-signed, issuer unknown, ...)
      cert.QueryInterface(Ci.nsIX509Cert3);
      var isSelfSigned = cert.isSelfSigned;
      sce.Debug.dump("isSelfSigned:" + isSelfSigned);
      if (isSelfSigned
          && !sce.Utils.prefService.getBoolPref("bypass_self_signed"))
        dontBypassFlags |= SCE_CERT_SELF_SIGNED;
      // NOTE: isSelfSigned *implies* ISSUER_UNKNOWN (should be handled
      // correctly in option dialog)

      var verificationResult = cert.verifyForUsage(Ci.nsIX509Cert.CERT_USAGE_SSLServer);
      switch (verificationResult) {
      case Ci.nsIX509Cert.ISSUER_NOT_TRUSTED: // including self-signed
        sce.Debug.dump("issuer not trusted");
      case Ci.nsIX509Cert.ISSUER_UNKNOWN:
        sce.Debug.dump("issuer unknown");
        if (!sce.Utils.prefService.getBoolPref("bypass_issuer_unknown"))
          dontBypassFlags |= Ci.nsIX509Cert.ISSUER_UNKNOWN;
      default:
        sce.Debug.dump("verificationResult: " + verificationResult);
        break;
      }
      var dontBypassTag = sce.Main._parseBadCertFlags(dontBypassFlags);
      sce.Debug.dump("dontBypassFlags=" + dontBypassFlags + ", " + dontBypassTag);

      // trigger notification
      if (sce.Utils.prefService.getBoolPref('notify')) {
        sce.Main.notification.willNotify = true;
        sce.Debug.dump("onSecurityChange: willNotify");
      }

      // Add cert exception (if bypass allowed by options)
      if (dontBypassFlags == 0) {
        sce.Main._addCertException(SSLStatus, uri, cert);
        sce.Main.notification.type = 'exceptionAdded';
      } else {
        sce.Main.notification.type = 'exceptionNotAdded';
        sce.Main.notification.dontBypassFlags = dontBypassTag;
      }

    }, // END onSecurityChange

    _getTabIndex: function(abrowser) {
      var tabbrowser = abrowser.getTabBrowser();
      var tabContainer = tabbrowser.tabs;

      var tabIndex = null;
      for (var i = 0; i < tabContainer.length; ++i) {
        if (abrowser == tabbrowser.getBrowserAtIndex(i)) {
          tabIndex = i;
          break;
        }
      }

      return tabIndex;
    },

    // "We can't look for this during onLocationChange since at that point the
    // document URI is not yet the about:-uri of the error page." (browser.js)
    // it *seems* that the scenario is as follows: badcert (onSecurityChange)
    // leading to about:blank, which triggers request of
    // about:document-onload-blocker, leading to about:certerror (called at
    // least twice)
    onStateChange: function (aBrowser, aWebProgress, aRequest, aStateFlags, aStatus) {

      // aProgress.DOMWindow is the tab/window which triggered the change.
      var originDoc = aWebProgress.DOMWindow.document;
      var originURI = originDoc.documentURI;
      sce.Debug.dump("onStateChange " + this._getTabIndex(aBrowser) + ": originURI=" + originURI);
      var safeRequestName = sce.Utils.safeGetName(aRequest);
      sce.Debug.dump("safeRequestName: " + safeRequestName);

      // WE JUST CAN'T CANCEL THE REQUEST FOR
      // about:certerr|about:document-onload-blocker
      // ...SO WE WAIT FOR IT !
      if (aStateFlags & (Ci.nsIWebProgressListener.STATE_STOP
                          |Ci.nsIWebProgressListener.STATE_IS_REQUEST)) {

        if (/^about:certerr/.test(originURI)) {
          this._certerrorCount++;
          sce.Debug.dump("certerrorCount=" + this._certerrorCount);

          if (this._certerrorCount < 2) {
            if (aStateFlags & (Ci.nsIWebProgressListener.STATE_STOP
                               |Ci.nsIWebProgressListener.STATE_RESTORING)) {
              // experienced only one certerr call during sessoin restore
              sce.Debug.dump("restoring");
            } else {
              sce.Debug.dump("certerrorCount not sufficient");
              return; // wait for last (?) call
            }
          }

          if (this._certExceptionJustAdded) {
            this._certExceptionJustAdded = false; // reset
            sce.Debug.dump("certEx changed: " + this._certExceptionJustAdded);

            aRequest.cancel(Components.results.NS_BINDING_ABORTED);
            aBrowser.loadURI(this._goto, null, null);
          }

          if (sce.Main.notification.willNotify) {
            sce.Debug.dump("onStateChange: willNotify");
            sce.Main.notify.willNotify = false; // reset
            sce.Main.notify(aBrowser);
          }

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
window.addEventListener("load", function (e) { sce.Main.onLoad(); }, false);
window.addEventListener("unload", function(e) { sce.Main.onQuit(); }, false);
