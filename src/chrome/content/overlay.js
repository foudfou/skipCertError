/* -*- Mode: js2; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/*
 * GLOBAL APPROACH:
 *
 * since we can't avoid the about:certerr page (1), and can't shortcut the
 * internal request to about:certerr gracefully (2), we:
 *
 * - add the cert exception
 * - wait for the full load of the about:certerr page (that's the tricky part)
 * - load the initially requested URL
 *
 * (1) certerror is hardly avoidable since it may be displayed whenever a
 * newsocket is created, see: nsNSSIOLayer.cpp: dialogs->ShowCertError,
 * nsHandleInvalidCertError, nsNSSBadCertHandler, nsSSLIOLayerNewSocket,
 * ./netwerk/base/src/nsSocketTransport2.cpp
 *
 * (2) a raw reload of the requested https page works, but is not very clean
 * since it shortcuts the internal request to about:certerr, and produces a
 * harmless *no element found* error (displayed shortly and not too noticeable
 * though)
 */

Components.utils.import("resource://sce/commons.js");

/**
 * sce namespace.
 */
if ("undefined" == typeof(sce)) {
  var sce = {};
};


sce.Main = {
  self: function() { return this; },

  onLoad: function() {
    let that = this;
    // initialization code
    this.initialized = null;
    this.strings = document.getElementById("sce-strings");
    this.overrideService = null;
    this.recentCertsService = null;
    this.notification = {
      willNotify: false,
      type: null,
      host: null,
      bypassTag: null
    };
    this.stash = {};

    try {
      // Set up preference change observer
      sce.Utils.prefService.QueryInterface(Ci.nsIPrefBranch2);
      // must stay out of _toggle()
      sce.Utils.prefService.addObserver("", that, false);

      // Get cert services
      // CAUTION: https://bugzilla.mozilla.org/show_bug.cgi?id=650858
      this.overrideService =
        Cc["@mozilla.org/security/certoverride;1"]
        .getService(Components.interfaces.nsICertOverrideService);
      this.recentCertsService = Cc["@mozilla.org/security/recentbadcerts;1"]
        .getService(Ci.nsIRecentBadCertsService);
    }
    catch (ex) {
      Components.utils.reportError("SkipCertError: " + ex);
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
    let that = this;
    // Remove observer
    sce.Utils.prefService.removeObserver("", that);

    this._toogle(false);

    sce.Debug.dump('SkipCertError UNLOADED !');
    this.initialized = false;
  },

  // since we are using a TabsProgressListener, it seems we do not need to keep
  // track of WebProgressListeners as indicated on
  // https://developer.mozilla.org/en/XUL_School/Intercepting_Page_Loads#WebProgressListeners
  _toggle: function (enable) {
    let that = this;
    sce.Debug.dump('toggle: '+enable);
    try {
      if (enable) {
        gBrowser.addTabsProgressListener(that.TabsProgressListener);
      } else {
        gBrowser.removeTabsProgressListener(that.TabsProgressListener);
      }
    } catch (ex) {
      Components.utils.reportError(ex);
      return false;
    }
    return true;
  },

  observe: function(subject, topic, data) {
    // Observer for pref changes
    if (topic != "nsPref:changed") return;
    sce.Debug.dump('Pref changed: ' + data);

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
    var knownCert = this.overrideService.hasMatchingOverride(
      uri.asciiHost,
      uri.port,
      cert,
      outFlags,
      outTempException);
    return knownCert;
  },

  _addCertException: function(SSLStatus, uri, cert) {
    var flags = 0;
    if(SSLStatus.isUntrusted)
      flags |= this.overrideService.ERROR_UNTRUSTED;
    if(SSLStatus.isDomainMismatch)
      flags |= this.overrideService.ERROR_MISMATCH;
    if(SSLStatus.isNotValidAtThisTime)
      flags |= this.overrideService.ERROR_TIME;
    this.overrideService.rememberValidityOverride(
      uri.asciiHost, uri.port,
      cert,
      flags,
      sce.Utils.prefService.getBoolPref('add_temporary_exceptions'));
    sce.Debug.dump("CertEx added");
    this.TabsProgressListener.certExceptionJustAdded = true;
    sce.Debug.dump("certEx changed: " + this.TabsProgressListener.certExceptionJustAdded);

    this.TabsProgressListener.goto_ = uri.spec;    // never reset
  },

  notify: function(abrowser) {
    let that = this;

    // find the correct tab to display notification on
    var mainWindow = window
      .QueryInterface(Ci.nsIInterfaceRequestor).getInterface(Ci.nsIWebNavigation)
      .QueryInterface(Ci.nsIDocShellTreeItem).rootTreeItem
      .QueryInterface(Ci.nsIInterfaceRequestor).getInterface(Ci.nsIDOMWindow);
    var notificationBox = mainWindow.gBrowser.getNotificationBox(abrowser);
    this.stash.notificationBox = notificationBox; // stash for later use

    // check notification not already here
    var notificationValue = this.notification.type + '_' + this.notification.host;
    if (notificationBox.getNotificationWithValue(notificationValue)) {
      sce.Debug.dump("notificationBox already here");
      return;
    }

    // build notification
    var isTemporaryException = sce.Utils.prefService.getBoolPref('add_temporary_exceptions') ?
      this.strings.getString('temporaryException') : this.strings.getString('permanentException');
    var msgArgs = [];
    var priority = null;  // notificationBox.PRIORITY_INFO_LOW not working ??
    switch (this.notification.type) {
    case 'exceptionAdded':
      msgArgs = [isTemporaryException, this.notification.host, this.notification.bypassTag];
      priority = 'PRIORITY_INFO_LOW';
      break;
    case 'exceptionNotAdded':
      msgArgs = [this.notification.host, this.notification.bypassTag];
      priority = 'PRIORITY_WARNING_LOW';
      break;
    case 'exceptionIgnored':
      msgArgs = [this.notification.bypassTag];
      priority = 'PRIORITY_INFO_MEDIUM';
      break;
    default:
      Components.utils.reportError("SkipCertError: notification.type unknown or undefined");
      break;
    }
		var message = this.strings.getFormattedString(this.notification.type, msgArgs);

    // appendNotification( label , value , image , priority , buttons )
    var notification = notificationBox.appendNotification(
      message, notificationValue, null, notificationBox[priority], null);

    // close notificatioBox if needed (will close automatically if reload)
    var exceptionDialogButton = abrowser.webProgress.DOMWindow
      .document.getElementById('exceptionDialogButton');
    exceptionDialogButton.addEventListener(
      "click", function(e){that.exceptionDialogButtonOnClick();}, false);

    this.notification = {}; // reset
  },

  exceptionDialogButtonOnClick: function(event) {
    let that = this;
    this._closeNotificationMaybe();
    event.originalTarget.removeEventListener(
      "click", function(e){that.exceptionDialogButtonOnClick();}, false);
  },

  _closeNotificationMaybe: function() {
    if (!this.stash.notificationBox)
      return;
    this.stash.notificationBox = null;
    this.stash.notificationBox.currentNotification.close();
  },


  // a TabProgressListner seems more appropriate than an Observer, which only
  // gets notified for document requests (not internal requests)
  TabsProgressListener: {
    // can't see the use of implementing QueryInterface(aIID)...

    certExceptionJustAdded: null, // used for communication btw
    // onSecurityChange, onStateChange, ...
    goto_: null,                  // target URL when after certerr encountered
    _certerrorCount: 0,           // certerr seems called more than once...

    _parseBadCertFlags: function(flags) {
      var tag = '';
      var ns = Ci.nsIX509Cert;
      if (flags == null) return 'unknown';

      if (flags == ns.VERIFIED_OK)
        tag += ', ' + sceMain().strings.getString('VERIFIED_OK');
      if (flags & ns.NOT_VERIFIED_UNKNOWN)
        tag += ', ' + sceMain().strings.getString('NOT_VERIFIED_UNKNOWN');
      if (flags & ns.CERT_REVOKED)
        tag += ', ' + sceMain().strings.getString('CERT_REVOKED');
      if (flags & ns.CERT_EXPIRED)
        tag += ', ' + sceMain().strings.getString('CERT_EXPIRED');
      if (flags & ns.CERT_NOT_TRUSTED)
        tag += ', ' + sceMain().strings.getString('CERT_NOT_TRUSTED');
      if (flags & ns.ISSUER_NOT_TRUSTED)
        tag += ', ' + sceMain().strings.getString('ISSUER_NOT_TRUSTED');
      if (flags & ns.ISSUER_UNKNOWN)
        tag += ', ' + sceMain().strings.getString('ISSUER_UNKNOWN');
      if (flags & ns.INVALID_CA)
        tag += ', ' + sceMain().strings.getString('INVALID_CA');
      if (flags & ns.USAGE_NOT_ALLOWED)
        tag += ', ' + sceMain().strings.getString('USAGE_NOT_ALLOWED');
      if (flags & SCE_CERT_SELF_SIGNED)
        tag += ', ' + sceMain().strings.getString('CERT_SELF_SIGNED');
      if (flags & SCE_SSL_DOMAIN_MISMATCH)
        tag += ', ' + sceMain().strings.getString('SSL_DOMAIN_MISMATCH');
      if (flags & SCE_SSL_NOT_VALID)
        tag += ', ' + sceMain().strings.getString('SSL_NOT_VALID');

      if (tag != "") tag = tag.substr(2); // remove leading ', '

      return tag;
    },

    // This method will be called on security transitions (eg HTTP -> HTTPS,
    // HTTPS -> HTTP, FOO -> HTTPS) and *after document load* completion. It
    // might also be called if an error occurs during network loading.
    onSecurityChange: function (aBrowser, aWebProgress, aRequest, aState) {
      var uri = aBrowser.currentURI;
      sce.Debug.dump("onSecurityChange: uri=" + uri.prePath);

      if (!uri.schemeIs("https")) return;

      this._certerrorCount = 0; // reset

      // retrieve bad cert from nsIRecentBadCertsService
      /* NOTE: experience shows that nsIRecentBadCertsService will not provide
       SSLStatus when cert is known or trusted. BUT... cert may also be
       untrusted, and nsIRecentBadCertsService won't provide SSLStatus (ex:
       revoked cert provides OCSP server). That's why we might need to get it
       from aRequest... TODO: for now we don't support OCSP */
      var port = uri.port;
      if (port == -1) port = 443; // thx http://gitorious.org/perspectives-notary-server/
      var hostWithPort = uri.host + ":" + port;
      sceMain().notification.host = uri.host;
      var SSLStatus = sceMain().recentCertsService.getRecentBadCert(hostWithPort);

      if (!SSLStatus) {
        sce.Debug.dump("no SSLStatus for: " + hostWithPort);
        return;
      }

      sce.Debug.dump("SSLStatus");
      sce.Debug.dumpObj(SSLStatus);
      var cert = SSLStatus.serverCert;
      sce.Debug.dump("cert");
      sce.Debug.dumpObj(cert);

      // check if cert already known/added
      var knownCert = sceMain()._getCertException(uri, cert);
      if (knownCert) {
        sce.Debug.dump("known cert: " + knownCert);
        return;
      }

      // Determine cert problems.
      /* Question is: IN WHICH CASES DO WE GET THE CERTERROR ?
       *
       * We know: there are 2 classes of errors: ERROR_CLASS_BAD_CERT,
       * ERROR_CLASS_SSL_PROTOCOL. We believe certerror is triggered when some
       * SSLStatus.is* are set (bitarray) OR verificationResult != 0 (exclusive
       * conditions)
       *
       * For now, we'll make it simple: if *all* encountered conditions are set
       * to bypass (see options), then we bypass. If some aren't set, we don't
       * bypass and notify. For all other errors, we don't bypass, and notify
       * "error not handled by SkipCertError"
       */
      var bypassFlags = 0;
      var dontBypassFlags = 0; // we record when bypass conditions encountered
                               // but not set in options
      var ignoreFlags = null;

      // we're only interested in certs with characteristics
      // defined in options (self-signed, issuer unknown, ...)
      cert.QueryInterface(Ci.nsIX509Cert3);
      var isSelfSigned = cert.isSelfSigned;
      sce.Debug.dump("isSelfSigned:" + isSelfSigned + ", bypass=" + sce.Utils.prefService.getBoolPref("bypass_self_signed"));
      if (isSelfSigned) {       // ex: https://www.pcwebshop.co.uk/
        if (sce.Utils.prefService.getBoolPref("bypass_self_signed"))
          bypassFlags |= SCE_CERT_SELF_SIGNED;
        else
          dontBypassFlags |= SCE_CERT_SELF_SIGNED;
      }

      var verificationResult = cert.verifyForUsage(Ci.nsIX509Cert.CERT_USAGE_SSLServer);
      sce.Debug.dump("verificationResult: " + verificationResult);
      // all conditions are exclusive - which is odd because a cert could be
      // revoked and expired (?)
      switch (verificationResult) {

      case Ci.nsIX509Cert.ISSUER_NOT_TRUSTED: // implied by self-signed, ex: https://linux.fr
        sce.Debug.dump("issuer_not_trusted, bypass=" + sce.Utils.prefService.getBoolPref("bypass_issuer_not_trusted"));
        if (sce.Utils.prefService.getBoolPref("bypass_issuer_not_trusted"))
          bypassFlags |= Ci.nsIX509Cert.ISSUER_NOT_TRUSTED;
        else
          dontBypassFlags |= Ci.nsIX509Cert.ISSUER_NOT_TRUSTED;
        break;

      case Ci.nsIX509Cert.ISSUER_UNKNOWN: // ex: https://www.cheepcheepboxes.com/
        sce.Debug.dump("issuer_unknown, bypass=" + sce.Utils.prefService.getBoolPref("bypass_issuer_unknown"));
        if (sce.Utils.prefService.getBoolPref("bypass_issuer_unknown"))
          bypassFlags |= Ci.nsIX509Cert.ISSUER_UNKNOWN;
        else
          dontBypassFlags |= Ci.nsIX509Cert.ISSUER_UNKNOWN;
        break;

      case Ci.nsIX509Cert.VERIFIED_OK: // ignored
        break; // keep ignoreFlags null to have tag "unknown"
      case Ci.nsIX509Cert.NOT_VERIFIED_UNKNOWN: // ignored
      case Ci.nsIX509Cert.CERT_REVOKED: // ignored, // OCSP ex: https://test-sspev.verisign.com:2443/test-SSPEV-revoked-verisign.html
      case Ci.nsIX509Cert.CERT_EXPIRED: // ignored // ex: https://www.mjvmobile.com.br/
      case Ci.nsIX509Cert.CERT_NOT_TRUSTED: // ignored
      case Ci.nsIX509Cert.INVALID_CA: // ignored
      case Ci.nsIX509Cert.USAGE_NOT_ALLOWED: // ignored
        ignoreFlags |= verificationResult;
        break;

      default:
        Components.utils.reportError(
          "SkipCertError: unknown cert verification: " + verificationResult);
        break;
      }

      /*
       * CAUTION: verificationResult (see later) can be 0, but cert still bad:
       * either because of SSLStatus.is*, or because OCSP query not issued yet
       */
      /*
       * NOTE: any of UNKNOWN_ISSUER, CA_CERT_INVALID, UNTRUSTED_ISSUER,
       * EXPIRED_ISSUER_CERTIFICATE, UNTRUSTED_CERT, INADEQUATE_KEY_USAGE
       * triggers nsICertOverrideService::ERROR_UNTRUSTED (nsNSSIOLayer.cpp)
       */
      if(SSLStatus.isUntrusted) {
        sce.Debug.dump("SSLStatus.isUntrusted");
        // ignoreFlags will be null => 'unknown'
      }
      if(SSLStatus.isDomainMismatch) { // ex: https://amazon.com/
        if (sce.Utils.prefService.getBoolPref("bypass_domain_mismatch"))
          bypassFlags |= SCE_SSL_DOMAIN_MISMATCH;
        else
          dontBypassFlags |= SCE_SSL_DOMAIN_MISMATCH;
      }
      if(SSLStatus.isNotValidAtThisTime) {
        sce.Debug.dump("SSLStatus.isNotValidAtThisTime");
        ignoreFlags |= SCE_SSL_NOT_VALID;
      }

      var bypassTags = this._parseBadCertFlags(bypassFlags);
      sce.Debug.dump("bypassFlags=" + bypassFlags + ", " + bypassTags);
      var dontBypassTags = this._parseBadCertFlags(dontBypassFlags);
      sce.Debug.dump("dontBypassFlags=" + dontBypassFlags + ", " + dontBypassTags);
      var ignoreTags = this._parseBadCertFlags(ignoreFlags);
      sce.Debug.dump("ignoreFlags=" + ignoreFlags + ", " + ignoreTags);

      // Add cert exception (if bypass allowed by options)
      if (dontBypassFlags) {    // ALL conditions must be set
        sceMain().notification.type = 'exceptionNotAdded';
        sceMain().notification.bypassTag = dontBypassTags;
      } else if (bypassFlags) {
        sceMain()._addCertException(SSLStatus, uri, cert);
        sceMain().notification.type = 'exceptionAdded';
        sceMain().notification.bypassTag = bypassTags;
      } else {
        sceMain().notification.type = 'exceptionIgnored';
        sceMain().notification.bypassTag = ignoreTags;
      }

      // trigger notification
      if (sce.Utils.prefService.getBoolPref('notify')) {
        sceMain().notification.willNotify = true;
        sce.Debug.dump("onSecurityChange: willNotify -> " + sceMain().notification.willNotify);
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
    // Experience shows that the order is as follows: badcert
    // (onSecurityChange) leading to about:blank, then request of
    // about:document-onload-blocker, leading to about:certerror (called at
    // least twice)
    onStateChange: function (aBrowser, aWebProgress, aRequest, aStateFlags, aStatus) {

      // aProgress.DOMWindow is the tab/window which triggered the change.
      var originDoc = aWebProgress.DOMWindow.document;
      var originURI = originDoc.documentURI;
      sce.Debug.dump("onStateChange " + this._getTabIndex(aBrowser) + ": originURI=" + originURI);
      var safeRequestName = sce.Utils.safeGetName(aRequest);
      sce.Debug.dump("safeRequestName: " + safeRequestName);

      // WE JUST CAN'T CANCEL THE REQUEST FOR about:certerr |
      // about:document-onload-blocker ...SO WE WAIT FOR IT !
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

          if (this.certExceptionJustAdded) {
            this.certExceptionJustAdded = false; // reset
            sce.Debug.dump("certEx changed: " + this.certExceptionJustAdded);
            aRequest.cancel(Components.results.NS_BINDING_ABORTED);
            aBrowser.loadURI(this.goto_, null, null);
          }

          if (sceMain().notification.willNotify) {
            sce.Debug.dump("onStateChange: willNotify");
            sceMain().notify.willNotify = false; // reset
            sceMain().notify(aBrowser);
          }

        }

      }

    }, // END onStateChange

    onLocationChange: function() { },
    onProgressChange: function() { },
    onStatusChange: function() { }

  } // END TabsProgressListener

}; // END Main
var sceMain = sce.Main.self.bind(sce.Main);


// should be sufficient for a delayed Startup (no need for window.setTimeout())
// https://developer.mozilla.org/en/Extensions/Performance_best_practices_in_extensions
// https://developer.mozilla.org/en/XUL_School/JavaScript_Object_Management.html
window.addEventListener("load", function (e) { sce.Main.onLoad(); }, false);
window.addEventListener("unload", function(e) { sce.Main.onQuit(); }, false);
