/* -*- Mode: js2; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/*
 * GLOBAL APPROACH:
 *
 * since we can't avoid the about:certerr page (1), and can't shortcut the
 * internal request to about:certerr gracefully (2), we:
 *
 * - add the cert exception (onSecurityChange)
 * - wait for the full load of the about:certerr page (onStateChange) — (that's
 *   the tricky part)
 * - load the initially requested URL (onStateChange)
 * - show a notification (onLocationChange)
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
Components.utils.import("resource://sce/sec.jsm");

// number of times, for a specific page, that we let the cert error page being
// called, before overriding it.
const SCE_CERTERROR_COUNT_MAX = 2;

let scelog = sce.Logging.getLogger("sce.Chrome");

var sceChrome = {

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
      this.recentCertsService = this._initBadCertService();
    }
    catch (ex) {
      scelog.error("SkipCertError: " + ex);
      return false;
    }

    var enabled = sce.Utils.prefService.getBoolPref('enabled');
    scelog.debug('enabled: '+enabled);
    if (enabled)
      this._toggle(true);

    scelog.debug('SkipCertError LOADED !');
    this.initialized = true;
    return true;
  },

  onQuit: function() {
    let that = this;
    // Remove observer
    sce.Utils.prefService.removeObserver("", that);

    this._toggle(false);

    scelog.debug('SkipCertError UNLOADED !');
    this.initialized = false;
  },

  // since we are using a TabsProgressListener, it seems we do not need to keep
  // track of WebProgressListeners as indicated on
  // https://developer.mozilla.org/en/XUL_School/Intercepting_Page_Loads#WebProgressListeners
  _toggle: function(enable) {
    let that = this;
    scelog.debug('toggle: '+enable);
    try {
      if (enable) {
        gBrowser.addTabsProgressListener(that.TabsProgressListener);
      } else {
        gBrowser.removeTabsProgressListener(that.TabsProgressListener);
      }
    } catch (ex) {
      scelog.error(ex);
      return false;
    }
    return true;
  },

  observe: function(subject, topic, data) {
    // Observer for pref changes
    if (topic != "nsPref:changed") return;
    scelog.debug('Pref changed: ' + data);

    switch(data) {
    case 'enabled':
      var enable = sce.Utils.prefService.getBoolPref('enabled');
      this._toggle(enable);
      break;
    }
  },

  _initBadCertService: function() {
    if (Cc["@mozilla.org/security/recentbadcerts;1"])
      return Cc["@mozilla.org/security/recentbadcerts;1"]
      .getService(Ci.nsIRecentBadCertsService);
    else {                      // Gecko 20+
      let isPrivate = false;
      return Cc["@mozilla.org/security/x509certdb;1"]
      .getService(Ci.nsIX509CertDB)
      .getRecentBadCerts(isPrivate);
    }
  },

  getCertException: function(uri, cert) {
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

  addCertException: function(SSLStatus, uri) {
    var flags = 0;
    if(SSLStatus.isUntrusted)
      flags |= this.overrideService.ERROR_UNTRUSTED;
    if(SSLStatus.isDomainMismatch)
      flags |= this.overrideService.ERROR_MISMATCH;
    if(SSLStatus.isNotValidAtThisTime)
      flags |= this.overrideService.ERROR_TIME;
    this.overrideService.rememberValidityOverride(
      uri.asciiHost, uri.port,
      SSLStatus.serverCert,
      flags,
      sce.Utils.prefService.getBoolPref('add_temporary_exceptions'));
    scelog.debug("CertEx added");
    this.TabsProgressListener.certExceptionJustAdded = true;
    scelog.debug("certEx changed: " + this.TabsProgressListener.certExceptionJustAdded);

    this.TabsProgressListener.goto_ = uri.spec;    // never reset
  },

  updateDiagWithFlagFromPref: function(diag, flag, prefName) {
    prefVal = sce.Utils.prefService.getBoolPref(prefName);
    scelog.debug(prefName + ", bypass=" + prefVal);
    if (prefVal) {
      diag.bypassFlags |= flag;
    } else {
      diag.dontBypassFlags |= flag;
    }
    return diag;
  },

  getSSLStatusFromRequest: function(request) {
    if (request instanceof Ci.nsIChannel) {
      request.QueryInterface(Ci.nsIChannel);
      let secInfo = request.securityInfo;
      if (secInfo instanceof Ci.nsISSLStatusProvider) {
        return secInfo.QueryInterface(Ci.nsISSLStatusProvider)
          .SSLStatus.QueryInterface(Ci.nsISSLStatus);
      }
    }
    return null;
  },

  isSelfSignedFromSSLStatus: function(status) {
    var cert = status.serverCert;
    cert.QueryInterface(Ci.nsIX509Cert3);
    var isSelfSigned = cert.isSelfSigned;
    scelog.debug("isSelfSigned:" + isSelfSigned);

    return isSelfSigned;
  },

  /*
   * Test with https://www.ssllabs.com/ssltest/index.html
   *
   * For now, we gather error information from 3 sources: the NSS request
   * status, the SSLSatus, and the cert.
   */
  diagnoseInsecureRequest: function(request, sslStatus) {
    if (!request) return null;
    if ("undefined" === typeof(sslStatus) ||
        !sslStatus) {
      log.debug("diagnoseInsecureRequest: sslStatus not provided");
      sslStatus = this.getSSLStatusFromRequest(request);
    }

    /* For now, we'll make it simple: if *all* encountered conditions are set
     to bypass (see options), then we bypass. If some aren't set, we don't
     bypass and notify. For all other errors, we don't bypass, and notify "error
     not handled by SkipCertError". */
    let diag = {
      bypassFlags: 0,
      // we record when bypass conditions encountered but not set in options
      dontBypassFlags: 0,
      ignoreFlags: null
    };

    let status = request.status;
    scelog.debug("sslStatus="+sslStatus+", status="+status);

    let nsModule = sce.Sec.NS_ERROR_GET_MODULE(status);
    scelog.debug("nsModule="+nsModule);
    if (nsModule === sce.Sec.NS_ERROR_MODULE_SECURITY) {
      let err = sce.Sec.getNSPRCode(status);
      scelog.debug("NSPRCode="+err);

      // all conditions seem exclusive - which is odd because a cert could be
      // revoked and expired (?)
      switch (err) {
      case sce.Sec.SEC_ERROR_UNTRUSTED_ISSUER: // implied by self-signed, ex: https://linuxfr.org

        this.updateDiagWithFlagFromPref(diag, SCE_ISSUER_NOT_TRUSTED,
                                        "bypass_issuer_not_trusted");
        break;
      case sce.Sec.SEC_ERROR_UNKNOWN_ISSUER:
        this.updateDiagWithFlagFromPref(diag, SCE_ISSUER_UNKNOWN,
                                        "bypass_issuer_unknown");
        break;
      default:                  // ignore
        break;
      }

    } else {
      scelog.debug("Not for security module");
    }

    let isSelfSigned = this.isSelfSignedFromSSLStatus(sslStatus);
    if (isSelfSigned) {       // ex: https://www.pcwebshop.co.uk/
      this.updateDiagWithFlagFromPref(diag, SCE_CERT_SELF_SIGNED,
                                 "bypass_self_signed");
    }
    if(sslStatus.isUntrusted) {
      scelog.debug("sslStatus.isUntrusted");
      // ignoreFlags will be null => 'unknown'
    }
    if(sslStatus.isDomainMismatch) { // ex: https://amazon.com/
      this.updateDiagWithFlagFromPref(diag, SCE_SSL_DOMAIN_MISMATCH,
                                 "bypass_domain_mismatch");
    }
    if(sslStatus.isNotValidAtThisTime) {
      scelog.debug("sslStatus.isNotValidAtThisTime");
      diag.ignoreFlags |= SCE_SSL_NOT_VALID;
    }

    return diag;
  },

  isBypassDomain: function(host) {
    var bypassDomains = sce.Utils.getArrayPref('bypass_domains');
    scelog.debug("*** bypassDomains:"+bypassDomains);
    for (let i=0, len=bypassDomains.length; i<len; ++i) {
      let domain = bypassDomains[i];
      let re = new RegExp(domain.replace(/\./g, "\\.")+"$");
      if (re.test(host)) return domain;
    }
    return null;
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
      scelog.debug("notificationBox already here");
      return;
    }

    // build notification
    var isTemporaryException = sce.Utils.prefService.getBoolPref('add_temporary_exceptions') ?
      this.strings.getString('temporaryException') : this.strings.getString('permanentException');
    var msgArgs = [];
    var priority = null;  // notificationBox.PRIORITY_INFO_LOW not working ??
    switch (this.notification.type) {
    case 'exceptionAddedKnownDomain':
      msgArgs = [isTemporaryException, this.notification.host, this.notification.bypassDomain];
      priority = 'PRIORITY_INFO_LOW';
      break;
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
      scelog.error("SkipCertError: notification.type unknown or undefined");
      break;
    }
    var message = this.strings.getFormattedString(this.notification.type, msgArgs);

    // appendNotification( label , value , image , priority , buttons )
    var notification = notificationBox.appendNotification(
      message, notificationValue, null, notificationBox[priority], null);
    scelog.debug("notified");

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


  // a TabsProgressListner seems more appropriate than an Observer, which only
  // gets notified for document requests (not internal requests)
  TabsProgressListener: {
    // can't see the use of implementing QueryInterface(aIID)...

    // used for communication btw onSecurityChange, onStateChange, ...
    certExceptionJustAdded: null,
    sslStatus: null,
    goto_: null,                  // target URL when after certerr encountered
    _certerrorCount: 0,           // certerr seems called more than once...

    _parseBadCertFlags: function(flags) {
      var tag = '';
      var ns = Ci.nsIX509Cert;
      if (flags == null) return 'unknown';

      if (flags == ns.VERIFIED_OK)
        tag += ', ' + sceChrome.strings.getString('VERIFIED_OK');
      if (flags & ns.NOT_VERIFIED_UNKNOWN)
        tag += ', ' + sceChrome.strings.getString('NOT_VERIFIED_UNKNOWN');
      if (flags & ns.CERT_REVOKED)
        tag += ', ' + sceChrome.strings.getString('CERT_REVOKED');
      if (flags & ns.CERT_EXPIRED)
        tag += ', ' + sceChrome.strings.getString('CERT_EXPIRED');
      if (flags & ns.CERT_NOT_TRUSTED)
        tag += ', ' + sceChrome.strings.getString('CERT_NOT_TRUSTED');
      if (flags & ns.ISSUER_NOT_TRUSTED)
        tag += ', ' + sceChrome.strings.getString('ISSUER_NOT_TRUSTED');
      if (flags & ns.ISSUER_UNKNOWN)
        tag += ', ' + sceChrome.strings.getString('ISSUER_UNKNOWN');
      if (flags & ns.INVALID_CA)
        tag += ', ' + sceChrome.strings.getString('INVALID_CA');
      if (flags & ns.USAGE_NOT_ALLOWED)
        tag += ', ' + sceChrome.strings.getString('USAGE_NOT_ALLOWED');
      if (flags & SCE_CERT_SELF_SIGNED)
        tag += ', ' + sceChrome.strings.getString('CERT_SELF_SIGNED');
      if (flags & SCE_SSL_DOMAIN_MISMATCH)
        tag += ', ' + sceChrome.strings.getString('SSL_DOMAIN_MISMATCH');
      if (flags & SCE_SSL_NOT_VALID)
        tag += ', ' + sceChrome.strings.getString('SSL_NOT_VALID');

      if (tag != "") tag = tag.substr(2); // remove leading ', '

      return tag;
    },

    /* This method will be called on security transitions (eg HTTP -> HTTPS,
     * HTTPS -> HTTP, FOO -> HTTPS) and *after document load* completion. It
     * might also be called if an error occurs during network loading.
     *
     * We could also check (aFlags ===
     * Ci.nsIWebProgressListener.LOCATION_CHANGE_ERROR_PAGE) onLocationChange,
     * but this doesn't seem to detect errors in iframes
     */
    onSecurityChange: function (aBrowser, aWebProgress, aRequest, aState) {
      var uri = aBrowser.currentURI;
      scelog.debug("onSecurityChange: uri=" + uri.prePath);
      scelog.debug("aState: "+aState);

      const wpl = Ci.nsIWebProgressListener;
      let stateInsecure = aState & wpl.STATE_IS_INSECURE;
      let stateBroken = aState & wpl.STATE_IS_BROKEN;
      let stateInsecureMixedBlocked = aState &
            (wpl.STATE_IS_INSECURE |
             wpl.STATE_BLOCKED_MIXED_ACTIVE_CONTENT);
      if (!uri.schemeIs("https")) return;
      if (!stateInsecure || !stateInsecureMixedBlocked) return;

      this.sslStatus = sceChrome.getSSLStatusFromRequest(aRequest);
      if (!this.sslStatus) {    // mostly on restoring
        scelog.info("no SSLStatus");
        return;
      }
      scelog.debug("this.sslStatus set: "+this.sslStatus);
      sceChrome.notification.host = uri.host;

      if (sce.Utils.prefService.getBoolPref('single_click_skip')) return;
      scelog.debug("single_click_skip false");

      this._certerrorCount = 0; // reset

      var cert = this.sslStatus.serverCert;
      scelog.debug("cert found: "+cert);

      // check if cert already known/added
      var knownCert = sceChrome.getCertException(uri, cert);
      if (knownCert) {
        scelog.debug("known cert: " + knownCert);
        return;
      }

      var domainBypass = sceChrome.isBypassDomain(uri.host);
      scelog.debug("*** domainBypass="+domainBypass);
      if (domainBypass) {
        sceChrome.addCertException(this.sslStatus, uri);
        sceChrome.notification.type = 'exceptionAddedKnownDomain';
        sceChrome.notification.bypassDomain = domainBypass;

      } else {
        var certDiag = sceChrome.diagnoseInsecureRequest(aRequest, this.sslStatus);

        // Add cert exception (if bypass allowed by options)
        if (certDiag.dontBypassFlags) {    // ALL conditions must be set
          sceChrome.notification.type = 'exceptionNotAdded';
          var dontBypassTags = this._parseBadCertFlags(certDiag.dontBypassFlags);
          scelog.debug("dontBypassFlags=" + certDiag.dontBypassFlags + ", " + dontBypassTags);
          sceChrome.notification.bypassTag = dontBypassTags;
        } else if (certDiag.bypassFlags) {
          sceChrome.addCertException(this.sslStatus, uri);
          sceChrome.notification.type = 'exceptionAdded';
          var bypassTags = this._parseBadCertFlags(certDiag.bypassFlags);
          scelog.debug("bypassFlags=" + certDiag.bypassFlags + ", " + bypassTags);
          sceChrome.notification.bypassTag = bypassTags;
        } else {
          sceChrome.notification.type = 'exceptionIgnored';
          var ignoreTags = this._parseBadCertFlags(certDiag.ignoreFlags);
          scelog.debug("ignoreFlags=" + certDiag.ignoreFlags + ", " + ignoreTags);
          sceChrome.notification.bypassTag = ignoreTags;
        }
      }

      // trigger notification
      if (sce.Utils.prefService.getBoolPref('notify')) {
        sceChrome.notification.willNotify = true;
        scelog.debug("onSecurityChange: willNotify -> " + sceChrome.notification.willNotify);
      }

    }, // END onSecurityChange

    _replaceExceptionDialogButton: function(doc, browser) {
      let exceptionDialogButton = doc.getElementById('exceptionDialogButton');
      if (!exceptionDialogButton) {
        scelog.error("no exceptionDialogButton found");
      }
      exceptionDialogButton.style.display = "none";

      if (doc.getElementById('SkipCertErrorButton')) {
        scelog.debug("skipCertButtun already here");
        return;
      }

      let newButton = doc.createElement("button");
      newButton.id = "SkipCertErrorButton";
      newButton.innerHTML = sceChrome.strings.getString('skipError');
      let that = this;
      newButton.addEventListener("click", function(event) {
        let uri = browser.currentURI;
        sceChrome.addCertException(that.sslStatus, uri);
        browser.loadURI(uri.spec, null, null);
      }, false);
      exceptionDialogButton.parentNode.appendChild(newButton);
    },

    /*
     * "We can't look for this during onLocationChange since at that point the
     * document URI is not yet the about:-uri of the error page." (browser.js)
     * Experience shows that the order is as follows: badcert
     * (onSecurityChange) leading to about:blank, then request of
     * about:document-onload-blocker, leading to about:certerror (called at
     * least twice)
     */
    onStateChange: function (aBrowser, aWebProgress, aRequest, aStateFlags, aStatus) {
      // WE JUST CAN'T CANCEL THE REQUEST FOR about:certerr |
      // about:document-onload-blocker ...SO WE WAIT FOR IT !
      if (aStateFlags & (Ci.nsIWebProgressListener.STATE_STOP |
                         Ci.nsIWebProgressListener.STATE_IS_REQUEST)) {

        // aWebProgress.DOMWindow is the tab/window which triggered the change.
        var originDoc = aWebProgress.DOMWindow.document;
        var originURI = originDoc.documentURI;
        scelog.debug("originURI="+originURI);

        if (/^about:certerr/.test(originURI)) {
          this._certerrorCount++;
          scelog.debug("certerrorCount=" + this._certerrorCount);

          if (this._certerrorCount < SCE_CERTERROR_COUNT_MAX) {
            if (aStateFlags & (Ci.nsIWebProgressListener.STATE_STOP
                               |Ci.nsIWebProgressListener.STATE_RESTORING)) {
              // experienced only one certerr call during sessoin restore
              scelog.debug("restoring");
            } else {
              scelog.debug("certerrorCount not sufficient");
              return; // wait for last (?) call
            }
          }

          if (sce.Utils.prefService.getBoolPref('single_click_skip')) {
            scelog.debug("single_click_skip");
            this._replaceExceptionDialogButton(originDoc, aBrowser);
            return;
          }

          if (this.certExceptionJustAdded) {
            this.certExceptionJustAdded = false; // reset
            scelog.debug("certEx changed: " + this.certExceptionJustAdded);
            aRequest.cancel(Components.results.NS_BINDING_ABORTED);
            aBrowser.loadURI(this.goto_, null, null);
          }

        } // END /^about:certerr/

      } // END STATE_STOP|STATE_IS_REQUEST
    }, // END onStateChange

    onLocationChange: function(aBrowser, aWebProgress, aRequest, aLocation, aFlags) {
      if (sceChrome.notification.willNotify) {
        scelog.debug("onStateChange: willNotify");
        sceChrome.notification.willNotify = false; // reset
        sceChrome.notify(aBrowser);
      }
    },

    onProgressChange: function() { },
    onStatusChange: function() { }

  } // END TabsProgressListener

}; // END Main


// should be sufficient for a delayed Startup (no need for window.setTimeout())
// https://developer.mozilla.org/en/Extensions/Performance_best_practices_in_extensions
// https://developer.mozilla.org/en/XUL_School/JavaScript_Object_Management.html
window.addEventListener("load", function(e) { sceChrome.onLoad(); }, false);
window.addEventListener("unload", function(e) { sceChrome.onQuit(); }, false);
