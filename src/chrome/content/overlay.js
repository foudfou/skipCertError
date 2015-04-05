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
 *
 * NOTE: there is a nsISSLErrorListener, to be tested
 */

Components.utils.import("resource://sce/commons.js");
Components.utils.import("resource://sce/sec.jsm");

// number of times, for a specific page, that we let the cert error page being
// called, before overriding it.
const SCE_CERTERROR_COUNT_MAX = 2;

let sce_log = sce.Logging.getLogger("sce.Chrome");

var sceChrome = {

  onLoad: function() {
    let that = this;
    // initialization code
    this.initialized = null;
    this.strings = document.getElementById("sce-strings");
    this.overrideService = null;
    this.notification = {
      willNotify: false,
      browser: null,
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
      this.overrideService =
        Cc["@mozilla.org/security/certoverride;1"]
        .getService(Ci.nsICertOverrideService);
    }
    catch (ex) {
      sce_log.error("SkipCertError: " + ex);
      return false;
    }

    var enabled = sce.Utils.prefService.getBoolPref('enabled');
    sce_log.debug('enabled: '+enabled);
    if (enabled)
      this._toggle(true);

    sce_log.debug('SkipCertError LOADED !');
    this.initialized = true;
    return true;
  },

  onQuit: function() {
    let that = this;
    // Remove observer
    sce.Utils.prefService.removeObserver("", that);

    this._toggle(false);

    sce_log.debug('SkipCertError UNLOADED !');
    this.initialized = false;
  },

  // since we are using a TabsProgressListener, it seems we do not need to keep
  // track of WebProgressListeners as indicated on
  // https://developer.mozilla.org/en/XUL_School/Intercepting_Page_Loads#WebProgressListeners
  _toggle: function(enable) {
    let that = this;
    sce_log.debug('toggle: '+enable);
    try {
      if (enable) {
        gBrowser.addTabsProgressListener(that.TabsProgressListener);
      } else {
        gBrowser.removeTabsProgressListener(that.TabsProgressListener);
      }
    } catch (ex) {
      sce_log.error(ex);
      return false;
    }
    return true;
  },

  observe: function(subject, topic, data) {
    // Observer for pref changes
    if (topic != "nsPref:changed") return;
    sce_log.debug('Pref changed: ' + data);

    switch(data) {
    case 'enabled':
      var enable = sce.Utils.prefService.getBoolPref('enabled');
      this._toggle(enable);
      break;
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
    sce_log.info("CertEx added");
    this.TabsProgressListener.certExceptionJustAdded = true;
    sce_log.debug("certEx changed: " + this.TabsProgressListener.certExceptionJustAdded);

    this.TabsProgressListener._goto = uri.spec;    // never reset
  },

  updateDiagWithFlagFromPref: function(diag, flag, prefName) {
    var prefVal = sce.Utils.prefService.getBoolPref(prefName);
    sce_log.debug(prefName + ", bypass=" + prefVal);
    if (prefVal) {
      diag.bypassFlags |= flag;
    } else {
      diag.dontBypassFlags |= flag;
    }
    return diag;
  },

  getSSLStatusFromRequest: function(request) {
    let sslStatus = null;
    if (request instanceof Ci.nsIChannel) {
      request.QueryInterface(Ci.nsIChannel);
      let secInfo = request.securityInfo;
      if (secInfo instanceof Ci.nsISSLStatusProvider) {
        sslStatus = secInfo.QueryInterface(Ci.nsISSLStatusProvider).SSLStatus;
        if (sslStatus) return sslStatus.QueryInterface(Ci.nsISSLStatus);
      }
    }

    return null;
  },

  getRemoteIpFromRequest: function(request) {
    if (request instanceof Ci.nsIChannel &&
        request instanceof Ci.nsIHttpChannel &&
        request instanceof Ci.nsIHttpChannelInternal) {
      let ip = request.remoteAddress;
      sce_log.debug("ip="+ip);
      if (ip) return ip;
    }
    return null;
  },

  isSelfSignedFromSSLStatus: function(status) {
    var cert = status.serverCert;
    cert.QueryInterface(SCE_X509CertInterface);
    var isSelfSigned = cert.isSelfSigned;
    sce_log.debug("isSelfSigned:" + isSelfSigned);

    return isSelfSigned;
  },

  /*
   * Test with https://www.ssllabs.com/ssltest/index.html
   *
   * For now, we gather error information from 3 sources: the NSS request
   * status, the SSLSatus, and the cert. Can't use CertVerifier.cpp :(
   */
  diagnoseCert: function(diag, verifystate) {
    const nsIX509Cert = Ci.nsIX509Cert;

    let checks_prefs = {
      NOT_VERIFIED_UNKNOWN:  null,
      CERT_REVOKED:          null,
      CERT_EXPIRED:          null,
      CERT_NOT_TRUSTED:      null,
      ISSUER_NOT_TRUSTED:    "bypass_issuer_not_trusted",
      ISSUER_UNKNOWN:        "bypass_issuer_unknown",
      INVALID_CA:            null,
      USAGE_NOT_ALLOWED:     null
    };

    for (let i=0, len=checks_prefs.length; i<len; ++i) {
      let check = checks[i];
      if (verifystate & nsIX509Cert[check]) {
        if (sce.Sec[check])
          this.updateDiagWithFlagFromPref(diag, sce.Sec[check], checks_prefs[check]);
        else
          diag.unsupportedFlags |= sce.Sec[check];
      }
    }

    return diag;
  },

  diagnoseInsecureRequest: function(diag, request) {
    let status = request.status;

    let nsModule = sce.Sec.NS_ERROR_GET_MODULE(status);
    sce_log.debug("nsModule="+nsModule);
    if (nsModule === sce.Sec.NS_ERROR_MODULE_SECURITY) {
      let err = sce.Sec.getNSPRCode(status);
      sce_log.debug("NSPRCode="+err);
      let code = err - Ci.nsINSSErrorsService.NSS_SEC_ERROR_BASE;
      sce_log.debug("SEC Code="+code);
      code = err - Ci.nsINSSErrorsService.NSS_SSL_ERROR_BASE;
      sce_log.debug("SSL Code="+code);
      code = err - Ci.nsINSSErrorsService.MOZILLA_PKIX_ERROR_BASE;
      sce_log.debug("PKIX Code="+code);

      switch (err) {
      // implied by self-signed, ex: https://linuxfr.org
      case sce.Sec.SEC_ERROR_UNTRUSTED_ISSUER:
        this.updateDiagWithFlagFromPref(diag, sce.Sec.ISSUER_NOT_TRUSTED, "bypass_issuer_not_trusted");
        break;
      case sce.Sec.SEC_ERROR_UNKNOWN_ISSUER:
        this.updateDiagWithFlagFromPref(diag, sce.Sec.ISSUER_UNKNOWN, "bypass_issuer_unknown");
        break;
      case sce.Sec.SSL_ERROR_BAD_CERT_DOMAIN:
        this.updateDiagWithFlagFromPref(diag, sce.Sec.SSL_DOMAIN_MISMATCH, "bypass_domain_mismatch");
        break;

      case sce.Sec.SEC_ERROR_EXPIRED_CERTIFICATE:
        diag.unsupportedFlags |= sce.Sec.CERT_EXPIRED;
        break;
      case sce.Sec.SEC_ERROR_REVOKED_CERTIFICATE:
        diag.unsupportedFlags |= sce.Sec.CERT_REVOKED;
        break;
      case sce.Sec.SEC_ERROR_UNTRUSTED_CERT:
        diag.unsupportedFlags |= sce.Sec.CERT_NOT_TRUSTED;
        break;

      case sce.Sec.SEC_ERROR_CA_CERT_INVALID:
        this.updateDiagWithFlagFromPref(diag, sce.Sec.CERT_SELF_SIGNED, "bypass_self_signed");
        // diag.unsupportedFlags |= sce.Sec.INVALID_CA;
        break;

      case sce.Sec.SEC_ERROR_EXPIRED_ISSUER_CERTIFICATE:
      case sce.Sec.SEC_ERROR_INADEQUATE_KEY_USAGE:
      case sce.Sec.SEC_ERROR_CERT_SIGNATURE_ALGORITHM_DISABLED:
      case sce.Sec.SEC_ERROR_INVALID_KEY:
      case sce.Sec.SSL_ERROR_NO_CYPHER_OVERLAP:
      case sce.Sec.SSL_ERROR_NO_CERTIFICATE:
      case sce.Sec.SSL_ERROR_BAD_CERTIFICATE:
      case sce.Sec.SSL_ERROR_UNSUPPORTED_CERTIFICATE_TYPE:
      case sce.Sec.SSL_ERROR_UNSUPPORTED_VERSION:
      case sce.Sec.PKIX_ERROR_INADEQUATE_KEY_SIZE:
        sce_log.warn("Unhandeled err("+err+")");
        break;

      default:                  // ignore
        sce_log.debug("SkipCertError: unknown err: " + err);
        break;
      }

    } else {
      sce_log.debug("Not for security module");
    }

    return diag;
  },

  diagnoseSSLStatus: function(diag, request, sslStatus) {
    if (!request) return null;
    if ("undefined" === typeof(sslStatus) ||
        !sslStatus) {
      sce_log.debug("diagnoseSSLStatus: sslStatus not provided");
      sslStatus = this.getSSLStatusFromRequest(request);
    }

    let isSelfSigned = this.isSelfSignedFromSSLStatus(sslStatus);
    if (isSelfSigned) {       // ex: https://www.pcwebshop.co.uk/
      this.updateDiagWithFlagFromPref(diag, sce.Sec.CERT_SELF_SIGNED,
                                      "bypass_self_signed");
    }
    if(sslStatus.isUntrusted) {
      sce_log.debug("sslStatus.isUntrusted");
      // unsupportedFlags will be null => 'unknown'
    }
    if(sslStatus.isDomainMismatch) { // ex: https://amazon.com/
      this.updateDiagWithFlagFromPref(diag, sce.Sec.SSL_DOMAIN_MISMATCH,
                                      "bypass_domain_mismatch");
    }
    if(sslStatus.isNotValidAtThisTime) {
      sce_log.debug("sslStatus.isNotValidAtThisTime");
      diag.unsupportedFlags |= sce.Sec.SSL_NOT_VALID;
    }

    return diag;
  },

  isBypassDomain: function(host, ip) {
    var bypassDomains = sce.Utils.getArrayPref('bypass_domains');
    sce_log.debug("*** bypassDomains:"+bypassDomains);
    for (let i=0, len=bypassDomains.length; i<len; ++i) {
      let domain = bypassDomains[i];
      let re_domain = new RegExp(domain.replace(/\./g, "\\.")+"$");
      if (re_domain.test(host)) return domain;
      let re_ip = new RegExp("^"+domain.replace(/\./g, "\\."));
      sce_log.debug("    ip="+ip+" re_ip="+re_ip+" "+re_ip.test(ip));
      if (re_ip.test(ip)) return domain;
    }
    return null;
  },

  notify: function(abrowser) {
    sce_log.debug("notify");
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
      sce_log.debug("notificationBox already here");
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
    case 'exceptionUnsupported':
      msgArgs = [this.notification.bypassTag];
      priority = 'PRIORITY_WARNING_MEDIUM';
      break;
    default:
      sce_log.error("SkipCertError: notification.type unknown or undefined");
      break;
    }
    var message = this.strings.getFormattedString(this.notification.type, msgArgs);

    // appendNotification( label , value , image , priority , buttons )
    var notification = notificationBox.appendNotification(
      message, notificationValue, null, notificationBox[priority], null);
    sce_log.debug("notified");

    // close notificatioBox if needed (will close automatically if reload)
    var exceptionDialogButton = abrowser.webProgress.DOMWindow
      .document.getElementById('exceptionDialogButton');
    if (exceptionDialogButton)
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


  parseBadCertFlags: function(flags) {
    var tag = '';
    if (flags == null) return 'unknown';
    if (flags == sce.Sec.VERIFIED_OK)
      tag += ', ' + sceChrome.strings.getString('VERIFIED_OK');

    let checks = ['NOT_VERIFIED_UNKNOWN', 'CERT_REVOKED', 'CERT_EXPIRED',
      'CERT_NOT_TRUSTED', 'ISSUER_NOT_TRUSTED', 'ISSUER_UNKNOWN', 'INVALID_CA',
      'USAGE_NOT_ALLOWED', 'CERT_SELF_SIGNED', 'SSL_DOMAIN_MISMATCH',
      'SSL_NOT_VALID'];

    for (let i=0, len=checks.length; i<len; ++i) {
      let check = checks[i];
      if (flags & sce.Sec[check])
        tag += ', ' + sceChrome.strings.getString(check);
    }

    if (tag != "") tag = tag.substr(2); // remove leading ', '

    return tag;
  },

  buildNotification: function(diag, uri, sslStatus) {
    // Add cert exception (if bypass allowed by options)
    if (diag.unsupportedFlags) {
      sceChrome.notification.type = 'exceptionUnsupported';
      var ignoreTags = sceChrome.parseBadCertFlags(diag.unsupportedFlags);
      sce_log.debug("unsupportedFlags=" + diag.unsupportedFlags + ", " + ignoreTags);
      sceChrome.notification.bypassTag = ignoreTags;
    } else if (diag.dontBypassFlags) {    // ALL conditions must be set
      sceChrome.notification.type = 'exceptionNotAdded';
      var dontBypassTags = sceChrome.parseBadCertFlags(diag.dontBypassFlags);
      sce_log.debug("dontBypassFlags=" + diag.dontBypassFlags + ", " + dontBypassTags);
      sceChrome.notification.bypassTag = dontBypassTags;
    } else if (diag.bypassFlags) {
      if (sslStatus) sceChrome.addCertException(sslStatus, uri);
      sceChrome.notification.type = 'exceptionAdded';
      var bypassTags = sceChrome.parseBadCertFlags(diag.bypassFlags);
      sce_log.debug("bypassFlags=" + diag.bypassFlags + ", " + bypassTags);
      sceChrome.notification.bypassTag = bypassTags;
    } else {
      // noop
    }
  },

  // a TabsProgressListener seems more appropriate than an Observer, which only
  // gets notified for document requests (not internal requests)
  TabsProgressListener: {
    // can't see the use of implementing QueryInterface(aIID)...

    // used for communication btw onSecurityChange, onStateChange, ...
    certExceptionJustAdded: null,
    _sslStatus: null,
    _goto: null,                  // target URL when after certerr encountered
    _certerrorCount: 0,           // certerr seems called more than once...

    /*
     * This method will be called on security transitions (eg HTTP -> HTTPS,
     * HTTPS -> HTTP, FOO -> HTTPS) and *after document load* completion. It
     * might also be called if an error occurs during network loading.
     *
     * We could also check (aFlags ===
     * Ci.nsIWebProgressListener.LOCATION_CHANGE_ERROR_PAGE) onLocationChange,
     * but this doesn't seem to detect errors in iframes
     */
    onSecurityChange: function (aBrowser, aWebProgress, aRequest, aState) {
      var uri = aBrowser.currentURI;
      sce_log.debug("onSecurityChange: uri=" + uri.prePath);
      sce_log.debug("aState: "+aState);

      if (!uri.schemeIs("https")) {
        sce_log.debug("uri not https");
        return;
      }

      const wpl = Ci.nsIWebProgressListener;
      let stateInsecure = aState & wpl.STATE_IS_INSECURE;
      let stateInsecureMixedBlocked = aState &
            (wpl.STATE_IS_INSECURE |
             wpl.STATE_BLOCKED_MIXED_ACTIVE_CONTENT);
      if (!stateInsecure || !stateInsecureMixedBlocked) {
        sce_log.debug("state not Insecure nor InsecureMixedBlocked");
        return;
      }

      if ("undefined" === typeof(aRequest) || !aRequest) {
        sce_log.debug("onSecurityChange: request not provided");
        return;
      }

      sceChrome.notification.host = uri.host;

      this._certerrorCount = 0; // reset

      /* SSLStatus is mainly needed for the cert, otherwise we'd have to get it
       with an XHR, and possibly use certdb.verifyCertNow(). See example in
       test_bug544442_checkCert.xul.  We also need to store it for
       onStateChange(). */
      this._sslStatus = sceChrome.getSSLStatusFromRequest(aRequest);
      // mostly on restoring or if neterror which is *not* overridable by
      // nsICertOverrideService !
      if (!this._sslStatus) {
        sce_log.info("no sslStatus");
        return;
      }
      sce_log.debug("sslStatus="+this._sslStatus);

      if (sce.Utils.prefService.getBoolPref('single_click_skip')) return;
      sce_log.debug("single_click_skip false");

      try {
        var ip = sceChrome.getRemoteIpFromRequest(aRequest);
      } catch(e) {}             // on restore
      var domainBypass = sceChrome.isBypassDomain(uri.host, ip);
      sce_log.debug("*** domainBypass="+domainBypass);
      if (domainBypass) {
        sceChrome.addCertException(this._sslStatus, uri);
        sceChrome.notification.type = 'exceptionAddedKnownDomain';
        sceChrome.notification.bypassDomain = domainBypass;

      } else {
        var cert = this._sslStatus.serverCert;
        sce_log.debug("cert found: "+cert);

        // check if cert already known/added
        var knownCert = sceChrome.getCertException(uri, cert);
        if (knownCert) {
          sce_log.debug("known cert: " + knownCert);
          return;
        }

        let that = this;
        function onCertVerificationComplete(cert, result) {
          if (!result || !cert) return;
          if (!(cert instanceof Ci.nsIX509Cert)) return;
          if (!(result instanceof Ci.nsICertVerificationResult)) return;

          var verifystate = {}, count = {}, usageList = {};
          result.getUsagesArrayResult(verifystate, count, usageList);

          sce_log.debug("verifystate="+verifystate.value); // see nsIX509Cert
          sce_log.debug("count="+count.value);
          sce_log.debug("usageList="+usageList.value);

          /* For now, we'll make it simple: if *all* encountered conditions are
           set to bypass (see options), then we bypass. If some aren't set, we
           don't bypass and notify. For all other errors, we don't bypass, and
           notify "error not handled by SkipCertError". */
          let diag = {
            bypassFlags: 0,
            // we record when bypass conditions encountered but not set in options
            dontBypassFlags: 0,
            unsupportedFlags: 0
          };
          diag = sceChrome.diagnoseInsecureRequest(diag, aRequest);
          diag = sceChrome.diagnoseCert(diag, verifystate.value);
          diag = sceChrome.diagnoseSSLStatus(diag, aRequest, that._sslStatus);
          sce_log.debug("bypassFlags="+diag.bypassFlags+", dontBypassFlags="+diag.dontBypassFlags+", unsupportedFlags="+diag.unsupportedFlags);

          sceChrome.buildNotification(diag, uri, that._sslStatus);
        } // END function onCertVerificationComplete

        if (cert instanceof SCE_X509CertInterface)
          cert.requestUsagesArrayAsync({notify: onCertVerificationComplete});
        else
          sce_log.warn("SkipCertError: Not instanceof SCE_X509CertInterface ?");

      }

      // trigger notification
      if (sce.Utils.prefService.getBoolPref('notify')) {
        sceChrome.notification.willNotify = true;
        sceChrome.notification.browser = aBrowser;
        sce_log.debug("onSecurityChange: willNotify -> " + sceChrome.notification.willNotify);
      }

    }, // END onSecurityChange

    _replaceExceptionDialogButton: function(doc, browser) {
      let exceptionDialogButton = doc.getElementById('exceptionDialogButton');
      if (!exceptionDialogButton) {
        sce_log.error("no exceptionDialogButton found");
      }
      exceptionDialogButton.style.display = "none";

      if (doc.getElementById('SkipCertErrorButton')) {
        sce_log.debug("skipCertButtun already here");
        return;
      }

      let newButton = doc.createElement("button");
      newButton.id = "SkipCertErrorButton";
      newButton.textContent = sceChrome.strings.getString('skipError');
      newButton.addEventListener("click", function(event) {
        let uri = browser.currentURI;
        sceChrome.addCertException(sceChrome.TabsProgressListener._sslStatus, uri);
        browser.loadURI(uri.spec, null, null);
      }, false);
      exceptionDialogButton.parentNode.appendChild(newButton);
      sce_log.debug("newButton installed");
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
        sce_log.debug("onStateChange originURI="+originURI);

        if (/^about:certerr/.test(originURI)) {
          this._certerrorCount++;
          sce_log.debug("certerrorCount=" + this._certerrorCount + " < _MAX="+SCE_CERTERROR_COUNT_MAX);

          if (this._certerrorCount < SCE_CERTERROR_COUNT_MAX) {
            if (aStateFlags & (Ci.nsIWebProgressListener.STATE_STOP
                               |Ci.nsIWebProgressListener.STATE_RESTORING)) {
              // experienced only one certerr call during sessoin restore
              sce_log.debug("restoring");
            } else {
              sce_log.debug("certerrorCount not sufficient");
              return; // wait for last (?) call
            }
          }

          if (sce.Utils.prefService.getBoolPref('single_click_skip')) {
            sce_log.debug("single_click_skip");
            this._replaceExceptionDialogButton(originDoc, aBrowser);
            return;
          }

          sce_log.debug("certExceptionJustAdded="+this.certExceptionJustAdded);
          if (this.certExceptionJustAdded) {
            this.certExceptionJustAdded = false; // reset
            aRequest.cancel(Components.results.NS_BINDING_ABORTED);
            aBrowser.loadURI(this._goto, null, null);
          }
        } // END /^about:certerr/

      } // END STATE_STOP|STATE_IS_REQUEST
    }, // END onStateChange

    onLocationChange: function(aBrowser, aWebProgress, aRequest, aLocation, aFlags) {
      sce_log.debug("onLocationChange: willNotify="+sceChrome.notification.willNotify);
      if (sceChrome.notification.willNotify && aBrowser === sceChrome.notification.browser) {
        sceChrome.notification.willNotify = false; // reset
        sceChrome.notification.browser = null;     // reset
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
