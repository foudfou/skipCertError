/* -*- Mode: js2; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/* lifted from TCPSocket.js, NSS secerr.h and BrowserElementChildPreload.js.
 SEE ALSO: https://developer.mozilla.org/en-US/docs/How_to_check_the_security_state_of_an_XMLHTTPRequest_over_SSL */

var EXPORTED_SYMBOLS = [ "sce" ];

const Cc = Components.classes;
const Ci = Components.interfaces;

Components.utils.import("resource://sce/logging.jsm");

const SEC_ERROR_BASE = Ci.nsINSSErrorsService.NSS_SEC_ERROR_BASE;
const SSL_ERROR_BASE = Ci.nsINSSErrorsService.NSS_SSL_ERROR_BASE;

/**
 * sce namespace.
 */
if ("undefined" == typeof(sce)) {
  var sce = {};
};

sce.Sec = {
  // custom const to keep track of cert errors inspired from nsIX509Cert.idl
  VERIFIED_OK:                  0,
  NOT_VERIFIED_UNKNOWN:         1 << 0,
  CERT_REVOKED:                 1 << 1,
  CERT_EXPIRED:                 1 << 2,
  CERT_NOT_TRUSTED:             1 << 3,
  ISSUER_NOT_TRUSTED:           1 << 4,
  ISSUER_UNKNOWN:               1 << 5,
  INVALID_CA:                   1 << 6,
  USAGE_NOT_ALLOWED:            1 << 7,
  SIGNATURE_ALGORITHM_DISABLED: 1 << 8,

  CERT_SELF_SIGNED:             1 << 9,
  SSL_DOMAIN_MISMATCH:          1 << 10,
  SSL_NOT_VALID:                1 << 11,

  SEC_ERROR_EXPIRED_CERTIFICATE:               (SEC_ERROR_BASE + 11),
  SEC_ERROR_REVOKED_CERTIFICATE:               (SEC_ERROR_BASE + 12),
  SEC_ERROR_UNKNOWN_ISSUER:                    (SEC_ERROR_BASE + 13),
  SEC_ERROR_UNTRUSTED_ISSUER:                  (SEC_ERROR_BASE + 20),
  SEC_ERROR_UNTRUSTED_CERT:                    (SEC_ERROR_BASE + 21),
  SEC_ERROR_EXPIRED_ISSUER_CERTIFICATE:        (SEC_ERROR_BASE + 30),
  SEC_ERROR_CA_CERT_INVALID:                   (SEC_ERROR_BASE + 36),
  SEC_ERROR_INADEQUATE_KEY_USAGE:              (SEC_ERROR_BASE + 90),
  SEC_ERROR_CERT_SIGNATURE_ALGORITHM_DISABLED: (SEC_ERROR_BASE + 176),

  SSL_ERROR_NO_CERTIFICATE:               (SSL_ERROR_BASE + 3),
  SSL_ERROR_BAD_CERTIFICATE:              (SSL_ERROR_BASE + 4),
  SSL_ERROR_UNSUPPORTED_CERTIFICATE_TYPE: (SSL_ERROR_BASE + 8),
  SSL_ERROR_UNSUPPORTED_VERSION:          (SSL_ERROR_BASE + 9),
  SSL_ERROR_BAD_CERT_DOMAIN:              (SSL_ERROR_BASE + 12),

  NS_ERROR_MODULE_BASE_OFFSET: 0x45,
  NS_ERROR_MODULE_SECURITY: 21,
  NS_ERROR_GET_MODULE: function(err) {
    return ((((err) >> 16) - this.NS_ERROR_MODULE_BASE_OFFSET) & 0x1fff);
  },

  NS_ERROR_GET_CODE: function(err) {
    return ((err) & 0xffff);
  },

  getNSPRCode: function(code) {
    return -1 * this.NS_ERROR_GET_CODE(code);
  }

};
