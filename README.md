SkipCertError
=============

Overview
--------

This Firefox extension (for Firefox 4 and higher) enables skipping the SSL/TLS
certificate error page, for specific configurable conditions, like self-signed
cert or unknown issuer, by adding a temporary exception.

Description
-----------

Tired of clicks for adding certificate exceptions ?

After letting Firefox show it's built-in certificate error page, SkipCertError
will add a temporary exception, and notify you unobtrusively.  There are very
few self-explanatory options, which include the conditions of the error
bypass. For now, few are supported: self-signed, issuer unknown, issuer
untrusted.

This addon is a complete rewrite of **MitM Me** for Firefox 4 and higer. **MitM
Me** was originally written by Johnathan Nightingale, and then maintained by
Andras Tim.

Notes
-----

* Hidden preference (edit with about:config) `single_click_skip`, to stil get
  the certerror page, but skip it in a single click.

* SkipCertError *won't skip* the cert error page when, after an OCSP query, a
  "valid" cert turns out to be revoked. It *won't notify* either. (This is an
  unsupported condition for the time being anyway)

* build instructions: `cd src; make`

* SkipCertError turns on the `expert_bad_cert` built-in preference, which
  enables adding a cert exception in 2 clicks (in FF4+).

* There are interesting arguments about FF's policy regarding self-signed certs
  on [Johnathan's blog](http://blog.johnath.com/2008/08/05/ssl-question-corner/
  "SSL Question Corner")

* You might also want to read of an argument regarding to equality further on
  [Nat's Blog](http://www.cs.uml.edu/~ntuck/mozilla/ "Mozilla SSL policy bad for
  the Web")

Acknowledgment
--------------

Some code pieces were inspired by the [Perspectives
extension](http://www.networknotary.org/ "Thanks guys").
