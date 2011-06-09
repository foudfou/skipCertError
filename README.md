SkipCertError
=============

Overview
--------

This Firefox extension (for FF 4.0 and higher) enables skipping the SSL/TLS
certificate error page, for specific configurable conditions, like self-signed
cert or unknown issuer, by adding a temporary exception.

Description
-----------

Tired of clicks for adding certificate exceptions ?

After letting Firefox show it's built-in certificate error page, SkipCertError
will add a temporary exception, and notify you unobtrusively.
There are very few self-explanatory options, which include the conditions of
the error bypass. For now, only two are supported: self-signed, issuer unknown.

This addon is a complete rewrite of **MitM Me**, originally written by
Johnathan Nightingale, then maintained by Andras Tim, intended for FF4+.

Notes
-----

* build instructions: `cd src; make`

* SkipCertError turns on the `expert_bad_cert` built-in preference, which
  enables adding a cert exception in 2 clicks (in FF4+).

Acknowledgment
--------------

Some code pieces were inspired by the [Perspectives
extension](http://www.networknotary.org/ "Thanks guys").
