SkipCertError
=============

This Firefox extension (for FF 4.0 and higher) enables skipping the SSL/TLS
certificate error page, for specific configurable conditions, like self-signed
cert or unknown issuer, by adding a temporary exception.

This addon is a rewrite of **MitM Me**, originally written by Johnathan
Nightingale, then maintained by Andras Tim.

Notes
-----

* build instructions: *cd src; make*

* SkipCertError turns on the *expert\_bad\_cert* built-in preference, which
  enables adding a cert exception in 2 clicks (in FF4+).


Acknowledgment
--------------

Some code pieces were inspired by the [Perspectives
extension](http://www.networknotary.org/ "Thanks guys").
