SkipCertError
=============

This Firefox extension (for FF 4.0 and higher) enables skipping the SSL/TLS
certificate error page, for specific configurable conditions, like self-signed
cert or unknown issuer, by adding a temporary exception to FF's cert DB.

When silent_mode is turned off (defaults to 'on'), the user will be able to
review the cert, before deciding to add it in one click or not.

This addon is a rewrite of **MitM Me**, originally written by Johnathan
Nightingale, then maintained by Andras Tim.
     
STATUS
------

The extension is doing the job. Though, in some situations, a harmless *no
element found* error may occur. This error is only visible in the console, and,
up to now, can't be avoided.

Acknowledgment
--------------

Some code parts were heavily influenced by the [Perspectives
extension](http://www.networknotary.org/ "Thanks guys").
