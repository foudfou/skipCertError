SkipCertError
=============

This Firefox extension (for FF 4.0 and higher) enables skipping the SSL/TLS
certificate error page, for specific configurable conditions, like self-signed
cert or unknown issuer, by adding a temporary exception to FF's cert DB.

When silent_mode is enabled (default), the about:certerr page will be displayed
shortly, before moving on to the requested HTTPS page. By design, since the
about:certerror page is unavoidable, we have to wait for it to be completely
displayed.

When silent_mode is disabled, a notification will provide the user with the
ability to review the cert, and add it in one click.

This addon is a rewrite of **MitM Me**, originally written by Johnathan
Nightingale, then maintained by Andras Tim.
     
Known bugs
----------

In very rare situation (like restoring the session), a harmless *no element
found* error may occur. This error is only visible in the console.

Acknowledgment
--------------

Some code parts were heavily influenced by the [Perspectives
extension](http://www.networknotary.org/ "Thanks guys").
