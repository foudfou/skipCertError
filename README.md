SkipCertError
=============

This Firefox extension (for FF 4.0 and higher) enables skipping the SSL/TLS
certificate error page, for specific configurable conditions, like self-signed
cert or unknown issuer, by adding a temporary exception to FF's cert DB.

This addon is a rewrite of **MitM Me**, originally written by Johnathan
Nightingale, then maintained by Andras Tim.

    
     
STATUS
------

At the moment, the extension is working with **limited features**: 

* *silent_mode* is always true (no matter the option),

* the cert errors conditions (issuer unknown, self-signed cert) cannot be configured.

These features are planned for a future release.
