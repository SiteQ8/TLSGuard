# Roadmap

These are directions for TLSGuard, roughly in order. Nothing here is a promise,
and pull requests that move any of it forward are welcome.

## Near term

* A watch mode that audits a list on a schedule and reports only what changed.
* Weak cipher enumeration behind a flag, for servers where the local library
  can still offer the older ciphers to test them.
* OCSP stapling and certificate transparency checks.
* A summary grade across a whole fleet, plus a compact one line per host mode.

## Later

* Optional export to formats that dashboards and monitoring systems can ingest.
* Certificate change detection, so a swapped certificate is flagged.
* A configuration file for thresholds, target lists, and per host exceptions.

## Out of scope for now

* Anything that sends unusual or hostile traffic. TLSGuard is a polite client
  that reads what a server offers, and it will stay that way.
* Acting as a certificate authority or issuing certificates.

Have an idea that is not here? Open an issue and start the conversation.
