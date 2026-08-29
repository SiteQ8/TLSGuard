# Changelog

All notable changes to this project are recorded here. The format follows
Keep a Changelog, and the project uses semantic versioning.

## [0.1.0] - 2025

### Added

* First public release.
* Command line interface with `scan` and `version` subcommands.
* Certificate checks: trust, expiry, hostname coverage, self signed, and issuer.
* Protocol probing from SSL 3.0 through TLS 1.3, with an honest untested state
  when the local library cannot offer a version.
* Negotiated cipher inspection, weak cipher detection, and a forward secrecy check.
* HTTPS enforcement check through the Strict Transport Security header.
* A letter grade from A+ to F, capped down by the worst problem found.
* Output in text and json.
* Concurrency for auditing many hosts at once, and a targets file.
* A fail under grade option for use in continuous integration.
* Continuous integration across Python 3.9, 3.11, and 3.12.
