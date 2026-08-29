# Contributing to TLSGuard

Thanks for helping. TLSGuard aims to stay small, fast, and dependency free, so
contributions that keep it that way are the most welcome.

## Getting set up

```bash
git clone https://github.com/SiteQ8/TLSGuard.git
cd TLSGuard
python -m unittest discover -s tests -v
```

There is nothing to install. The whole project runs on the Python standard
library.

## Good first contributions

* Add a new check, such as certificate transparency or OCSP stapling.
* Improve a finding or its remediation text.
* Add weak cipher enumeration behind a flag.
* Expand the test suite, especially around grading edge cases.

## How the pieces fit

* `audit.py` connects to a host and gathers raw facts.
* `certs.py` decodes certificates and answers questions about them.
* `protocols.py` probes which TLS versions a server accepts.
* `grading.py` turns facts into findings and a grade.
* `report.py` prints the result.

Most new checks touch `audit.py` to gather a fact and `grading.py` to judge it.

## Before you open a pull request

1. Run the tests and make sure they pass.
2. Keep the grading logic covered by a test when you change it.
3. Keep changes focused, and describe what you changed and why.

## A note on testing servers

Please write tests against synthetic data where you can, as the suite does now,
so the tests stay fast and do not depend on the network. If you must reach a
live endpoint, use a public host that exists for this purpose and keep it out of
the default test run.
