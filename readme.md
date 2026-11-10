# AcmeCorp Rule Audit Tool

## What it does

Parses a firewall ruleset from a CSV file and automatically flags security risks.

## How to run

1. Ensure the virtual environment is active (`.\venv\Scripts\activate`).
2. Run the tool: `python rule_audit.py`

## How to run tests

Run `pytest -v` to execute the test suite.

## Flags reported

* `ANY_ANY`: Allows traffic from any source to any destination on any port.
* `INSECURE_PORT`: Allows insecure ports (21, 23, 80, 3389).
* `NO_LOGGING`: Rule is set to ALLOW but logging is off.
* `WIDE_PORT_RANGE`: Allows a port range spanning more than 5 ports.
* `SHADOWED`: Rule is unreachable because an earlier rule matches its traffic.
