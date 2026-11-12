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


# AcmeCorp Rule Audit Tool

## What it does

Parses a firewall ruleset from a CSV file and automatically flags security risks.

## How to run the tool with Docker

AcmeCorp does not need to install Python or any dependencies. Just ensure you have a folder named `data` containing `acme_rules.csv` in your current directory, and run:

```bash
docker build -t acme-audit-tool .
docker run --rm -v "${PWD}/data:/app/data" acme-audit-tool
```


Running the tests

To run the automated test suite inside the container without needing a local Python setup, run:

**bash**

```
docker run --rm acme-audit-tool pytest -v
```

If you want to run the tests locally in your virtual environment, just use:

**bash**

```
pytest -v
```

## What it flags

* `ANY_ANY`: Allows traffic from any source to any destination on any port.
* `INSECURE_PORT`: Allows insecure ports (21, 23, 80, 3389).
* `NO_LOGGING`: Rule is set to ALLOW but logging is off.
* `WIDE_PORT_RANGE`: Allows a port range spanning more than 5 ports.
* `SHADOWED`: Rule is unreachable because an earlier rule matches its traffic.

## What the regression test protects

The regression test (`test_regression.py`) runs the audit tool against a saved "known good" output file. This ensures that if anyone touches the audit logic later, the AcmeCorp findings won't accidentally change. If the output changes, the test fails and alerts us.
