# DockShield

**Automated Dockerfile Security Auditor & Misconfiguration Scanner**

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Focus](https://img.shields.io/badge/focus-DevSecOps-informational)

DockShield is a lightweight, modern DevSecOps tool that statically analyzes
Dockerfiles **before** images are built or deployed. It detects common
container misconfigurations (running as root, hard-coded secrets, unpinned base
images, and more) that can lead to host compromise or data leakage, and reports
them with clear remediation guidance. Its rule set is aligned with
recommendations from the CIS Docker Benchmark.

## Features

- **Object-oriented, dependency-light design**: standard library only, plus
  [`colorama`](https://pypi.org/project/colorama/) for colored output.
- **Rule-driven engine**: all checks live in `security_rules.json`; add or tune
  rules without touching the code.
- **Multi-stage aware**: root-user and HEALTHCHECK checks evaluate the *final*
  build stage; stage aliases are not mistaken for base images.
- **Robust parsing**: handles line continuations (`\`), comments, and blank
  lines; validates input and rules with clear error messages.
- **Secret-safe reports**: values of detected secrets are masked
  (`ENV DB_PASSWORD=********`) in both console and JSON output.
- **Colorized CLI report**: red for critical/high, yellow for medium/low,
  green for passed checks.
- **CI/CD friendly**: machine-readable `audit_report.json` and meaningful exit
  codes.

## Built-in Rules

| ID     | Severity | Check                                   | CIS Docker Benchmark |
|--------|----------|-----------------------------------------|----------------------|
| DS-001 | CRITICAL | Container runs as root (no/`root` USER) | 4.1                  |
| DS-002 | CRITICAL | Hard-coded secrets in `ENV` / `ARG`     | 4.10                 |
| DS-003 | HIGH     | Unpinned or `:latest` base image        | 4.2                  |
| DS-004 | MEDIUM   | `ADD` used instead of `COPY`            | 4.9                  |
| DS-005 | LOW      | Missing `HEALTHCHECK`                   | 4.6                  |

> Section numbers refer to the CIS Docker Benchmark; verify them against the
> benchmark version you follow. DockShield is not an official CIS product.

## Project Structure

```text
.
├── docker_auditor.py     # Main executable script
├── security_rules.json   # Security rules used for scanning
├── audit_report.json     # JSON report generated after each scan
└── README.md
```

## Installation

Requires **Python 3.8+**.

```bash
git clone https://github.com/mohamad329/dockshield.git
cd dockshield
pip install colorama
```

(`colorama` is optional; without it DockShield runs without colors.)

## Usage

```bash
# Basic scan
python docker_auditor.py path/to/Dockerfile

# Custom rules file and report location
python docker_auditor.py Dockerfile --rules my_rules.json --output reports/scan.json

# Fail the pipeline only on CRITICAL findings
python docker_auditor.py Dockerfile --fail-on critical

# Disable colors (e.g. for CI logs)
python docker_auditor.py Dockerfile --no-color
```

| Option            | Description                                                       |
|-------------------|-------------------------------------------------------------------|
| `dockerfile`      | Path to the Dockerfile to audit                                   |
| `-r, --rules`     | Rules file (default: `security_rules.json` next to the script)    |
| `-o, --output`    | JSON report path (default: `audit_report.json`)                   |
| `--fail-on LEVEL` | `critical`, `high` (default), `medium`, `low`, or `none`          |
| `--no-color`      | Disable colored output                                            |

### Exit codes

| Code | Meaning                                                     |
|------|-------------------------------------------------------------|
| 0    | Scan completed; nothing at/above the `--fail-on` threshold  |
| 1    | Scan completed; findings at/above the threshold exist       |
| 2    | Input, rules, or I/O error                                  |

### Try it

Create a deliberately weak `Dockerfile.vulnerable`:

```dockerfile
FROM python:latest
ENV DB_PASSWORD=SuperSecret123
ADD . /app
RUN pip install -r /app/requirements.txt
CMD ["python", "/app/main.py"]
```

```bash
python docker_auditor.py Dockerfile.vulnerable
```

Example output (colors omitted):

```text
[*] Target : Dockerfile.vulnerable
[*] Ruleset: DockShield Baseline (aligned with CIS Docker Benchmark) (5 rules)
[*] Parsed : 5 instructions

[CRITICAL] DS-001  Container runs as root user  (CIS Docker Benchmark 4.1)
    Line 1  : FROM python:latest
    Issue   : No USER instruction in the final build stage; the container runs as root by default.
    Fix     : Create an unprivileged user and switch to it with a USER instruction.

[CRITICAL] DS-002  Hard-coded secret in ENV/ARG  (CIS Docker Benchmark 4.10)
    Line 2  : ENV DB_PASSWORD=********
    ...

----------------------------------------------------------------
Rules passed : 0 / 5
Findings     : CRITICAL 2 | HIGH 1 | MEDIUM 1 | LOW 1
Verdict      : FAIL (fail threshold: HIGH)
```

## CI/CD Integration (GitHub Actions)

```yaml
name: dockerfile-audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install colorama
      - run: python docker_auditor.py Dockerfile --no-color --fail-on high
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: audit-report
          path: audit_report.json
```

## Extending the Rules

Rules are plain JSON objects. Supported rule types:

| Type               | Behavior                                                         |
|--------------------|------------------------------------------------------------------|
| `forbid_pattern`   | Fails when a regex matches an instruction                        |
| `require_pattern`  | Fails when no instruction matches the regex                      |
| `user_check`       | Fails when the final stage has no non-root `USER`                |
| `base_image_check` | Fails on untagged / forbidden-tag base images                    |

Optional fields: `applies_to` (instruction keywords), `scope`
(`file` or `final_stage`), `exclude_pattern`, `redact`, `params`.

```json
{
  "id": "DS-006",
  "title": "SSH port exposed",
  "severity": "MEDIUM",
  "type": "forbid_pattern",
  "applies_to": ["EXPOSE"],
  "pattern": "(?:^|\\s)22(?:/tcp)?(?:\\s|$)",
  "remediation": "Do not run SSH in containers; use `docker exec` or your orchestrator.",
  "cis_reference": "Best practice"
}
```

## Limitations

DockShield performs static, line-based analysis. It does not resolve build
arguments, scan image layers, or detect vulnerable packages. Use it alongside
image scanners (e.g. Trivy, Grype) as part of a layered security strategy.

## Legal Disclaimer

DockShield is intended **solely for defensive security analysis and auditing**
of Dockerfiles that you own or are explicitly authorized to assess. It does not
exploit vulnerabilities or attack any system. The authors provide it "as is",
without warranty of any kind, and accept no liability for misuse or for any
damage resulting from its use. A passing result does not guarantee that an
image is secure.

## License

Released under the MIT License.