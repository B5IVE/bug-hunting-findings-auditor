# bug-hunting-findings-auditor

A zero-dependency Python 3.10+ CLI tool for **bug-hunting & vulnerability triage, CWE/severity validation, reproduction/remediation completeness checks, and priority scoring**.

Designed to keep vulnerability notes, proof-of-concept reproduction steps, and remediation guidance structured and audit-ready before submission or disclosure.

## Checks & Scoring

- **Schema, Severity & CWE Validation (`BUG-001`–`BUG-004`, `SEV-001`, `CWE-001`, `TGT-001`, `STS-001`):** Validates required fields, standard severities (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), CWE formatting (`CWE-<num>`), target endpoints, workflow statuses, and duplicate finding IDs (`DUP-BUG`).
- **PoC & Remediation Completeness (`REP-001`, `REM-001`):** Flags missing or overly brief reproduction steps and remediation notes.
- **Deterministic Priority Scoring:** Computes a `0.00–10.00` priority score from severity weight, verification status, and reproduction completeness, sorting findings highest-first.
- **Dual Output & CI Exit Codes:** Exports `bug_hunt_audit.json` and `bug_hunt_report.md`, returning exit code `1` when hard `ERROR` issues occur.

## Quickstart

Requires **Python 3.10+** (standard library only).

```bash
git clone [https://github.com/B5IVE/bug-hunting-findings-auditor.git](https://github.com/B5IVE/bug-hunting-findings-auditor.git)
cd bug-hunting-findings-auditor

python3 audit_findings.py sample_findings.jsonl
