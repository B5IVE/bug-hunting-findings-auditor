#!/usr/bin/env python3
"""
bug-hunting-findings-auditor: Vulnerability & Bug-Hunting PoC Findings CLI.

Validates JSONL vulnerability/bug-hunting finding records (severity, CVSS/CWE
identifiers, affected target/endpoint, reproduction steps, and remediation
status), flags incomplete or unverified reports, computes a triage priority
score, and outputs a JSON audit report plus a Markdown findings summary.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
VALID_STATUSES = {"NEW", "TRIAGED", "CONFIRMED", "REMEDIATED", "WONTFIX"}
CWE_REGEX = re.compile(r"^CWE-\d+$", re.IGNORECASE)
MIN_REPRO_LEN = 20
MIN_REMEDIATION_LEN = 15


@dataclass
class FindingIssue:
    line_number: int
    finding_id: str
    severity: str  # ERROR, WARN
    code: str
    message: str


@dataclass
class TriagedFinding:
    finding_id: str
    title: str
    severity: str
    cwe: str
    target: str
    status: str
    priority_score: float
    verified: bool


def compute_priority_score(severity: str, verified: bool, has_repro: bool) -> float:
    base_weights = {
        "CRITICAL": 9.5,
        "HIGH": 7.5,
        "MEDIUM": 5.0,
        "LOW": 2.5,
        "INFO": 0.5,
    }
    score = base_weights.get(severity.upper(), 3.0)
    if verified:
        score = min(10.0, score + 0.4)
    if not has_repro:
        score = max(0.0, score - 1.5)
    return round(score, 2)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit bug-hunting findings JSONL records for completeness, CWE/severity validity, and priority."
    )
    parser.add_argument("findings_file", type=Path, help="Path to findings .jsonl file")
    parser.add_argument(
        "--json-out",
        type=Path,
        default=Path("bug_hunt_audit.json"),
        help="Output JSON report path (default: bug_hunt_audit.json)",
    )
    parser.add_argument(
        "--md-out",
        type=Path,
        default=Path("bug_hunt_report.md"),
        help="Output Markdown summary path (default: bug_hunt_report.md)",
    )
    args = parser.parse_args()

    if not args.findings_file.is_file():
        print(f"Error: Findings file not found: {args.findings_file}", file=sys.stderr)
        return 2

    issues: list[FindingIssue] = []
    triaged: list[TriagedFinding] = []
    seen_ids: dict[str, int] = {}
    sev_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    total_records = 0

    with args.findings_file.open("r", encoding="utf-8") as handle:
        for line_num, raw in enumerate(handle, start=1):
            stripped = raw.strip()
            if not stripped:
                continue
            total_records += 1

            try:
                rec: dict[str, Any] = json.loads(stripped)
            except json.JSONDecodeError as exc:
                issues.append(
                    FindingIssue(line_num, f"line-{line_num}", "ERROR", "BUG-001", f"Malformed JSON line: {exc}")
                )
                continue

            if not isinstance(rec, dict):
                issues.append(
                    FindingIssue(line_num, f"line-{line_num}", "ERROR", "BUG-002", "Record must be a JSON object.")
                )
                continue

            fid = str(rec.get("finding_id", "")).strip()
            title = str(rec.get("title", "")).strip()
            sev = str(rec.get("severity", "")).strip().upper()
            cwe = str(rec.get("cwe", "")).strip().upper()
            target = str(rec.get("target", "")).strip()
            status = str(rec.get("status", "NEW")).strip().upper() or "NEW"
            repro = str(rec.get("reproduction_steps", rec.get("poc", ""))).strip()
            remediation = str(rec.get("remediation", "")).strip()
            verified = bool(rec.get("verified", False))

            if not fid:
                issues.append(
                    FindingIssue(line_num, f"rec-{line_num}", "ERROR", "BUG-003", "Missing finding_id.")
                )
                continue

            if fid in seen_ids:
                issues.append(
                    FindingIssue(
                        line_num,
                        fid,
                        "WARN",
                        "DUP-BUG",
                        f"Duplicate finding_id '{fid}' (first seen on line {seen_ids[fid]}).",
                    )
                )
            else:
                seen_ids[fid] = line_num

            if not title:
                issues.append(
                    FindingIssue(line_num, fid, "ERROR", "BUG-004", f"Missing vulnerability title for '{fid}'.")
                )

            if sev not in VALID_SEVERITIES:
                issues.append(
                    FindingIssue(
                        line_num,
                        fid,
                        "ERROR",
                        "SEV-001",
                        f"Invalid severity {sev!r}; allowed: {sorted(VALID_SEVERITIES)}.",
                    )
                )
                sev = "MEDIUM"

            if not CWE_REGEX.match(cwe):
                issues.append(
                    FindingIssue(
                        line_num,
                        fid,
                        "WARN",
                        "CWE-001",
                        f"Missing or non-standard CWE identifier {cwe!r} (expected format like CWE-79 or CWE-89).",
                    )
                )
                cwe = cwe or "CWE-UNKNOWN"

            if not target:
                issues.append(
                    FindingIssue(line_num, fid, "ERROR", "TGT-001", f"Missing affected target/endpoint for '{fid}'.")
                )

            if status not in VALID_STATUSES:
                issues.append(
                    FindingIssue(
                        line_num,
                        fid,
                        "WARN",
                        "STS-001",
                        f"Non-standard status {status!r}; allowed: {sorted(VALID_STATUSES)}.",
                    )
                )

            has_repro = len(repro) >= MIN_REPRO_LEN
            if not has_repro:
                issues.append(
                    FindingIssue(
                        line_num,
                        fid,
                        "WARN",
                        "REP-001",
                        f"Reproduction steps/PoC missing or too brief ({len(repro)} chars; min {MIN_REPRO_LEN}).",
                    )
                )

            if len(remediation) < MIN_REMEDIATION_LEN:
                issues.append(
                    FindingIssue(
                        line_num,
                        fid,
                        "WARN",
                        "REM-001",
                        f"Remediation guidance missing or too brief ({len(remediation)} chars; min {MIN_REMEDIATION_LEN}).",
                    )
                )

            score = compute_priority_score(sev, verified, has_repro)
            sev_counts[sev] += 1
            status_counts[status] += 1

            triaged.append(
                TriagedFinding(
                    finding_id=fid,
                    title=title or "(untitled)",
                    severity=sev,
                    cwe=cwe,
                    target=target or "unknown",
                    status=status,
                    priority_score=score,
                    verified=verified,
                )
            )

    triaged_sorted = sorted(triaged, key=lambda t: (-t.priority_score, t.finding_id))
    err_count = sum(1 for i in issues if i.severity == "ERROR")
    warn_count = sum(1 for i in issues if i.severity == "WARN")

    audit_obj = {
        "metadata": {
            "source_file": str(args.findings_file),
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "total_records": total_records,
            "triaged_count": len(triaged_sorted),
            "severity_distribution": dict(sev_counts),
            "status_distribution": dict(status_counts),
            "error_count": err_count,
            "warning_count": warn_count,
        },
        "findings": [asdict(t) for t in triaged_sorted],
        "quality_issues": [asdict(i) for i in issues],
    }

    args.json_out.write_text(json.dumps(audit_obj, indent=2), encoding="utf-8")

    md_lines = [
        "# Bug-Hunting Findings & Triage Audit Report",
        "",
        f"- **Source File:** `{args.findings_file.name}` | **Generated (UTC):** `{audit_obj['metadata']['generated_utc']}`",
        f"- **Findings Triaged:** `{len(triaged_sorted)}` | **QA Issues:** `{err_count}` errors, `{warn_count}` warnings",
        "",
        "## Prioritized Findings",
        "",
        "| Priority | Finding ID | Severity | CWE | Target | Status | Title |",
        "| :---: | :--- | :---: | :--- | :--- | :---: | :--- |",
    ]

    for t in triaged_sorted:
        md_lines.append(
            f"| **{t.priority_score:.2f}** | `{t.finding_id}` | **{t.severity}** | `{t.cwe}` | "
            f"`{t.target}` | `{t.status}` | {t.title} |"
        )

    md_lines.extend(["", "## Report Quality & Completeness Checks", ""])
    if not issues:
        md_lines.append("_All bug-hunting records passed schema, CWE, reproduction, and remediation checks._")
    else:
        md_lines.extend(
            [
                "| Line | Finding ID | Severity | Code | Diagnostic Detail |",
                "| :---: | :--- | :---: | :--- | :--- |",
            ]
        )
        for item in issues:
            md_lines.append(
                f"| {item.line_number} | `{item.finding_id}` | **{item.severity}** | `{item.code}` | {item.message} |"
            )

    args.md_out.write_text("\n".join(md_lines).strip() + "\n", encoding="utf-8")

    print(
        f"[+] Bug Hunt Audit: {len(triaged_sorted)} finding(s) scored, "
        f"{err_count} errors, {warn_count} warnings."
    )
    print(f"[+] Wrote {args.json_out} and {args.md_out}")

    return 1 if err_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
