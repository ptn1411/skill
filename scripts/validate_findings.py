#!/usr/bin/env python3
"""
validate_findings.py — Validate findings.json against report-schema.json and AUDIT-METHOD.md.

Standard library only (no external jsonschema dependency). Supports both contracts
defined in report-schema.json:

1. Standalone report-envelope object (`schema_version == "1.0"`, `target`, `findings`):
   - Top-level fields restricted to `TOP_FIELDS` (`additionalProperties: false`)
   - `target_sha256`, when present, must be 64 lowercase hex chars
   - Each finding in `findings`: unique `id` matching `F-NNN`, non-empty `title`,
     `verdict` in `{confirmed, needs_validation, rejected}`, non-empty `trust_boundary`
   - `severity` required when `verdict == "confirmed"`, and must be absent or `null` otherwise
   - `confirmed` requires non-empty `evidence`; `rejected` requires non-empty `reason`

2. Orchestrator record-array format (`[ ... ]` emitted by `scripts/findings_aggregator.py`):
   - Each record carries `verdict`, `fingerprint`, `skill`, `title`, `category`
   - `confirmed` requires `severity`, `boundary` (`principal`, `input`, `control`,
     `affected`, `result`), non-empty `trace`, non-empty `evidence`, and `fix`
   - `needs_validation` must NOT carry authoritative `severity` (may carry
     `candidate_severity`), and requires `location.file`, `missing_fact`, `validation_plan`
   - `rejected` requires `reason`

Usage:
    python <skill-folder>/scripts/validate_findings.py [output/findings.json]

Exit code 0 = valid, 1 = invalid (errors printed, one per line).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

VERDICTS = {"confirmed", "needs_validation", "rejected"}
SEVERITIES = {"critical", "high", "medium", "low", "informational"}
ENVELOPE_SEVERITIES = SEVERITIES | {"Critical", "High", "Medium", "Low", "Info"}

FP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$")
ID_RE = re.compile(r"^F-[0-9]{3}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
TRACE_KINDS = {"entrypoint", "propagation", "sink"}

TOP_FIELDS = {"schema_version", "target", "target_sha256", "generated", "scope_note", "findings"}
ENVELOPE_FINDING_FIELDS = {
    "id", "title", "verdict", "trust_boundary", "severity",
    "evidence", "reason", "location", "impact", "remediation",
}
CONFIRMED_ARRAY_FIELDS = {
    "verdict", "fingerprint", "skill", "title", "category", "severity",
    "boundary", "trace", "evidence", "root_cause", "fix",
}
NEEDS_VALIDATION_ARRAY_FIELDS = {
    "verdict", "fingerprint", "skill", "title", "category",
    "candidate_severity", "location", "evidence", "missing_fact", "validation_plan",
}
REJECTED_ARRAY_FIELDS = {
    "verdict", "fingerprint", "skill", "title", "category", "reason",
}


def _err(errors: list[str], idx: int, msg: str) -> None:
    errors.append(f"record[{idx}]: {msg}")


def _require_str(errors: list[str], idx: int, rec: dict, key: str) -> None:
    if not isinstance(rec.get(key), str) or not rec[key].strip():
        _err(errors, idx, f"missing/empty string field '{key}'")


def _check_common(errors: list[str], idx: int, rec: dict) -> None:
    fp = rec.get("fingerprint")
    if not isinstance(fp, str) or not FP_RE.match(fp or ""):
        _err(errors, idx, "fingerprint missing or not matching required pattern")
    for key in ("skill", "title", "category"):
        _require_str(errors, idx, rec, key)


def _check_confirmed(errors: list[str], idx: int, rec: dict) -> None:
    _check_common(errors, idx, rec)
    for key in sorted(rec):
        if key not in CONFIRMED_ARRAY_FIELDS:
            _err(errors, idx, f"unknown field {key!r}")
    if rec.get("severity") not in SEVERITIES:
        _err(errors, idx, "confirmed record needs a valid 'severity'")
    _require_str(errors, idx, rec, "fix")

    b = rec.get("boundary")
    if not isinstance(b, dict):
        _err(errors, idx, "confirmed record needs a 'boundary' object")
    else:
        for key in ("principal", "input", "control", "affected", "result"):
            if not isinstance(b.get(key), str) or not b[key].strip():
                _err(errors, idx, f"boundary.{key} missing/empty")

    trace = rec.get("trace")
    if not isinstance(trace, list) or not trace:
        _err(errors, idx, "confirmed record needs a non-empty 'trace' array")
    else:
        for j, step in enumerate(trace):
            if not isinstance(step, dict):
                _err(errors, idx, f"trace[{j}] not an object")
                continue
            if step.get("kind") not in TRACE_KINDS:
                _err(errors, idx, f"trace[{j}].kind invalid")
            if not isinstance(step.get("file"), str) or not step["file"].strip():
                _err(errors, idx, f"trace[{j}].file missing")
            if not isinstance(step.get("description"), str) or not step["description"].strip():
                _err(errors, idx, f"trace[{j}].description missing")

    ev = rec.get("evidence")
    if not isinstance(ev, list) or not ev or not all(isinstance(e, str) and e.strip() for e in ev):
        _err(errors, idx, "confirmed record needs a non-empty 'evidence' string array")


def _check_needs_validation(errors: list[str], idx: int, rec: dict) -> None:
    _check_common(errors, idx, rec)
    if "severity" in rec:
        _err(errors, idx, "needs_validation must NOT carry authoritative 'severity' "
                          "(use 'candidate_severity')")
    for key in sorted(rec):
        if key not in NEEDS_VALIDATION_ARRAY_FIELDS and key != "severity":
            _err(errors, idx, f"unknown field {key!r}")
    cs = rec.get("candidate_severity")
    if cs is not None and cs not in SEVERITIES:
        _err(errors, idx, "candidate_severity invalid")
    loc = rec.get("location")
    if not isinstance(loc, dict) or not isinstance(loc.get("file"), str) or not loc["file"].strip():
        _err(errors, idx, "needs_validation record needs location.file")
    _require_str(errors, idx, rec, "missing_fact")
    _require_str(errors, idx, rec, "validation_plan")


def _check_rejected(errors: list[str], idx: int, rec: dict) -> None:
    _check_common(errors, idx, rec)
    for key in sorted(rec):
        if key not in REJECTED_ARRAY_FIELDS:
            _err(errors, idx, f"unknown field {key!r}")
    _require_str(errors, idx, rec, "reason")


def _validate_envelope(data: dict) -> list[str]:
    errors: list[str] = []
    for key in sorted(data):
        if key not in TOP_FIELDS:
            errors.append(f"unknown top-level field {key!r}")
    if data.get("schema_version") != "1.0":
        errors.append("schema_version must be '1.0'")
    if not isinstance(data.get("target"), str) or not data["target"].strip():
        errors.append("target must be a non-empty string")
    sha = data.get("target_sha256")
    if sha is not None and not (isinstance(sha, str) and SHA_RE.match(sha)):
        errors.append("target_sha256 must be 64 lowercase hex characters")
    findings = data.get("findings")
    if not isinstance(findings, list):
        errors.append("findings must be a list")
        return errors

    seen_ids: set[str] = set()
    for i, item in enumerate(findings):
        where = f"findings[{i}]"
        if not isinstance(item, dict):
            errors.append(f"{where}: must be an object")
            continue
        for key in sorted(item):
            if key not in ENVELOPE_FINDING_FIELDS:
                errors.append(f"{where}: unknown field {key!r}")
        fid = item.get("id")
        if not isinstance(fid, str) or not ID_RE.match(fid):
            errors.append(f"{where}: id must match F-NNN, got {fid!r}")
        elif fid in seen_ids:
            errors.append(f"{where}: duplicate id {fid}")
        else:
            seen_ids.add(fid)
        if not isinstance(item.get("title"), str) or not item["title"].strip():
            errors.append(f"{where}: title must be a non-empty string")
        verdict = item.get("verdict")
        if verdict not in VERDICTS:
            errors.append(f"{where}: verdict must be one of {sorted(VERDICTS)}")
            continue
        if not isinstance(item.get("trust_boundary"), str) or not item["trust_boundary"].strip():
            errors.append(f"{where}: trust_boundary must be a non-empty string")
        severity = item.get("severity")
        if verdict == "confirmed":
            if severity not in ENVELOPE_SEVERITIES:
                errors.append(f"{where}: confirmed findings require a valid severity")
            if not isinstance(item.get("evidence"), str) or not item["evidence"].strip():
                errors.append(f"{where}: confirmed findings require non-empty evidence")
        else:
            if severity is not None:
                errors.append(f"{where}: severity must be absent or null unless verdict is confirmed")
        if verdict == "rejected":
            if not isinstance(item.get("reason"), str) or not item["reason"].strip():
                errors.append(f"{where}: rejected findings require a reason")
    return errors


def validate(data: object) -> list[str]:
    if isinstance(data, dict):
        return _validate_envelope(data)
    if not isinstance(data, list):
        return ["top-level value must be a JSON object (envelope) or array of finding records"]
    errors: list[str] = []
    dispatch = {
        "confirmed": _check_confirmed,
        "needs_validation": _check_needs_validation,
        "rejected": _check_rejected,
    }
    for idx, rec in enumerate(data):
        if not isinstance(rec, dict):
            _err(errors, idx, "record is not an object")
            continue
        verdict = rec.get("verdict")
        checker = dispatch.get(verdict)
        if not checker:
            _err(errors, idx, f"invalid verdict {verdict!r} "
                              "(expected confirmed|needs_validation|rejected)")
            continue
        checker(errors, idx, rec)
    return errors


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "output/findings.json")
    if not path.exists():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 1
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON in {path}: {exc}", file=sys.stderr)
        return 1

    errors = validate(data)
    if errors:
        for e in errors:
            print(f"INVALID: {e}")
        print(f"INVALID: {len(errors)} error(s) in {path}")
        return 1

    if isinstance(data, dict):
        n = len(data.get("findings", []))
    else:
        n = len(data) if isinstance(data, list) else 0
    print(f"VALID: {path} ({n} finding(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
