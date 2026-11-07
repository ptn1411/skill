#!/usr/bin/env python3
"""
findings_aggregator.py — Normalize sub-skill scanner output into one findings.json
that follows the verdict discipline in AUDIT-METHOD.md / report-schema.json.

Design principle (from the Cloudflare security-audit method): a static/heuristic
scanner hit has NOT demonstrated a crossed trust boundary with an observable
result. It is a *candidate*, so every auto-harvested finding is emitted as
`needs_validation` — never `confirmed`. The scanner's own severity is preserved
as `candidate_severity` (advisory triage priority only). A human or a verifier
step promotes a candidate to `confirmed` (adding boundary/trace/evidence/fix) or
to `rejected`; this module never assigns authoritative severity itself.

Used by orchestrate.py, but importable and testable on its own.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable

_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
_FP_SANITIZE = re.compile(r"[^A-Za-z0-9._:/@+-]+")


def _norm_severity(value: Any) -> str:
    """Map a scanner's severity string onto the canonical enum; default 'low'."""
    s = str(value or "").strip().lower()
    if s in _SEVERITIES:
        return s
    return {
        "crit": "critical",
        "warn": "medium",
        "warning": "medium",
        "moderate": "medium",
        "info": "informational",
        "note": "informational",
    }.get(s, "low")


def _fingerprint(skill: str, category: str, file: str, line: Any, title: str) -> str:
    """Stable, schema-safe id that survives re-runs (path is normalized)."""
    norm_file = str(file or "").replace("\\", "/").lower()
    digest = hashlib.sha1(
        f"{skill}|{category}|{norm_file}|{line}|{title}".encode("utf-8", "replace")
    ).hexdigest()[:12]
    prefix = _FP_SANITIZE.sub("-", f"{skill}:{category}").strip("-") or "finding"
    return f"{prefix}:{digest}"


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _candidate(
    skill: str,
    category: str,
    title: str,
    file: str,
    line: Any,
    severity: Any,
    evidence: Iterable[str],
    missing_fact: str,
    validation_plan: str,
) -> dict:
    line_int: int | None
    try:
        line_int = int(line)
    except (TypeError, ValueError):
        line_int = None
    location: dict[str, Any] = {"file": str(file or "unknown")}
    if line_int is not None and line_int >= 0:
        location["line"] = line_int
    ev = [str(e).strip() for e in evidence if str(e).strip()]
    return {
        "verdict": "needs_validation",
        "fingerprint": _fingerprint(skill, category, file, line, title),
        "skill": skill,
        "title": title or category or "candidate",
        "category": category or "general",
        "candidate_severity": _norm_severity(severity),
        "location": location,
        "evidence": ev,
        "missing_fact": missing_fact,
        "validation_plan": validation_plan,
    }


# --- Per-skill adapters ------------------------------------------------------
# Each adapter is defensive: unknown/renamed fields degrade, they never raise.

_GENERIC_MISSING = (
    "Static/heuristic match only: the crossed boundary, reachability, and "
    "observable result are not yet demonstrated."
)


def _from_generic_findings(skill: str, data: Any, plan: str) -> list[dict]:
    """Read the common {'findings': [{severity,category,title,file,line,evidence}]} shape."""
    out: list[dict] = []
    items = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return out
    for it in items:
        if not isinstance(it, dict):
            continue
        ev = []
        for key in ("evidence", "recommendation", "why", "fix"):
            val = it.get(key)
            if val:
                ev.append(f"{key}: {val}")
        out.append(_candidate(
            skill=skill,
            category=str(it.get("category") or it.get("id") or "general"),
            title=str(it.get("title") or it.get("category") or "candidate"),
            file=str(it.get("file") or it.get("path") or "unknown"),
            line=it.get("line"),
            severity=it.get("severity"),
            evidence=ev,
            missing_fact=_GENERIC_MISSING,
            validation_plan=plan,
        ))
    return out


def harvest(out_dir: Path) -> list[dict]:
    """Scan a completed orchestrator output dir and return normalized candidate records."""
    findings: list[dict] = []
    seen: set[str] = set()

    sources = [
        # (skill, json path, validation plan)
        ("container-cloud-auditor",
         out_dir / "container-cloud-auditor" / "findings.json",
         "Render the config for the real deployment and confirm the risky setting "
         "reaches a live/exposed surface before treating it as confirmed."),
        ("sbom-supply-chain-auditor",
         out_dir / "sbom-supply-chain-auditor" / "findings.json",
         "Verify the flagged package/version is actually resolved and installed in "
         "the build, and check the advisory against the pinned lockfile."),
        ("license-robustness-audit",
         out_dir / "license-audit" / "license_findings.json",
         "Trace the validation path in the running app (owner-observed) to confirm "
         "the weakness is reachable; keep this defensive — no bypass is produced."),
        ("secrets-scan",
         out_dir / "audit-results" / "findings.json",
         "Confirm the value is a live secret (not a placeholder/test fixture) and "
         "that it is reachable by an untrusted principal before confirming."),
    ]

    for skill, path, plan in sources:
        if not path.exists():
            continue
        data = _load_json(path)
        if data is None:
            continue
        for rec in _from_generic_findings(skill, data, plan):
            if rec["fingerprint"] in seen:
                continue
            seen.add(rec["fingerprint"])
            findings.append(rec)

    # Fallback: any other *findings*.json produced by a future/renamed skill.
    for path in out_dir.rglob("*findings*.json"):
        if path.name == "findings.json" and path.parent == out_dir:
            continue  # our own aggregated file
        rel_parent = path.parent.name or "unknown-skill"
        if rel_parent in {s[0] for s in sources} or "license-audit" in str(path):
            continue  # already handled above
        data = _load_json(path)
        if data is None:
            continue
        for rec in _from_generic_findings(rel_parent, data, _GENERIC_MISSING):
            if rec["fingerprint"] in seen:
                continue
            seen.add(rec["fingerprint"])
            findings.append(rec)

    return findings


def summarize(findings: list[dict]) -> dict:
    """Counts by verdict and, for candidates, by advisory severity."""
    by_verdict: dict[str, int] = {}
    by_candidate_severity: dict[str, int] = {}
    for f in findings:
        by_verdict[f["verdict"]] = by_verdict.get(f["verdict"], 0) + 1
        if f["verdict"] == "needs_validation":
            sev = f.get("candidate_severity", "low")
            by_candidate_severity[sev] = by_candidate_severity.get(sev, 0) + 1
    return {
        "total": len(findings),
        "by_verdict": by_verdict,
        "candidate_severity": by_candidate_severity,
    }


def write_findings(out_dir: Path) -> tuple[Path, dict]:
    """Harvest, write output/findings.json, and return (path, summary)."""
    findings = harvest(out_dir)
    path = out_dir / "findings.json"
    path.write_text(json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8")
    return path, summarize(findings)


if __name__ == "__main__":
    import sys
    d = Path(sys.argv[1] if len(sys.argv) > 1 else "output").resolve()
    p, s = write_findings(d)
    print(f"[+] Wrote {p}")
    print(json.dumps(s, indent=2))
