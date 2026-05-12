#!/usr/bin/env python3
"""Validate the minimum contract expected by the orchestrator skill toolkit."""
from __future__ import annotations

import argparse
import re
from pathlib import Path


REQUIRED_SECTIONS = ["## Purpose", "## Workflow", "## Outputs", "## Anti-Patterns"]


def validate_skill(skill_dir: Path | str) -> dict:
    root = Path(skill_dir)
    errors: list[str] = []
    warnings: list[str] = []
    skill_md = root / "SKILL.md"

    if not root.exists():
        errors.append("skill directory does not exist")
    if not skill_md.exists():
        errors.append("missing SKILL.md")
    else:
        text = skill_md.read_text(encoding="utf-8", errors="ignore")
        if not re.search(r"(?ms)^---\s*$.*?^---\s*$", text):
            errors.append("SKILL.md missing frontmatter block")
        if not re.search(r"(?m)^name:\s*[a-z0-9-]+", text):
            errors.append("SKILL.md missing normalized name")
        if not re.search(r"(?m)^description:\s*.+", text):
            errors.append("SKILL.md missing description")
        for section in REQUIRED_SECTIONS:
            if section not in text:
                warnings.append(f"missing section: {section}")

    if not (root / "scripts").exists():
        warnings.append("missing scripts directory")
    if not (root / "agents").exists():
        warnings.append("missing agents directory")
    if not (root / "tests").exists():
        warnings.append("missing tests directory")

    return {"skill": str(root), "errors": errors, "warnings": warnings}


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate toolkit skill contract.")
    parser.add_argument("skill_dir")
    args = parser.parse_args()
    result = validate_skill(Path(args.skill_dir))
    for item in result["errors"]:
        print(f"ERROR: {item}")
    for item in result["warnings"]:
        print(f"WARN: {item}")
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
