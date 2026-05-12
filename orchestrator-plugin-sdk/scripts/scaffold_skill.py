#!/usr/bin/env python3
"""Scaffold a skill that follows this toolkit's contract."""
from __future__ import annotations

import argparse
import re
from pathlib import Path


def normalize_name(name: str) -> str:
    slug = re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-")
    if not slug:
        raise ValueError("skill name cannot be empty")
    return slug


def scaffold_skill(root: Path | str, name: str, description: str) -> Path:
    base = Path(root)
    slug = normalize_name(name)
    skill_dir = base / slug

    (skill_dir / "scripts").mkdir(parents=True, exist_ok=True)
    (skill_dir / "references").mkdir(parents=True, exist_ok=True)
    (skill_dir / "agents").mkdir(parents=True, exist_ok=True)
    (skill_dir / "tests").mkdir(parents=True, exist_ok=True)

    (skill_dir / "SKILL.md").write_text(
        f"""---
name: {slug}
description: {description}
---

# {slug}

## Purpose

{description}

## Workflow

1. Run the script in `scripts/`.
2. Review generated outputs.

## Outputs

- `findings.json`
- `REPORT.md`

## Anti-Patterns

- Do not run outside authorized scope.
""",
        encoding="utf-8",
    )

    (skill_dir / "references" / "README.md").write_text(f"# {slug} References\n", encoding="utf-8")
    for agent in ("codex", "gemini", "openai"):
        (skill_dir / "agents" / f"{agent}.yaml").write_text(
            f"name: {slug}\ndescription: {description}\nentrypoint: SKILL.md\n",
            encoding="utf-8",
        )
    return skill_dir


def main() -> int:
    parser = argparse.ArgumentParser(description="Scaffold a toolkit skill.")
    parser.add_argument("name")
    parser.add_argument("--description", required=True)
    parser.add_argument("--root", default=".")
    args = parser.parse_args()
    path = scaffold_skill(Path(args.root), args.name, args.description)
    print(f"[+] Created {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
