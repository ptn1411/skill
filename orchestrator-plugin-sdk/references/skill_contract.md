# Toolkit Skill Contract

## Required Metadata

Every skill must have a `SKILL.md` file with YAML frontmatter:

```yaml
---
name: lowercase-kebab-case-name
description: One sentence explaining when to use the skill.
---
```

## Required Directories

- `scripts/` for executable entry points.
- `agents/` for `codex.yaml`, `gemini.yaml`, and `openai.yaml`.
- `tests/` for direct `unittest`-style tests.
- `references/` for domain notes or pattern catalogs.

## Preferred Outputs

Analyzer skills should write:

- `findings.json`
- `REPORT.md`

The JSON result should include `target`, `skill`, `summary`, `findings`, and `artifacts`.

## Orchestrator Registration Checklist

1. Add a detection helper for inputs the skill can handle.
2. Add a `run_<skill>()` phase runner returning `PhaseResult`.
3. Chain the runner only after cheap input checks pass.
4. Add a focused test for pure detection logic.
5. Keep destructive operations behind explicit flags.

## Test Checklist

Run these before claiming the skill is ready:

```powershell
python -m py_compile <skill>\scripts\<entrypoint>.py
python <skill>\tests\test_<skill>.py
python scripts\validate_agents.py
```
