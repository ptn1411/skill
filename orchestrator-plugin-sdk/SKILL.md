---
name: orchestrator-plugin-sdk
description: Scaffold and validate new toolkit skills with the standard file layout, metadata, output contract, and orchestrator registration checklist.
---

# Orchestrator Plugin SDK

## Purpose

Use this skill when adding a new local skill to the toolkit or validating that an existing skill can be chained from the master orchestrator.

## Workflow

1. Scaffold a skill with `python orchestrator-plugin-sdk/scripts/scaffold_skill.py <name> --description "<description>"`.
2. Implement scripts and tests inside the generated directories.
3. Validate the contract with `python orchestrator-plugin-sdk/scripts/validate_skill_contract.py <skill-dir>`.
4. Register the skill in `scripts/orchestrate.py` only after its CLI and tests are stable.

## Outputs

- A skill directory with `SKILL.md`, `scripts/`, `references/`, `agents/`, and `tests/`.
- Contract validation output with errors and warnings.

## Anti-Patterns

- Do not register a skill in the orchestrator before it has a CLI smoke test.
- Do not create skills without a clear output contract.
