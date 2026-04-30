#!/usr/bin/env python3
"""Validate all agent yaml files parse cleanly."""
import glob
import sys
import yaml


def main() -> int:
    files = sorted(glob.glob("**/agents/*.yaml", recursive=True))
    print(f"Found {len(files)} agent yaml files")
    failed = []
    for f in files:
        try:
            yaml.safe_load(open(f, encoding="utf-8"))
        except Exception as e:
            failed.append((f, str(e)))
            print(f"FAIL: {f}: {e}")
    if failed:
        return 1
    print("All parse OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
