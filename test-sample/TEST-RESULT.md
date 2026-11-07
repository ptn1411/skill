# test-sample — result (2026-10-30)

Run on Linux with Python 3 standard library only, from the skill package folder.

- Sample artifact: `test-sample/sample-app.js`
  - SHA-256: `4f0bb7dc881fd84ff81343f60e2b08346005b0248f5789660406da95adf2bf6b`
  - This is a fake sample. It contains no real secret.
- `python scripts/validate_findings.py test-sample/findings.json`
  - Result: VALID, 3 findings (1 confirmed / High, 1 needs_validation with no severity, 1 rejected with a reason).
- `python scripts/validate_findings.py test-sample/findings-bad.json`
  - Result: INVALID, 2 errors — severity on a needs_validation record, and a duplicate id.
- Extra-field check (schema `additionalProperties: false`)
  - Result: INVALID, 1 error — unknown top-level field.
- `python -m py_compile scripts/validate_findings.py`: OK.
- `report-schema.json` and `test-sample/findings.json` parse as JSON: OK.

This closes the earlier gap “skill chưa được chạy thử trên artifact mẫu”.
It does not prove the skill works on a real target; it proves the
validator, schema, and verdict/severity rules agree on a sample.
