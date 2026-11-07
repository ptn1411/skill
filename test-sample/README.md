# test-sample — how this sample was checked

Sample only. No real secret, no real app, no network call.

Run from the skill package folder:

```bash
python scripts/validate_findings.py test-sample/findings.json
# expected: VALID, 3 findings (1 confirmed, 1 needs_validation, 1 rejected)

python scripts/validate_findings.py test-sample/findings-bad.json
# expected: INVALID — severity on a needs_validation record, and a duplicate id
```

What the sample proves:

- A `confirmed` record carries a trust boundary, concrete evidence, and a severity.
- A `needs_validation` record carries no severity.
- A `rejected` record carries a reason, not a severity.
- The validator rejects the bad file instead of silently accepting it.

SHA-256 of the sample artifact is recorded by the test run in
`test-sample/TEST-RESULT.md` after the validator is run; the hash is of
this fake sample only, not of a real target.
