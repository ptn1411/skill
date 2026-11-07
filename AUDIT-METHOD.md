# Audit Method — Evidence & Verdict Discipline

Shared methodology for every audit in this toolkit and the bundled normative
method for `authorized-artifact-auditor`. It is shipped with the skill, not
assumed to exist elsewhere. It defines what counts as a real finding, how
certainty is separated from priority, how untrusted target code is handled and
executed safely, how secrets are redacted, and how coverage is reported
honestly. It complements the routing in [SKILL.md](SKILL.md) and the boundary
rules in [MASTER_POLICY.md](MASTER_POLICY.md); on any conflict, `MASTER_POLICY`
wins, and for verdict/severity decisions this file wins over shorter summaries.

Adapted from Cloudflare's open `security-audit` skill
(<https://github.com/cloudflare/security-audit-skill>), kept defensive and
source-first: the audit **describes** fixes, it does not weaken or circumvent
controls.

## 1. Require a boundary and a result

A candidate is a finding only when you can name all six:

1. **Principal** — the lower-trust actor or input source.
2. **Input / action** — the accepted value, request, or resource selector.
3. **Control** — the check that should reject, bind, isolate, limit, or revoke it.
4. **Boundary crossed** — the trust edge that is violated.
5. **Affected principal / resource** — what is reached on the other side.
6. **Observed result** — the concrete, owner-observable outcome.

If you cannot state both the crossed trust boundary and the concrete observed
result (a file, program output, request, response, or reproduced behavior — not
a tool guess), the record is at most `needs_validation`. Do **not** elevate a
missing best practice, a guessed deployment behaviour, a generic parser crash,
or self-impact into a security finding.

## 2. Verdict discipline — separate certainty from priority

Every record in `findings.json` carries a `verdict`:

- **`confirmed`** — the boundary and result were demonstrated by source evidence
  plus, where needed, a bounded local check. The evidence must be specific
  enough for someone else to reproduce the check (file path, command, input, and
  observed output). Only `confirmed` records receive an authoritative
  **`severity`**.
- **`needs_validation`** — a scanner hit, pattern match, or specific
  source-grounded hypothesis that is blocked on one fact outside static source
  (reachability, deployment, provider, identity, runtime). It states the
  **`missing_fact`** and a safe **`validation_plan`**, and has **no**
  authoritative `severity` (leave `severity` absent or `null`; in the array
  contract it may carry an advisory `candidate_severity` for triage order only).
- **`rejected`** — investigated and found not to violate a real boundary; states
  a `reason` (what was checked and why it does not hold). Keeping rejected
  records prevents the same candidate from being re-raised as new.

**Automated scanner output is `needs_validation` by default.** A static or
heuristic pattern match has not demonstrated a crossed boundary, so the
orchestrator harvests all sub-skill hits as candidates (see
[scripts/findings_aggregator.py](scripts/findings_aggregator.py)). Promotion to
`confirmed` — adding the boundary, trace, evidence, and fix — is a deliberate
human or verifier step, never automatic.

`needs_validation` is **not** a low-confidence `confirmed`. It is a blocked
hypothesis, and giving it an authoritative severity is an anti-pattern.

## 3. Severity anchors (confirmed records only)

Overall severity can never exceed demonstrated impact:

- **critical** (`Critical`) — unauthenticated actor gains code execution, full
  data-store access, or takeover of arbitrary accounts/entitlements.
- **high** (`High`) — an explicit control is fully defeated with real
  consequences: auth bypass, cross-tenant read/write, stored script execution
  affecting other users, authenticated code execution, or unauthenticated remote
  stop of a shared service.
- **medium** (`Medium`) — a real boundary violation with limited blast radius or
  uncommon preconditions.
- **low** (`Low`) — disclosure of non-secret internals, minor hardening gap, or
  high effort for minimal gain.
- **informational** (`Info`) — a confirmed but minimal-impact observation,
  useful mainly as context or a prerequisite inside a larger finding.

The high/medium test: does the demonstrated result **fully defeat** an explicit
control for an action with real consequences, or only weaken it? If you cannot
state the concrete damage, the severity is lower than it feels.

## 4. Bounded, local, safe evidence & untrusted artifact handling

Before inspecting a file artifact, record its **SHA-256 hash** and work on a
copy in an isolated working directory so the original artifact is never
modified. Do not execute any script, binary, or installer extracted from an
artifact without first reading it statically and confirming it is in scope.

Static analysis establishes the source path. When behaviour must be observed, use
the **narrowest local check** that settles the claim — an existing unit test, a
minimal function harness, a small malformed fixture, a dummy-tenant call, or a
locally rendered config — and stop at the first decisive effect (wrong return
value, unauthorized dummy record, sanitizer hit, policy difference).

Run target-controlled builds, tests, processes, browsers, emulators, fuzzers, or
fixture processing **only** inside an OS-enforced sandbox that provides *all* of:

- no external network (isolated loopback only when a local client/server is needed);
- an empty environment populated from an explicit allowlist of safe, non-secret
  values, with scratch-local `HOME`, temp, and caches;
- a read-only target and toolchain; the target process may write only to its own
  `scratch/` directory;
- explicit low CPU, memory, process, file-size, disk, and wall-clock limits.

Do not install or fetch dependencies for the target, probe deployed endpoints or
shared infrastructure, use real credentials, test availability against a live or
shared process, or continue past the minimum effect needed to establish the defect.
If any control cannot be enforced, **do not execute**: record a `needs_validation`
blocker with the missing sandbox capability and a safe validation plan.

## 5. Secrets & redaction discipline

Never record a raw secret, token, private key, or license key in any output,
including `evidence`, `REPORT.md`, or `FINDINGS.md`. Record only:

- `location`: file and line or path where it was found;
- secret type (for example: API token, private key, signing key);
- a fingerprint, such as a truncated SHA-256 hash, never the value itself.

If you cannot describe a finding without the raw value, describe the location
and the handling risk instead, and stop there.

## 6. Respect source visibility

Deployment controls, proxy behaviour, provider settings, browser headers, identity
policy, packaging, and topology are real controls. If one is required but absent
from the artifact, do not assume presence *or* absence — record `needs_validation`
with the exact missing fact and a safe owner-observed or local plan.

## 7. Smallest effective source fix

For each `confirmed` finding, identify the invariant the code must enforce and the
narrowest change that enforces it at the last trusted decision point. Prefer
specific repository-relative changes and regression tests over generic hardening
advice. Never produce a bypass, keygen, patch, or repack that weakens a control —
redirect to the defensive alternative per [MASTER_POLICY.md](MASTER_POLICY.md).

## 8. Report coverage honestly

No single pass is complete. State what was and was not covered, and never imply
that one run exhausts the target. A scoped or quick run must present itself as
**partial** coverage. Profiles change breadth, never the evidence bar: do not scale
away the candidate gate, the source/local execution boundary, `needs_validation`
discipline, schema validation, or independent verification of `confirmed` records.

## 9. Anti-patterns

1. Checklist deviations presented as vulnerabilities.
2. Defense-in-depth advice with no reachable boundary violation.
3. Live or shared-environment testing where bounded local evidence is enough.
4. Guessing provider, proxy, browser, identity, or deployment behaviour not in source.
5. Treating same-principal authority or self-impact as a cross-boundary result.
6. Reporting an effect stronger than the one observed.
7. Assigning authoritative severity to a `needs_validation` record.
8. Auto-promoting a scanner hit to `confirmed` without a demonstrated boundary + result.
9. Writing the report before candidates are validated, or letting prose and JSON disagree.
10. Printing a raw secret value instead of a redacted fingerprint, or embedding personal donation/payment details in an audit report.

## 10. The machine-readable contract & validation

`findings.json` conforms to [report-schema.json](report-schema.json) and is
checked by [scripts/validate_findings.py](scripts/validate_findings.py):

```bash
python <skill-folder>/scripts/validate_findings.py <output-dir>/findings.json
```

`<skill-folder>` is the folder containing this skill's `SKILL.md`;
`<output-dir>` is the audit output folder (e.g. `output/<target>-<YYYY-MM-DD>/`),
not a folder inside the skill.

The validator uses only the Python standard library (no extra install). It
supports both the orchestrator's record-array contract (`findings_aggregator.py`)
and the standalone report-envelope contract (`schema_version: "1.0"`, `target`,
`findings`), enforcing required fields, no unknown fields, unique IDs/fingerprints,
and the verdict/severity rules above. A report may not be published with a
failing validation: fix the record, or downgrade the verdict, and re-run the
validator.
