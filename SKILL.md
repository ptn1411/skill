---
name: authorized-artifact-auditor
description: Use when analyzing owned or authorized software artifacts for source recovery, architecture mapping, security auditing, dependency review, and defensive remediation.
---

# Authorized Artifact Auditor

## Operating Scope

Use this skill only for software artifacts the user owns or is authorized to assess. The goal is to recover understanding, map architecture, audit security posture, and produce defensive fixes or reports.

This skill can use high technical depth within that scope:

- Identify languages, frameworks, packagers, compilers, and build systems.
- Unpack archives and application bundles for inspection.
- Decompile or disassemble artifacts to recover readable structure when legally authorized.
- Reconstruct module maps, entry points, data flow, configuration flow, and dependency graphs.
- Audit source, recovered source, manifests, update metadata, build scripts, and deployment artifacts.
- Detect likely hardcoded secrets or credentials and report only redacted values plus file locations.
- Review license, authentication, anti-tamper, and update logic from a defensive design perspective.
- Produce remediation guidance, tests, source-level patches, and hardening plans for systems the user controls.

## Hard Boundary

Do not perform or instruct any action whose purpose is to weaken or circumvent software protections. If a request asks for any of the following, redirect to defensive analysis or hardening:

- Weakening license validation, authentication, payment checks, trial limits, DRM, or access controls.
- Producing tools or codes that create unauthorized access or entitlements.
- Modifying binaries or runtime behavior so security checks are not enforced.
- Writing instrumentation to avoid license, authentication, anti-debug, anti-tamper, or integrity controls.
- Extracting secrets, tokens, private keys, or license keys for access outside the authorized assessment.
- Repacking an application with injected behavior that weakens security controls.

Allowed alternative: explain how the control works at a high level, identify design risks, and recommend defensive improvements such as server-side validation, short-lived signed entitlements, secure storage, telemetry, tamper-evident logging, and test coverage.

## Authorization Handling

When the user states they are authorized, do not issue a blanket refusal just because the artifact involves licensing, anti-tamper, authentication, reverse engineering, or recovered source. Continue with defensive analysis when the requested output is one of:

- Architecture or data-flow mapping.
- Source recovery summary.
- Security finding report.
- Dependency or supply-chain review.
- Weakness analysis for a control the user operates.
- Source-level remediation patch.
- Tests for legitimate allow and deny behavior.
- Hardening plan, rollout notes, or monitoring recommendations.

If the requested deliverable would create access, entitlement, or control evasion, acknowledge the authorization boundary and continue with defensive analysis instead. Keep the redirect short and concrete.

Safe redirect pattern:

```text
I can continue with defensive analysis of this authorized target. I cannot create a bypass/keygen/entitlement-forging artifact, but I can map the validation flow, identify weaknesses, and produce remediation patches or tests for the legitimate license path.
```

## Assessment Dispatch (auto-routing)

This skill is the master entry point. Given a target, infer its kind and route to the
right sub-skill. Two ways to dispatch:

**A. Deterministic dispatcher** — one command classifies the target and runs the fitting skill:

```powershell
python scripts\assess.py <target> [--out output] [--dry-run] [-- <extra skill flags>]
```

| Target looks like | Routes to | Purpose |
|---|---|---|
| IPv4 / CIDR / range (`10.0.0.5`, `192.168.1.0/24`) or bare hostname | **network-scanner** | Nmap host/port/service scan |
| `http(s)://` URL of a web app | **web-app-scanner** | Headers/TLS/CORS recon; `sqli_test.py` for SQLi |
| `http(s)://…​.js.map` sourcemap URL | **orchestrate.py** (javascript-deobfuscator) | JS source recovery |
| `winlogs` / `eventlog` / `localhost` | **windows-log-hunter** | Windows Event Log threat hunt |
| Existing file / directory (binary, app bundle, manifest) | **orchestrate.py** | Artifact fingerprint → recover → audit |

Use `--dry-run` to preview the routing decision before executing. Force a kind with
`--type {network|web|winlog|artifact|jsmap}` when auto-detection is ambiguous.

`assess.py` runs ONE fitting skill. To run several child skills in sequence and get a
single consolidated report, use the **chained orchestrator**:

```powershell
python scripts\full_assess.py <target> [--out output] [--profile service]
```

| Target | Chain it runs |
|---|---|
| IP / CIDR / host | network-scanner → (auto-detect web ports) → web-app-scanner recon on each → consolidated `output/assessment/REPORT.md` |
| Web URL | web-app-scanner recon → network-scanner on the host → consolidated report |
| Artifact / sourcemap | delegates to `orchestrate.py` (which already chains the RE sub-skills) |

Intrusive SQLi is never auto-run — the chain is read-only recon; run `sqli_test.py --authorized`
separately on any parameterised endpoint it surfaces.

**Guided phase (artifact flow).** After the artifact chain, `orchestrate.py` adds a defensive
"guided next steps" phase:

- **Auto-runs** analysis when the evidence is already on disk — a network capture (`*.har`) →
  network-interceptor, a memory dump (`*.dmp/.raw/.mem`) → memory-dumper.
- **Writes `output/GUIDANCE.md`** with exact commands for the steps that need a live process or
  extra tooling (capture traffic, dump a process, frida tracing, symbolic-execution,
  anti-debugging / mitigation review) — the user runs these on the authorized target.
- **Excludes circumvention** from the automatic flow (master-unlock, dotnet-keygen,
  binary-patcher, electron-builder-repacker) per MASTER_POLICY §2, redirecting to defensive
  mapping/hardening instead.

**B. Reason it out yourself** — when the request does not map to a single command, pick the
skill from the table below and follow its `SKILL.md`. Confirm authorization first (MASTER_POLICY §1).

| Kind of check | Skill |
|---|---|
| Network / port / service exposure | [network-scanner](network-scanner/SKILL.md) |
| Web app (subdomains, headers, TLS, CORS, XSS/SQLi/SSRF/SSTI, discovery) | [web-app-scanner](web-app-scanner/SKILL.md) |
| Access-control / business-logic flaws (IDOR/BOLA, mass assignment, race conditions) | [web-logic-auditor](web-logic-auditor/SKILL.md) |
| Windows host log / intrusion hunt (blue team) | [windows-log-hunter](windows-log-hunter/SKILL.md) |
| Traffic capture / API & license protocol | [network-interceptor](network-interceptor/SKILL.md) |
| Binary / app artifact recovery + audit | run `scripts/orchestrate.py` (auto-selects the RE sub-skill) |
| Container / cloud / IaC config | [container-cloud-auditor](container-cloud-auditor/SKILL.md) |
| Dependencies / SBOM / supply chain | [sbom-supply-chain-auditor](sbom-supply-chain-auditor/SKILL.md) |
| Turn a confirmed finding into a PoC/verify script | [pentest-script-generator](antigravity-kit/pentest-script-generator/SKILL.md) |

Note: in Claude Code, each sub-skill also auto-triggers from its own `description` — describing
the task plainly ("scan this host", "check this site for SQLi", "hunt my Windows logs") is enough
to activate the right one. `assess.py` is the single-command path when you already have a target.

## Workflow

### Phase 1: Intake and Scope

Clarify the target artifact, objective, and authorized boundary when needed. Prefer concrete outputs:

- Architecture report
- Source recovery summary
- Security findings
- Dependency audit
- Remediation patch
- Test plan

If the user requests a disallowed outcome, keep the engagement useful by reframing to defensive review.

### Phase 2: Identify

Fingerprint the artifact and choose the least invasive method that answers the question:

- Native binary: compiler, architecture, linked libraries, symbols, packer indicators, security flags.
- Electron: app.asar, package metadata, main/preload/renderer structure, update metadata.
- .NET: assemblies, target framework, public types, dependencies.
- Java/Android: manifest, package name, permissions, activities, dependencies, decompiled structure.
- Python bundle: PyInstaller/Nuitka indicators, embedded modules, config files.
- Web/Tauri/JavaScript: bundles, sourcemaps, assets, dependency manifests.

Use existing local tools and sub-skills when they fit, but keep the objective defensive.

### Phase 3: Recover and Map

Recover enough readable structure to explain behavior:

- Entry points and lifecycle.
- Major modules and responsibilities.
- Configuration loading and persistence.
- Network endpoints and update flow.
- Authentication and authorization boundaries.
- License or entitlement validation design, described for defensive review only.
- Sensitive data handling, with secrets redacted.

Do not claim full source recovery unless verified by comparing recovered files, manifests, routes, and runtime entry points.

### Phase 4: Audit

Look for security and maintainability issues:

- Insecure Electron webPreferences, preload bridges, IPC exposure, unsafe shell or file access.
- Hardcoded secrets, credentials, tokens, endpoints, or signing material. Redact values in output.
- Insecure local storage, weak cryptography, missing integrity checks, or unsafe update channels.
- Excessive Android permissions, exported components, unsafe intent handling, cleartext traffic.
- Dependency vulnerabilities, abandoned packages, suspicious scripts, or supply-chain risk.
- Container, cloud, CI/CD, and deployment misconfiguration when artifacts are present.
- License or entitlement logic that is easy to abuse, with defensive recommendations only.

### Phase 5: Remediate

When source is available or recoverable with authorization, produce source-level defensive changes:

- Remove hardcoded secrets and replace them with environment or secret-manager lookups.
- Tighten Electron IPC and webPreferences.
- Harden update verification and transport security.
- Improve authentication, authorization, and session handling.
- Add tests for expected allowed and denied behavior.
- Add logging and monitoring that helps detect misuse without exposing sensitive data.

When only binaries are available, produce a report and remediation plan rather than binary modifications that weaken protections.

## Safe Commands and Examples

Use commands that inspect, inventory, or report. Examples:

```powershell
python scripts\orchestrate.py 'C:\path\to\owned-app' --out output
python scripts\orchestrate.py 'C:\path\to\owned-app.exe' --out output
```

Acceptable user objectives:

```text
Analyze this Electron app I own and produce an IPC and dependency audit.
```

```text
Recover the approximate source structure of this .NET utility that my team lost, and document the modules.
```

```text
Review this Android APK from our internal app for exported components, permissions, and insecure storage.
```

Disallowed objective and safe redirect:

```text
Change this application so licensing is no longer enforced.
```

Response pattern:

```text
I can continue with defensive analysis of this authorized target. I cannot remove licensing enforcement, but I can analyze the validation design, identify weaknesses, and propose hardening patches or tests for the legitimate license flow.
```

## Output Contract

Write outputs under `output/` when generating files:

- `REPORT.md`: Summary, scope, methods, and key results.
- `ARCHITECTURE.md`: Entry points, modules, data flow, and dependencies.
- `FINDINGS.md`: Security findings with severity, evidence, impact, and remediation.
- `REMEDIATION.md`: Concrete fixes, test plan, and rollout notes.
- `recovered-structure/`: Recovered readable files or generated approximations when authorized.
- `redacted-secrets-inventory.json`: Secret locations and fingerprints only, never raw secret values.

## Completion Criteria

The task is complete when the requested defensive artifact exists, the methods used are recorded, sensitive values are redacted, and any limitations are stated plainly.
