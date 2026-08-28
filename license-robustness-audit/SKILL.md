---
name: license-robustness-audit
description: "Defensive audit of a license/entitlement/activation mechanism on software you own or are authorized to test. Maps the validation surface, flags design weaknesses that make checks easy to abuse, and produces hardening guidance plus an allow/deny test scaffold — without generating keygens, patches, or bypasses."
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

# License Robustness Audit

> Test how hard your licensing is to abuse — defensively. Map where validation happens, identify the design weaknesses that would let it be bypassed, and get a concrete hardening plan and tests for the legitimate allow/deny path.

> **Language rule**: All skill instructions use English.
> **Final summary presented to the user must be in Vietnamese.**

---

## 0. Authorization & Boundary

Operates under [MASTER_POLICY.md](../MASTER_POLICY.md) §1-§2. Use only on software you own or are authorized to assess.

This is the **defensive counterpart** to keygen/patch/bypass. It answers *"is my license easy to bypass, and how do I harden it?"* It **does not** produce a working keygen, license file, patch, or repacked binary — those remain out of scope by policy. Instead it yields an abuse-case analysis and source-level fixes.

| Sibling skill | When |
|---|---|
| [dotnet-decompiler](../dotnet-decompiler/SKILL.md) | Recover .NET source first, then audit it here |
| [java-decompiler](../java-decompiler/SKILL.md) | Recover Java source first |
| [electron-app-analyzer](../electron-app-analyzer/SKILL.md) | Recover Electron JS first |
| [network-interceptor](../network-interceptor/SKILL.md) | Confirm whether validation calls a server |

---

## Step 1 — Point it at your source

Run over an owned source tree or a recovered/decompiled one:

```powershell
python license-robustness-audit\scripts\audit_license.py <source_dir> --out output\license-audit
```

```bash
python license-robustness-audit/scripts/audit_license.py output/dotnet-decompiled --out output/license-audit
```

It scans `.cs/.js/.ts/.java/.py/.cpp/.go/...` files for licensing logic.

---

## Step 2 — Read the audit

Outputs in `--out`:
- **`LICENSE_AUDIT.md`** — validation surface, weaknesses (abuse-case view, severity-ranked), a hardening plan, and a test plan.
- **`ATTACK_PATH.md`** — design-level attack paths for a red-team write-up: a mermaid flow diagram of where the decision breaks, plus per-weakness *precondition → technique class → effect → control*. Descriptive findings, **not** a working bypass/keygen/patch.
- **`license_findings.json`** — structured findings.
- **`test_license_behavior.py`** — a pytest scaffold; wire `evaluate_license()` to your real check to prove valid→allow / expired/tampered/missing→deny.

---

## What it flags (design weaknesses)

| Category | Why it's abusable |
|---|---|
| Client-side validation gate | A client-held check can be observed and forced true |
| Bare boolean license decision | One-instruction bypass target |
| Hardcoded secret / signing key | Shipped secrets let an attacker mint valid licenses |
| Embedded public key + local verify | Verify path + key can be swapped together |
| Static key comparison | Accept condition trivially discoverable |
| Weak hash (MD5/SHA-1) in license path | Collision-prone integrity |
| Local trial/activation state | Resettable to extend usage |
| No server-side validation signal | Whole decision is local ⇒ tamperable |

---

## Hardening direction (the fix, not the bypass)

1. Authoritative check **server-side**; client only renders the signed decision.
2. **Signed, short-lived entitlements** (Ed25519 / RSA-PSS): user, features, expiry.
3. **No secrets in the client**; keep signing keys server-side and rotate them.
4. Bind trial/activation to an **account/device server-side**; local files are cache only.
5. **Fail closed** on any error; add tamper-evidence and verification telemetry.

Use the generated test scaffold to lock in correct allow/deny behavior as a regression guard.
