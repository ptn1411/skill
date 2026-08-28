---
name: windows-log-hunter
description: "Blue-team CLI threat hunt over Windows Event Logs. Sweeps high-signal security events (failed logons, new accounts/services, cleared logs, PowerShell, Sysmon) via native PowerShell or Hayabusa/Sigma, and produces a triaged findings report."
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

# Windows Log Hunter

> Defensive threat hunting over Windows Event Logs from the command line. Detects suspicious authentication, account, persistence, and execution activity, then produces a severity-ranked report for triage.

> **Language rule**: All skill instructions use English.
> **Final summary presented to the user must be in Vietnamese.**

---

## 0. Authorization & Routing

Operates under [MASTER_POLICY.md](../MASTER_POLICY.md) §1-§2.

**Scope gate.** Hunt only on systems you **own or are authorized to monitor** (your host, your org's endpoints, an IR engagement, or a lab). This is a **read-only defensive** skill — it inspects logs, it does not modify the system.

| Sibling skill | When |
|---|---|
| [network-scanner](../network-scanner/SKILL.md) | Map attack surface / exposed services |
| [network-interceptor](../network-interceptor/SKILL.md) | Inspect suspicious network traffic |
| [container-cloud-auditor](../container-cloud-auditor/SKILL.md) | Audit exposed container/cloud config |

---

## Engines

| Engine | Needs | Best for |
|---|---|---|
| **native** (default) | PowerShell only — no install | Live triage of the current machine |
| **hayabusa** | [Hayabusa](https://github.com/Yamato-Security/hayabusa) exe in PATH | Deep Sigma-rule timeline over `.evtx` files |

Run PowerShell **as Administrator** so the Security log is readable; otherwise those categories are skipped with a collection note.

---

## Step 0 — Check environment

```powershell
python windows-log-hunter\scripts\hunt_eventlog.py --check
```

Reports PowerShell, optional Hayabusa, and whether you have admin rights.

---

## Step 1 — Native hunt (no external tools)

Sweep the last 24 hours of high-signal events on the current host:

```powershell
python windows-log-hunter\scripts\hunt_eventlog.py --hours 24 --out output\hunt
```

Adjust window / volume:

```powershell
python windows-log-hunter\scripts\hunt_eventlog.py --hours 72 --max 500 --out output\hunt
```

What it collects (via `Get-WinEvent`):

| Area | Event IDs |
|---|---|
| Authentication | 4625 failed logon, 4624 logon, 4672 special privileges |
| Accounts | 4720 created, 4726 deleted, 4732/4728 added to group |
| Persistence | 7045 new service, 4698 scheduled task, 7030 |
| Defense evasion | 1102 audit log cleared |
| Execution | 4688 new process, 4104 PowerShell script block |
| Sysmon (if installed) | 1 process, 3 network, 11 file create |

---

## Step 2 — Hayabusa timeline (optional, deeper)

If Hayabusa is installed, run Sigma detections over the live log folder or a collected evtx set:

```powershell
python windows-log-hunter\scripts\hunt_eventlog.py --engine hayabusa --logdir C:\Windows\System32\winevt\Logs --out output\hunt
```

Install Hayabusa: download the single-file release from https://github.com/Yamato-Security/hayabusa and put it in PATH.

---

## Step 3 — Read the report

Both engines write to `--out`:
- `FINDINGS.md` — signals grouped by severity (critical→info), counts by category, and triage guidance.
- `findings.json` — structured events for correlation / downstream skills.

Re-parse raw output without re-scanning:

```powershell
python windows-log-hunter\scripts\parse_findings.py output\hunt\events.json --kind native --out output\hunt
```

---

## Triage priorities

1. **1102** (audit log cleared) and spikes of **4625** (failed logons) — possible intrusion / brute force.
2. **4720 / 4732 / 4728** — new account or privilege escalation; confirm it was authorized.
3. **7045 / 4698** — new service / scheduled task; classic persistence.
4. Correlate suspicious **4104 PowerShell** and **4688 process** events against the timestamps above.

All output is for **defensive** response: containment, account review, persistence removal, and detection tuning.
