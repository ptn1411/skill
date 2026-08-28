# Windows Event Hunt — Detection Reference

High-signal event IDs the native engine collects, why they matter, and what to check.

## Authentication (Security log)
| ID | Meaning | Investigate when |
|---|---|---|
| 4625 | Failed logon | Many in a short window from one source = brute force / spraying. Check `LogonType` (3=network, 10=RDP) and source IP. |
| 4624 | Successful logon | Type 10 (RDP) or type 3 (network) from unexpected hosts/accounts. |
| 4672 | Special privileges assigned at logon | Admin-equivalent logon; correlate with the account. |
| 4648 | Explicit credential logon | Lateral movement (runas / pass-the-hash patterns). |

## Account & privilege changes
| ID | Meaning |
|---|---|
| 4720 | User account created |
| 4726 | User account deleted |
| 4722/4725 | Account enabled / disabled |
| 4728 | Member added to a **global** group (e.g. Domain Admins) |
| 4732 | Member added to a **local** group (e.g. Administrators) |
| 4756 | Member added to a **universal** group |

Any addition to an admin group should map to a known change ticket.

## Persistence
| ID | Log | Meaning |
|---|---|---|
| 7045 | System | New service installed — common malware persistence |
| 7030 | System | Service configured to interact with desktop (suspicious) |
| 4698 | Security | Scheduled task created |
| 4699/4702 | Security | Scheduled task deleted / updated |

## Defense evasion
| ID | Meaning |
|---|---|
| 1102 | Security audit log cleared — **high priority**, attackers cover tracks |
| 104  | An event log was cleared (System) |

## Execution
| ID | Log | Meaning |
|---|---|---|
| 4688 | Security | New process created (enable "audit process creation" + command line auditing for full value) |
| 4104 | PowerShell/Operational | Script block logging — deobfuscated PowerShell content |
| 400/800 | Windows PowerShell | Engine start / pipeline execution |

## Sysmon (Microsoft-Windows-Sysmon/Operational) — if installed
| ID | Meaning |
|---|---|
| 1  | Process create (with hashes + command line) |
| 3  | Network connection |
| 7  | Image/DLL loaded |
| 8  | CreateRemoteThread (injection) |
| 11 | File create |
| 13 | Registry value set |

Install Sysmon with a curated config (e.g. SwiftOnSecurity or Olaf Hartong `sysmon-modular`) for far richer telemetry than the default Windows auditing.

## Enabling better auditing
- `auditpol /set /subcategory:"Process Creation" /success:enable`
- Group Policy → *Include command line in process creation events* = Enabled.
- Enable **PowerShell Script Block Logging** via GPO for event 4104.

## Notes
- The **Security** log requires Administrator to read — run PowerShell elevated.
- For post-incident review of another machine, collect its `.evtx` files (e.g. with KAPE) and run the **hayabusa** engine against that folder offline.
