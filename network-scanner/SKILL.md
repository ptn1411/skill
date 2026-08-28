---
name: network-scanner
description: "Run authorized network reconnaissance with Nmap on Windows (or Linux). Host discovery, port/service/version scanning, OS detection, and safe NSE scripts, parsed into a severity-ranked defensive findings report (exposed services, CVEs from vuln/vulners NSE, weak TLS/SSH, anonymous/default credentials, EOL versions)."
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

# Network Scanner (Nmap)

> Authorized network reconnaissance and attack-surface mapping with Nmap. Discovers live hosts, open ports, services, versions, and OS fingerprints, then produces a defensive findings report.

> **Language rule**: All skill instructions use English.
> **Final summary presented to the user must be in Vietnamese.**

---

## 0. Authorization & Routing

Operates under [MASTER_POLICY.md](../MASTER_POLICY.md) §1-§2.

**Scope gate — required before any scan.** Only scan hosts/ranges the user **owns or is explicitly authorized to assess** (written engagement, bug-bounty scope, internal assignment, lab/CTF, or their own network). If scope is unclear, ask one concise question before scanning. Do **not** scan third-party or public infrastructure without stated authorization.

This skill performs **read-only reconnaissance**. It does not exploit, brute-force, DoS, or run intrusive NSE categories (`dos`, `exploit`, `brute`, `intrusive`) unless the user explicitly requests them and confirms authorization.

| Sibling skill | When |
|---|---|
| [network-interceptor](../network-interceptor/SKILL.md) | Capture/analyze traffic once services are found |
| [container-cloud-auditor](../container-cloud-auditor/SKILL.md) | Audit exposed container/cloud services |
| [sbom-supply-chain-auditor](../sbom-supply-chain-auditor/SKILL.md) | Review dependency exposure of discovered services |

---

## Prerequisites (Windows)

1. Install Nmap for Windows (bundles **Npcap**, required for raw packet scans):
   - **Recommended:** download the latest installer from https://nmap.org/download.html and run it **as Administrator** (the Npcap driver needs elevation).
   - Avoid `winget install Insecure.Nmap` for now — its manifest points at a stale 7.80 URL and fails with a download-size error.
   - Without Npcap, Nmap still works via TCP connect scan (`-sT`); you lose SYN scan and OS detection.
2. Default install path: `C:\Program Files (x86)\Nmap\nmap.exe`. The wrapper auto-detects PATH and this path.
3. **Run PowerShell as Administrator** for `-sS` (SYN scan), OS detection (`-O`), and raw-packet host discovery. Without admin, Nmap falls back to TCP connect scan (`-sT`), which still works.
4. Python 3 for the parser (only Python stdlib is used — no extra install).

Verify:

```powershell
python network-scanner\scripts\nmap_scan.py --check
```

---

## Step 1 — Host Discovery (find live hosts)

Ping-sweep a subnet to see what is up (no port scan):

```powershell
python network-scanner\scripts\nmap_scan.py 192.168.1.0/24 --profile discovery --out output\nmap
```

```bash
python network-scanner/scripts/nmap_scan.py 192.168.1.0/24 --profile discovery --out output/nmap
```

---

## Step 2 — Port & Service Scan

Scan a host for open ports with service/version detection (default profile):

```powershell
python network-scanner\scripts\nmap_scan.py 192.168.1.10 --profile service --out output\nmap
```

Profiles:

| Profile | Nmap flags | Use |
|---|---|---|
| `discovery` | `-sn` | Live-host ping sweep, no ports |
| `quick` | `-T4 -F` | Fast top-100 ports |
| `service` | `-sV -T4 --top-ports 1000` | **Default.** Open ports + versions |
| `full` | `-p- -sV -T4` | All 65535 ports (slow) |
| `os` | `-O -sV` | OS + service detection (needs admin) |
| `safe-scripts` | `-sV -sC` | `service` + default NSE scripts (`safe`/`default` only) |
| `vuln` | `-sV --script vuln` | Known-CVE NSE checks (authorized targets only) |

Pass extra raw Nmap flags after `--`:

```powershell
python network-scanner\scripts\nmap_scan.py 192.168.1.10 --profile service --out output\nmap -- -p 22,80,443,3389
```

---

## Step 3 — Parse into Findings Report

Every run writes raw Nmap output (`.xml`, `.nmap`) plus a parsed report. To re-parse an existing XML:

```powershell
python network-scanner\scripts\parse_nmap.py output\nmap\scan.xml --out output\nmap
```

Produces:
- `output/nmap/FINDINGS.md` — hosts, open ports, services, versions, plus a **severity-ranked Findings** section.
- `output/nmap/findings.json` — structured results (including the derived `findings[]`) for downstream skills.

The parser derives findings from the scan (best results with `--profile vuln` or `safe-scripts`):
- **Exposed services** — classified by risk (cleartext FTP/Telnet, RDP/VNC, exposed databases, SMB).
- **CVEs** — pulls `CVE-…` IDs from `vuln`/`vulners` NSE output; `VULNERABLE` states → critical/high.
- **Weak TLS/SSL** — SSLv3 / TLS 1.0–1.1 / RC4 / EXPORT / DES / MD5 / low cipher grade.
- **Weak SSH** — arcfour / CBC / DH group1 / ssh-dss.
- **Default / anonymous credentials** — `ftp-anon`, `*-default-accounts`, brute-found creds.
- **EOL / known-bad versions** — e.g. vsftpd 2.3.4 backdoor, OpenSSH < 7, Apache 2.2, IIS ≤ 6, PHP 5.

> To populate CVE/TLS/SSH/cred findings, run NSE: `--profile vuln` or `--profile safe-scripts`.

---

## Notes & Safety

- Timing: `service`/`full` on a `/24` can take minutes to hours. Start narrow (single host or `quick`), widen as needed.
- The wrapper refuses `dos`, `exploit`, and `brute` NSE categories by default; passing them requires `--allow-intrusive` and explicit user authorization.
- All findings are reported for **defensive** purposes: attack-surface reduction, patching EOL services, closing unnecessary ports, hardening exposed management interfaces (RDP/SSH/SMB).
