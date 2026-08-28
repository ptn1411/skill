# Nmap Profiles & Windows Cheat Sheet

## Wrapper profiles

| Profile | Flags | Notes |
|---|---|---|
| `discovery` | `-sn` | Host discovery only (ping sweep), no port scan. |
| `quick` | `-T4 -F` | Fast scan of the top 100 ports. |
| `service` | `-sV -T4 --top-ports 1000` | Default. Open ports + service/version. |
| `full` | `-p- -sV -T4` | All 65535 TCP ports. Slow. |
| `os` | `-O -sV` | OS fingerprint (needs admin/root). |
| `safe-scripts` | `-sV -sC` | Runs the `default`/`safe` NSE scripts. |
| `vuln` | `-sV --script vuln` | Known-CVE checks. Authorized targets only. |

## Privileges on Windows

- SYN scan (`-sS`), OS detection (`-O`), and raw-packet host discovery need **Administrator** + **Npcap** (installed with Nmap).
- Without admin, Nmap uses TCP connect scan (`-sT`) automatically — slower and noisier but functional.
- Run: right-click PowerShell → **Run as administrator**.

## Common raw flags (pass after `--`)

```
-p 22,80,443          scan specific ports
-p-                   all 65535 ports
-Pn                   skip host discovery (treat host as up) — useful when ICMP is filtered
-T0..T5               timing (T4 = fast, T0 = stealthy/slow)
--top-ports N         scan N most common ports
-sU                   UDP scan (slow; needs admin)
-6                    IPv6
--open                show only open ports
-A                    aggressive: -O -sV -sC --traceroute
```

## Output formats (the wrapper uses -oX + -oN)

```
-oX file.xml     XML (parsed by parse_nmap.py)
-oN file.nmap    normal human-readable
-oG file.gnmap   greppable
-oA base         all three at once
```

## Timing guidance

- Single host `service`: seconds–minutes.
- `/24` `service`: minutes–tens of minutes.
- `/24` `full` (`-p-`): can be hours. Narrow the port range or host set first.

## Defensive reading of results

- **RDP (3389) / SSH (22) / SMB (445)** open to untrusted networks → restrict to VPN/allowlist, enable MFA/NLA.
- **Databases (1433/3306/5432/6379/27017/9200)** reachable → should never face untrusted networks; enable auth.
- **Telnet (23) / FTP (21)** → cleartext; replace with SSH/SFTP.
- Old product/version banners → check for EOL and known CVEs, then patch or retire.
