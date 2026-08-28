---
name: web-app-scanner
description: "Authorized web application testing from the CLI. Native security-header / cookie / TLS / CORS recon (no install), optional nuclei & ffuf discovery, and guarded sqlmap-based SQL injection testing, all parsed into a defensive findings report."
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

# Web App Scanner

> CLI web application assessment for authorized targets. Passive recon (headers, cookies, TLS, CORS, tech disclosure) with zero dependencies, plus optional active scanning (nuclei, ffuf) and guarded SQL injection testing (sqlmap).

> **Language rule**: All skill instructions use English.
> **Final summary presented to the user must be in Vietnamese.**

---

## 0. Authorization & Routing

Operates under [MASTER_POLICY.md](../MASTER_POLICY.md) §1-§2.

**Scope gate — required.** Test only web apps you **own or are explicitly authorized to assess** (written engagement, bug-bounty scope in-scope asset, CTF, or your own lab). Passive recon (`web_recon.py`) is low-impact; **active SQLi testing (`sqli_test.py`) is intrusive** and requires the explicit `--authorized` flag. If scope is unclear, ask one concise question first. Never point these at third-party sites without authorization.

| Sibling skill | When |
|---|---|
| [network-scanner](../network-scanner/SKILL.md) | Find which hosts/ports serve the web app |
| [network-interceptor](../network-interceptor/SKILL.md) | Capture the app's API/auth traffic |
| [pentest-script-generator](../antigravity-kit/pentest-script-generator/SKILL.md) | Turn a confirmed finding into a PoC/verify script |
| [container-cloud-auditor](../container-cloud-auditor/SKILL.md) | Audit the hosting config behind the app |

---

## Step 0 — Environment check

```powershell
python web-app-scanner\scripts\web_recon.py --check
python web-app-scanner\scripts\sqli_test.py --check
```

Native recon needs only Python. Optional tools:
- **nuclei** — https://github.com/projectdiscovery/nuclei (single binary in PATH)
- **ffuf** — https://github.com/ffuf/ffuf (single binary in PATH)
- **sqlmap** — `pip install sqlmap` (or clone the repo)

---

## Step 1 — Passive recon (no install)

```powershell
python web-app-scanner\scripts\web_recon.py https://app.local --out output\web
```

Checks and reports:
- Missing security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
- Cookie flags: Secure / HttpOnly / SameSite.
- TLS protocol version + certificate summary (flags TLS < 1.2).
- CORS reflection (echoed Origin, `*` + credentials).
- Tech disclosure via Server / X-Powered-By.

---

## Step 2 — Active discovery (optional)

Template scan + content discovery when the tools are installed:

```powershell
python web-app-scanner\scripts\web_recon.py https://app.local --nuclei --ffuf wordlist.txt --out output\web
```

Tool output is saved under `output\web\` and referenced from `FINDINGS.md`.

---

## Step 3 — SQL injection testing (guarded, authorized only)

Detection with safe defaults (`--level 1 --risk 1 --batch`):

```powershell
python web-app-scanner\scripts\sqli_test.py "https://app.local/item?id=1" --authorized --out output\sqli
```

From a saved Burp request:

```powershell
python web-app-scanner\scripts\sqli_test.py --request req.txt --authorized --out output\sqli
```

Guardrails:
- Refuses to run without `--authorized`.
- Blocks data-dump / OS-takeover switches (`--dump*`, `--os-shell`, `--file-read`, `--sql-shell`, ...) unless `--allow-exploit` is set — for documented, authorized engagements only. This skill's purpose is **confirming and fixing** SQLi, not exfiltrating data.

Raise depth when needed: `--level 3 --risk 2`.

---

## Step 4 — Report & remediate

`web_recon.py` writes `FINDINGS.md` + `findings.json` (severity-ranked). For SQLi, review sqlmap's session output for injectable parameters, DBMS, and technique.

Defensive fixes to recommend:
- **SQLi** → parameterized queries / prepared statements, ORM binding, least-privilege DB accounts, input allow-listing.
- **Headers/cookies** → add the missing headers; set Secure/HttpOnly/SameSite.
- **TLS** → enforce ≥ 1.2, valid cert, HSTS.
- **CORS** → explicit trusted origins; never `*`/reflected origin with credentials.

See [references/web_checklist.md](references/web_checklist.md) for the full checklist.
