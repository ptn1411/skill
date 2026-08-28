# Web App Test Checklist (defensive)

A lightweight OWASP-aligned checklist for authorized web assessments.

## Attack surface (covered by subdomain_enum.py / scan_all.py)
- [ ] Enumerate subdomains (crt.sh + subfinder, optional DNS brute) and identify web-alive hosts.
- [ ] Subdomain takeover — dangling CNAME to an unclaimed GitHub Pages/S3/Heroku/Azure/Fastly/Shopify service (`--takeover`).
- [ ] Scan **every** live subdomain, not just the apex — `scan_all.py example.com --active --crawl 1 --authorized`.

## Recon (covered by web_recon.py)
- [ ] Security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
- [ ] Cookies: Secure, HttpOnly, SameSite on session cookies.
- [ ] TLS ≥ 1.2, valid certificate, HSTS with adequate max-age.
- [ ] CORS: no `*` or reflected Origin combined with credentials.
- [ ] Tech disclosure: Server / X-Powered-By / framework version banners.

## Active checks (covered by vuln_checks.py via `web_recon.py --active`)
- [ ] Exposed VCS/config: `/.git/HEAD`, `/.git/config`, `/.env`, `/.svn`, Spring `/actuator/env`, backups.
- [ ] Reflected XSS — params reflected unencoded into HTML.
- [ ] Open redirect — `redirect`/`next`/`url`/`return` params sending `Location` off-site.
- [ ] Path traversal / LFI — `file`/`path`/`include` params returning `/etc/passwd` or `win.ini`.
- [ ] Directory listing / autoindex.
- [ ] Header injection / CRLF response splitting — param value breaks into a new response header.
- [ ] SSTI — `{{a*b}}` / `${a*b}` / `<%= a*b %>` evaluated server-side.
- [ ] SSRF — url-taking param fetches internal/metadata (169.254.169.254); verify blind SSRF with an OOB callback.
- [ ] Advanced CORS — null origin, arbitrary subdomain, prefix/suffix trust combined with credentials (via `web_recon.py`).
- [ ] Use `--crawl DEPTH` so these run on discovered endpoints, not just the entry URL.

## Injection
- [ ] **SQLi** — test each parameter (sqli_test.py / sqlmap). Fix: parameterized queries, ORM binding, least-privilege DB user.
- [ ] Command / template / LDAP / NoSQL injection — same principle: never concatenate untrusted input into an interpreter.

## Authentication & session
- [ ] Brute-force protection / lockout / rate limiting on login.
- [ ] Session fixation, predictable tokens, missing logout invalidation.
- [ ] MFA available for sensitive accounts.

## Access control (often highest impact)
- [ ] IDOR / BOLA — object references not authorized per user.
- [ ] Missing function-level authorization (admin endpoints reachable by normal users).
- [ ] Forced browsing to restricted paths.

## Client-side
- [ ] XSS (reflected / stored / DOM) — output encoding + CSP.
- [ ] CSRF — anti-CSRF tokens / SameSite cookies.
- [ ] Open redirect on `?redirect=`/`?next=` parameters.

## Data & config
- [ ] Sensitive data in responses, error stack traces, or `.git`/backup files.
- [ ] Verbose errors leaking DB/framework internals.
- [ ] Default credentials / exposed admin panels.

## sqlmap quick reference
```
sqlmap -u "https://app/item?id=1" --batch --level 1 --risk 1      # detect
sqlmap -r req.txt --batch                                          # from Burp request
sqlmap -u "..." --dbs        # (exploit — authorized engagements only, --allow-exploit)
sqlmap -u "..." --technique BEUSTQ   # tune techniques
```
Detection is enough to file and fix a finding — avoid dumping real data unless the engagement requires proof and permits it.

## nuclei / ffuf quick reference
```
nuclei -u https://app.local -severity medium,high,critical
ffuf -u https://app.local/FUZZ -w wordlist.txt -mc 200,301,401,403
```

## Reporting
For each finding record: endpoint, parameter, severity, reproduction, and a source-level remediation. Redact any real secrets/data (per MASTER_POLICY §3).
