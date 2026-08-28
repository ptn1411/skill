# Web App Test Checklist (defensive)

A lightweight OWASP-aligned checklist for authorized web assessments.

## Recon (covered by web_recon.py)
- [ ] Security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
- [ ] Cookies: Secure, HttpOnly, SameSite on session cookies.
- [ ] TLS ≥ 1.2, valid certificate, HSTS with adequate max-age.
- [ ] CORS: no `*` or reflected Origin combined with credentials.
- [ ] Tech disclosure: Server / X-Powered-By / framework version banners.

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
