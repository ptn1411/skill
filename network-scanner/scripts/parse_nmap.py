#!/usr/bin/env python3
"""
parse_nmap.py — Parse an Nmap XML report into a defensive findings report.

Reads nmap -oX XML (stdlib only) and emits:
  - FINDINGS.md   human-readable, hosts/ports/services + notable exposures
  - findings.json structured results for downstream skills

Usage:
    python parse_nmap.py output/nmap/scan.xml --out output/nmap
"""

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")

# Exposed-service severity by port (cleartext / management / datastore exposure).
SERVICE_SEVERITY = {
    21: ("high", "Cleartext FTP exposed"), 23: ("high", "Cleartext Telnet exposed"),
    3389: ("high", "RDP exposed to the network"), 5900: ("high", "VNC exposed (often weak auth)"),
    445: ("medium", "SMB exposed"), 139: ("medium", "NetBIOS/SMB exposed"),
    1433: ("high", "MSSQL database exposed"), 1521: ("high", "Oracle DB exposed"),
    3306: ("high", "MySQL database exposed"), 5432: ("high", "PostgreSQL database exposed"),
    6379: ("high", "Redis exposed (often unauthenticated)"),
    27017: ("high", "MongoDB exposed (often unauthenticated)"),
    9200: ("high", "Elasticsearch exposed (often unauthenticated)"),
    25: ("medium", "SMTP exposed — check open relay"),
}

# (product regex, version regex, severity, note) — light EOL / known-bad version heuristics.
EOL_VERSIONS = [
    (r"vsftpd", r"^2\.3\.4$", "critical", "vsftpd 2.3.4 shipped with a backdoor (CVE-2011-2523)."),
    (r"OpenSSH", r"^[0-6]\.", "medium", "OpenSSH < 7.0 is end-of-life; upgrade."),
    (r"Apache httpd", r"^2\.2\.", "medium", "Apache httpd 2.2.x is end-of-life; upgrade to 2.4+."),
    (r"Microsoft IIS", r"^[0-6]\.", "high", "IIS <= 6.0 is end-of-life (CVE-2017-7269 for 6.0)."),
    (r"PHP", r"^5\.", "medium", "PHP 5.x is end-of-life; upgrade."),
    (r"ProFTPD", r"^1\.3\.3", "high", "ProFTPD 1.3.3c had a backdoor; verify version."),
    (r"OpenSSL", r"^1\.0\.", "medium", "OpenSSL 1.0.x is end-of-life; upgrade."),
]

# NSE script signatures -> findings.
WEAK_TLS_RE = re.compile(r"SSLv3|TLSv1\.0|TLSv1\.1|RC4|EXPORT|_DES_|MD5|least strength:\s*[CDF]", re.I)
WEAK_SSH_RE = re.compile(r"arcfour|-cbc|diffie-hellman-group1-|group-exchange-sha1|\bssh-dss\b", re.I)


def _sev_rank(f: dict) -> int:
    return SEV_ORDER.get(f.get("severity", "info"), 9)


def derive_findings(data: dict) -> list[dict]:
    """Turn parsed hosts/ports/NSE output into severity-ranked findings."""
    findings = []

    def add(sev, category, title, host, port, detail):
        findings.append({"severity": sev, "category": category, "title": title,
                         "host": host, "port": port, "detail": detail})

    for h in data["hosts"]:
        addr = h["address"]
        for p in h["ports"]:
            port, svc = p["port"], p["service"]
            ver = " ".join(x for x in (p["product"], p["version"]) if x)

            # 1) exposed-service classification
            if port in SERVICE_SEVERITY:
                sev, title = SERVICE_SEVERITY[port]
                add(sev, "exposure", title, addr, port, p.get("note", ""))

            # 2) EOL / known-bad versions
            for prod_rx, ver_rx, sev, note in EOL_VERSIONS:
                if p["product"] and re.search(prod_rx, p["product"], re.I) \
                        and p["version"] and re.search(ver_rx, p["version"]):
                    add(sev, "version", f"Outdated/vulnerable {p['product']} {p['version']}", addr, port, note)

            # 3) NSE script output
            for s in p["scripts"]:
                sid, out = s.get("id", ""), s.get("output", "") or ""
                low = out.lower()
                cves = sorted(set(CVE_RE.findall(out)))
                if "vuln" in sid and "vulnerable" in low:
                    sev = "critical" if cves else "high"
                    add(sev, "vuln", f"{sid}: VULNERABLE", addr, port,
                        (", ".join(cves[:8]) or out.splitlines()[0][:120]))
                elif sid == "vulners" and cves:
                    add("high", "cve", f"vulners CVEs on {svc or port}", addr, port, ", ".join(cves[:12]))
                elif cves and sid not in ("vulners",):
                    add("medium", "cve", f"CVE reference from {sid}", addr, port, ", ".join(cves[:8]))
                if sid.startswith("ssl") and WEAK_TLS_RE.search(out):
                    add("medium", "tls", "Weak TLS/SSL configuration", addr, port,
                        "Weak protocol/cipher (SSLv3/TLS1.0-1.1/RC4/EXPORT/DES/MD5).")
                if "expired" in low and "cert" in sid:
                    add("medium", "tls", "Expired TLS certificate", addr, port, out.splitlines()[0][:120])
                if sid.startswith("ssh") and WEAK_SSH_RE.search(out):
                    add("medium", "ssh", "Weak SSH algorithms offered", addr, port,
                        "Deprecated cipher/KEX/host-key (arcfour/CBC/group1/ssh-dss).")
                if sid == "ftp-anon" and "anonymous" in low:
                    add("high", "default-cred", "Anonymous FTP login allowed", addr, port, out.splitlines()[0][:120])
                if "default" in sid and ("valid" in low or "found" in low or "account" in low):
                    add("high", "default-cred", f"Default credentials ({sid})", addr, port, out.splitlines()[0][:120])
                if "brute" in sid and "valid credentials" in low:
                    add("critical", "default-cred", f"Weak credentials found ({sid})", addr, port, out.splitlines()[0][:120])

    findings.sort(key=_sev_rank)
    return findings

# port -> (label, defensive note) for services worth flagging
NOTABLE = {
    21:   ("FTP", "Cleartext auth; prefer SFTP/FTPS."),
    23:   ("Telnet", "Cleartext remote shell; disable, use SSH."),
    25:   ("SMTP", "Check for open relay / STARTTLS."),
    135:  ("MSRPC", "Windows RPC; restrict at firewall."),
    139:  ("NetBIOS", "Legacy SMB; disable if unused."),
    445:  ("SMB", "Ensure patched (EternalBlue etc.); restrict exposure."),
    1433: ("MSSQL", "Database exposed; restrict to app hosts."),
    1521: ("Oracle DB", "Database exposed; restrict access."),
    3306: ("MySQL", "Database exposed; restrict to app hosts."),
    3389: ("RDP", "Remote Desktop; enable NLA, restrict, MFA/VPN."),
    5432: ("PostgreSQL", "Database exposed; restrict to app hosts."),
    5900: ("VNC", "Often weak/no auth; tunnel over VPN."),
    6379: ("Redis", "Frequently unauthenticated; bind localhost/ACL."),
    27017:("MongoDB", "Frequently unauthenticated; enable auth, restrict."),
    9200: ("Elasticsearch", "Often unauthenticated; restrict, enable security."),
}


def parse(xml_path: Path) -> dict:
    tree = ET.parse(xml_path)
    root = tree.getroot()
    result = {"args": root.get("args", ""), "hosts": []}

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        addr = ""
        for a in host.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr", "")
                break

        hostnames = [hn.get("name", "") for hn in host.findall("./hostnames/hostname")]

        os_guess = ""
        osmatch = host.find("./os/osmatch")
        if osmatch is not None:
            os_guess = f"{osmatch.get('name', '')} ({osmatch.get('accuracy', '')}%)"

        ports = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = int(port.get("portid", 0))
            svc = port.find("service")
            service = svc.get("name", "") if svc is not None else ""
            product = svc.get("product", "") if svc is not None else ""
            version = svc.get("version", "") if svc is not None else ""
            extrainfo = svc.get("extrainfo", "") if svc is not None else ""
            scripts = [{"id": s.get("id"), "output": (s.get("output") or "").strip()}
                       for s in port.findall("script")]

            label, note = NOTABLE.get(portid, ("", ""))
            ports.append({
                "port": portid,
                "protocol": port.get("protocol", "tcp"),
                "service": service,
                "product": product,
                "version": version,
                "extrainfo": extrainfo,
                "scripts": scripts,
                "notable": bool(label),
                "note": note,
                "label": label,
            })

        result["hosts"].append({
            "address": addr,
            "hostnames": [h for h in hostnames if h],
            "os": os_guess,
            "ports": sorted(ports, key=lambda p: p["port"]),
        })
    return result


def to_markdown(data: dict) -> str:
    lines = ["# Nmap Findings", "", f"_Scan args_: `{data.get('args','')}`", ""]
    up_hosts = data["hosts"]
    total_open = sum(len(h["ports"]) for h in up_hosts)
    lines.append(f"**Hosts up:** {len(up_hosts)} — **Open ports total:** {total_open}")
    lines.append("")

    fset = data.get("findings", [])
    real = [f for f in fset if f["severity"] != "info"]
    if real:
        from collections import Counter
        c = Counter(f["severity"] for f in real)
        lines.append("## Findings (severity-ranked)")
        lines.append("**Totals:** " + "  ".join(
            f"{k}: {c[k]}" for k in sorted(c, key=lambda s: SEV_ORDER.get(s, 9))))
        lines.append("")
        lines.append("| Severity | Category | Finding | Host:Port | Detail |")
        lines.append("|---|---|---|---|---|")
        for f in fset:
            detail = str(f["detail"]).replace("|", "\\|")[:80]
            lines.append(f"| {f['severity']} | {f['category']} | {f['title']} "
                         f"| {f['host']}:{f['port']} | {detail} |")
        lines.append("")

    exposures = []
    for h in up_hosts:
        title = h["address"] + (f" ({', '.join(h['hostnames'])})" if h["hostnames"] else "")
        lines.append(f"## {title}")
        if h["os"]:
            lines.append(f"- **OS:** {h['os']}")
        if not h["ports"]:
            lines.append("- No open ports detected.")
            lines.append("")
            continue

        lines.append("")
        lines.append("| Port | Proto | Service | Product / Version | Note |")
        lines.append("|---|---|---|---|---|")
        for p in h["ports"]:
            ver = " ".join(x for x in (p["product"], p["version"], p["extrainfo"]) if x)
            note = f"⚠️ {p['label']}: {p['note']}" if p["notable"] else ""
            lines.append(f"| {p['port']} | {p['protocol']} | {p['service']} | {ver} | {note} |")
            if p["notable"]:
                exposures.append(f"{h['address']}:{p['port']} — {p['label']} ({p['note']})")
            for s in p["scripts"]:
                if s["output"]:
                    first = s["output"].splitlines()[0][:120]
                    lines.append(f"| | | | _{s['id']}_ | {first} |")
        lines.append("")

    lines.append("## Notable Exposures (defensive)")
    if exposures:
        for e in exposures:
            lines.append(f"- {e}")
    else:
        lines.append("- None flagged by the built-in heuristics. Review services manually.")
    lines.append("")
    lines.append("> Recommendations: close unused ports, restrict management interfaces "
                 "(RDP/SSH/SMB) to VPN/allowlists, patch or retire EOL services, and enable "
                 "authentication on any exposed databases.")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Parse Nmap XML into a findings report.")
    ap.add_argument("xml", help="Path to nmap -oX XML file.")
    ap.add_argument("--out", default="output/nmap", help="Output directory.")
    args = ap.parse_args()

    xml_path = Path(args.xml)
    if not xml_path.exists():
        print(f"[!] XML not found: {xml_path}", file=sys.stderr)
        return 1

    try:
        data = parse(xml_path)
    except ET.ParseError as e:
        print(f"[!] Failed to parse XML: {e}", file=sys.stderr)
        return 1

    data["findings"] = derive_findings(data)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "findings.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    (out_dir / "FINDINGS.md").write_text(to_markdown(data), encoding="utf-8")

    up = len(data["hosts"])
    openp = sum(len(h["ports"]) for h in data["hosts"])
    nf = sum(1 for f in data["findings"] if f["severity"] != "info")
    print(f"[+] Parsed {up} host(s), {openp} open port(s), {nf} finding(s).")
    print(f"[+] {out_dir / 'FINDINGS.md'}")
    print(f"[+] {out_dir / 'findings.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
