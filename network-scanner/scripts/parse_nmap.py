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
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

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

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "findings.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    (out_dir / "FINDINGS.md").write_text(to_markdown(data), encoding="utf-8")

    up = len(data["hosts"])
    openp = sum(len(h["ports"]) for h in data["hosts"])
    print(f"[+] Parsed {up} host(s), {openp} open port(s).")
    print(f"[+] {out_dir / 'FINDINGS.md'}")
    print(f"[+] {out_dir / 'findings.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
