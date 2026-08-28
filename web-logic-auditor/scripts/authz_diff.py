#!/usr/bin/env python3
"""
authz_diff.py — IDOR/BOLA & broken-access-control differ (stdlib, authorized only).

Sends the SAME request under two identities (and optionally unauthenticated) and
diffs the responses. If a non-owner (or anonymous) principal receives a response
that closely matches the owner's, the object reference is likely not authorized
per-user — an IDOR / BOLA candidate for manual confirmation.

Detection is comparison-only. GET is the default; state-changing methods require
--allow-write. Only test targets you own or are authorized to assess (MASTER_POLICY §1).

Usage:
    python authz_diff.py --url "https://app/api/orders/1001" \
        --auth-a "Cookie: session=OWNER" --auth-b "Cookie: session=OTHER" --authorized
    python authz_diff.py --url "https://app/api/orders/1001" \
        --auth-a "Authorization: Bearer A" --auth-b "Authorization: Bearer B" \
        --baseline-unauth --authorized
"""

import argparse
import difflib
import json
import ssl
import sys
from urllib.parse import urlparse
from urllib.request import Request, build_opener, HTTPSHandler
from urllib.error import HTTPError, URLError

UA = "web-logic-auditor/1.0 (authorized)"
TIMEOUT = 20
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _opener():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return build_opener(HTTPSHandler(context=ctx))


def send(url: str, method: str, headers: dict, data: bytes | None):
    req = Request(url, method=method, data=data, headers={"User-Agent": UA, **headers})
    try:
        with _opener().open(req, timeout=TIMEOUT) as resp:
            body = resp.read(200_000).decode("utf-8", "replace")
            return {"status": resp.status, "len": len(body), "body": body}
    except HTTPError as e:
        try:
            body = e.read(200_000).decode("utf-8", "replace")
        except Exception:  # noqa
            body = ""
        return {"status": e.code, "len": len(body), "body": body}
    except (URLError, ssl.SSLError, OSError) as e:
        return {"status": None, "len": 0, "body": "", "error": str(e)}


def parse_header(items: list[str]) -> dict:
    out = {}
    for it in items or []:
        if ":" in it:
            k, v = it.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a[:5000], b[:5000]).ratio()


def looks_like_denied(resp: dict) -> bool:
    if resp["status"] in (401, 403, 404):
        return True
    low = resp["body"].lower()
    return any(s in low for s in ("access denied", "forbidden", "unauthorized",
                                  "not allowed", "please log in", "login required"))


def main() -> int:
    ap = argparse.ArgumentParser(description="IDOR/BOLA response differ.")
    ap.add_argument("--url", required=True)
    ap.add_argument("--auth-a", action="append", default=[], help="Owner header 'Name: value' (repeatable).")
    ap.add_argument("--auth-b", action="append", default=[], help="Other principal header (repeatable).")
    ap.add_argument("--baseline-unauth", action="store_true", help="Also send with no auth.")
    ap.add_argument("--method", default="GET")
    ap.add_argument("--data", help="Request body (implies a content type you should set via --auth-*).")
    ap.add_argument("--authorized", action="store_true", help="Confirm scope (required).")
    ap.add_argument("--allow-write", action="store_true", help="Permit state-changing methods.")
    ap.add_argument("--threshold", type=float, default=0.85, help="Body-similarity IDOR threshold.")
    args = ap.parse_args()

    if not args.authorized:
        print("[!] Re-run with --authorized (this sends requests to the target).", file=sys.stderr)
        return 2
    method = args.method.upper()
    if method in WRITE_METHODS and not args.allow_write:
        print(f"[!] {method} is state-changing; re-run with --allow-write if intended.", file=sys.stderr)
        return 2
    if urlparse(args.url).scheme not in ("http", "https"):
        ap.error("URL must be http(s).")

    data = args.data.encode() if args.data else None
    a = send(args.url, method, parse_header(args.auth_a), data)
    b = send(args.url, method, parse_header(args.auth_b), data)
    result = {"url": args.url, "method": method, "owner_a": {k: a[k] for k in a if k != "body"},
              "other_b": {k: b[k] for k in b if k != "body"}, "findings": []}

    sim = similarity(a["body"], b["body"])
    result["similarity_a_b"] = round(sim, 3)
    if a["status"] and 200 <= a["status"] < 300 and b["status"] and 200 <= b["status"] < 300 \
            and not looks_like_denied(b) and sim >= args.threshold:
        result["findings"].append({
            "severity": "high", "category": "idor",
            "title": "IDOR/BOLA candidate — non-owner sees owner's resource",
            "detail": f"A={a['status']} B={b['status']} similarity={sim:.2f} (>= {args.threshold})."})

    if args.baseline_unauth:
        u = send(args.url, method, {}, data)
        result["unauth"] = {k: u[k] for k in u if k != "body"}
        if u["status"] and 200 <= u["status"] < 300 and not looks_like_denied(u):
            result["findings"].append({
                "severity": "high", "category": "broken-access-control",
                "title": "Resource reachable without authentication",
                "detail": f"Anonymous request returned {u['status']}."})

    print(json.dumps(result, indent=2))
    real = [f for f in result["findings"]]
    print(f"\n[+] {len(real)} finding(s). similarity(A,B)={sim:.2f}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
