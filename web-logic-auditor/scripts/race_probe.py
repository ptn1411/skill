#!/usr/bin/env python3
"""
race_probe.py — Concurrency / race-condition & idempotency probe (stdlib, authorized only).

Fires N identical requests concurrently to see whether an operation that should
succeed once actually succeeds multiple times (coupon double-spend, balance
double-withdraw, limit bypass) or whether an idempotency key is not enforced.

Race testing is state-changing by nature: this tool REQUIRES --authorized and,
for non-GET methods, --allow-write. Use only on targets you own or are
authorized to test (MASTER_POLICY §1). Prefer a disposable/staging account.

Usage:
    python race_probe.py --url "https://app/api/redeem" --method POST \
        --data "code=SAVE10" --header "Cookie: session=YOU" \
        -n 20 --authorized --allow-write
"""

import argparse
import concurrent.futures
import json
import ssl
import sys
import time
from collections import Counter
from urllib.parse import urlparse
from urllib.request import Request, build_opener, HTTPSHandler
from urllib.error import HTTPError, URLError

UA = "web-logic-auditor/1.0 (authorized)"
TIMEOUT = 25
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _opener():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return build_opener(HTTPSHandler(context=ctx))


def parse_header(items):
    out = {}
    for it in items or []:
        if ":" in it:
            k, v = it.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def one(url, method, headers, data):
    req = Request(url, method=method, data=data, headers={"User-Agent": UA, **headers})
    t0 = time.perf_counter()
    try:
        with _opener().open(req, timeout=TIMEOUT) as resp:
            body = resp.read(4000).decode("utf-8", "replace")
            return {"status": resp.status, "ms": round((time.perf_counter() - t0) * 1000), "snippet": body[:80]}
    except HTTPError as e:
        return {"status": e.code, "ms": round((time.perf_counter() - t0) * 1000), "snippet": ""}
    except (URLError, ssl.SSLError, OSError) as e:
        return {"status": None, "ms": round((time.perf_counter() - t0) * 1000), "snippet": str(e)[:80]}


def main() -> int:
    ap = argparse.ArgumentParser(description="Race-condition / idempotency probe.")
    ap.add_argument("--url", required=True)
    ap.add_argument("--method", default="GET")
    ap.add_argument("--data")
    ap.add_argument("--header", action="append", default=[], help="Header 'Name: value' (repeatable).")
    ap.add_argument("-n", "--count", type=int, default=20, help="Concurrent request count.")
    ap.add_argument("--authorized", action="store_true")
    ap.add_argument("--allow-write", action="store_true")
    args = ap.parse_args()

    if not args.authorized:
        print("[!] Re-run with --authorized (this sends concurrent requests to the target).", file=sys.stderr)
        return 2
    method = args.method.upper()
    if method in WRITE_METHODS and not args.allow_write:
        print(f"[!] {method} is state-changing; re-run with --allow-write if intended.", file=sys.stderr)
        return 2
    if urlparse(args.url).scheme not in ("http", "https"):
        ap.error("URL must be http(s).")
    if args.count < 2 or args.count > 200:
        ap.error("--count must be between 2 and 200.")

    data = args.data.encode() if args.data else None
    headers = parse_header(args.header)
    print(f"[*] Firing {args.count} concurrent {method} to {args.url} ...", file=sys.stderr)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.count) as ex:
        results = list(ex.map(lambda _: one(args.url, method, headers, data), range(args.count)))

    dist = Counter(r["status"] for r in results)
    success = sum(1 for r in results if r["status"] and 200 <= r["status"] < 300)
    findings = []
    if success > 1:
        findings.append({
            "severity": "medium", "category": "race-condition",
            "title": "Multiple concurrent successes — possible race / missing idempotency",
            "detail": f"{success}/{args.count} requests returned 2xx. If the action should "
                      f"succeed only once, this indicates a race window or unscoped idempotency key. "
                      f"Verify server-side state (balance, coupon uses, inventory)."})

    out = {"url": args.url, "method": method, "count": args.count,
           "status_distribution": dict(dist), "successes_2xx": success,
           "findings": findings, "samples": results[:10]}
    print(json.dumps(out, indent=2))
    print(f"\n[+] 2xx successes: {success}/{args.count}. Distribution: {dict(dist)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
