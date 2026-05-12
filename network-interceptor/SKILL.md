---
name: network-interceptor
description: "Capture, analyze, and replay network traffic between app and license/API servers. Uses mitmproxy for capture and built-in analysis for endpoint discovery, OAuth detection, and token extraction."
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

# Network Interceptor

> Capture and analyze app-server communication to discover license protocols, API endpoints, and authentication flows.

> **Language rule**: All skill instructions use English.
> **Final summary presented to the user must be in Vietnamese.**

---

## 0. Authorization & Routing

Operates under [MASTER_POLICY.md](../MASTER_POLICY.md) §1-§2.

| Sibling skill | When |
|---|---|
| [electron-app-analyzer](../electron-app-analyzer/SKILL.md) | JS endpoint analysis from source |
| [writerpro-pentest](../writerpro-pentest/SKILL.md) | Keygen from discovered API patterns |
| [frida-hooker](../frida-hooker/SKILL.md) | Bypass SSL pinning before capture |
| [memory-dumper](../memory-dumper/SKILL.md) | Extract tokens from process memory |

---

## Step 1 — Capture Traffic

```bash
python scripts/capture_traffic.py --port 8080 --duration 120 --out captured.har
```

```powershell
python scripts\capture_traffic.py --port 8080 --duration 120 --out captured.har
```

Requires: `pip install mitmproxy`

---

## Step 2 — Analyze Traffic

```bash
python scripts/analyze_traffic.py captured.har --out analysis/
```

Detects: API endpoints, OAuth flows, Bearer tokens, license validation calls, HWID submissions.

---

## Step 3 — Replay

```bash
python scripts/analyze_traffic.py captured.har --replay 5 --out replay_script.py
```

Generates standalone Python `requests` script to replay any captured request.

---

## Final Report (Vietnamese)

```
🌐 Phân tích network hoàn tất:

  📡 Requests captured : <COUNT>
  🔗 API endpoints     : <COUNT> unique
  🔑 Tokens found      : <COUNT>
  🔐 OAuth flow        : <DETECTED/NONE>
  📋 License calls     : <COUNT>

  💾 Output: analysis/
```

---

## Anti-Patterns

| ❌ Don't | ✅ Do |
|----------|-------|
| Capture without SSL intercept cert | Install mitmproxy CA cert first |
| Ignore non-HTTP protocols | Some license servers use raw TCP/gRPC |
| Miss OAuth flows | Look for /authorize, /token, /callback patterns |
| Skip response bodies | License responses contain feature flags and expiry |
