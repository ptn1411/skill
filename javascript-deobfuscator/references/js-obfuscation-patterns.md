# JavaScript Obfuscation Patterns

Use this reference after `analyze_js.py` flags obfuscation indicators.

## Static Patterns

| Pattern | Signals | Safe action |
|---|---|---|
| Base64 / base64url | Long strings with `A-Za-z0-9+/=_-`, `atob(...)` | Decode offline, redact secrets |
| URL / Unicode escapes | `%2f`, `\x2f`, `\u002f` | Normalize before endpoint extraction |
| String array | `_0xabc = ["..."]` plus index lookups | Extract array strings; resolve simple index references |
| Eval packer | `eval(function(p,a,c,k,e,d)` | Capture final payload offline; do not execute network calls |
| Control-flow flattening | `while(!![])`, large `switch` dispatcher | Prioritize strings/endpoints before manual cleanup |
| Webpack / Vite chunks | `__webpack_require__`, `webpackChunk`, `/@vite/client` | Analyze all chunks and sourcemaps in scope |
| WebAssembly loader | `WebAssembly.instantiate` | Record WASM source and move to WASM/binary analysis |

## Runtime Trace Targets

Hook or stub these APIs when static analysis is insufficient:

- `eval`, `Function`
- `atob`, `btoa`, `decodeURIComponent`
- `fetch`, `XMLHttpRequest`
- `localStorage`, `sessionStorage`, `document.cookie`
- `crypto.subtle.decrypt`, `crypto.subtle.importKey`
- `WebAssembly.instantiate`

`runtime_trace.js` stubs network calls and logs arguments. Treat Node `vm` as a triage harness, not a hard security sandbox.

## Findings To Report

Report these as remediation-oriented findings:

- Exposed sourcemap with source content.
- Hardcoded client-side API key, token, license secret, key, or IV.
- Client-side crypto where the decrypt key ships to every user.
- Runtime unpacking that hides risky code paths from review.
- Sensitive endpoints discoverable from public chunks.
- WebAssembly modules loaded from public URLs without integrity checks.

Do not print live reusable secrets in the final user response. Use `<redacted>` and identify the file, variable name, and exposure class instead.
