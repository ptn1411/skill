# Common API & License Server Patterns — Reference

## OAuth2 Flows

| Flow | Endpoints | Indicators |
|------|-----------|-----------|
| Authorization Code | `/authorize` → `/callback` → `/token` | `code=`, `redirect_uri=`, `grant_type=authorization_code` |
| Client Credentials | `/token` | `grant_type=client_credentials`, `client_id`, `client_secret` |
| Device Code | `/device/code` → `/token` | `device_code=`, polling pattern |
| PKCE | Same as Auth Code + `code_verifier` | `code_challenge=`, `code_challenge_method=S256` |

## License Server Patterns

| Pattern | Request | Response |
|---------|---------|----------|
| Online activation | POST `/activate` with `{hwid, serial_key}` | `{status, expiry, features}` |
| Heartbeat | GET/POST `/verify` with `{license_id, hwid}` | `{valid: true, remaining_days}` |
| Feature flags | GET `/features?license=X` | `{features: ["pro", "export"]}` |
| Offline activation | POST `/offline-activate` with `{request_code}` | `{response_code}` (base64) |

## Common Header Patterns

| Header | Purpose |
|--------|---------|
| `Authorization: Bearer <JWT>` | API authentication |
| `X-API-Key: <key>` | Simple API key auth |
| `X-License-Key: <key>` | License key in header |
| `X-HWID: <hash>` | Hardware fingerprint |
| `X-App-Version: <ver>` | Client version reporting |

## HWID Collection Methods

| Method | Platform | Data |
|--------|----------|------|
| `MachineGuid` | Windows Registry | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` |
| MAC Address | Cross-platform | Network interface MAC |
| Disk Serial | Windows | `wmic diskdrive get serialnumber` |
| CPU ID | Cross-platform | CPUID instruction result |
| Motherboard Serial | Windows | `wmic baseboard get serialnumber` |
