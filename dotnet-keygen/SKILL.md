---
name: dotnet-keygen
description: "Extract license validation algorithms from decompiled .NET source and generate keygens. Supports common license libraries (Cryptlex, LimeLM, custom), serial format detection, and crypto parameter extraction (RSA/AES/HMAC)."
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

# .NET Keygen

> Extract the license validation algorithm from decompiled .NET code and generate a standalone keygen script.

> **Language rule**: All skill instructions use English.
> **Final summary presented to the user must be in Vietnamese.**

---

## 0. Authorization & Routing

Operates under [MASTER_POLICY.md](../MASTER_POLICY.md) §1-§2.

| Sibling skill | When |
|---|---|
| [dotnet-decompiler](../dotnet-decompiler/SKILL.md) | Decompile assembly first to get C# source |
| [dotnet-patcher](../dotnet-patcher/SKILL.md) | Patch binary instead of keygen (simpler but less elegant) |
| [writerpro-pentest](../writerpro-pentest/SKILL.md) | Generic keygen template for non-.NET apps |
| [network-interceptor](../network-interceptor/SKILL.md) | Capture license server protocol for online validation |

---

## Step 1 — Extract License Algorithm

```bash
python scripts/extract_license_algo.py decompiled/ --out license_info.json
```

```powershell
python scripts\extract_license_algo.py decompiled\ --out license_info.json
```

Detects:
- **Serial format**: `XXXXX-XXXXX-XXXXX` patterns, length, charset, checksum algorithm
- **Crypto parameters**: RSA public keys (modulus/exponent), AES keys/IVs, HMAC secrets
- **Validation logic**: Check digit algorithms, hash comparisons, date encoding
- **License libraries**: Cryptlex, LimeLM, Infralution, SoftwareKey, custom implementations
- **HWID binding**: Machine ID generation algorithm, what hardware data is collected
- **Feature flags**: How license tiers map to features (Pro, Enterprise, etc.)

---

## Step 2 — Generate Keygen

### From extracted info

```bash
python scripts/generate_keygen.py license_info.json --out keygen.py
```

### From template (common patterns)

```bash
python scripts/generate_keygen.py --template serial-checksum --format "XXXXX-XXXXX-XXXXX-XXXXX" --out keygen.py
python scripts/generate_keygen.py --template rsa-signed --pubkey extracted_key.pem --out keygen.py
python scripts/generate_keygen.py --template hwid-hash --algo sha256 --secret "extracted_secret" --out keygen.py
```

### Test generated keygen

```bash
python keygen.py --count 5
python keygen.py --hwid "YOUR_MACHINE_GUID"
python keygen.py --features pro --expiry 2030-12-31
```

---

## Available Templates

| Template | File | Use Case |
|----------|------|----------|
| `serial_checksum` | `templates/serial_checksum.py` | Simple serial with check digit (Luhn, mod97, custom) |
| `rsa_signed` | `templates/rsa_signed.py` | RSA-signed license (need private key or weak key) |
| `hwid_hash` | `templates/hwid_hash.py` | HWID-bound license with shared secret |
| `time_based` | `templates/time_based.py` | Time-limited trial with date encoding |
| `feature_flags` | `templates/feature_flags.py` | License with encoded feature bitmask |

---

## Final Report (Vietnamese)

```
🔑 Keygen generation hoàn tất:

  📋 License type     : <TYPE>
  🔐 Crypto           : <RSA/AES/HMAC/None>
  📐 Serial format    : <FORMAT>
  🖥️ HWID binding     : <YES/NO>
  ⏰ Time-limited     : <YES/NO>
  🎯 Feature flags    : <COUNT> tiers

  💾 Keygen: keygen.py
  📊 Info: license_info.json
```

---

## Anti-Patterns

| ❌ Don't | ✅ Do |
|----------|-------|
| Assume simple serial without analyzing | Always extract the full validation algorithm |
| Ignore RSA key size | Keys < 512 bits can be factored; larger need private key leak |
| Skip HWID analysis | Keygen must generate HWID-bound keys if app requires it |
| Generate keys without testing | Always validate generated keys against extracted algorithm |
| Ignore online validation | Some apps check key locally AND online — need both |
| Miss obfuscated string constants | Use dotnet-decompiler with de4dot first |
