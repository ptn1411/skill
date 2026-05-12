# .NET License Systems — Reference

## Common License Libraries

| Library | Detection | Key Format | Validation | Keygen Difficulty |
|---------|-----------|-----------|------------|-------------------|
| **Cryptlex** | `LexActivator`, `Cryptlex` namespace | UUID + server | Online API + local cache | Hard (server-side) |
| **LimeLM / TurboActivate** | `TurboActivate`, `LimeLM` | Custom format | Online + offline | Hard (server-side) |
| **Infralution** | `Infralution.Licensing` | Base64 blob | RSA signature | Medium (need privkey) |
| **Standard.Licensing** | `Standard.Licensing` | XML + RSA sig | RSA-2048 default | Medium (need privkey) |
| **SoftwareKey** | `SoftwareKey`, `InstantLicense` | Numeric serial | Server + local | Medium |
| **Custom (checksum)** | Manual validation code | XXXXX-XXXXX-... | Checksum/hash | Easy |
| **Custom (HWID)** | WMI/Registry queries + hash | Hash-based | HMAC/SHA | Easy-Medium |
| **Custom (RSA)** | `RSACryptoServiceProvider` | Base64 signed blob | RSA verify | Depends on key size |

## Keygen Strategy Decision Tree

```
1. Is there online validation?
   YES → Need server emulation or patch out network call
   NO  → Continue

2. Is RSA used?
   YES → Check key size
         <= 512 bits → Factor modulus (factordb.com, msieve, yafu)
         512-1024 bits → Try factoring, may take hours/days
         >= 2048 bits → Need private key leak or patch
   NO  → Continue

3. Is AES/HMAC used with hardcoded key?
   YES → Extract key from source → generate valid licenses
   NO  → Continue

4. Is it a simple serial with checksum?
   YES → Reverse checksum algorithm → serial-checksum template
   NO  → Continue

5. Is HWID binding used?
   YES → Extract HWID generation algo + shared secret → hwid-hash template
   NO  → Simpler approach possible
```

## RSA Key Analysis

### Extracting RSA Parameters from C#

```csharp
// Common patterns in decompiled code:

// Pattern 1: XML string
rsa.FromXmlString("<RSAKeyValue><Modulus>BASE64...</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>");

// Pattern 2: CSP blob
byte[] keyBlob = Convert.FromBase64String("...");
rsa.ImportCspBlob(keyBlob);

// Pattern 3: Parameters struct
RSAParameters p = new RSAParameters();
p.Modulus = Convert.FromBase64String("...");
p.Exponent = Convert.FromBase64String("AQAB"); // 65537
```

### Factoring Weak RSA Keys

```bash
# Check key size (modulus bit length)
python -c "import base64; m=base64.b64decode('BASE64_MODULUS'); print(f'{len(m)*8} bits')"

# Try factoring with msieve
msieve -v -e 0xMODULUS_HEX

# Or use factordb.com API
curl "http://factordb.com/api?query=MODULUS_DECIMAL"

# Reconstruct private key from factors p, q
python -c "
from Crypto.PublicKey import RSA
import gmpy2
n = p * q
e = 65537
phi = (p-1) * (q-1)
d = int(gmpy2.invert(e, phi))
key = RSA.construct((n, e, d, p, q))
print(key.export_key().decode())
"
```

## HWID Generation Methods

| Method | C# Code | Hash Input |
|--------|---------|-----------|
| Registry GUID | `Registry.GetValue(@"HKLM\SOFTWARE\Microsoft\Cryptography", "MachineGuid")` | MachineGuid string |
| WMI CPU | `ManagementObjectSearcher("SELECT * FROM Win32_Processor")` | ProcessorId |
| WMI Disk | `ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive")` | SerialNumber |
| WMI Board | `ManagementObjectSearcher("SELECT * FROM Win32_BaseBoard")` | SerialNumber |
| MAC Address | `NetworkInterface.GetAllNetworkInterfaces()[0].GetPhysicalAddress()` | MAC bytes |
| Combined | Multiple sources concatenated | hash(CPU + DISK + MAC + ...) |

## Serial Format Patterns

| Format | Example | Typical Validation |
|--------|---------|-------------------|
| 5x5 alphanumeric | `A1B2C-D3E4F-G5H6I-J7K8L-M9N0P` | Last char = checksum |
| 4x4 alphanumeric | `ABCD-EFGH-IJKL-MNOP` | Mod97 check |
| Numeric only | `1234-5678-9012-3456` | Luhn algorithm |
| Base64 blob | `eyJuYW1lIjoi...` | JSON + signature |
| UUID | `550e8400-e29b-41d4-a716-446655440000` | Server lookup |
| Hex string | `A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4` | HMAC verify |

## Common Checksum Algorithms

| Algorithm | Formula | Used By |
|-----------|---------|---------|
| **Luhn** | Double every 2nd digit from right, sum, mod 10 = 0 | Credit cards, some serials |
| **Mod97** | Convert chars to numbers, compute mod 97 | IBAN, some license keys |
| **XOR fold** | XOR all bytes, result = check byte | Simple custom schemes |
| **CRC32** | Standard CRC-32 of key body | Custom schemes |
| **Custom positional** | Sum of (char_value * position) mod N | Many custom implementations |
