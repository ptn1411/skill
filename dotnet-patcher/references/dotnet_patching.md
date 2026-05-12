# .NET IL Patching — Reference

## IL Opcode Quick Reference

| Opcode | Hex | Description |
|--------|-----|-------------|
| `nop` | `00` | No operation |
| `ldc.i4.0` | `16` | Push 0 (false) |
| `ldc.i4.1` | `17` | Push 1 (true) |
| `ret` | `2A` | Return |
| `br.s` | `2B` | Short branch |
| `brfalse.s` | `2C` | Branch if false |
| `brtrue.s` | `2D` | Branch if true |
| `call` | `28` | Call method (4-byte token) |
| `callvirt` | `6F` | Virtual call (4-byte token) |
| `ldstr` | `72` | Load string (4-byte token) |
| `ceq` | `FE 01` | Compare equal |
| `pop` | `26` | Discard top of stack |
| `ldarg.0` | `02` | Load argument 0 (this) |
| `ldnull` | `14` | Push null |
| `throw` | `7A` | Throw exception |

## Method Header Formats

### Tiny Header (1 byte)
```
Bit layout: [size:6][type:2]
type = 0x02 (tiny format)
size = body size in bytes (max 63)
No local vars, no exceptions, maxstack = 8
```

### Fat Header (12 bytes)
```
Offset  Size  Field
0       2     Flags + Size (bits: [size:4][flags:12])
2       2     MaxStack
4       4     CodeSize
8       4     LocalVarSigTok
```
Flags: 0x3 = fat format, 0x8 = more sections (exception handlers), 0x10 = init locals

## Common Patch Recipes

### Force bool method to return true
```
Before: [various IL checking logic] ret
After:  nop nop nop ... ldc.i4.1 ret
```
Replace entire body with NOPs except last 2 bytes: `17 2A`

### Force bool method to return false
Same but use `16 2A` (ldc.i4.0 + ret)

### NOP a method call (remove license server check)
```
Before: ldarg.0  call <token>  brfalse.s <offset>
After:  nop      nop nop nop nop  nop nop
```
NOP the `call` opcode (1 byte) + method token (4 bytes) = 5 NOPs.
Also NOP the branch that depends on the call result.

### Patch string comparison to always succeed
```
Before: ldstr "expected_key"  ldarg.1  call String::Equals  brfalse.s <fail>
After:  ldstr "expected_key"  ldarg.1  call String::Equals  nop nop
```
Or replace `ceq` (FE 01) with `ldc.i4.1 nop`

### Remove anti-tamper module constructor
```
<Module>.cctor body -> nop nop ... ret
```

## Strong Name Removal

| Step | Location | Action |
|------|----------|--------|
| 1 | CLI Header + 32 | Read StrongNameSignature RVA |
| 2 | SN data at RVA | Zero out all bytes |
| 3 | CLI Header + 16 | Clear bit 3 (STRONGNAMESIGNED) in Flags |

After removing strong name, any `[assembly: AssemblyKeyFile]` or `InternalsVisibleTo` with public key will cause runtime errors — may need to patch those strings too.

## Metadata Token Format

```
Token: 0x0XYYYYY
  XX = table index (06 = MethodDef, 04 = FieldDef, 01 = TypeRef, etc.)
  YYYYY = row index (1-based)

Example: 0x06000042 = MethodDef table, row 66
```

## Common License Check Patterns in IL

### Pattern 1: Direct bool check
```csharp
// C#: if (!LicenseManager.IsValid()) Application.Exit();
// IL:
call bool LicenseManager::IsValid()
brfalse.s EXIT_LABEL
```
Patch: NOP the brfalse or force IsValid to return true

### Pattern 2: Trial date check
```csharp
// C#: if (DateTime.Now > expiryDate) ShowTrialExpired();
// IL:
call DateTime::get_Now()
ldloc.0  // expiryDate
call bool DateTime::op_GreaterThan(...)
brtrue.s EXPIRED_LABEL
```
Patch: NOP the brtrue

### Pattern 3: Server validation
```csharp
// C#: var response = httpClient.PostAsync(url, content).Result;
// IL:
callvirt Task<HttpResponseMessage>::get_Result()
```
Patch: Replace the HTTP call chain with ldc.i4.1 + ret, or mock at network level

## dnSpy Patch Workflow (GUI Alternative)

1. Open assembly in dnSpy
2. Navigate to license method
3. Right-click method → Edit Method Body
4. Change IL instructions
5. File → Save Module
6. Verify with `peverify` or test run
