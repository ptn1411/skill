# License Hardening Reference

The defensive playbook behind the audit. The goal is not an unbreakable client
(impossible) but making abuse **expensive, detectable, and low-value**.

## Threat model
An attacker controls the client: debugger, disassembler, patched binary, faked
files/registry, and a proxy over network calls. Assume anything shipped can be
read and modified.

## Principles
1. **Server is the source of truth.** The client requests a decision; it never
   computes the authoritative one. A patched client can flip a local boolean —
   it cannot forge a server signature it does not hold the key for.
2. **Signed, short-lived entitlements.** Issue a token (user, features, expiry,
   device) signed with Ed25519 / RSA-PSS. The client verifies the signature and
   honors expiry. Short lifetimes limit replay.
3. **Keep signing keys off the client.** Only the public key ships (if any local
   verify happens at all). Private keys stay server-side and rotate on leak.
4. **Fail closed.** Any error — parse failure, network error, clock skew beyond
   grace — denies access. Never `catch { return true; }`.
5. **Bind trial/activation server-side** to an account/device. Treat local state
   as a cache; the server enforces the real count/expiry.
6. **Tamper-evidence + telemetry.** Report verification failures, integrity
   mismatches, and impossible states. Detection beats a silent local check.

## Anti-patterns the audit flags
- `bool IsLicensed()` consumed by a single `if` → one-instruction bypass target.
- Hardcoded secret / signing key in the client → attacker mints valid licenses.
- `serial == "CONSTANT"` → accept condition is trivially discoverable.
- MD5/SHA-1 for integrity → collisions.
- Trial state only in registry/file → reset to extend.
- No network/server call anywhere in the license path → whole decision is local.

## Offline grace (if you must)
If the product needs offline use, allow a bounded offline window backed by the
last signed entitlement's expiry, and reconcile on reconnect. Document the policy
so "server unreachable" has a defined, fail-safe behavior.

## Verify with tests
Wire `test_license_behavior.py`'s `evaluate_license()` to your real check and keep
it green: valid→allow; expired/tampered/missing→deny. This locks the legitimate
behavior as a regression guard after hardening.
