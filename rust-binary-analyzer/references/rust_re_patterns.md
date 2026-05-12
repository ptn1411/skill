# Rust Reverse Engineering Patterns

## Symbol Mangling

### Legacy (v0) — `_ZN...E`
```
_ZN5myapp6config12load_settingsE
→ myapp::config::load_settings

_ZN3std2io5write17h1234567890abcdefE
→ std::io::write  (hash suffix stripped)
```

### Rust v0 — `_R...`
More complex encoding. Use `rustfilt` for reliable demangling:
```
pip install rustfilt
echo "_RNvMs_..." | rustfilt
```

## Panic Strings — Source Path Goldmine

Rust panic messages include the full source path:
```
panicked at 'assertion failed: key.is_valid()', src/license/validator.rs:42:5
thread 'main' panicked at 'called `Result::unwrap()` on an `Err` value', src/crypto/aes.rs:118:22
```

### What panic paths reveal
- Full module hierarchy (src/module/submodule/file.rs)
- Line numbers of assertions and unwrap() calls
- Error handling locations (often near security-critical code)
- Crate paths (registry/src/github.com-xxx/cratename-version/src/...)

## Framework Signatures

| Framework | Key strings | Purpose |
|-----------|------------|---------|
| Tauri | `tauri::app`, `__TAURI__`, `wry::webview` | Desktop + webview |
| Actix Web | `actix_web`, `actix::actor` | Web server |
| Axum | `axum::Router`, `axum::extract` | Web server |
| Rocket | `rocket::Rocket`, `#[get(` | Web server |
| Tokio | `tokio::runtime`, `tokio::spawn` | Async runtime |
| Reqwest | `reqwest::Client` | HTTP client |
| Serde | `serde::Deserialize` | Serialization |
| Diesel | `diesel::query_builder` | ORM |
| SQLx | `sqlx::query`, `sqlx::Pool` | Database |

## License Check Patterns in Rust

### Common function names
```
check_license, validate_key, is_licensed, is_registered
is_activated, verify_serial, check_trial, is_expired
```

### Common string indicators
```
"Invalid license key"
"Trial expired"
"Enter your license key"
"Activation failed"
"Licensed to:"
"days remaining"
```

### Typical Rust license check flow
```rust
fn check_license(key: &str) -> Result<LicenseInfo, LicenseError> {
    // 1. Parse key format
    // 2. Verify checksum / signature
    // 3. Check HWID binding
    // 4. Check expiry
    // 5. Return Ok(info) or Err(error)
}
```

In the binary, look for:
- String "Invalid" near a branch instruction
- Comparison of return values (bool or Result)
- Calls to crypto functions (sha256, hmac) near license strings

## Tauri-Specific Patterns

### IPC flow
```
Frontend JS                    Rust Backend
──────────                    ────────────
invoke('check_license', {     #[tauri::command]
  key: "XXXX-XXXX"           fn check_license(key: &str) -> bool
})                             → validates key
  ↕ IPC bridge (wry)
```

### Finding Tauri commands
1. In JS: search for `invoke('command_name'`
2. In binary: search for `tauri::command` or the command name string
3. Commands are registered in `tauri::Builder::default().invoke_handler()`

## Binary Patching Notes

### Patching a license check in Rust binary
1. Find the function (via symbols or IDA/Ghidra)
2. Locate the conditional branch (JE/JNE after comparison)
3. Patch: NOP the branch or force JMP to success path

### Beware
- Rust inlines aggressively — the license check may be duplicated
- `#[inline(always)]` means multiple patch points
- LTO (Link-Time Optimization) further complicates function boundaries
- Use `frida-hooker` for dynamic bypass when static patching is complex
