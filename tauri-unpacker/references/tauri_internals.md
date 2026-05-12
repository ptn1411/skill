# Tauri App Internals

## Architecture

```
┌────────────────────────────────────────┐
│            Tauri Application           │
├──────────────────┬─────────────────────┤
│  Rust Backend    │  Web Frontend       │
│  (native code)   │  (HTML/JS/CSS)      │
│                  │                     │
│  Commands        │  UI / Logic         │
│  File I/O        │  invoke() → IPC     │
│  Network         │  listen() → events  │
│  System APIs     │                     │
├──────────────────┴─────────────────────┤
│  WRY (WebView wrapper)                 │
│  TAO (Window management)              │
├────────────────────────────────────────┤
│  OS WebView (WebView2/WebKit/GTK)     │
└────────────────────────────────────────┘
```

## Asset Embedding

### Tauri v1
- Build step: `tauri build` → `tauri-codegen` → `include_bytes!`
- Assets compiled into binary as static byte arrays
- Keyed by relative path (e.g., `"index.html"`, `"assets/main.js"`)
- May be brotli-compressed (default for production builds)
- PHF (Perfect Hash Function) map for O(1) lookup

### Tauri v2
- Similar embedding but with plugin architecture
- Assets in `_up_` directory or embedded via codegen
- New permission system for API access

## Config: tauri.conf.json

Embedded in binary. Key security fields:

```json
{
  "tauri": {
    "security": {
      "csp": "default-src 'self'; script-src 'self'",
      "dangerousDisableAssetCspModification": false
    },
    "allowlist": {
      "all": false,
      "shell": { "all": false, "execute": false },
      "fs": { "all": false, "readFile": true, "scope": ["$APPDATA/*"] },
      "http": { "all": false, "request": true, "scope": ["https://api.example.com/*"] }
    }
  }
}
```

### Dangerous permissions
- `shell.execute` → arbitrary command execution
- `fs.all` → full filesystem access
- `http.all` → unrestricted network access
- No CSP or `unsafe-eval` → XSS → full compromise

## IPC Protocol

### Frontend → Backend (invoke)
```javascript
// Tauri v1
window.__TAURI__.invoke('command_name', { arg1: 'value' })

// Tauri v2
import { invoke } from '@tauri-apps/api/core';
await invoke('command_name', { arg1: 'value' });
```

### Backend → Frontend (events)
```javascript
import { listen } from '@tauri-apps/api/event';
await listen('event-name', (event) => {
    console.log(event.payload);
});
```

### Command registration (Rust side)
```rust
#[tauri::command]
fn check_license(key: String) -> Result<bool, String> {
    // validation logic
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![check_license])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

## Extraction Strategies

### Strategy 1: Raw binary scan
- Search for HTML/JS/CSS signatures in binary data
- Works when assets are not compressed
- May have null bytes between content blocks

### Strategy 2: Brotli decompression
- Tauri uses brotli compression by default in production
- Find asset name strings, then scan nearby data for brotli blobs
- `pip install brotli` for decompression

### Strategy 3: Runtime memory dump
- Start the app → assets are decompressed into memory
- Use `memory-dumper` to capture the WebView process
- Extract web content from the dump

### Strategy 4: WebView DevTools
- Set `WEBKIT_INSPECTOR_SERVER` (Linux) or debug flags
- Attach Chrome DevTools to the WebView
- View/modify frontend in real-time

### Strategy 5: Frida instrumentation
- Hook `wry::webview::WebView::new` or asset loading functions
- Intercept decompressed assets before rendering
- Modify assets on-the-fly (e.g., bypass license UI)

## Common License Patterns in Tauri Apps

### Frontend (JS)
```javascript
// License input form
async function activateLicense(key) {
    const result = await invoke('validate_license', { key });
    if (result.valid) {
        localStorage.setItem('license_key', key);
        showMainApp();
    } else {
        showError(result.message);
    }
}
```

### Backend (Rust)
```rust
#[tauri::command]
fn validate_license(key: String) -> Result<LicenseResult, String> {
    // Verify format, checksum, HWID, expiry
}
```

### Bypass approaches
1. Patch the Rust `validate_license` to always return Ok(valid)
2. Hook via Frida: replace return value
3. Modify extracted JS: skip validation, call showMainApp() directly
4. Patch localStorage check in JS
