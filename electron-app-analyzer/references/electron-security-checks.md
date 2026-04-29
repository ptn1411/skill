# Electron Security Checks

Use this reference after `analyze_electron.py` finds Electron artifacts or risky settings.

## High-Value Checks

| Area | Risk signal | Safer direction |
|---|---|---|
| Renderer privileges | `nodeIntegration: true` | Keep Node disabled in renderer |
| Isolation | `contextIsolation: false` | Enable context isolation |
| Remote module | `enableRemoteModule: true`, `electron.remote` | Remove remote module usage |
| Sandbox | `sandbox: false` | Enable sandbox where practical |
| Web security | `webSecurity: false`, `allowRunningInsecureContent: true` | Keep browser protections enabled |
| IPC bridge | Broad `ipcRenderer` exposed to `window` | Expose narrow, validated methods only |
| External links | `shell.openExternal(url)` | Validate protocol and allowlist hosts |
| Updates | `app-update.yml`, update URL | Verify signature, TLS, channel control |
| ASAR | `app.asar` | Extract copy for review; do not modify original |

## IPC Review

Prefer this shape in preload code:

```javascript
contextBridge.exposeInMainWorld("appApi", {
  getVersion: () => ipcRenderer.invoke("app:getVersion")
});
```

Avoid exposing raw `ipcRenderer`, arbitrary channel names, or generic `send(channel, ...args)` wrappers.

## Report Wording

Report exact files and setting names, but redact reusable tokens, API keys, cookies, passwords, and license values. Frame findings as remediation tasks: constrain IPC, disable renderer Node access, enable isolation, validate external URLs, and verify update signing.
