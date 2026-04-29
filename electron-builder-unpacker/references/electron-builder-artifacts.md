# Electron Builder Artifacts

Use this reference when preparing an Electron Builder app for offline analysis.

## Common Layouts

| Artifact | Meaning |
|---|---|
| `resources/app.asar` | Main packaged app source and assets |
| `resources/app.asar.unpacked/` | Native modules or files excluded from ASAR |
| `resources/app/` | App content when ASAR packaging is disabled |
| `app-update.yml` | Runtime auto-update configuration |
| `latest.yml` | Release update metadata |
| `*.blockmap` | Differential update block map |
| `package.json` | App metadata, main entry, scripts, dependencies |

## Safe Workflow

1. Work on a copy of the installed app or extracted installer.
2. Extract ASAR to a new output directory.
3. Preserve `app.asar.unpacked` next to extracted source for path references.
4. Run `electron-app-analyzer` on extracted source.
5. Run `javascript-deobfuscator` on renderer bundles or preload scripts.

## Review Priorities After Unpacking

- `package.json` `main` entry.
- `main.js`, `background.js`, `preload.js`, `renderer/`, `dist/`.
- `BrowserWindow` creation sites.
- `contextBridge` and `ipcRenderer` exposures.
- Update URLs and signing assumptions.
- Native modules in `app.asar.unpacked`.

Do not modify or repackage third-party apps. Use unpacked files for offline review and remediation reporting only.
