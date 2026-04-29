# Electron Builder Repack Guidance

Use this reference when turning authorized Electron changes back into a local QA artifact or a production installer.

## Choose The Right Repack Mode

| Goal | Preferred path |
|---|---|
| Quick local QA of extracted app content | `repack_electron_builder.py` to stage `resources/app.asar` |
| Full production installer | Original source repo + `electron-builder` |
| Native module present | Stage `app.asar.unpacked` beside `app.asar` |
| Signed release | Use legitimate signing certs and CI config |

## Local ASAR Stage

```bash
python electron-builder-repacker/scripts/repack_electron_builder.py extracted/app_asar --out electron-repacked
```

With native resources:

```bash
python electron-builder-repacker/scripts/repack_electron_builder.py extracted/app_asar \
  --unpacked-dir extracted/resources/app.asar.unpacked \
  --out electron-repacked
```

## Production Build From Source

Use the app owner’s source project:

```bash
npm install
npm run build
npx electron-builder --dir
npx electron-builder --win
```

Do not reuse third-party signing identities, redirect update metadata, bypass integrity checks, or distribute modified third-party apps.

## Validation

After repacking:

- Confirm `resources/app.asar` exists.
- Run `electron-builder-unpacker` on the new ASAR to verify it can be extracted.
- Run `electron-app-analyzer` on the repacked content.
- Compare `repack_manifest.json` with expected changed files.
