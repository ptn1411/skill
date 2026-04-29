#!/usr/bin/env python3
"""
Repack authorized Electron app assets into ASAR/resources layout.

This script is for offline QA/remediation validation on owned or authorized apps.
It does not sign installers, bypass signatures, or modify update channels.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
from pathlib import Path
from typing import Any


IGNORE_NAMES = {".git", "node_modules/.cache", "__pycache__"}


def rel(path: Path, root: Path) -> str:
    return str(path.relative_to(root)).replace("\\", "/")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def make_pickle_string(text: str) -> bytes:
    raw = text.encode("utf-8")
    payload = struct.pack("<I", len(raw)) + raw
    payload += b"\x00" * ((4 - (len(payload) % 4)) % 4)
    return struct.pack("<I", len(payload)) + payload


def should_skip(path: Path, source: Path) -> bool:
    parts = set(path.relative_to(source).parts)
    return bool(parts & IGNORE_NAMES)


def build_tree(files: list[tuple[str, bytes]]) -> dict[str, Any]:
    offset = 0
    root: dict[str, Any] = {"files": {}}
    for relative, content in files:
        parts = relative.split("/")
        cursor = root["files"]
        for part in parts[:-1]:
            cursor = cursor.setdefault(part, {"files": {}})["files"]
        cursor[parts[-1]] = {"size": len(content), "offset": str(offset)}
        offset += len(content)
    return root


def collect_files(source: Path) -> list[Path]:
    files = []
    for path in source.rglob("*"):
        if not path.is_file() or should_skip(path, source):
            continue
        files.append(path)
    return sorted(files, key=lambda p: rel(p, source))


def pack_asar(source_dir: Path | str, out_asar: Path | str) -> dict[str, Any]:
    source = Path(source_dir)
    out = Path(out_asar)
    if not source.is_dir():
        raise NotADirectoryError(source)

    file_paths = collect_files(source)
    files = [(rel(path, source), path.read_bytes()) for path in file_paths]
    header = json.dumps(build_tree(files), separators=(",", ":"))
    header_pickle = make_pickle_string(header)
    size_pickle = struct.pack("<II", 4, len(header_pickle))
    data = b"".join(content for _, content in files)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(size_pickle + header_pickle + data)

    return {
        "source": str(source),
        "asar": str(out),
        "files": len(files),
        "bytes": out.stat().st_size,
        "sha256": sha256_file(out),
        "entries": [relative for relative, _ in files],
    }


def copy_unpacked(unpacked_dir: Path, target: Path) -> dict[str, Any]:
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(unpacked_dir, target)
    files = [path for path in target.rglob("*") if path.is_file()]
    return {"source": str(unpacked_dir), "target": str(target), "files": len(files)}


def repack_path(source_dir: Path | str, out_dir: Path | str, unpacked_dir: Path | str | None = None) -> dict[str, Any]:
    source = Path(source_dir)
    out = Path(out_dir)
    resources = out / "resources"
    resources.mkdir(parents=True, exist_ok=True)
    asar_path = resources / "app.asar"

    pack_result = pack_asar(source, asar_path)
    result: dict[str, Any] = {
        "mode": "asar-stage",
        "source": str(source),
        "output": str(out),
        "resources": str(resources),
        "asar": pack_result,
        "unpacked": None,
    }

    if unpacked_dir:
        unpacked = Path(unpacked_dir)
        if not unpacked.is_dir():
            raise NotADirectoryError(unpacked)
        result["unpacked"] = copy_unpacked(unpacked, resources / "app.asar.unpacked")

    write_outputs(result, out)
    return result


def write_outputs(result: dict[str, Any], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "repack_manifest.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [
        "# Electron Builder Repack Report",
        "",
        f"Source: `{result['source']}`",
        f"Output: `{result['output']}`",
        f"ASAR: `{result['asar']['asar']}`",
        f"Files packed: {result['asar']['files']}",
        f"SHA256: `{result['asar']['sha256']}`",
        "",
        "## Unpacked Resources",
    ]
    if result.get("unpacked"):
        lines.append(f"- Copied `{result['unpacked']['source']}` to `{result['unpacked']['target']}`")
    else:
        lines.append("- none")
    lines.extend(
        [
            "",
            "## Next Steps",
            "- Use this staged resources directory for local/offline QA only.",
            "- For production installers, rebuild from the original source with electron-builder and proper signing.",
        ]
    )
    (out_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Repack authorized Electron app source/extracted ASAR into resources/app.asar")
    parser.add_argument("source", help="Extracted app directory, usually app_asar/")
    parser.add_argument("--unpacked-dir", help="Optional app.asar.unpacked directory to stage beside app.asar")
    parser.add_argument("--out", default="electron-repacked", help="Output directory")
    parser.add_argument("--json", action="store_true", help="Print manifest JSON to stdout")
    args = parser.parse_args()

    result = repack_path(Path(args.source), Path(args.out), Path(args.unpacked_dir) if args.unpacked_dir else None)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"[+] Packed files: {result['asar']['files']}")
        print(f"[+] ASAR: {result['asar']['asar']}")
        print(f"[+] SHA256: {result['asar']['sha256']}")
        print(f"[+] Manifest: {Path(args.out) / 'repack_manifest.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
