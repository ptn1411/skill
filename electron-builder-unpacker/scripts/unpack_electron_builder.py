#!/usr/bin/env python3
"""
Unpack Electron Builder artifacts for offline analysis.

Supports locating and extracting app.asar, copying app.asar.unpacked and
resources/app directories, and writing a manifest for downstream analyzers.
"""

from __future__ import annotations

import argparse
import json
import shutil
import struct
from pathlib import Path
from typing import Any


UPDATE_NAMES = {"app-update.yml", "latest.yml", "dev-app-update.yml"}
MAX_HEADER_SIZE = 100_000_000


class AsarError(Exception):
    pass


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def safe_output_path(base: Path, relative: str) -> Path:
    target = (base / relative).resolve()
    base_resolved = base.resolve()
    if not str(target).startswith(str(base_resolved)):
        raise AsarError(f"unsafe path in ASAR: {relative}")
    return target


def parse_asar_header(data: bytes) -> tuple[dict[str, Any], int]:
    if len(data) < 16:
        raise AsarError("file too small for ASAR header")

    # ASAR uses a Chromium pickle containing the header pickle length:
    # uint32 payload_size (=4), uint32 header_pickle_size, then header pickle.
    header_pickle_size = struct.unpack_from("<I", data, 4)[0]
    if header_pickle_size <= 0 or header_pickle_size > MAX_HEADER_SIZE:
        raise AsarError("invalid ASAR header pickle size")

    header_start = 8
    header_end = header_start + header_pickle_size
    if header_end > len(data):
        raise AsarError("ASAR header extends past file end")

    header_pickle = data[header_start:header_end]
    if len(header_pickle) < 8:
        raise AsarError("invalid ASAR header pickle")

    payload_size = struct.unpack_from("<I", header_pickle, 0)[0]
    if payload_size + 4 > len(header_pickle):
        raise AsarError("invalid ASAR header payload size")

    json_size = struct.unpack_from("<I", header_pickle, 4)[0]
    json_start = 8
    json_end = json_start + json_size
    if json_end > len(header_pickle):
        raise AsarError("invalid ASAR JSON size")

    raw_json = header_pickle[json_start:json_end].rstrip(b"\x00")
    try:
        header = json.loads(raw_json.decode("utf-8"))
    except Exception as exc:
        raise AsarError(f"failed to parse ASAR header JSON: {exc}") from exc

    return header, header_end


def iter_asar_files(node: dict[str, Any], prefix: str = ""):
    files = node.get("files", {})
    for name, meta in files.items():
        relative = f"{prefix}/{name}" if prefix else name
        if "files" in meta:
            yield from iter_asar_files(meta, relative)
        else:
            yield relative, meta


def extract_asar(asar_path: Path, out_dir: Path) -> dict[str, Any]:
    data = asar_path.read_bytes()
    header, data_start = parse_asar_header(data)
    extracted = []
    skipped = []

    out_dir.mkdir(parents=True, exist_ok=True)
    for relative, meta in iter_asar_files(header):
        if meta.get("unpacked"):
            skipped.append({"path": relative, "reason": "unpacked"})
            continue
        if "offset" not in meta or "size" not in meta:
            skipped.append({"path": relative, "reason": "missing offset/size"})
            continue
        offset = data_start + int(meta["offset"])
        size = int(meta["size"])
        if offset < data_start or offset + size > len(data):
            skipped.append({"path": relative, "reason": "range outside archive"})
            continue
        target = safe_output_path(out_dir, relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data[offset : offset + size])
        extracted.append(relative)

    return {"archive": str(asar_path), "output": str(out_dir), "files": extracted, "skipped": skipped}


def copy_tree(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)


def find_artifacts(root: Path) -> dict[str, list[Path]]:
    search_root = root if root.is_dir() else root.parent
    artifacts = {
        "asar_archives": [],
        "unpacked_dirs": [],
        "app_dirs": [],
        "update_configs": [],
        "blockmaps": [],
        "package_json": [],
    }
    if root.is_file() and root.suffix.lower() == ".asar":
        artifacts["asar_archives"].append(root)

    for path in search_root.rglob("*"):
        if path.is_file() and path.name == "app.asar":
            artifacts["asar_archives"].append(path)
        elif path.is_dir() and path.name == "app.asar.unpacked":
            artifacts["unpacked_dirs"].append(path)
        elif path.is_dir() and path.name == "app" and path.parent.name == "resources":
            artifacts["app_dirs"].append(path)
        elif path.is_file() and path.name in UPDATE_NAMES:
            artifacts["update_configs"].append(path)
        elif path.is_file() and path.suffix.lower() == ".blockmap":
            artifacts["blockmaps"].append(path)
        elif path.is_file() and path.name == "package.json":
            artifacts["package_json"].append(path)
    return {key: sorted(set(value)) for key, value in artifacts.items()}


def unpack_path(input_path: Path | str, out_dir: Path | str) -> dict[str, Any]:
    root = Path(input_path)
    output = Path(out_dir)
    if not root.exists():
        raise FileNotFoundError(root)

    artifacts = find_artifacts(root)
    search_root = root if root.is_dir() else root.parent
    output.mkdir(parents=True, exist_ok=True)

    result: dict[str, Any] = {
        "input": str(root),
        "output": str(output),
        "asar_archives": [rel(path, search_root) for path in artifacts["asar_archives"]],
        "unpacked_dirs": [rel(path, search_root) for path in artifacts["unpacked_dirs"]],
        "app_dirs": [rel(path, search_root) for path in artifacts["app_dirs"]],
        "update_configs": [rel(path, search_root) for path in artifacts["update_configs"]],
        "blockmaps": [rel(path, search_root) for path in artifacts["blockmaps"]],
        "package_json": [rel(path, search_root) for path in artifacts["package_json"]],
        "extractions": [],
        "errors": [],
    }

    for asar in artifacts["asar_archives"]:
        name = asar.name.replace(".", "_")
        # Keep the common app.asar output stable for downstream commands.
        target = output / ("app_asar" if asar.name == "app.asar" else name)
        try:
            result["extractions"].append(extract_asar(asar, target))
        except Exception as exc:
            result["errors"].append({"artifact": rel(asar, search_root), "error": str(exc)})

    for directory in artifacts["unpacked_dirs"]:
        target = output / "unpacked" / rel(directory, search_root)
        copy_tree(directory, target)

    for directory in artifacts["app_dirs"]:
        target = output / "resources_app"
        copy_tree(directory, target)

    write_outputs(result, output)
    return result


def write_outputs(result: dict[str, Any], out_dir: Path) -> None:
    (out_dir / "unpack_manifest.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [
        "# Electron Builder Unpack Report",
        "",
        f"Input: `{result['input']}`",
        f"Output: `{result['output']}`",
        "",
        "## ASAR Archives",
    ]
    lines.extend(f"- `{item}`" for item in result["asar_archives"] or ["none"])
    lines.extend(["", "## Unpacked Directories"])
    lines.extend(f"- `{item}`" for item in result["unpacked_dirs"] or ["none"])
    lines.extend(["", "## Update Metadata"])
    for item in result["update_configs"] + result["blockmaps"]:
        lines.append(f"- `{item}`")
    if not result["update_configs"] and not result["blockmaps"]:
        lines.append("- none")
    if result["errors"]:
        lines.extend(["", "## Errors"])
        lines.extend(f"- `{err['artifact']}`: {err['error']}" for err in result["errors"])
    lines.extend(["", "## Next Step", "- Run `electron-app-analyzer` against extracted directories such as `app_asar/`."])
    (out_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Unpack authorized Electron Builder app artifacts for offline analysis")
    parser.add_argument("path", help="Electron Builder app directory, extracted installer directory, release directory, or app.asar")
    parser.add_argument("--out", default="electron-unpacked", help="Output directory")
    parser.add_argument("--json", action="store_true", help="Print JSON manifest to stdout")
    args = parser.parse_args()

    result = unpack_path(Path(args.path), Path(args.out))
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"[+] ASAR archives: {len(result['asar_archives'])}")
        print(f"[+] Unpacked dirs: {len(result['unpacked_dirs'])}")
        print(f"[+] Update configs: {len(result['update_configs'])}")
        print(f"[+] Manifest: {Path(args.out) / 'unpack_manifest.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
