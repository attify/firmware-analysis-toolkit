#!/usr/bin/env python3
"""Verify or build the versioned FAT runtime-data ZIP."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import zipfile


REPO = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO / "share" / "fat" / "manifest.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def workspace_version() -> str:
    text = (REPO / "Cargo.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not match:
        raise SystemExit("workspace package version not found")
    return match.group(1)


def load_and_verify() -> tuple[dict, list[tuple[str, Path]]]:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if manifest.get("data_version") != workspace_version():
        raise SystemExit("runtime-data version does not match the FAT workspace version")
    entries: list[tuple[str, Path]] = []
    seen: set[str] = set()
    for item in manifest.get("files", []):
        relative = item["path"]
        if relative in seen or Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise SystemExit(f"unsafe or duplicate runtime-data path: {relative}")
        seen.add(relative)
        source = REPO / relative
        if not source.is_file():
            raise SystemExit(f"runtime-data source is missing: {relative}")
        actual = sha256(source)
        if actual.lower() != item["sha256"].lower():
            raise SystemExit(
                f"runtime-data SHA-256 mismatch for {relative}: expected {item['sha256']}, got {actual}"
            )
        entries.append((relative, source))
    if not entries:
        raise SystemExit("runtime-data manifest must contain at least one file")
    return manifest, sorted(entries)


def add_bytes(archive: zipfile.ZipFile, name: str, data: bytes, mode: int) -> None:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = mode << 16
    archive.writestr(info, data)


def build(output: Path, manifest: dict, entries: list[tuple[str, Path]]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w") as archive:
        manifest_bytes = (json.dumps(manifest, indent=2) + "\n").encode()
        add_bytes(archive, "manifest.json", manifest_bytes, 0o100644)
        for relative, source in entries:
            mode = 0o100755 if source.stat().st_mode & 0o111 else 0o100644
            add_bytes(archive, relative, source.read_bytes(), mode)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="verify sources without writing")
    parser.add_argument("--output", type=Path, help="output fat-data ZIP path")
    args = parser.parse_args()
    if not args.check and args.output is None:
        parser.error("provide --check or --output")
    manifest, entries = load_and_verify()
    if args.output is not None:
        build(args.output, manifest, entries)
        digest = sha256(args.output)
        Path(f"{args.output}.sha256").write_text(f"{digest}\n", encoding="ascii")
        print(
            f"built {args.output} with {len(entries)} verified files "
            f"(sha256 {digest})"
        )
    elif args.check:
        print(f"verified FAT data {manifest['data_version']} with {len(entries)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
