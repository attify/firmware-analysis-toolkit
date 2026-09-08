#!/usr/bin/env python3
"""Verify user-supplied, non-redistributed FAT runtime assets."""

import argparse
import hashlib
import json
from pathlib import Path
import sys


REPO = Path(__file__).resolve().parent.parent


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(64 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--asset-dir", type=Path)
    args = parser.parse_args()
    manifest = json.loads((REPO / "assets/manifest.json").read_text())
    assets = [item for item in manifest["external_requirements"] if item.get("sha256")]
    if not assets:
        raise SystemExit("no verifiable external assets are declared")
    required = ["id", "filename", "sha256", "provenance_status", "license_status"]
    for item in assets:
        missing = [field for field in required if not item.get(field)]
        if missing:
            raise SystemExit(f"external asset record missing {missing}: {item}")
    if args.check:
        print(f"verified {len(assets)} external asset identity records")
        return 0
    if args.asset_dir is None:
        parser.error("provide --asset-dir or --check")
    verified = 0
    for item in assets:
        path = args.asset_dir / item["filename"]
        if not path.is_file():
            continue
        actual = digest(path)
        if actual != item["sha256"]:
            raise SystemExit(f"SHA-256 mismatch for {path}: expected {item['sha256']}, got {actual}")
        print(f"verified {item['id']}: {path}")
        verified += 1
    if verified == 0:
        raise SystemExit("no declared external assets were found in the supplied directory")
    print("Identity verified; provenance and redistribution permission are not established.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
