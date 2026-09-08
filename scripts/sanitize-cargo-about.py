#!/usr/bin/env python3
"""Convert cargo-about's host-specific JSON into FAT's stable public schema."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def sanitize(raw: dict) -> dict:
    packages: dict[tuple[str, str], dict] = {}
    for item in raw.get("crates", []):
        package = item.get("package", {})
        source = package.get("source")
        if not source:
            continue
        name = package.get("name")
        version = package.get("version")
        if not name or not version:
            continue
        packages[(name, version)] = {
            "name": name,
            "version": version,
            "license": item.get("license") or package.get("license") or "UNKNOWN",
            "repository": package.get("repository"),
            "source": source,
        }

    licenses: dict[tuple[str, str], dict] = {}
    for item in raw.get("licenses", []):
        identifier = item.get("id")
        text = item.get("text")
        if not identifier or not text:
            continue
        licenses[(identifier, text)] = {
            "id": identifier,
            "name": item.get("name") or identifier,
            "text": text,
        }

    return {
        "schema_version": 1,
        "generated_by": "cargo-about 0.8.2",
        "packages": [packages[key] for key in sorted(packages)],
        "licenses": [licenses[key] for key in sorted(licenses)],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    raw = json.loads(args.input.read_text(encoding="utf-8"))
    result = sanitize(raw)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
