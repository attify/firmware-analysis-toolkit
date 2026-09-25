#!/usr/bin/env python3
"""Smoke-test an extracted release archive outside its source checkout."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
import zipfile


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    archive = args.archive.resolve()
    checksum = Path(f"{archive}.sha256").read_text().split()[0]
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == checksum, "archive checksum mismatch"

    with tempfile.TemporaryDirectory(prefix="fat release smoke ") as scratch:
        root = Path(scratch)
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as source:
                source.extractall(root)
        else:
            with tarfile.open(archive) as source:
                source.extractall(root, filter="data")
        binaries = list(root.rglob("fat.exe" if os.name == "nt" else "fat"))
        binary, = [path for path in binaries if path.is_file()]
        data_root = binary.parent / "share/fat"
        manifest = json.loads((data_root / "manifest.json").read_text())
        assert manifest["data_version"] == args.version
        licenses = json.loads((binary.parent / "third-party-licenses.json").read_text())
        assert licenses["packages"] and licenses["licenses"], "dependency licenses missing"
        environment = os.environ.copy()
        environment.pop("FAT_DATA_DIR", None)

        def run(*arguments: str) -> str:
            result = subprocess.run(
                [str(binary), *arguments], cwd=root, env=environment,
                text=True, capture_output=True, timeout=60, check=True,
            )
            return result.stdout

        assert run("--version").strip() == f"fat {args.version}"
        verified = json.loads(run("data", "verify", "--json"))
        assert verified["data_version"] == args.version
        assert verified["verified_files"] == len(manifest["files"])
        assert data_root.resolve() == Path(verified["data_root"]).resolve(), verified
        status = json.loads(run("data", "status", "--json"))
        assert status["status"] == "ready", status
        assert data_root.resolve() == Path(status["data_root"]).resolve(), status
        blob = bytearray(512)
        for index, value in enumerate([0x20001000, 0x08000101] + [0x08000121] * 14):
            struct.pack_into("<I", blob, index * 4, value)
        blob[0x100:0x104] = b"\x00\xbf\xfe\xe7"
        blob[0x120:0x122] = b"\xfe\xe7"
        firmware = root / "synthetic.bin"
        firmware.write_bytes(blob)
        for command in [("identify",), ("inspect", "mcu")]:
            result = json.loads(run(*command, "--file", str(firmware), "--json"))
            assert "ARM Cortex-M" in json.dumps(result), result
        if os.name != "nt":
            inspector = "otool" if os.uname().sysname == "Darwin" else "ldd"
            command = [inspector, "-L", str(binary)] if inspector == "otool" else [inspector, str(binary)]
            dependencies = subprocess.check_output(command, text=True)
            assert "not found" not in dependencies, dependencies
            assert "/opt/homebrew/" not in dependencies and "/usr/local/" not in dependencies, dependencies
            print(dependencies)
        print(f"Verified FAT {args.version}: {archive.name}, {len(manifest['files'])} data files, identify, inspect mcu")


if __name__ == "__main__":
    main()
