#!/usr/bin/env python3
"""Build the pinned Sasquatch helpers in a user-selected installation prefix."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request


RELEASE = "sasquatch-v4.5.1-6"
SOURCE_URL = f"https://github.com/onekey-sec/sasquatch/archive/refs/tags/{RELEASE}.tar.gz"
SOURCE_SHA256 = "57f2b90852d1d43a90f0a228337dc66642da4842494b84ba1896f34765edfc47"
# The portability patch used by Sasquatch's own Nix build.
DARWIN_PATCH_URL = "https://raw.githubusercontent.com/NixOS/nixpkgs/ed81545df5083a95ddcfbff0c029774ecb0326bd/pkgs/tools/filesystems/squashfs/darwin.patch"
DARWIN_PATCH_SHA256 = "e61176732d71a76453aff17e33bb8bff0fa86b9832dee77940255cd3370bbf49"
BINARIES = ("sasquatch", "sasquatch-v4be")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def download(url: str, expected: str, destination: Path) -> None:
    with urllib.request.urlopen(url, timeout=60) as response:
        destination.write_bytes(response.read())
    if digest(destination) != expected:
        raise RuntimeError(f"SHA-256 mismatch for {url}")


def unpack(archive: Path, destination: Path) -> None:
    with tarfile.open(archive) as source:
        for member in source.getmembers():
            path = Path(member.name)
            if path.is_absolute() or ".." in path.parts or not (member.isfile() or member.isdir()):
                raise RuntimeError(f"unsafe source archive entry: {member.name}")
        source.extractall(destination)


def install(prefix: Path, jobs: int) -> None:
    binary_dir = prefix / "bin"
    receipt = prefix / "share" / "fat-install" / "sasquatch.json"
    for name in BINARIES:
        if (binary_dir / name).is_symlink():
            raise RuntimeError(f"{binary_dir / name} is a symlink; choose a different --prefix")
    if receipt.parent.is_symlink() or receipt.is_symlink():
        raise RuntimeError(f"refusing symlink at {receipt}")
    try:
        recorded = json.loads(receipt.read_text())
        if recorded == {
            "source": SOURCE_SHA256,
            "darwin_patch": DARWIN_PATCH_SHA256 if platform.system() == "Darwin" else None,
            "binaries": {name: digest(binary_dir / name) for name in BINARIES},
        } and all(os.access(binary_dir / name, os.X_OK) for name in BINARIES):
            print(f"Using {RELEASE} at {binary_dir}")
            return
    except (OSError, ValueError):
        pass

    for command in ("make", "cc", "c++"):
        if not shutil.which(command):
            raise RuntimeError(f"{command} is required; rerun with --install-system-deps")
    with tempfile.TemporaryDirectory(prefix="fat-sasquatch-") as temporary:
        scratch = Path(temporary)
        archive = scratch / "source.tar.gz"
        download(SOURCE_URL, SOURCE_SHA256, archive)
        unpack(archive, scratch)
        source = scratch / f"sasquatch-{RELEASE}"
        cflags = ""
        ldflags = ""
        if platform.system() == "Darwin":
            patch = scratch / "darwin.patch"
            download(DARWIN_PATCH_URL, DARWIN_PATCH_SHA256, patch)
            subprocess.run(["patch", "-p1", "-i", str(patch)], cwd=source, check=True)
            brew = subprocess.check_output(["brew", "--prefix"], text=True).strip()
            cflags = f"-I{brew}/include"
            ldflags = f"-L{brew}/lib"
        build = ["make", "-C", str(source / "squashfs-tools")]
        for name in BINARIES:
            subprocess.run([*build, "clean"], check=True)
            flags = cflags + (" -DFIX_BE" if name == "sasquatch-v4be" else "")
            subprocess.run([
                *build, f"-j{jobs}", "sasquatch", f"EXTRA_CFLAGS={flags}",
                f"EXTRA_LDFLAGS={ldflags}",
            ], check=True)
            shutil.copy2(source / "squashfs-tools" / "sasquatch", scratch / name)
        # Build both variants before replacing any existing executable.
        binary_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".sasquatch-", dir=binary_dir) as staging:
            for name in BINARIES:
                staged = Path(staging) / name
                shutil.copy2(scratch / name, staged)
                staged.chmod(0o755)
                staged.replace(binary_dir / name)
        receipt.parent.mkdir(parents=True, exist_ok=True)
        receipt.write_text(json.dumps({
            "source": SOURCE_SHA256,
            "darwin_patch": DARWIN_PATCH_SHA256 if platform.system() == "Darwin" else None,
            "binaries": {name: digest(binary_dir / name) for name in BINARIES},
        }, indent=2) + "\n")
    print(f"Installed {RELEASE}: sasquatch and sasquatch-v4be")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--jobs", type=int, required=True)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    try:
        install(args.prefix, args.jobs)
    except (OSError, RuntimeError, subprocess.SubprocessError, tarfile.TarError) as error:
        raise SystemExit(f"error: Sasquatch installation failed: {error}\n"
                         "Install build dependencies with --install-system-deps and retry.") from error


if __name__ == "__main__":
    main()
