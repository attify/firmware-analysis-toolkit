#!/usr/bin/env python3
"""Stage verified runtime data and the release README for cargo-dist archives."""

from pathlib import Path
import runpy
import shutil
import zipfile


REPO = Path(__file__).resolve().parent.parent
builder = runpy.run_path(str(REPO / "scripts/build-runtime-data-bundle.py"))
manifest, entries = builder["load_and_verify"]()
version = manifest["data_version"]
archive = REPO / "dist" / f"fat-data-{version}.zip"
builder["build"](archive, manifest, entries)
Path(f"{archive}.sha256").write_text(builder["sha256"](archive) + "\n", encoding="ascii")
stage = REPO / "target/release-resources"
data = stage / "share/fat"
if data.exists():
    shutil.rmtree(data)
with zipfile.ZipFile(archive) as source:
    source.extractall(data)
shutil.copyfile(REPO / f"release-notes/v{version}.md", stage / "README.md")
print(f"Staged FAT {version}: {len(entries)} runtime files and release notes")
