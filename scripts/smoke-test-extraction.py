#!/usr/bin/env python3
"""Run a bounded end-to-end extraction smoke test against an installed FAT."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import zipfile


MARKER_NAME = "synthetic-fat-extraction-marker.txt"
MARKER_TEXT = "FAT synthetic extraction smoke test passed\n"
FIRMWARE_NAME = "synthetic-extraction-smoke.bin"


def run(command: list[str], cwd: Path, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def build_synthetic_firmware(path: Path) -> None:
    # Binwalk sees a ZIP member after a non-archive firmware-like prefix. FAT's
    # native filesystem scanner does not handle ZIP, so successful recovery
    # proves the external extraction path executed.
    path.write_bytes(b"FAT-SYNTHETIC-FIRMWARE\0" + bytes(range(32)))
    with zipfile.ZipFile(path, "a", compression=zipfile.ZIP_DEFLATED) as archive:
        info = zipfile.ZipInfo(f"etc/{MARKER_NAME}", date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o100644 << 16
        archive.writestr(info, MARKER_TEXT.encode())


def locate_project(work_dir: Path) -> Path:
    projects = [path for path in (work_dir / ".fat-projects").iterdir() if path.is_dir()]
    if len(projects) != 1:
        raise SystemExit(f"expected one smoke-test project, found {len(projects)}")
    return projects[0]


def verify_extraction(project: Path) -> None:
    manifest_path = project / "work" / "extraction-manifest.json"
    if not manifest_path.is_file():
        raise SystemExit(f"extraction manifest is missing: {manifest_path}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"invalid extraction manifest: {error}") from error
    file_count = manifest.get("file_count")
    if not isinstance(file_count, int) or file_count < 1:
        raise SystemExit("extraction manifest contains no recovered artifacts")

    binwalk_log = project / "work" / "binwalk.log"
    if not binwalk_log.is_file():
        raise SystemExit("Binwalk log is missing; the external engine was not exercised")
    log_text = binwalk_log.read_text(encoding="utf-8", errors="replace")
    if "skipped binwalk" in log_text.lower():
        raise SystemExit("FAT skipped Binwalk during the extraction smoke test")

    extraction_root = project / "work" / "extractions"
    markers = list(extraction_root.rglob(MARKER_NAME))
    if len(markers) != 1:
        raise SystemExit(f"expected one recovered marker, found {len(markers)}")
    if markers[0].read_text(encoding="utf-8") != MARKER_TEXT:
        raise SystemExit("recovered marker contents do not match the synthetic firmware")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fat", type=Path, required=True, help="installed FAT executable")
    parser.add_argument(
        "--work-dir",
        type=Path,
        help="retain smoke-test state in this empty directory instead of a temporary directory",
    )
    args = parser.parse_args()
    fat = args.fat.expanduser().resolve()
    if not fat.is_file():
        raise SystemExit(f"FAT executable is missing: {fat}")

    temporary: tempfile.TemporaryDirectory[str] | None = None
    if args.work_dir is None:
        temporary = tempfile.TemporaryDirectory(prefix="fat-extraction-smoke-")
        work_dir = Path(temporary.name)
    else:
        work_dir = args.work_dir.expanduser().resolve()
        if work_dir.exists() and any(work_dir.iterdir()):
            raise SystemExit(f"smoke-test work directory must be empty: {work_dir}")
        work_dir.mkdir(parents=True, exist_ok=True)

    try:
        firmware = work_dir / FIRMWARE_NAME
        build_synthetic_firmware(firmware)
        run([str(fat), "doctor", "--strict"], cwd=work_dir)
        run([str(fat), "extract", str(firmware)], cwd=work_dir)
        project = locate_project(work_dir)
        verify_extraction(project)
        print(f"verified synthetic Binwalk extraction with {fat}")
        return 0
    finally:
        if temporary is not None:
            temporary.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
