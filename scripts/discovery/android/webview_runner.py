#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Execute an Android WebView instrumentation lane.")
    parser.add_argument("--serial")
    parser.add_argument("--package", required=True)
    parser.add_argument("--apk", required=True)
    parser.add_argument("--split-apk", action="append", default=[])
    parser.add_argument("--artifact-dir", required=True)
    parser.add_argument("--entry-url", required=True)
    parser.add_argument("--runner", required=True)
    parser.add_argument("--skip-install", action="store_true")
    return parser.parse_args()


def adb_prefix(serial: str | None) -> list[str]:
    command = ["adb"]
    if serial:
        command.extend(["-s", serial])
    return command


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def install_apks(serial: str | None, apk: str, split_apks: list[str]) -> subprocess.CompletedProcess[str]:
    command = adb_prefix(serial)
    if split_apks:
        command.extend(["install-multiple", "-r", apk, *split_apks])
    else:
        command.extend(["install", "-r", apk])
    return run(command)


def write_text(path: Path, contents: str) -> None:
    path.write_text(contents, encoding="utf-8")


def main() -> int:
    args = parse_args()
    serial = args.serial or os.environ.get("ANDROID_SERIAL")
    artifact_dir = Path(args.artifact_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)

    install_result = None
    if not args.skip_install:
        install_result = install_apks(serial, args.apk, args.split_apk)
        if install_result and install_result.returncode != 0:
            (artifact_dir / "runner.json").write_text(
                json.dumps(
                    {
                        "status": "install-failed",
                        "adapter_kind": "android-instrumentation-webview",
                        "package": args.package,
                        "serial": serial,
                        "install_returncode": install_result.returncode,
                        "install_stderr": install_result.stderr,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            return install_result.returncode

    run(adb_prefix(serial) + ["shell", "am", "force-stop", args.package])
    run(adb_prefix(serial) + ["logcat", "-c"])

    command = adb_prefix(serial) + [
        "shell",
        "am",
        "instrument",
        "-w",
        "-e",
        "target_url",
        args.entry_url,
        args.runner,
    ]
    instrument_result = run(command)
    logcat_result = run(adb_prefix(serial) + ["logcat", "-d"])

    write_text(artifact_dir / "stdout.txt", instrument_result.stdout)
    write_text(artifact_dir / "stderr.txt", instrument_result.stderr)
    write_text(artifact_dir / "logcat.txt", logcat_result.stdout)
    (artifact_dir / "runner.json").write_text(
        json.dumps(
            {
                "status": "ok" if instrument_result.returncode == 0 else "failed",
                "adapter_kind": "android-instrumentation-webview",
                "package": args.package,
                "serial": serial,
                "command": command,
                "install_returncode": None if install_result is None else install_result.returncode,
                "returncode": instrument_result.returncode,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return instrument_result.returncode


if __name__ == "__main__":
    sys.exit(main())
