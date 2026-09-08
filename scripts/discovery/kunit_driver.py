#!/usr/bin/env python3

import argparse
import os
import shlex
import subprocess
import sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Thin FAT discovery driver for KUnit-backed lanes."
    )
    parser.add_argument("--suite", required=True)
    parser.add_argument("--kunit-config", required=True)
    parser.add_argument("--source-root", default="")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    runner = os.environ.get("FAT_KUNIT_RUNNER", "").strip()
    if not runner:
        print("missing FAT_KUNIT_RUNNER", file=sys.stderr)
        return 2

    command = shlex.split(runner)
    command.extend(["--suite", args.suite, "--kunit-config", args.kunit_config])
    if args.source_root:
        command.extend(["--source-root", args.source_root])

    completed = subprocess.run(command, capture_output=True, text=True)
    if completed.stdout:
        sys.stdout.write(completed.stdout)
    if completed.stderr:
        sys.stderr.write(completed.stderr)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
