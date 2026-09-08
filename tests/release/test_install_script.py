#!/usr/bin/env python3
"""Hermetic tests for the pre-release source installer."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


REPO = Path(__file__).resolve().parents[2]
INSTALLER = REPO / "scripts" / "install.sh"


def write_executable(path: Path, text: str) -> None:
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
    path.chmod(0o755)


class InstallScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fake_bin = self.root / "fake-bin"
        self.fake_bin.mkdir()
        self.log = self.root / "commands.log"
        self.home = self.root / "home"
        self.home.mkdir()

        write_executable(
            self.fake_bin / "cc",
            """
            #!/usr/bin/env sh
            exit 0
            """,
        )
        write_executable(
            self.fake_bin / "c++",
            """
            #!/usr/bin/env sh
            exit 0
            """,
        )
        write_executable(
            self.fake_bin / "pkg-config",
            """
            #!/usr/bin/env sh
            exit 0
            """,
        )
        write_executable(
            self.fake_bin / "rustc",
            """
            #!/usr/bin/env sh
            printf 'rustc 1.90.0 (test 1970-01-01)\\n'
            """,
        )
        fake_fat = textwrap.dedent(
            f"""\
            #!{sys.executable}
            import os
            from pathlib import Path
            import shutil
            import sys

            args = sys.argv[1:]
            with Path(os.environ["FAKE_INSTALL_LOG"]).open("a", encoding="utf-8") as output:
                output.write("fat " + " ".join(args) + "\\n")

            if args == ["--version"]:
                print("fat 2.0.0-alpha.1")
                raise SystemExit(0)
            if len(args) >= 2 and args[:2] == ["data", "install"]:
                data_dir = Path(args[args.index("--data-dir") + 1])
                data_dir.mkdir(parents=True, exist_ok=True)
                (data_dir / "verified-test-data").write_text("ready\\n", encoding="utf-8")
                print("installed test data")
                raise SystemExit(0)
            if len(args) >= 2 and args[:2] == ["data", "verify"]:
                data_dir = Path(args[args.index("--data-dir") + 1])
                if (data_dir / "verified-test-data").is_file():
                    print("verified test data")
                    raise SystemExit(0)
                raise SystemExit(1)
            if args and args[0] == "doctor":
                if "--strict" in args and shutil.which("binwalk") is None:
                    raise SystemExit(1)
                print("doctor ready")
                raise SystemExit(0)
            if len(args) == 2 and args[0] == "extract":
                project = Path.cwd() / ".fat-projects" / "synthetic-extraction-smoke"
                extraction = project / "work" / "extractions" / "binwalk" / "etc"
                extraction.mkdir(parents=True, exist_ok=True)
                (extraction / "synthetic-fat-extraction-marker.txt").write_text(
                    "FAT synthetic extraction smoke test passed\\n", encoding="utf-8"
                )
                (project / "work" / "binwalk.log").write_text(
                    "binwalk extracted synthetic ZIP\\n", encoding="utf-8"
                )
                (project / "work" / "extraction-manifest.json").write_text(
                    '{{"rootfs_path": null, "kernel_paths": [], "file_count": 1}}\\n',
                    encoding="utf-8",
                )
                print("synthetic extraction complete")
                raise SystemExit(0)
            raise SystemExit(2)
            """
        )
        write_executable(
            self.fake_bin / "cargo",
            f"""
            #!{sys.executable}
            import os
            from pathlib import Path
            import stat
            import sys

            args = sys.argv[1:]
            log = Path(os.environ["FAKE_INSTALL_LOG"])
            with log.open("a", encoding="utf-8") as output:
                output.write("cargo " + " ".join(args) + "\\n")

            if not args or args[0] != "install":
                raise SystemExit(0)

            root = Path(args[args.index("--root") + 1])
            binary_dir = root / "bin"
            binary_dir.mkdir(parents=True, exist_ok=True)
            if "binwalk" in args:
                binary = binary_dir / "binwalk"
                binary.write_text(
                    "#!/usr/bin/env sh\\nprintf 'binwalk 3.1.0\\\\n'\\n",
                    encoding="utf-8",
                )
            else:
                binary = binary_dir / "fat"
                binary.write_text({fake_fat!r}, encoding="utf-8")
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
            """,
        )

        self.environment = os.environ.copy()
        self.environment.update(
            {
                "HOME": str(self.home),
                "PATH": f"{self.fake_bin}:/usr/bin:/bin",
                "FAT_INSTALL_CARGO": str(self.fake_bin / "cargo"),
                "FAT_INSTALL_RUSTC": str(self.fake_bin / "rustc"),
                "FAT_INSTALL_PYTHON": sys.executable,
                "FAKE_INSTALL_LOG": str(self.log),
            }
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_installer(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(INSTALLER), *arguments],
            cwd=REPO,
            env=self.environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_extraction_profile_installs_pinned_binwalk_and_is_idempotent(self) -> None:
        prefix = self.root / "extraction-prefix"
        first = self.run_installer(
            "--profile",
            "extraction",
            "--prefix",
            str(prefix),
            "--jobs",
            "2",
            "--test",
        )
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertTrue((prefix / "bin" / "fat").is_file())
        self.assertTrue((prefix / "bin" / "binwalk").is_file())
        self.assertTrue((prefix / "share" / "fat" / "verified-test-data").is_file())

        second = self.run_installer(
            "--profile", "extraction", "--prefix", str(prefix), "--jobs", "2"
        )
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)

        log = self.log.read_text(encoding="utf-8")
        self.assertIn("cargo test --workspace --locked --jobs 2", log)
        self.assertEqual(log.count("cargo install binwalk"), 1)
        self.assertIn("--version 3.1.0", log)
        self.assertEqual(log.count("fat data install"), 1)
        self.assertIn("fat doctor --strict", log)
        self.assertIn("fat extract", log)

    def test_core_profile_does_not_install_binwalk(self) -> None:
        prefix = self.root / "core-prefix"
        result = self.run_installer(
            "--profile", "core", "--prefix", str(prefix), "--jobs", "1"
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((prefix / "bin" / "fat").is_file())
        self.assertFalse((prefix / "bin" / "binwalk").exists())
        log = self.log.read_text(encoding="utf-8")
        self.assertNotIn("cargo install binwalk", log)
        self.assertIn("fat doctor\n", log)
        self.assertNotIn("fat doctor --strict", log)

    def test_extraction_profile_fails_before_build_without_binwalk_native_deps(self) -> None:
        write_executable(
            self.fake_bin / "pkg-config",
            """
            #!/usr/bin/env sh
            exit 1
            """,
        )
        prefix = self.root / "missing-deps-prefix"
        result = self.run_installer(
            "--profile", "extraction", "--prefix", str(prefix), "--jobs", "1"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Binwalk needs Fontconfig and FreeType", result.stderr)
        self.assertFalse(self.log.exists(), "Cargo must not start before preflight passes")

    def test_refuses_filesystem_root_as_prefix(self) -> None:
        result = self.run_installer("--prefix", "/", "--dry-run")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing unsafe installation prefix", result.stderr)

    def test_dry_run_preserves_existing_scratch_and_installation(self) -> None:
        scratch = self.root / "fat-install.DRY_RUN"
        scratch.mkdir()
        marker = scratch / "keep.txt"
        marker.write_text("existing data")
        self.environment["TMPDIR"] = str(self.root)
        prefix = self.root / "dry-prefix"
        result = self.run_installer("--prefix", str(prefix), "--dry-run")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(marker.is_file(), "dry-run deleted existing data")
        self.assertEqual(marker.read_text(), "existing data")
        self.assertFalse(prefix.exists())
        self.assertFalse(self.log.exists())

    def test_prefix_and_compiler_paths_with_spaces(self) -> None:
        compiler = self.root / "rust compiler"
        compiler.write_bytes((self.fake_bin / "rustc").read_bytes())
        compiler.chmod(0o755)
        self.environment["FAT_INSTALL_RUSTC"] = str(compiler)
        prefix = self.root / "prefix with spaces"
        result = self.run_installer("--profile", "core", "--prefix", str(prefix))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((prefix / "bin/fat").is_file())

    def test_custom_data_dir_is_discoverable_and_idempotent(self) -> None:
        prefix = self.root / "custom-prefix"
        data = self.root / "custom data"
        for _ in range(2):
            result = self.run_installer(
                "--profile", "core", "--prefix", str(prefix), "--data-dir", str(data)
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue((prefix / "share/fat/verified-test-data").is_file())
            self.assertEqual((prefix / "share/fat").resolve(), data.resolve())

    def test_custom_data_dir_refuses_to_replace_existing_data(self) -> None:
        prefix = self.root / "existing-prefix"
        existing = prefix / "share/fat"
        existing.mkdir(parents=True)
        marker = existing / "keep.txt"
        marker.write_text("existing data")
        result = self.run_installer(
            "--profile", "core", "--prefix", str(prefix),
            "--data-dir", str(self.root / "elsewhere")
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("runtime-data discovery path", result.stderr)
        self.assertEqual(marker.read_text(), "existing data")
        self.assertFalse(self.log.exists(), "conflict must fail before Cargo runs")

    def test_rejects_old_rust_before_installing(self) -> None:
        write_executable(
            self.fake_bin / "rustc",
            "#!/bin/sh\nprintf 'rustc 1.88.0 (test 1970-01-01)\\n'\n",
        )
        result = self.run_installer("--profile", "core")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Rust 1.90 or newer is required; found 1.88.0", result.stderr)
        self.assertFalse(self.log.exists())

    def test_custom_data_dir_refuses_existing_conflicting_symlink(self) -> None:
        prefix = self.root / "linked-prefix"
        link = prefix / "share/fat"
        link.parent.mkdir(parents=True)
        previous = self.root / "previous-data"
        link.symlink_to(previous)  # A dangling link is still an owned path.
        result = self.run_installer(
            "--profile", "core", "--prefix", str(prefix),
            "--data-dir", str(self.root / "other-data")
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("runtime-data discovery path", result.stderr)
        self.assertEqual(link.readlink(), previous)
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
