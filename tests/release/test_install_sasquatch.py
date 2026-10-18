#!/usr/bin/env python3
"""Offline tests for managed Sasquatch installation and source verification."""

import importlib.util
import io
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("sasquatch_installer", REPO / "scripts/install-sasquatch.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class SasquatchInstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.prefix = self.root / "prefix with spaces"
        self.archive = self.root / "source.tar.gz"
        with tarfile.open(self.archive, "w:gz") as archive:
            member = tarfile.TarInfo(f"sasquatch-{installer.RELEASE}/squashfs-tools/Makefile")
            archive.addfile(member, io.BytesIO())

    def fake_download(self, url, expected, destination):
        if url == installer.SOURCE_URL:
            shutil.copyfile(self.archive, destination)
        else:
            destination.write_text("test portability patch")

    def fake_build(self, command, **kwargs):
        if command[0] == "make" and "sasquatch" in command:
            source = Path(command[command.index("-C") + 1])
            (source / "sasquatch").write_text("big-endian" if "EXTRA_CFLAGS= -DFIX_BE" in command else "normal")

    def install(self, system="Linux"):
        with mock.patch.object(installer, "download", side_effect=self.fake_download), \
             mock.patch.object(installer.shutil, "which", return_value="/test/tool"), \
             mock.patch.object(installer.platform, "system", return_value=system), \
             mock.patch.object(installer.subprocess, "check_output", return_value="/opt/homebrew\n"), \
             mock.patch.object(installer.subprocess, "run", side_effect=self.fake_build) as commands:
            installer.install(self.prefix, 2)
            return commands

    def test_installs_both_variants_and_reuses_verified_binaries(self):
        self.install()
        self.assertEqual((self.prefix / "bin/sasquatch").read_text(), "normal")
        self.assertEqual((self.prefix / "bin/sasquatch-v4be").read_text(), "big-endian")
        self.assertEqual(self.install().call_count, 0)

    def test_changed_binary_is_rebuilt(self):
        self.install()
        (self.prefix / "bin/sasquatch").write_text("obsolete wrapper")
        self.assertGreater(self.install().call_count, 0)
        self.assertEqual((self.prefix / "bin/sasquatch").read_text(), "normal")

    def test_symlink_target_is_preserved(self):
        target = self.root / "external"
        target.write_text("external helper")
        (self.prefix / "bin").mkdir(parents=True)
        (self.prefix / "bin/sasquatch").symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, "symlink"):
            self.install()
        self.assertEqual(target.read_text(), "external helper")

    def test_failed_build_preserves_existing_helpers(self):
        (self.prefix / "bin").mkdir(parents=True)
        for name in installer.BINARIES:
            (self.prefix / "bin" / name).write_text("old helper")
        with mock.patch.object(installer, "download", side_effect=self.fake_download), \
             mock.patch.object(installer.shutil, "which", return_value="/test/tool"), \
             mock.patch.object(installer.platform, "system", return_value="Linux"), \
             mock.patch.object(installer.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "make")):
            with self.assertRaises(subprocess.CalledProcessError):
                installer.install(self.prefix, 2)
        for name in installer.BINARIES:
            self.assertEqual((self.prefix / "bin" / name).read_text(), "old helper")

    def test_macos_applies_patch_and_builds_big_endian_variant(self):
        commands = [call.args[0] for call in self.install("Darwin").call_args_list]
        self.assertEqual(commands[0][0], "patch")
        self.assertTrue(any("EXTRA_CFLAGS=-I/opt/homebrew/include -DFIX_BE" in c for c in commands))
        self.assertTrue(any("EXTRA_LDFLAGS=-L/opt/homebrew/lib" in c for c in commands))

    def test_download_rejects_incorrect_checksum(self):
        with mock.patch.object(installer.urllib.request, "urlopen", return_value=io.BytesIO(b"wrong source")):
            with self.assertRaisesRegex(RuntimeError, "SHA-256 mismatch"):
                installer.download(installer.SOURCE_URL, installer.SOURCE_SHA256, self.root / "bad.tar.gz")

    def test_archive_rejects_escape_paths_and_links(self):
        for name, kind in (("../escape", tarfile.REGTYPE), ("/absolute", tarfile.REGTYPE),
                           ("link", tarfile.SYMTYPE), ("hardlink", tarfile.LNKTYPE)):
            with self.subTest(name=name):
                with tarfile.open(self.archive, "w:gz") as archive:
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    member.linkname = "/tmp/escape"
                    archive.addfile(member)
                with self.assertRaisesRegex(RuntimeError, "unsafe source archive"):
                    installer.unpack(self.archive, self.root / "extract")


if __name__ == "__main__":
    unittest.main()
