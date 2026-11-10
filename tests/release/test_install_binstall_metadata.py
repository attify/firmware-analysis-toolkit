#!/usr/bin/env python3
"""Keep the cargo-binstall metadata aligned with the cargo-dist archives."""

from __future__ import annotations

from pathlib import Path
import tomllib
import unittest

REPO = Path(__file__).resolve().parents[2]
DIST_CONFIG = REPO / "dist-workspace.toml"
CLI_MANIFEST = REPO / "crates" / "fat_cli" / "Cargo.toml"

# cargo-dist names every archive `{package}-{target}{extension}` and places the
# package contents under a directory with the archive's stem.
ARCHIVE_PREFIX = "{ name }-{ target }"


def load(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


class BinstallMetadataTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dist = load(DIST_CONFIG)["dist"]
        self.manifest = load(CLI_MANIFEST)
        self.package = self.manifest["package"]
        self.binstall = self.package["metadata"]["binstall"]
        self.overrides = self.binstall.get("overrides", {})

    def test_package_matches_the_distributed_package(self) -> None:
        self.assertEqual(self.dist["packages"], [self.package["name"]])
        self.assertTrue(self.package["repository"])

    def test_default_url_uses_the_platform_archive_name(self) -> None:
        url = self.binstall["pkg-url"]
        self.assertTrue(
            url.endswith(self.dist["unix-archive"]),
            f"{url} must end with the unix archive extension",
        )
        self.assertIn(ARCHIVE_PREFIX, url)
        self.assertIn("v{ version }", url)
        self.assertEqual(self.binstall["pkg-fmt"], "tgz")

    def test_binary_path_matches_the_archive_layout(self) -> None:
        # The executable sits inside the archive's top-level directory, beside
        # the share/fat runtime data that binstall does not install.
        self.assertEqual(
            self.binstall["bin-dir"], f"{ARCHIVE_PREFIX}/{{ bin }}{{ binary-ext }}"
        )
        binaries = [binary["name"] for binary in self.manifest.get("bin", [])]
        self.assertIn("fat", binaries)

    def test_each_dist_target_uses_its_archive_format(self) -> None:
        windows_targets = [t for t in self.dist["targets"] if "windows" in t]
        self.assertTrue(windows_targets)
        for target in windows_targets:
            override = self.overrides[target]
            self.assertTrue(override["pkg-url"].endswith(self.dist["windows-archive"]))
            self.assertEqual(override["pkg-fmt"], "zip")
        self.assertEqual(
            set(self.overrides), set(windows_targets), "only Windows needs an override"
        )


if __name__ == "__main__":
    unittest.main()
