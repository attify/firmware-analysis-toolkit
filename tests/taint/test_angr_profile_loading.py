#!/usr/bin/env python3
"""Hermetic tests for angr_taint.py's profile loading.

The angr bridge and the Rust sink catalog are two implementations of one rule:
core models are authoritative, an external profile may add to them, and a
profile that restates a core entry is refused. They drifted once — the Rust
catalog kept the core definition while this script kept the external one, so
the same profile produced different models depending on which path ran it.
These tests pin this half; `profile.rs`'s unit tests pin the other.

angr itself is stubbed: nothing here reaches the analysis, only the loader.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import types
import unittest


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "crates" / "fat_taint" / "scripts" / "angr_taint.py"
CORE_PROFILE = REPO / "crates" / "fat_taint" / "profiles" / "core.yaml"


def load_angr_taint():
    """Import the script with `angr` stubbed out."""
    sys.modules.setdefault("angr", types.ModuleType("angr"))
    spec = importlib.util.spec_from_file_location("angr_taint", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProfileLoadingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            import yaml  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("PyYAML is required to load taint profiles")
        cls.module = load_angr_taint()

    def profile_dir(self, external: str) -> str:
        directory = Path(tempfile.mkdtemp())
        (directory / "core.yaml").write_text(
            CORE_PROFILE.read_text(encoding="utf-8"), encoding="utf-8"
        )
        (directory / "external.yaml").write_text(external, encoding="utf-8")
        return str(directory)

    def test_an_external_profile_may_add_models(self) -> None:
        directory = self.profile_dir(
            "name: example-platform\n"
            "sources:\n"
            "  primary:\n"
            "    - name: nvram_get\n"
            "sinks:\n"
            "  - name: xmldbc_ep\n"
            "    arg: 0\n"
        )

        primary, _secondary, sinks, _blockers = self.module.load_profiles(directory, set())

        self.assertIn("nvram_get", primary)
        self.assertEqual(sinks["xmldbc_ep"], 0)
        # Core survives alongside the additions.
        self.assertEqual(sinks["system"], 0)

    def test_an_external_profile_may_not_redefine_a_core_model(self) -> None:
        directory = self.profile_dir(
            "name: example-platform\nsinks:\n  - name: system\n    arg: 1\n"
        )

        with self.assertRaises(SystemExit) as raised:
            self.module.load_profiles(directory, set())

        self.assertIn("redefines system", str(raised.exception))

    def test_core_names_are_reserved_across_all_model_roles(self) -> None:
        for name in ("getenv", "system", "crypt"):
            for section in ("sources:\n  primary", "sources:\n  secondary", "sinks", "blockers"):
                with self.subTest(name=name, section=section):
                    directory = self.profile_dir(
                        f"name: example-platform\n{section}: [{{name: {name}}}]\n"
                    )
                    with self.assertRaises(SystemExit) as raised:
                        self.module.load_profiles(directory, set())
                    self.assertIn(f"redefines {name}", str(raised.exception))

    def test_an_external_profile_may_add_a_blocker(self) -> None:
        directory = self.profile_dir(
            "name: example-platform\nblockers: [{name: example_digest}]\n"
        )
        *_, blockers = self.module.load_profiles(directory, set())
        self.assertEqual(blockers, {"crypt", "example_digest"})

    def test_blockers_come_only_from_the_profiles(self) -> None:
        """The script carries no blocker list of its own.

        A stale copy used to sit at module scope, unread, which made the
        profiles' deliberately narrow set look like an oversight.
        """
        self.assertFalse(hasattr(self.module, "TAINT_BLOCKERS"))

        directory = self.profile_dir("name: example-platform\n")
        *_, blockers = self.module.load_profiles(directory, set())
        self.assertEqual(blockers, {"crypt"})

    def test_a_missing_profile_directory_is_an_error(self) -> None:
        with self.assertRaises(SystemExit):
            self.module.load_profiles("/nonexistent/profiles", set())


if __name__ == "__main__":
    unittest.main()
