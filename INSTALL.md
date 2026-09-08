# Installation details

The minimal quick start (clone, build, install) lives in the [README](README.md). This page is the full installation reference: installer options, external tools, and optional components.

## Installer options

The source installer requires Rust 1.90+, Python 3, and a C compiler. The default extraction profile also needs Binwalk's native build dependencies; use `--install-system-deps` to install the supported host packages.

```bash
./scripts/install.sh --install-system-deps
# CLI and runtime data only, with paths containing spaces:
./scripts/install.sh --profile core --prefix "$HOME/FAT tools" \
  --data-dir "$HOME/FAT data"
```

| Option | Effect |
| --- | --- |
| `--profile core\|extraction` | CLI plus runtime data, optionally with Binwalk (default: extraction) |
| `--prefix PATH` | Install under PATH (default: `~/.local`); add its `bin` directory to your shell's PATH |
| `--data-dir PATH` | Store data there and link `PREFIX/share/fat` for automatic discovery; refuse an existing conflicting path |
| `--jobs N`, `--native` | Choose Cargo concurrency or optimize for this CPU |
| `--test` | Run locked workspace tests before installation |
| `--dry-run` | Print mutating commands without executing them or deleting temporary files |
| `--skip-extraction-smoke` | Explicitly skip the synthetic extraction check |

No `FAT_DATA_DIR` export is needed for installer-managed custom data. An existing `FAT_DATA_DIR` environment override still takes precedence; unset it to use the installation's data. Keep the linked custom directory in place when using FAT.

## External tools

FAT orchestrates external tools. Install only those needed for your workflow; `fat doctor` reports what it finds. For binwalk and unblob, strict mode requires a bounded version probe to succeed, not merely a matching executable name.

| Tool | Needed for | Typical installation |
| --- | --- | --- |
| binwalk | Firmware extraction | `./scripts/install.sh --profile extraction` installs pinned Rust Binwalk 3.1.0 |
| unblob | Alternative extraction | `pipx install unblob` |
| debugfs | ext filesystem extraction and ext2 repair | `brew install e2fsprogs` or `apt install e2fsprogs` |
| radare2 | Binary triage and symbol resolution | `brew install radare2` or `apt install radare2` |
| Ghidra | Decompilation and taint normalization | Install from [ghidra-sre.org](https://ghidra-sre.org/) and set `GHIDRA_HOME` |
| Joern | CPG proof stage | Install from [joern.io](https://joern.io/) |
| QEMU | System-mode emulation | `brew install qemu` or `apt install qemu-system` |
| Docker | Containerized emulation backends | Follow the [Docker installation guide](https://docs.docker.com/get-docker/) |
| Python 3 | Discovery runners | `apt install python3` |
| Python 3.10+ and angr | Optional binary taint engine | Isolated environment in [Optional angr setup](#optional-angr-setup) |

## Optional angr setup

Python alone does not install angr. Following the [upstream installation guidance](https://docs.angr.io/en/latest/getting-started/installing.html), create an isolated environment with Python 3.10 or newer:

```bash
python3 -m venv "$HOME/.local/share/fat-angr-venv"
"$HOME/.local/share/fat-angr-venv/bin/python" -m pip install angr pyyaml
export FAT_PYTHON="$HOME/.local/share/fat-angr-venv/bin/python"
"$FAT_PYTHON" -c 'import angr, yaml; print(angr.__version__)'
```

Keep `FAT_PYTHON` set in shells running FAT. On Debian/Ubuntu, install `python3-venv` if environment creation is unavailable. `fat doctor --strict` checks extraction-engine readiness; it does not validate the optional angr environment. The import command above checks that environment without running firmware analysis.

## macOS ext2 builder image

`FAT_EXT2_BUILDER_IMAGE` may point to an operator-provided image pinned by digest. FAT does not pull that image or install packages at runtime. The builder disables networking, mounts firmware source read-only, enables `no-new-privileges`, and uses five narrow capabilities.
