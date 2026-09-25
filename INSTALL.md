# Installation details

The minimal quick start (clone, build, install) lives in the [README](README.md). This page is the full installation reference: installer options, external tools, and optional components.

## Release downloads

Choose a bundle for your operating system and CPU from [FAT Releases](https://github.com/attify/firmware-analysis-toolkit/releases/latest).
Binary bundles contain `fat` (`fat.exe` on Windows), the matching `share/fat` runtime data, and dependency license notices.
Choose the target matching your machine:

| System | CPU | Target |
| --- | --- | --- |
| macOS | Apple Silicon | `aarch64-apple-darwin` |
| macOS | Intel | `x86_64-apple-darwin` |
| Linux | x86-64 | `x86_64-unknown-linux-gnu` |
| Linux | ARM64 | `aarch64-unknown-linux-gnu` |
| Windows | x86-64 | `x86_64-pc-windows-msvc` |

Linux x86-64 requires glibc 2.35 or newer; Linux ARM64 requires glibc 2.39 or newer.
The archives are tested on Ubuntu 22.04 (x86-64), Ubuntu 24.04 (ARM64), and Fedora 42 (both CPUs).

Verify the archive against its adjacent `.sha256` file, extract it, and keep the executable and `share` directory together:

```bash
# Substitute the target from the release's asset list.
shasum -a 256 -c firmware-analysis-toolkit-TARGET.tar.gz.sha256
tar -xzf firmware-analysis-toolkit-TARGET.tar.gz
cd firmware-analysis-toolkit-TARGET
./fat --version
./fat data verify
./fat doctor
export PATH="$PWD:$PATH"
```

On Windows, use `Get-FileHash` to compare the ZIP's SHA-256 with its `.sha256` file, extract with `Expand-Archive`, and run `.\fat.exe data verify` from the extracted directory.
The Windows binary supports native analysis commands; workflows using Linux filesystem semantics or external Unix tools should run under WSL with the Linux build.

For a Cargo-installed executable, download the same version's `fat-data-VERSION.zip` and run `fat data install --archive ./fat-data-VERSION.zip`.
The source installer below installs both the executable and its runtime data.

## Upgrading from FAT 1.x

FAT 2 is a Rust CLI with a new installation and project workflow.
Install it in a separate directory, run `fat doctor`, and create a project with `fat new ./firmware.bin`.
Use the `fat` commands in the [quick start](README.md#quick-start); the FAT 1.x `setup.sh`, `fat.py`, and `fat.config` instructions apply to the older release.
Keep existing FAT 1.x workspaces until you have recreated the projects you need in FAT 2.

## Arch Linux and Omarchy

Use a regular account with `sudo` access. This sequence was validated on Omarchy 4.0.4 (x86-64), using an 8 GB VM and two build jobs. A clean Arch installation was not separately tested.

### Install FAT and the default extraction engine

Install the prerequisites with a full system upgrade, then initialize Rust. If you already installed Rust through rustup, omit `rustup` from the package list below:

```bash
sudo pacman -Syu --needed git rustup python
rustup default stable
rustc --version  # must be 1.90 or newer
```

The installer requires Rust and Python to be present; `--install-system-deps` does not bootstrap them.

Clone FAT, or use your existing checkout, and run the installer as your regular user:

```bash
git clone https://github.com/attify/firmware-analysis-toolkit.git
cd firmware-analysis-toolkit
./scripts/install.sh --install-system-deps --jobs 2
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
```

This installs FAT, its runtime data, and pinned Binwalk 3.1.0 when no usable Binwalk is already available. Use `--jobs 1` if the build runs short of memory. Add the `PATH` export to your shell's startup file to keep it in future sessions.

The installer uses Arch packages when `/etc/os-release` identifies Arch/Manjaro directly or an otherwise unrecognized distribution declares `arch` in `ID_LIKE`, as Omarchy does. Explicitly supported distribution IDs take precedence.

For an older FAT checkout that rejects Omarchy, install the native packages manually and rerun without `--install-system-deps`:

```bash
sudo pacman -S --needed base-devel pkgconf fontconfig freetype2 e2fsprogs 7zip squashfs-tools
./scripts/install.sh --jobs 2
```

`7zip` is the current Arch package name; the installer's `p7zip` request resolves through its compatibility alias on the tested host.

Verify the installed CLI and data:

```bash
fat --version
fat data verify
fat doctor --strict
```

Binwalk 3.1.0 can occasionally exit before scanning its input. FAT retries that specific zero-file result up to twice, keeps incomplete output and logs beside `work/binwalk.log`, and reports failure if all attempts scan zero files.

The installer also extracts a synthetic ZIP and verifies the recovered contents. To repeat that check from the checkout:

```bash
python3 scripts/smoke-test-extraction.py --fat "$HOME/.local/bin/fat"
```

### Add the tools your workflow needs

Each group is optional; the default extraction setup above does not need all of them.

| Workflow | Arch packages or setup |
| --- | --- |
| Binary triage and `fat decompile` | `sudo pacman -S --needed radare2 r2ghidra` |
| Ghidra headless analysis and taint normalization | `sudo pacman -S --needed ghidra jdk21-openjdk`, then `export GHIDRA_HOME=/opt/ghidra` |
| ARM and MIPS system emulation | `sudo pacman -S --needed qemu-system-arm qemu-system-mips` |
| User-mode emulation and debugging | `sudo pacman -S --needed qemu-user gdb` |
| Bootloader terminal sessions | `sudo pacman -S --needed tmux` |
| Python tool environments | `sudo pacman -S --needed python-pip python-pipx` |
| Container backends | See the Docker steps below |
| Binary taint analysis | Follow [Optional angr setup](#optional-angr-setup) |
| Joern CPG analysis | Follow the [upstream installation guide](https://docs.joern.io/installation/); put its `joern` and C/C++ frontend commands on `PATH` |

`r2ghidra` supplies the radare2 decompiler plugin used by `fat decompile`. Installing standalone Ghidra does not install that plugin. The Ghidra package above was tested with JDK 21; follow the package's Java requirement if a later release changes it.

For Docker, install and start the service:

```bash
sudo pacman -S --needed docker
sudo systemctl start docker
sudo docker run --rm hello-world
```

FAT must also be able to contact Docker as the user running FAT. Configure rootless Docker or your intended Docker access method using the [upstream post-installation guide](https://docs.docker.com/engine/install/linux-postinstall/), then verify `docker info` without `sudo`. Membership in the `docker` group grants root-level privileges. Installing Docker or QEMU alone does not configure a FirmAE, Firmadyne, or EMUX backend; `fat doctor` reports missing bundles and recipes separately.

For native unblob, install the Python application and common extractors:

```bash
sudo pacman -S --needed python-pipx erofs-utils lz4 lzop zstd partclone unarchiver android-tools
pipx install unblob
pipx install jefferson
pipx install ubi-reader
unblob --show-external-dependencies
```

The base packages and these additions still do not supply every unblob extractor. In particular, its SquashFS handler needs `sasquatch` even when `unsquashfs` is installed. Treat missing entries in the dependency report as unavailable format support. Follow [unblob's extractor installation instructions](https://unblob.org/installation/#install-extractors) for the remaining formats, or use its upstream Docker distribution:

```bash
docker pull ghcr.io/onekey-sec/unblob:latest
docker run --rm --network none ghcr.io/onekey-sec/unblob:latest --show-external-dependencies
```

The container supplied all reported extractors and recovered a test SquashFS file on the validated host. Follow the [upstream container usage instructions](https://unblob.org/installation/#docker-image) to mount your input and output directories. This is a separate unblob invocation; it does not add those extractors to the host's native unblob installation.

`fat doctor --strict` requires a usable extraction engine. It does not verify every unblob extractor, the angr Python environment, or a successful firmware boot. The synthetic extraction check above tests a real extraction operation.

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
| unblob | Alternative extraction | `pipx install unblob`, plus its [external extractors](https://unblob.org/installation/#install-extractors) |
| debugfs | ext filesystem extraction and ext2 repair | `brew install e2fsprogs` or `apt install e2fsprogs` |
| radare2 | Binary triage and symbol resolution | `brew install radare2` or `apt install radare2` |
| r2ghidra | `fat decompile` | Install the [radare2 plugin](https://github.com/radareorg/r2ghidra); Arch: `pacman -S radare2 r2ghidra` |
| Ghidra | Headless analysis and taint normalization | Install from [ghidra-sre.org](https://ghidra-sre.org/) and set `GHIDRA_HOME` |
| Joern | CPG proof stage | Install from [joern.io](https://joern.io/) |
| QEMU | System-mode emulation | `brew install qemu` or `apt install qemu-system` |
| Docker | Containerized emulation backends | Follow the [Docker installation guide](https://docs.docker.com/get-docker/) |
| GDB | Debugger integration | `gdb` or `gdb-multiarch`, with support for the target architecture |
| tmux | Bootloader emulation sessions | `pacman -S tmux`, `apt install tmux`, or `brew install tmux` |
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

For angr releases that provide the optional Unicorn extra, install it in the same environment if you need native execution acceleration:

```bash
"$FAT_PYTHON" -m pip install 'angr[unicorn]'
```

This resolved the optional Unicorn loading warning with angr 10.0.0 on the tested Omarchy host. Normal SSH login shells and non-interactive SSH commands can load different startup files; export `FAT_PYTHON` explicitly in scripts or one-shot SSH commands instead of assuming an interactive shell configuration was loaded.

## macOS ext2 builder image

`FAT_EXT2_BUILDER_IMAGE` may point to an operator-provided image pinned by digest. FAT does not pull that image or install packages at runtime. The builder disables networking, mounts firmware source read-only, enables `no-new-privileges`, and uses five narrow capabilities.
