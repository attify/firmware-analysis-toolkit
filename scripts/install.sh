#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
release_version="$(awk -F'"' '/^version = "/ { print $2; exit }' "$repo_root/Cargo.toml")"
rust_minimum="$(awk -F'"' '/^rust-version = "/ { print $2; exit }' "$repo_root/Cargo.toml")"

profile="extraction"
prefix="${FAT_INSTALL_PREFIX:-${HOME:?HOME is required}/.local}"
data_dir=""
jobs="${FAT_INSTALL_JOBS:-}"
run_tests=false
install_system_deps=false
native=false
dry_run=false
run_extraction_smoke=true

cargo_bin="${FAT_INSTALL_CARGO:-cargo}"
rustc_bin="${FAT_INSTALL_RUSTC:-rustc}"
python_bin="${FAT_INSTALL_PYTHON:-python3}"
binwalk_version="4.0.0"
binwalk_expected_version="binwalk-ng $binwalk_version"
install_binwalk=true

usage() {
  cat <<'EOF'
Install FAT from this source checkout.

Usage: ./scripts/install.sh [options]

Options:
  --profile core|extraction  Install FAT only, or FAT plus Binwalk (default: extraction)
  --prefix PATH              Installation prefix (default: $FAT_INSTALL_PREFIX or ~/.local)
  --data-dir PATH            Runtime-data root (default: PREFIX/share/fat)
  --jobs N                   Parallel Cargo jobs (default: min(CPU count, 8))
  --test                     Run the locked workspace test suite before installation
  --install-system-deps      Install supported OS packages through sudo/brew
  --native                   Optimize the installed binaries for this CPU
  --dry-run                  Print mutating commands without running them
  --skip-extraction-smoke    Skip the synthetic Binwalk extraction check
  -h, --help                 Show this help

The extraction profile installs pinned binwalk-ng (executable: binwalk) into
PREFIX/bin and verifies its version and extraction. Heavy integrations such as Ghidra and Joern
are intentionally not installed by this script.
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

say() {
  printf '==> %s\n' "$*"
}

print_command() {
  printf '    '
  printf '%q ' "$@"
  printf '\n'
}

run() {
  print_command "$@"
  if [[ "$dry_run" == false ]]; then
    "$@"
  fi
}

command_available() {
  command -v "$1" >/dev/null 2>&1
}

# Version probes must not leave an installation waiting indefinitely on a broken
# executable. Keep the selected path explicit so a different PATH entry cannot
# satisfy verification of the managed installation.
tool_version_at() {
  "$python_bin" -c '
import os, signal, subprocess, sys
try:
    child = subprocess.Popen([sys.argv[1], "--version"], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        output, _ = child.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGKILL)
        child.communicate()
        sys.exit(1)
    version = output.decode("utf-8", errors="replace").strip()
    if child.returncode or not version:
        sys.exit(1)
    print(version)
except OSError:
    sys.exit(1)
' "$1"
}

while (($#)); do
  case "$1" in
    --profile)
      (($# >= 2)) || die "--profile requires a value"
      profile="$2"
      shift 2
      ;;
    --prefix)
      (($# >= 2)) || die "--prefix requires a path"
      prefix="$2"
      shift 2
      ;;
    --data-dir)
      (($# >= 2)) || die "--data-dir requires a path"
      data_dir="$2"
      shift 2
      ;;
    --jobs)
      (($# >= 2)) || die "--jobs requires a number"
      jobs="$2"
      shift 2
      ;;
    --test)
      run_tests=true
      shift
      ;;
    --install-system-deps)
      install_system_deps=true
      shift
      ;;
    --native)
      native=true
      shift
      ;;
    --dry-run)
      dry_run=true
      shift
      ;;
    --skip-extraction-smoke)
      run_extraction_smoke=false
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

case "$profile" in
  core|extraction) ;;
  *) die "unsupported profile '$profile'; choose core or extraction" ;;
esac

[[ -n "$prefix" && "$prefix" != "/" ]] || die "refusing unsafe installation prefix '$prefix'"
if [[ -z "$data_dir" ]]; then
  data_dir="$prefix/share/fat"
fi
[[ -n "$data_dir" && "$data_dir" != "/" ]] || die "refusing unsafe runtime-data root '$data_dir'"
# Keep custom data links valid when paths were supplied relative to the caller.
[[ "$prefix" = /* ]] || prefix="$PWD/$prefix"
[[ "$data_dir" = /* ]] || data_dir="$PWD/$data_dir"
data_link="$prefix/share/fat"
prefix_was_on_path=false
if [[ ":$PATH:" == *":$prefix/bin:"* ]]; then
  prefix_was_on_path=true
fi
export PATH="$prefix/bin:$PATH"
binwalk_path="$prefix/bin/binwalk"

if [[ -z "$jobs" ]]; then
  cpu_count="$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')"
  if ((cpu_count > 8)); then
    jobs=8
  else
    jobs="$cpu_count"
  fi
fi
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || die "--jobs must be a positive integer"

linux_dependency_id() {
  # Keep absent release fields independent of the caller's environment. The
  # override lets installer tests use a fixture without changing the host.
  local ID="" ID_LIKE=""
  local os_release="${FAT_INSTALL_OS_RELEASE:-/etc/os-release}"
  if [[ -r "$os_release" ]]; then
    # shellcheck disable=SC1090
    source "$os_release"
  fi
  case "${ID:-}" in
    fedora|rhel|centos|ubuntu|debian|arch|manjaro) ;;
    *)
      # Derivatives such as Omarchy declare compatibility through ID_LIKE.
      # Preserve explicit recipes and match a whole whitespace-separated token.
      if [[ "${ID_LIKE:-}" =~ (^|[[:space:]])arch($|[[:space:]]) ]]; then
        ID=arch
      fi
      ;;
  esac
  printf '%s\n' "${ID:-}"
}

install_build_dependencies() {
  if [[ "$(uname -s)" == "Darwin" ]]; then
    if ! command_available cc; then
      die "install the Xcode command-line tools first: xcode-select --install"
    fi
    return
  fi

  case "$(linux_dependency_id)" in
    fedora|rhel|centos)
      run sudo dnf install -y gcc make
      ;;
    ubuntu|debian)
      run sudo apt-get update
      run sudo apt-get install -y build-essential
      ;;
    arch|manjaro)
      run sudo pacman -S --needed base-devel
      ;;
    *)
      die "unsupported OS; install a C compiler and make, then rerun without --install-system-deps"
      ;;
  esac
}

install_extraction_dependencies() {
  if [[ "$(uname -s)" == "Darwin" ]]; then
    command_available brew || die "Homebrew is required for automatic macOS dependencies"
    run brew install pkgconf p7zip squashfs lzop lzo lz4 xz zstd
    return
  fi

  case "$(linux_dependency_id)" in
    fedora)
      run sudo dnf install -y \
        gcc-c++ pkgconf-pkg-config zlib-devel xz-devel lzo-devel lz4-devel libzstd-devel \
        e2fsprogs 7zip lz4 zstd squashfs-tools util-linux-script lzop
      ;;
    rhel|centos)
      run sudo dnf install -y \
        gcc-c++ pkgconf-pkg-config zlib-devel xz-devel lzo-devel lz4-devel libzstd-devel \
        e2fsprogs p7zip p7zip-plugins squashfs-tools util-linux-script lzop
      ;;
    ubuntu|debian)
      run sudo apt-get update
      run sudo apt-get install -y \
        pkg-config zlib1g-dev liblzma-dev liblzo2-dev liblz4-dev libzstd-dev \
        e2fsprogs p7zip-full squashfs-tools lzop
      ;;
    arch|manjaro)
      run sudo pacman -S --needed \
        pkgconf zlib xz lzo lz4 zstd e2fsprogs p7zip squashfs-tools lzop
      ;;
    *)
      say "Skipping optional extraction utilities on unsupported OS ${ID:-unknown}."
      ;;
  esac
}

if [[ "$install_system_deps" == true ]]; then
  say "Installing native build dependencies"
  install_build_dependencies
  if [[ "$profile" == "extraction" ]]; then
    say "Installing common extraction utilities"
    install_extraction_dependencies
  fi
fi

if [[ "$dry_run" == false ]]; then
  command_available "$cargo_bin" || die "Cargo is missing; install Rust $rust_minimum+ from https://rustup.rs"
  command_available "$rustc_bin" || die "rustc is missing; install Rust $rust_minimum+ from https://rustup.rs"
  command_available "$python_bin" || die "Python 3 is required to assemble the runtime-data bundle"

  rust_version="$("$rustc_bin" --version | awk '{ print $2 }')"
  if ! "$python_bin" -c '
import sys
def version(text):
    parts = list(map(int, text.split("-", 1)[0].split(".")))
    return tuple((parts + [0, 0, 0])[:3])
sys.exit(version(sys.argv[1]) < version(sys.argv[2]))
' "$rust_version" "$rust_minimum"; then
    die "Rust $rust_minimum or newer is required; found $rust_version"
  fi

  # Refuse conflicts before compiling or installing anything. Never replace an
  # existing runtime-data tree (or a link to a different tree).
  "$python_bin" -c '
import os, sys
link, data, prefix = sys.argv[1:]
if os.path.realpath(data) == "/" or os.path.realpath(prefix) == "/":
    sys.exit("error: refusing filesystem root as installation or runtime-data path")
if os.path.realpath(link) != os.path.realpath(data) and os.path.lexists(link):
    sys.exit("error: runtime-data discovery path already exists: " + link + "; use its current data directory or a different prefix")
' "$data_link" "$data_dir" "$prefix"

  if ! command_available cc && ! command_available gcc && ! command_available clang; then
    die "a C compiler is required; rerun with --install-system-deps or install gcc/clang"
  fi

  if [[ "$profile" == "extraction" ]]; then
    if [[ "$(tool_version_at "$binwalk_path" || true)" == "$binwalk_expected_version" ]]; then
      install_binwalk=false
    elif [[ -L "$binwalk_path" ]]; then
      die "$binwalk_path is a symlink; choose a different --prefix to preserve its target"
    fi
    tool_version_at lzop >/dev/null \
      || die "lzop is missing or unusable; rerun with --install-system-deps"
  fi
fi

if [[ "$run_tests" == true ]]; then
  say "Running the locked workspace test suite"
  run "$cargo_bin" test --workspace --locked --jobs "$jobs" \
    --manifest-path "$repo_root/Cargo.toml"
fi

# Bash 3.2, which macOS still ships, treats "${empty[@]}" under `set -u` as an
# unbound variable, so the optional RUSTFLAGS prefix is applied by a wrapper
# rather than by expanding a possibly-empty array at the call site.
run_cargo_install() {
  if [[ "$native" == true ]]; then
    run env "RUSTFLAGS=${RUSTFLAGS:+$RUSTFLAGS }-C target-cpu=native" "$@"
  else
    run "$@"
  fi
}

if [[ "$profile" == "extraction" ]]; then
  say "Installing Sasquatch extraction helpers"
  run "$python_bin" "$repo_root/scripts/install-sasquatch.py" --prefix "$prefix" --jobs "$jobs"
fi

say "Installing FAT $release_version into $prefix"
run_cargo_install "$cargo_bin" install \
  --path "$repo_root/crates/fat_cli" \
  --root "$prefix" \
  --locked \
  --force \
  --jobs "$jobs"

fat_bin="$prefix/bin/fat"
if [[ "$dry_run" == false ]]; then
  [[ -x "$fat_bin" ]] || die "Cargo completed without installing $fat_bin"
  actual_version="$("$fat_bin" --version)"
  [[ "$actual_version" == "fat $release_version" ]] \
    || die "installed binary version mismatch: expected 'fat $release_version', got '$actual_version'"
fi

scratch=""
cleanup() {
  if [[ -n "$scratch" && -d "$scratch" ]]; then
    rm -rf "$scratch"
  fi
}
if [[ "$dry_run" == false ]]; then
  scratch="$(mktemp -d "${TMPDIR:-/tmp}/fat-install.XXXXXX")"
  trap cleanup EXIT
else
  scratch="${TMPDIR:-/tmp}/fat-install.DRY_RUN"
fi
data_archive="$scratch/fat-data-$release_version.zip"

say "Building and installing matching FAT runtime data"
run "$python_bin" "$repo_root/scripts/build-runtime-data-bundle.py" --output "$data_archive"
if [[ "$dry_run" == false ]] && "$fat_bin" data verify --data-dir "$data_dir" >/dev/null 2>&1; then
  say "Runtime data at $data_dir is already installed and verified"
else
  run "$fat_bin" data install --archive "$data_archive" --data-dir "$data_dir"
fi
run "$fat_bin" data verify --data-dir "$data_dir"

if [[ "$data_link" != "$data_dir" ]]; then
  say "Making custom runtime data discoverable from the installed executable"
  run "$python_bin" -c '
import os, sys
link, data = sys.argv[1:]
if os.path.realpath(link) != os.path.realpath(data):
    os.makedirs(os.path.dirname(link), exist_ok=True)
    os.symlink(data, link)
' "$data_link" "$data_dir"
fi

if [[ "$profile" == "extraction" ]]; then
  if [[ "$install_binwalk" == true ]]; then
    if [[ -e "$binwalk_path" ]]; then
      say "Replacing $binwalk_path with $binwalk_expected_version"
    else
      say "Installing $binwalk_expected_version into $prefix"
    fi
    run_cargo_install "$cargo_bin" install binwalk-ng \
      --version "=$binwalk_version" \
      --root "$prefix" \
      --locked \
      --force \
      --jobs "$jobs"
  else
    say "Using $binwalk_expected_version at $binwalk_path"
  fi
  if [[ "$dry_run" == false ]]; then
    actual_binwalk_version="$(tool_version_at "$binwalk_path")" \
      || die "Binwalk version probe failed at $binwalk_path"
    [[ "$actual_binwalk_version" == "$binwalk_expected_version" ]] \
      || die "Binwalk version mismatch at $binwalk_path: expected '$binwalk_expected_version', got '$actual_binwalk_version'"
  fi
  if [[ "$run_extraction_smoke" == true ]]; then
    say "Verifying Binwalk ZIP/SquashFS extraction and LZO decompression"
    run "$python_bin" "$repo_root/scripts/smoke-test-extraction.py" --fat "$fat_bin" \
      --expected-binwalk-version "$binwalk_expected_version" --format-helpers
  fi
fi

say "Running FAT installation checks"
run "$fat_bin" --version
run "$fat_bin" data verify --data-dir "$data_dir"
if [[ "$profile" == "extraction" ]]; then
  run "$fat_bin" doctor --strict
else
  run "$fat_bin" doctor
fi

say "FAT installation complete"
printf 'Binary: %s\n' "$fat_bin"
printf 'Runtime data: %s\n' "$data_dir"
if [[ "$profile" == "extraction" ]]; then
  printf 'Binwalk: %s (%s)\n' "$binwalk_path" "$binwalk_expected_version"
fi
if [[ "$profile" == "extraction" || "$prefix_was_on_path" == false ]]; then
  printf 'Put this installation first on PATH in your shell:\n'
  # Expand the existing PATH in the user's shell, not in this installer.
  # shellcheck disable=SC2016
  printf '  export PATH=%q:"$PATH"\n' "$prefix/bin"
fi
