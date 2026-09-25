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
binwalk_version="${FAT_INSTALL_BINWALK_VERSION:-3.1.0}"

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

The extraction profile ensures that `binwalk --version` succeeds and finishes
with `fat doctor --strict`. Heavy optional integrations such as Ghidra and Joern
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
    run brew install pkgconf fontconfig freetype p7zip squashfs
    return
  fi

  case "$(linux_dependency_id)" in
    fedora)
      run sudo dnf install -y \
        gcc-c++ pkgconf-pkg-config fontconfig-devel freetype-devel \
        e2fsprogs 7zip lz4 zstd squashfs-tools util-linux-script
      ;;
    rhel|centos)
      run sudo dnf install -y \
        gcc-c++ pkgconf-pkg-config fontconfig-devel freetype-devel \
        e2fsprogs p7zip p7zip-plugins squashfs-tools util-linux-script
      ;;
    ubuntu|debian)
      run sudo apt-get update
      run sudo apt-get install -y \
        g++ pkg-config libfontconfig1-dev libfreetype6-dev \
        e2fsprogs p7zip-full squashfs-tools
      ;;
    arch|manjaro)
      run sudo pacman -S --needed \
        fontconfig freetype2 e2fsprogs p7zip squashfs-tools
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

  existing_binwalk=""
  if command_available binwalk && binwalk --version >/dev/null 2>&1; then
    existing_binwalk="$(command -v binwalk)"
  elif [[ -x "$prefix/bin/binwalk" ]] \
    && "$prefix/bin/binwalk" --version >/dev/null 2>&1; then
    existing_binwalk="$prefix/bin/binwalk"
  fi
  if [[ "$profile" == "extraction" && -z "$existing_binwalk" ]]; then
    command_available c++ \
      || die "Binwalk needs a C++ compiler; rerun with --install-system-deps"
    command_available pkg-config \
      || die "Binwalk needs pkg-config; rerun with --install-system-deps"
    pkg-config --exists fontconfig freetype2 \
      || die "Binwalk needs Fontconfig and FreeType development files; rerun with --install-system-deps"
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

export PATH="$prefix/bin:$PATH"
if [[ "$profile" == "extraction" ]]; then
  if ! command_available binwalk || ! binwalk --version >/dev/null 2>&1; then
    say "Installing Binwalk into $prefix"
    run_cargo_install "$cargo_bin" install binwalk \
      --version "$binwalk_version" \
      --root "$prefix" \
      --locked \
      --force \
      --jobs "$jobs"
  else
    say "Using existing Binwalk at $(command -v binwalk)"
  fi
  if [[ "$dry_run" == false ]]; then
    command_available binwalk || die "Binwalk installation completed but binwalk is not on PATH"
    binwalk --version >/dev/null || die "Binwalk was found but its version probe failed"
  fi
  if [[ "$run_extraction_smoke" == true ]]; then
    say "Running synthetic Binwalk extraction smoke test"
    run "$python_bin" "$repo_root/scripts/smoke-test-extraction.py" --fat "$fat_bin"
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
if [[ "$prefix_was_on_path" == false ]]; then
  printf 'Add this directory to PATH: %s/bin\n' "$prefix"
fi
