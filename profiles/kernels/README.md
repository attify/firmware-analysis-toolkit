# Experimental kernel resources

These files describe kernel selection and experimental kernel builds. Kernel
binaries, a container builder image, and QEMU are separate prerequisites.

| Resource | Purpose |
| --- | --- |
| `catalog.json` | Kernel candidates, artifact identities, and compatibility requirements used by emulation planning. |
| `machines/` | QEMU version, machine, CPU, console, and architecture bindings. |
| `recipes/` and `config/` | Kernel build targets and ordered Kconfig fragments; `fat kernel recipes` lists the recipes. |
| `source-locks/` | Kernel source URLs and expected archive digests. |
| `builders/` | Container image identity, base image, package versions, and build timestamp. |
| `promotion-policy-v1.json` | Evidence requirements for evaluating whether an experimental kernel can be promoted. |
| `ATTRIBUTION.md` | Source and attribution information for the build inputs. |

The maintained-kernel catalog entries are experimental and `not-promoted`.
Their presence does not establish compatibility with a particular firmware.

## Prepare the builder from a source checkout

The `localhost/fat-kernel-builder@sha256:...` reference in
`builders/debian-13-cross.json` identifies an image in the local container
store. It is not a public registry download. The kernel build script uses
`--pull never`, so that exact image must already be present.

The source checkout includes `kernel/builder/Containerfile`, its build script,
and fixture sources. The runtime-data ZIP contains the records above, but
does not include those builder sources. Use a full source checkout for this
procedure, on a Linux host or VM with Podman and `jq`. Building the container
requires network access to its pinned Debian base and package repositories.

From the repository root, build a candidate image using the recorded timestamp:

```bash
podman build --format oci \
  --timestamp "$(jq -r '.build_timestamp' profiles/kernels/builders/debian-13-cross.json)" \
  -f kernel/builder/Containerfile \
  -t localhost/fat-kernel-builder .
```

Check the resulting image against the recorded manifest digest before using
the checked-in recipes:

```bash
expected_digest=$(jq -r '.manifest_digest' profiles/kernels/builders/debian-13-cross.json)
actual_digest=$(podman image inspect localhost/fat-kernel-builder --format '{{.Digest}}')
if [ "$actual_digest" != "$expected_digest" ]; then
  echo "Builder digest differs: expected $expected_digest, observed $actual_digest" >&2
  exit 1
fi
builder_image=$(jq -r '.image' profiles/kernels/builders/debian-13-cross.json)
podman image inspect "$builder_image" >/dev/null
```

A successful container build does not guarantee this digest will match.
Package availability, host architecture, and build tooling can affect a rebuild;
the Containerfile does not pin a Debian package snapshot. If a package version
is unavailable or the digest differs, the checked-in builder has not been
reproduced. Do not substitute a tag or edit the recorded digest to bypass the
check. A different builder requires a reviewed builder record and corresponding
recipe identities; existing artifact and compatibility claims do not transfer.

Podman's [build options](https://docs.podman.io/en/stable/markdown/podman-build.1.html)
describe timestamp handling; [image inspection](https://docs.podman.io/en/stable/markdown/podman-image-inspect.1.html)
reports the manifest digest used by the comparison.

## Build a kernel with a matching builder

Acquire the archive named by `source-locks/linux-6.18.45.json` and verify its
provenance using the upstream signature/checksum references. FAT's source
verification script checks the archive against the recorded SHA-256.
From the repository root, with the archive saved as `.tmp/linux.tar.xz`:

```bash
sh scripts/fat-kernel-verify-source.sh \
  .tmp/linux.tar.xz profiles/kernels/source-locks/linux-6.18.45.json

sh scripts/fat-kernel-build.sh \
  --engine podman \
  --source .tmp/linux.tar.xz \
  --source-lock profiles/kernels/source-locks/linux-6.18.45.json \
  --builder profiles/kernels/builders/debian-13-cross.json \
  --recipe profiles/kernels/recipes/linux-arm32-eabi-le-v7-4k.json \
  --profiles profiles/kernels \
  --output .tmp/kernel-armv7
```

Use a dedicated empty output directory: the builder replaces its contents.
The kernel build runs offline and uses a 16 GB temporary filesystem limit;
provision sufficient memory and storage in the Linux host or VM. Other target
recipes are listed in `recipes/`. Building an artifact does not establish that
it boots your firmware; QEMU machine compatibility and target execution need
separate validation.
