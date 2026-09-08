# FAT scripts

These files support source installation and optional runtime features. They are not all installed with the executable. The
binary and runtime-data ZIPs include scripts declared in
[`share/fat/manifest.json`](../share/fat/manifest.json).

| Purpose | Files |
| --- | --- |
| Source installation | `install.sh`, `build-runtime-data-bundle.py`, `smoke-test-extraction.py` |
| Android runtime adapters | `discovery/android/adb_icc_runner.py`, `discovery/android/webview_runner.py`, `discovery/android/native_runner.py` |
| Optional KUnit example driver | `discovery/kunit_driver.py` |
| QEMU tracing and GDB fallback | `fat-hook-plugin.c`, `fat-instrument.py` |
| Source for the embedded MIPSEL startup helper | `fat-init-trampoline-mipsel.S` |
| Kernel builds and input verification | `fat-kernel-build.sh`, `fat-kernel-verify-source.sh` |
| User-supplied emulation asset verification | `verify-external-assets.py` |
| Dependency license reports | `generate-third-party-licenses.sh`, `sanitize-cargo-about.py`, `check-third-party-license-determinism.sh` |

Start with `./scripts/install.sh --help` for installation options. The KUnit
driver requires an external runner configured through `FAT_KUNIT_RUNNER`;
the corresponding example is in `examples/discovery/`.

See [Android helper setup](discovery/android/README.md) for device, APK, and
instrumentation-runner prerequisites, and
[kernel resource setup](../profiles/kernels/README.md) for the local builder
image and pinned-source requirements.

`fat-hook.so` is locally compiled output, and `__pycache__/` contains Python
cache files. Neither belongs in the source release.
