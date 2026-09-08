# Android runtime helpers

These optional scripts execute Android test actions and save command output,
device logs, and `runner.json`. FAT's Android runtime handoff refers to them;
the runtime-data bundle includes them alongside the profiles.

All three require:

- Python 3.10 or newer; the scripts use only Python's standard library.
- Android Platform Tools with `adb` on `PATH`, and an authorized, connected
  test device or emulator.
- A matching package name and installable APK; supply split APKs where needed.
  Use `--skip-install` only when the appropriate app is already installed.
- A writable artifact directory. Select the device with `--serial` or
  `ANDROID_SERIAL` when more than one is connected.

| Script | Additional prerequisite |
| --- | --- |
| `adb_icc_runner.py` | An activity invocation appropriate to the app, described by its component, action, data URI, or extras. |
| `webview_runner.py` | An installed instrumentation runner implementing the `target_url` input, plus the URL to test. |
| `native_runner.py` | An installed instrumentation runner implementing the `binder_transaction` and `native_symbol` inputs. |

FAT does not supply the APKs or instrumentation test runners. The WebView and
native helpers launch the supplied runner; they do not create test logic for it.

From a source checkout or the root of an extracted runtime-data bundle, inspect
the arguments without connecting to a device:

```bash
python3 scripts/discovery/android/adb_icc_runner.py --help
python3 scripts/discovery/android/webview_runner.py --help
python3 scripts/discovery/android/native_runner.py --help
```

Actual execution can install or replace the supplied app, force-stop the target
package, and clear logcat before collecting new logs. Use a test device whose
app state and logs can be changed. A reported `ok` status reflects the command's
exit status; inspect the collected evidence to determine what the test observed.
