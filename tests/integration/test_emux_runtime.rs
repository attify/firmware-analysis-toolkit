use std::path::PathBuf;
use std::process::Command;

use tempfile::tempdir;

#[test]
fn fat_emulate_prepares_emux_reference_device_runtime() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let emux_dir = tempdir().expect("emux dir");
    let path_dir = tempdir().expect("path dir");

    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    write_executable(
        path_dir.path().join("docker"),
        "#!/bin/sh\nif [ \"$1\" = \"info\" ]; then printf '29.2.1\\n'; exit 0; fi\nprintf 'docker:%s\\n' \"$*\"\nexit 0\n",
    );

    write_fake_emux_recipe(emux_dir.path());

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");

    let project_dir = projects_dir.path().join("demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    std::fs::write(
        project_dir.join("analysis").join("signals.txt"),
        "arch:mipsel\nfs:squashfs\ninit:busybox\nweb:cgi\nnvram:present\n",
    )
    .expect("signals file");

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_EMUX_DIR", emux_dir.path())
        .env("FAT_EMUX_REFERENCE_DEVICE", "firmware/TRI227WF")
        .env("FAT_EMUX_TUN_DEVICE", emux_dir.path().join("tun"))
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "emux",
            "--port",
            "8080",
            "--session-id",
            "emux-ref-1",
        ])
        .output()
        .expect("fat emulate runs");

    assert!(emulate_output.status.success(), "{emulate_output:?}");
    let stdout = String::from_utf8_lossy(&emulate_output.stdout);
    assert!(stdout.contains("backend: emux"), "{stdout}");
    assert!(stdout.contains("substrate: docker-engine"), "{stdout}");
    assert!(stdout.contains("session status: active"), "{stdout}");
    assert!(stdout.contains("run status: running"), "{stdout}");

    let store = fat_core::runtime_store::RuntimeStore::open(&project_dir).expect("runtime store");
    let session_id = parse_keyed_output(&stdout)
        .get("session")
        .expect("session id")
        .to_string();
    let run_id = parse_keyed_output(&stdout)
        .get("run")
        .expect("run id")
        .to_string();
    let outputs_dir = store
        .run_path(&session_id, &run_id)
        .parent()
        .expect("run parent")
        .join("outputs");
    assert!(outputs_dir.join("emux-launch-command.log").exists());
    assert!(outputs_dir.join("emux-launch-stdout.log").exists());
    assert!(outputs_dir.join("emux-userspace-command.log").exists());
    assert!(outputs_dir.join("emux-userspace-stdout.log").exists());
    assert!(outputs_dir.join("emux-userspace-state.json").exists());
    assert!(outputs_dir.join("emux-runtime-status.json").exists());
    let launch_command = std::fs::read_to_string(outputs_dir.join("emux-launch-command.log"))
        .expect("launch command");
    let launch_stdout =
        std::fs::read_to_string(outputs_dir.join("emux-launch-stdout.log")).expect("launch stdout");
    let userspace_stdout = std::fs::read_to_string(outputs_dir.join("emux-userspace-stdout.log"))
        .expect("userspace stdout");
    assert!(launch_command.contains("emux-launch-helper.sh"));
    assert!(!launch_command.contains(" -lc "));
    assert!(launch_stdout.contains("launch:"));
    assert!(userspace_stdout.contains("userspace:"));
    let runtime_status = std::fs::read_to_string(outputs_dir.join("emux-runtime-status.json"))
        .expect("runtime status");
    assert!(runtime_status.contains("\"runtime_phase\": \"userspace-started\""));
}

#[test]
fn fat_emulate_generates_rootful_podman_adapter_with_container_root() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let emux_dir = tempdir().expect("emux dir");
    let path_dir = tempdir().expect("path dir");

    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");
    write_executable(
        path_dir.path().join("docker"),
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'podman version 5.8.1\\n'; exit 0; fi\nexit 0\n",
    );
    write_executable(path_dir.path().join("sudo"), "#!/bin/sh\nexit 0\n");
    write_fake_emux_recipe(emux_dir.path());

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");
    let project_dir = projects_dir.path().join("demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    std::fs::write(
        project_dir.join("analysis/signals.txt"),
        "arch:mipsel\nfs:squashfs\ninit:busybox\n",
    )
    .expect("signals file");

    let mut child = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", path_dir.path().display()),
        )
        .env("FAT_EMUX_DIR", emux_dir.path())
        .env("FAT_EMUX_REFERENCE_DEVICE", "firmware/TRI227WF")
        .env("FAT_EMUX_TUN_DEVICE", emux_dir.path().join("tun"))
        .env("FAT_EMUX_ROOTFUL_PODMAN", "1")
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "emux",
            "--session-id",
            "emux-podman-root-user",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("fat emulate runs");
    let adapter_dir = std::env::temp_dir().join(format!("fat-emux-rootful-podman-{}", child.id()));
    child.wait().expect("fat emulate exits");

    let adapter = std::fs::read_to_string(adapter_dir.join("docker")).expect("Podman adapter");
    assert!(
        adapter.contains("run --privileged --user root"),
        "rootful EMUX must bypass the image's unavailable in-container sudo transition: {adapter}"
    );
    std::fs::remove_dir_all(adapter_dir).expect("remove Podman adapter");
}

#[test]
fn fat_emulate_reasserts_rootful_podman_adapter_after_pty_shell_startup() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let emux_dir = tempdir().expect("emux dir");
    let path_dir = tempdir().expect("path dir");
    let shadow_path_dir = tempdir().expect("shadow path dir");
    let runtime_log = path_dir.path().join("runtime.log");

    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");
    write_executable(
        path_dir.path().join("docker"),
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'podman version 5.8.1\\n'; fi\nexit 0\n",
    );
    write_executable(
        path_dir.path().join("sudo"),
        "#!/bin/sh\n[ \"$1\" = \"-n\" ] || exit 64\nshift\nruntime=$1\nshift\nprintf 'adapter %s\\n' \"$*\" >> \"$FAT_TEST_DOCKER_LOG\"\nexec \"$runtime\" \"$@\"\n",
    );
    write_executable(
        shadow_path_dir.path().join("docker"),
        "#!/bin/sh\nprintf 'direct %s\\n' \"$*\" >> \"$FAT_TEST_DOCKER_LOG\"\nexit 0\n",
    );
    let shell_wrapper = path_dir.path().join("test-shell");
    write_executable(
        shell_wrapper.clone(),
        "#!/bin/sh\nPATH=\"$FAT_TEST_SHADOW_PATH:$PATH\"\nexport PATH\nexec /bin/sh \"$@\"\n",
    );
    write_fake_emux_recipe(emux_dir.path());
    write_executable(
        emux_dir.path().join("run-emux-docker"),
        "#!/bin/sh\ndocker run emux-fixture /bin/true\nexit 1\n",
    );

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");
    let project_dir = projects_dir.path().join("demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    std::fs::write(
        project_dir.join("analysis/signals.txt"),
        "arch:mipsel\nfs:squashfs\ninit:busybox\n",
    )
    .expect("signals file");

    Command::new(env!("CARGO_BIN_EXE_fat"))
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", path_dir.path().display()),
        )
        .env("SHELL", shell_wrapper)
        .env("FAT_TEST_SHADOW_PATH", shadow_path_dir.path())
        .env("FAT_TEST_DOCKER_LOG", &runtime_log)
        .env("FAT_EMUX_DIR", emux_dir.path())
        .env("FAT_EMUX_REFERENCE_DEVICE", "firmware/TRI227WF")
        .env("FAT_EMUX_TUN_DEVICE", emux_dir.path().join("tun"))
        .env("FAT_EMUX_ROOTFUL_PODMAN", "1")
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "emux",
            "--session-id",
            "emux-podman-pty-path",
        ])
        .output()
        .expect("fat emulate runs");

    let runtime_calls = std::fs::read_to_string(runtime_log).expect("runtime calls");
    assert!(
        runtime_calls.contains("adapter run --privileged --user root emux-fixture /bin/true"),
        "the PTY shell must not bypass the explicit rootful Podman adapter: {runtime_calls}"
    );
    assert!(
        !runtime_calls.contains("direct run emux-fixture"),
        "the user-level Docker-compatible path must remain unreachable: {runtime_calls}"
    );
}

#[test]
fn fat_emulate_stop_removes_explicit_rootful_podman_container() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let emux_dir = tempdir().expect("emux dir");
    let path_dir = tempdir().expect("path dir");
    let runtime_log = path_dir.path().join("runtime.log");

    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");
    write_executable(
        path_dir.path().join("docker"),
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'podman version 5.8.1\\n'; exit 0; fi\nif [ \"$1\" = \"info\" ]; then exit 125; fi\nexit 0\n",
    );
    write_executable(
        path_dir.path().join("sudo"),
        "#!/bin/sh\n[ \"$1\" = \"-n\" ] || exit 64\nshift\nruntime=$1\nshift\nprintf '%s\\n' \"$*\" >> \"$FAT_TEST_DOCKER_LOG\"\ncase \"$1 $2\" in\n  'container inspect') exit 0 ;;\n  'rm -f') exit 0 ;;\nesac\nif [ \"$1\" = info ]; then exit 0; fi\nexec \"$runtime\" \"$@\"\n",
    );
    write_fake_emux_recipe(emux_dir.path());

    let new_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware_path.to_str().expect("firmware path"),
            "--projects-dir",
            projects_dir.path().to_str().expect("projects dir"),
        ])
        .output()
        .expect("fat new runs");
    assert!(new_output.status.success(), "{new_output:?}");
    let project_dir = projects_dir.path().join("demo");
    std::fs::create_dir_all(project_dir.join("analysis")).expect("analysis dir");
    std::fs::write(
        project_dir.join("analysis/signals.txt"),
        "arch:mipsel\nfs:squashfs\ninit:busybox\n",
    )
    .expect("signals file");

    let emulate_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_TEST_DOCKER_LOG", &runtime_log)
        .env("FAT_EMUX_DIR", emux_dir.path())
        .env("FAT_EMUX_REFERENCE_DEVICE", "firmware/TRI227WF")
        .env("FAT_EMUX_TUN_DEVICE", emux_dir.path().join("tun"))
        .env("FAT_EMUX_ROOTFUL_PODMAN", "1")
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--backend",
            "emux",
            "--session-id",
            "emux-podman-stop",
        ])
        .output()
        .expect("fat emulate runs");
    assert!(emulate_output.status.success(), "{emulate_output:?}");
    let stdout = String::from_utf8_lossy(&emulate_output.stdout);
    let session_id = parse_keyed_output(&stdout)
        .get("session")
        .expect("session id")
        .to_string();

    let stop_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_TEST_DOCKER_LOG", &runtime_log)
        .env("FAT_EMUX_ROOTFUL_PODMAN", "1")
        .args([
            "emulate",
            "--project",
            project_dir.to_str().expect("project path"),
            "--stop",
            "--session-id",
            &session_id,
        ])
        .output()
        .expect("fat stop runs");
    assert!(stop_output.status.success(), "{stop_output:?}");
    let runtime_calls = std::fs::read_to_string(runtime_log).expect("runtime calls");
    assert!(
        runtime_calls.contains("container inspect emux-docker"),
        "{runtime_calls}"
    );
    assert!(
        runtime_calls.contains("rm -f emux-docker"),
        "{runtime_calls}"
    );
}

fn parse_keyed_output(stdout: &str) -> std::collections::HashMap<String, String> {
    stdout
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            Some((key.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

fn write_fake_emux_recipe(root: &std::path::Path) {
    std::fs::create_dir_all(root.join("files/emux/run")).expect("recipe dirs");
    std::fs::create_dir_all(root.join("files/emux/firmware/TRI227WF/kernel")).expect("device dirs");
    std::fs::create_dir_all(root.join("files/emux/firmware/DV-MIPSEL/kernel"))
        .expect("device dirs");
    std::fs::write(
        root.join("files/emux/firmware/devices"),
        "firmware/TRI227WF,qemu-system-arm,versatilepb,,,128M,zImage,TRI227WF,Trivision Camera\nfirmware/DV-MIPSEL,qemu-system-mipsel,malta,,,128M,vmlinux,DV-MIPSEL,Damn Vulnerable MIPS Router (Little Endian)\n",
    )
    .expect("devices file");
    std::fs::write(
        root.join("files/emux/firmware/TRI227WF/config"),
        "# fake emux config\nid=firmware/TRI227WF\nrootfs=rootfs\ninitcommands=\"/bin/sh\"\n",
    )
    .expect("config");
    std::fs::write(
        root.join("files/emux/firmware/DV-MIPSEL/config"),
        "# fake emux config\nid=firmware/DV-MIPSEL\nrootfs=rootfs\ninitcommands=\"/bin/sh\"\n",
    )
    .expect("config");
    write_executable(
        root.join("files/emux/firmware/TRI227WF/run-init"),
        "#!/bin/sh\nprintf 'userspace:%s\\n' \"$*\"\nexit 0\n",
    );
    write_executable(
        root.join("files/emux/firmware/DV-MIPSEL/run-init"),
        "#!/bin/sh\nprintf 'userspace:%s\\n' \"$*\"\nexit 0\n",
    );
    write_executable(
        root.join("run-emux-docker"),
        "#!/bin/sh\ntarget=\"${3:-$2}\"\ncmd=$(/usr/bin/python3 - \"$PWD\" \"$target\" <<'PY'\nimport pathlib\nimport sys\n\npwd = pathlib.Path(sys.argv[1])\ntarget = sys.argv[2]\n\ndef rewrite(text: str) -> str:\n    return text.replace('/home/r0/workspace/', f'{pwd}/workspace/').replace('/emux/', f'{pwd}/files/emux/')\n\nif target.startswith('/home/r0/workspace/'):\n    script_path = pathlib.Path(rewrite(target))\n    print(rewrite(script_path.read_text()), end='')\nelse:\n    print(rewrite(target), end='')\nPY\n)\nexport PATH=/usr/bin:/bin\nexec /bin/sh -c \"$cmd\"\n",
    );
    write_executable(
        root.join("emux-docker-shell"),
        "#!/bin/sh\ntarget=\"${3:-$2}\"\ncmd=$(/usr/bin/python3 - \"$PWD\" \"$target\" <<'PY'\nimport pathlib\nimport sys\n\npwd = pathlib.Path(sys.argv[1])\ntarget = sys.argv[2]\n\ndef rewrite(text: str) -> str:\n    return text.replace('/home/r0/workspace/', f'{pwd}/workspace/').replace('/emux/', f'{pwd}/files/emux/')\n\nif target.startswith('/home/r0/workspace/'):\n    script_path = pathlib.Path(rewrite(target))\n    print(rewrite(script_path.read_text()), end='')\nelse:\n    print(rewrite(target), end='')\nPY\n)\nexport PATH=/usr/bin:/bin\nexec /bin/sh -c \"$cmd\"\n",
    );
    for script in [
        "launcher",
        "hostfs-emux.sh",
        "emuxps",
        "emuxmaps",
        "emuxnetstat",
        "emuxgdb",
        "monitor",
    ] {
        let contents = match script {
            "launcher" => {
                "#!/bin/sh\nmarker=\"${fundialog%/*}/emux-runtime.marker\"\nprintf 'launch:%s\\n' \"$*\"\nprintf 'fundialog=%s\\n' \"$fundialog\"\nwhile [ -e \"$marker\" ]; do /bin/sleep 0.1; done\nexit 0\n"
            }
            "hostfs-emux.sh" => {
                "#!/bin/sh\nworkspace_dir=${fundialog%/*}\nmarker=\"$workspace_dir/emux-runtime.marker\"\n[ -e \"$marker\" ] || { printf 'missing-marker\\n' >&2; exit 42; }\nprintf 'userspace:%s\\n' \"$*\"\nprintf 'fundialog=%s\\n' \"$fundialog\"\nexit 0\n"
            }
            _ => "#!/bin/sh\nexit 0\n",
        };
        write_executable(root.join("files/emux/run").join(script), contents);
    }
    std::fs::write(root.join("tun"), b"tun").expect("tun");
}

fn write_executable(path: PathBuf, contents: &str) {
    std::fs::write(&path, contents).expect("script written");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("permissions");
    }
}
