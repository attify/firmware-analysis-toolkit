use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

use tempfile::tempdir;

#[test]
fn fat_emux_debug_plane_exposes_process_maps_and_gdb_helpers() {
    let projects_dir = tempdir().expect("projects dir");
    let firmware_dir = tempdir().expect("firmware dir");
    let emux_dir = tempdir().expect("emux dir");
    let path_dir = tempdir().expect("path dir");

    let firmware_path = firmware_dir.path().join("demo.bin");
    std::fs::write(&firmware_path, b"firmware-bytes").expect("firmware file");

    write_executable(
        path_dir.path().join("docker"),
        "#!/bin/sh\nif [ \"$1\" = \"info\" ]; then printf '29.2.1\\n'; exit 0; fi\nif [ \"$1\" = \"exec\" ]; then\n  cmd=\"$5\"\n  target=\"${cmd##* }\"\n  case \"$cmd\" in\n    */emuxps)\n      printf 'PID TTY STAT TIME COMMAND\\n'\n      printf '1 ? Ss 00:00 /sbin/init\\n'\n      printf '77 ? S 00:00 /usr/sbin/uhttpd\\n'\n      exit 0\n      ;;\n    */emuxmaps*)\n      printf 'maps-target:%s\\n' \"$target\"\n      printf 'maps-helper:ready\\n'\n      exit 0\n      ;;\n    */emuxgdb*)\n      printf 'gdb-target:%s\\n' \"$target\"\n      printf 'gdb-helper:ready\\n'\n      exit 0\n      ;;\n    */emuxnetstat*)\n      printf 'Active Internet connections (only servers)\\n'\n      printf 'Proto Recv-Q Send-Q Local Address           Foreign Address         State\\n'\n      printf 'tcp        0      0 0.0.0.0:22222           0.0.0.0:*               LISTEN\\n'\n      exit 0\n      ;;\n    *127.0.0.1*55555*)\n      printf 'monitor-helper:ready\\n'\n      printf 'monitor-command:info version\\n'\n      exit 0\n      ;;\n  esac\nfi\nprintf 'docker:%s\\n' \"$*\"\nexit 0\n",
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
    let parsed = parse_keyed_output(&stdout);
    let session_id = parsed.get("session").expect("session id").to_string();
    let run_id = parsed.get("run").expect("run id").to_string();

    let debug_surfaces_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_EMUX_DIR", emux_dir.path())
        .env("FAT_EMUX_REFERENCE_DEVICE", "firmware/TRI227WF")
        .args([
            "debug",
            "surfaces",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            &session_id,
        ])
        .output()
        .expect("fat debug surfaces runs");

    assert!(
        debug_surfaces_output.status.success(),
        "{debug_surfaces_output:?}"
    );
    let debug_surfaces_stdout = String::from_utf8_lossy(&debug_surfaces_output.stdout);
    assert!(debug_surfaces_stdout.contains("surface count: 4"));
    assert!(debug_surfaces_stdout.contains("surface port-8080 [forwarded-port]"));
    assert!(debug_surfaces_stdout.contains("surface emux-userspace [shell]"));
    assert!(debug_surfaces_stdout.contains("surface emux-monitor [monitor]"));
    assert!(debug_surfaces_stdout.contains("surface emux-gdb [debugger]"));

    let observe_net_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_EMUX_DIR", emux_dir.path())
        .env("FAT_EMUX_REFERENCE_DEVICE", "firmware/TRI227WF")
        .args([
            "observe",
            "net",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            &session_id,
        ])
        .output()
        .expect("fat observe net runs");

    assert!(
        observe_net_output.status.success(),
        "{observe_net_output:?}"
    );
    let observe_net_stdout = String::from_utf8_lossy(&observe_net_output.stdout);
    assert!(observe_net_stdout.contains("network endpoint count: 1"));
    assert!(observe_net_stdout.contains("network tcp-22222-LISTEN [service]: tcp://0.0.0.0:22222"));

    let observe_ps_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_EMUX_DIR", emux_dir.path())
        .env("FAT_EMUX_REFERENCE_DEVICE", "firmware/TRI227WF")
        .args([
            "observe",
            "ps",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            &session_id,
        ])
        .output()
        .expect("fat observe ps runs");

    assert!(observe_ps_output.status.success(), "{observe_ps_output:?}");
    let observe_ps_stdout = String::from_utf8_lossy(&observe_ps_output.stdout);
    assert!(observe_ps_stdout.contains("process count: 2"));
    assert!(observe_ps_stdout.contains("process 1"));
    assert!(observe_ps_stdout.contains("process 77"));

    let debug_maps_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_EMUX_DIR", emux_dir.path())
        .env("FAT_EMUX_REFERENCE_DEVICE", "firmware/TRI227WF")
        .args([
            "debug",
            "maps",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            &session_id,
            "--target",
            "77",
        ])
        .output()
        .expect("fat debug maps runs");

    assert!(debug_maps_output.status.success(), "{debug_maps_output:?}");
    let debug_maps_stdout = String::from_utf8_lossy(&debug_maps_output.stdout);
    assert!(debug_maps_stdout.contains("maps-helper:ready"));

    let debug_gdb_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_EMUX_DIR", emux_dir.path())
        .env("FAT_EMUX_REFERENCE_DEVICE", "firmware/TRI227WF")
        .args([
            "debug",
            "gdb",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            &session_id,
            "--target",
            "uhttpd",
        ])
        .output()
        .expect("fat debug gdb runs");

    assert!(debug_gdb_output.status.success(), "{debug_gdb_output:?}");
    let debug_gdb_stdout = String::from_utf8_lossy(&debug_gdb_output.stdout);
    assert!(debug_gdb_stdout.contains("gdb-helper:ready"));

    let debug_monitor_output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("PATH", path_dir.path())
        .env("FAT_EMUX_DIR", emux_dir.path())
        .env("FAT_EMUX_REFERENCE_DEVICE", "firmware/TRI227WF")
        .args([
            "debug",
            "monitor",
            "--project",
            project_dir.to_str().expect("project path"),
            "--session-id",
            &session_id,
            "--command",
            "info version",
        ])
        .output()
        .expect("fat debug monitor runs");

    assert!(
        debug_monitor_output.status.success(),
        "{debug_monitor_output:?}"
    );
    let debug_monitor_stdout = String::from_utf8_lossy(&debug_monitor_output.stdout);
    assert!(debug_monitor_stdout.contains("monitor-helper:ready"));
    assert!(debug_monitor_stdout.contains("monitor-command:info version"));

    let store = fat_core::runtime_store::RuntimeStore::open(&project_dir).expect("runtime store");
    let outputs_dir = store
        .run_path(&session_id, &run_id)
        .parent()
        .expect("run parent")
        .join("outputs");
    assert!(outputs_dir.join("process-snapshot.json").exists());
    assert!(outputs_dir.join("debug-maps-transcript.json").exists());
    assert!(outputs_dir.join("debug-monitor-transcript.json").exists());
    assert!(outputs_dir.join("debug-gdb-transcript.json").exists());
}

fn parse_keyed_output(stdout: &str) -> HashMap<String, String> {
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
        "# fake emux config\nid=firmware/DV-MIPSEL\nnvram=\nrootfs=rootfs-mipsel\nrandomize_va_space=0\nlegacy_va_layout=1\nmount_dev_tree=1\ninitcommands=\"/etc/rc.local;/bin/sh\"\n",
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
            "emuxps" => {
                "#!/bin/sh\nprintf 'PID TTY STAT TIME COMMAND\\n'\nprintf '1 ? Ss 00:00 /sbin/init\\n'\nprintf '77 ? S 00:00 /usr/sbin/uhttpd\\n'\n"
            }
            "emuxmaps" => {
                "#!/bin/sh\nprintf 'maps-target:%s\\n' \"$1\"\nprintf 'maps-helper:ready\\n'\n"
            }
            "emuxgdb" => {
                "#!/bin/sh\nprintf 'gdb-target:%s\\n' \"$1\"\nprintf 'gdb-helper:ready\\n'\n"
            }
            "monitor" => "#!/bin/sh\nprintf 'monitor-helper:ready\\n'\n",
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
