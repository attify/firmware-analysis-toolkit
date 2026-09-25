use std::path::{Path, PathBuf};

use fat_core::data_dir::{DataResolver, DataRootOrigin};
use tempfile::tempdir;

fn resource(root: &Path, relative: &str) -> PathBuf {
    let path = root.join(relative);
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn marked_checkout(root: &Path) {
    std::fs::write(root.join("Cargo.toml"), "[workspace]\n").unwrap();
    std::fs::create_dir_all(root.join("profiles")).unwrap();
}

#[test]
fn explicit_root_wins_over_every_other_source() {
    let temp = tempdir().unwrap();
    let explicit = resource(&temp.path().join("explicit"), "profiles/rehosting");
    let environment = resource(&temp.path().join("environment"), "profiles/rehosting");
    let prefix = temp.path().join("prefix");
    let executable = prefix.join("bin/fat");
    let installed = resource(&prefix.join("share/fat"), "profiles/rehosting");
    let user = resource(&temp.path().join("user"), "profiles/rehosting");
    let development = temp.path().join("development");
    std::fs::create_dir_all(&development).unwrap();
    marked_checkout(&development);
    let checkout = resource(&development, "profiles/rehosting");

    let resolver = DataResolver::from_paths(
        Some(explicit.parent().unwrap().parent().unwrap().to_path_buf()),
        Some(
            environment
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .to_path_buf(),
        ),
        Some(executable),
        Some(user.parent().unwrap().parent().unwrap().to_path_buf()),
        Some(development),
    );
    let resolved = resolver.resolve_required("profiles/rehosting").unwrap();

    assert_eq!(resolved.origin, DataRootOrigin::Explicit);
    assert_eq!(resolved.path, explicit);
    assert_ne!(resolved.path, environment);
    assert_ne!(resolved.path, installed);
    assert_ne!(resolved.path, user);
    assert_ne!(resolved.path, checkout);
}

#[test]
fn resolver_falls_back_through_environment_installed_user_and_development_roots() {
    let temp = tempdir().unwrap();
    let environment_root = temp.path().join("environment");
    let prefix = temp.path().join("prefix");
    let executable = prefix.join("bin/fat");
    let installed_root = prefix.join("share/fat");
    let user_root = temp.path().join("user");
    let development_root = temp.path().join("development");
    std::fs::create_dir_all(&development_root).unwrap();
    marked_checkout(&development_root);

    let relative = "schemas/rehosting-pack.json";
    for (root, expected_origin) in [
        (&environment_root, DataRootOrigin::Environment),
        (&installed_root, DataRootOrigin::ExecutableRelative),
        (&user_root, DataRootOrigin::User),
        (&development_root, DataRootOrigin::Development),
    ] {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{}\n").unwrap();

        let resolver = DataResolver::from_paths(
            None,
            Some(environment_root.clone()),
            Some(executable.clone()),
            Some(user_root.clone()),
            Some(development_root.clone()),
        );
        let resolved = resolver.resolve_required(relative).unwrap();
        assert_eq!(resolved.origin, expected_origin);
        assert_eq!(resolved.path, path);

        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn portable_bundle_uses_adjacent_data_before_parent_prefix_or_user_data() {
    let temp = tempdir().unwrap();
    let prefix = temp.path().join("portable bundle");
    let adjacent = resource(&prefix.join("share/fat"), "profiles/rehosting");
    resource(&temp.path().join("share/fat"), "profiles/rehosting");
    let user = temp.path().join("user");
    resource(&user, "profiles/rehosting");

    for name in ["fat", "fat.exe"] {
        let resolver = DataResolver::from_paths(
            None,
            None,
            Some(prefix.join(name)),
            Some(user.clone()),
            None,
        );
        let resolved = resolver.resolve_required("profiles/rehosting").unwrap();
        assert_eq!(resolved.origin, DataRootOrigin::ExecutableRelative);
        assert_eq!(resolved.path, adjacent);
    }
}

#[test]
fn unmarked_development_directory_is_not_a_candidate() {
    let temp = tempdir().unwrap();
    let development = temp.path().join("not-a-checkout");
    let path = development.join("profiles/rehosting");
    std::fs::create_dir_all(&path).unwrap();

    let resolver = DataResolver::from_paths(None, None, None, None, Some(development));
    let error = resolver.resolve_required("profiles/rehosting").unwrap_err();

    assert!(error.searched.is_empty());
}

#[test]
fn missing_resource_error_lists_every_searched_root_and_origin() {
    let temp = tempdir().unwrap();
    let explicit = temp.path().join("explicit");
    let environment = temp.path().join("environment");
    let user = temp.path().join("user");
    let development = temp.path().join("development");
    std::fs::create_dir_all(&development).unwrap();
    marked_checkout(&development);

    let resolver = DataResolver::from_paths(
        Some(explicit.clone()),
        Some(environment.clone()),
        None,
        Some(user.clone()),
        Some(development.clone()),
    );
    let error = resolver
        .resolve_required("schemas/missing.json")
        .unwrap_err();
    let rendered = error.to_string();

    assert_eq!(error.searched.len(), 4);
    assert!(rendered.contains("schemas/missing.json"));
    assert!(rendered.contains("explicit"));
    assert!(rendered.contains("environment"));
    assert!(rendered.contains("user"));
    assert!(rendered.contains("development"));
}

#[test]
fn managed_root_resolves_resources_from_the_active_version() {
    let temp = tempdir().unwrap();
    let managed_root = temp.path().join("managed");
    let active_root = managed_root.join("versions/0.1.4");
    let resource = active_root.join("profiles/rehosting");
    std::fs::create_dir_all(&resource).unwrap();
    std::fs::write(
        active_root.join("manifest.json"),
        serde_json::json!({
            "schema_version": 1,
            "data_version": "0.1.4",
            "compatible_fat": format!("={}", env!("CARGO_PKG_VERSION")),
            "files": [],
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(
        managed_root.join("active.json"),
        r#"{"data_version":"0.1.4","relative_path":"versions/0.1.4"}"#,
    )
    .unwrap();

    let resolver = DataResolver::from_paths(Some(managed_root), None, None, None, None);
    let resolved = resolver.resolve_required("profiles/rehosting").unwrap();

    assert_eq!(resolved.path, resource);
    assert_eq!(resolved.root, active_root);
    assert_eq!(resolved.origin, DataRootOrigin::Explicit);
}

#[test]
fn managed_active_version_outranks_stale_direct_files() {
    let temp = tempdir().unwrap();
    let managed_root = temp.path().join("managed");
    let stale = resource(&managed_root, "profiles/rehosting");
    let active_root = managed_root.join("versions/0.1.4");
    let active = resource(&active_root, "profiles/rehosting");
    std::fs::write(
        active_root.join("manifest.json"),
        serde_json::json!({
            "schema_version": 1,
            "data_version": "0.1.4",
            "compatible_fat": format!("={}", env!("CARGO_PKG_VERSION")),
            "files": [],
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(
        managed_root.join("active.json"),
        r#"{"data_version":"0.1.4","relative_path":"versions/0.1.4"}"#,
    )
    .unwrap();

    let resolver = DataResolver::from_paths(Some(managed_root), None, None, None, None);
    let resolved = resolver.resolve_required("profiles/rehosting").unwrap();

    assert_eq!(resolved.path, active);
    assert_ne!(resolved.path, stale);
}

#[test]
fn invalid_authoritative_active_record_blocks_lower_priority_fallback() {
    let temp = tempdir().unwrap();
    let prefix = temp.path().join("prefix");
    let executable = prefix.join("bin/fat");
    let installed_root = prefix.join("share/fat");
    std::fs::create_dir_all(&installed_root).unwrap();
    std::fs::write(
        installed_root.join("active.json"),
        r#"{"data_version":"0.1.4","relative_path":"versions/missing"}"#,
    )
    .unwrap();

    let user_root = temp.path().join("user");
    let fallback = resource(&user_root, "profiles/rehosting");
    let resolver = DataResolver::from_paths(None, None, Some(executable), Some(user_root), None);

    let error = resolver
        .resolve_required("profiles/rehosting")
        .expect_err("present invalid active.json must be authoritative");

    assert_eq!(error.searched[0].origin, DataRootOrigin::ExecutableRelative);
    assert!(
        !error
            .searched
            .iter()
            .any(|root| root.origin == DataRootOrigin::User),
        "lower-priority fallback must not be searched: {error:?}"
    );
    assert!(
        fallback.exists(),
        "the rejected fallback must be otherwise valid"
    );
}

#[test]
fn release_builds_never_include_the_compile_time_checkout_as_a_data_root() {
    if cfg!(debug_assertions) {
        return;
    }
    let resolver = DataResolver::for_current_process(None);
    assert!(
        resolver
            .roots()
            .iter()
            .all(|root| root.origin != DataRootOrigin::Development),
        "release binaries must resolve only explicit, environment, installed, or user data"
    );
}
