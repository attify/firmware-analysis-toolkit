//! BMC-specific assets and measured service observations; lifecycle stays in emulate_cmd.
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::Command;

use fat_core::bmc_boot::BmcBootConfig;
use fat_emulate::system_runner::SystemLaunchSpec;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub fn materialize(source: &Path, spec: &SystemLaunchSpec, config: &BmcBootConfig) -> Result<()> {
    config.validate()?;
    let mut input = File::open(source)?;
    let size = input.metadata()?.len();
    if size > 512 * 1024 * 1024 || config.flash_offset + config.flash_size > size {
        return Err(
            "BMC source exceeds 512 MiB or does not contain the declared flash region".into(),
        );
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let input_sha256 = format!("{:x}", hasher.finalize());
    if !input_sha256.eq_ignore_ascii_case(&config.source_sha256) {
        return Err(format!(
            "BMC source SHA-256 mismatch: expected {}, observed {input_sha256}",
            config.source_sha256
        )
        .into());
    }
    input.seek(SeekFrom::Start(config.flash_offset))?;
    let mut flash = vec![0; config.flash_size as usize];
    input.read_exact(&mut flash)?;
    let root = Path::new(&spec.serial_log)
        .parent()
        .ok_or("missing BMC staging root")?;
    fs::create_dir_all(root)?;
    let mut assets = vec![
        serde_json::json!({"name": "flash.bin", "sha256": digest(&flash), "bytes": flash.len()}),
    ];
    let mut adaptations = Vec::new();
    if let Some(vendor) = &config.vendor_kernel {
        let fit = &flash[vendor.fit_offset as usize..];
        let kernel = fat_analyze::bmc_boot_assets::fit_payload(fit, &vendor.kernel_node, "kernel")?;
        let original_dtb =
            fat_analyze::bmc_boot_assets::fit_payload(fit, &vendor.dtb_node, "flat_dt")?;
        if let Some(node) = &vendor.initrd_node {
            let initrd = fat_analyze::bmc_boot_assets::fit_payload(fit, node, "ramdisk")?;
            write_new(&root.join("initrd.bin"), &initrd)?;
            assets.push(serde_json::json!({"name":"initrd.bin","sha256":digest(&initrd),"bytes":initrd.len()}));
        }
        let mut dtb = original_dtb.clone();
        for node in &vendor.disable_nodes {
            dtb = fat_analyze::bmc_boot_assets::disable_dtb_node(&dtb, node)?;
            adaptations.push(serde_json::json!({"node": node, "property": "status", "operation": "disable-enabled-node", "new_value": "disabled"}));
        }
        for (name, data) in [
            ("kernel.bin", &kernel),
            ("original.dtb", &original_dtb),
            ("boot.dtb", &dtb),
        ] {
            write_new(&root.join(name), data)?;
            assets.push(
                serde_json::json!({"name": name, "sha256": digest(data), "bytes": data.len()}),
            );
        }
    }
    write_new(Path::new(&spec.rootfs_image), &flash)?;
    let qemu = Command::new(&spec.qemu_binary).arg("--version").output()?;
    if !qemu.status.success() {
        return Err("cannot identify QEMU runtime".into());
    }
    let manifest = serde_json::json!({
        "version": 1, "mode": config.mode(), "profile": config,
        "source": source, "source_sha256": input_sha256, "source_bytes": size,
        "snapshot": true, "bootloader_bypassed": config.vendor_kernel.is_some(),
        "raw_env_hints_used": false, "assets": assets, "dtb_adaptations": adaptations,
        "qemu_version": String::from_utf8_lossy(&qemu.stdout).trim(),
        "command": std::iter::once(&spec.qemu_binary).chain(spec.args.iter()).collect::<Vec<_>>(),
        "surfaces": spec.registered_surfaces,
    });
    write_new(
        &root.join("bmc-boot-manifest.json"),
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?
        .write_all(bytes)?;
    Ok(())
}
fn digest(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceObservation {
    pub url: String,
    pub checked_at_unix: u64,
    pub tls_certificate_verified: bool,
    pub service_root_status: Option<u16>,
    pub service_root_valid: bool,
    pub managers_status: Option<u16>,
    pub unauthenticated_managers_denied: bool,
    pub service_root: Option<serde_json::Value>,
    pub failure: Option<String>,
}

pub fn probe_service(url: &str) -> ServiceObservation {
    probe_service_with(url, &mut fetch_response)
}

fn probe_service_with(
    url: &str,
    fetch: &mut impl FnMut(&str) -> Result<(u16, Vec<u8>)>,
) -> ServiceObservation {
    let mut observation = ServiceObservation {
        url: url.into(),
        checked_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        tls_certificate_verified: false,
        service_root_status: None,
        service_root_valid: false,
        managers_status: None,
        unauthenticated_managers_denied: false,
        service_root: None,
        failure: None,
    };
    // Probe only the fixed resource on a FAT-owned IPv4 loopback endpoint.
    let Some(authority) = url
        .strip_prefix("https://127.0.0.1:")
        .and_then(|s| s.strip_suffix("/redfish/v1/"))
    else {
        observation.failure = Some("invalid BMC loopback endpoint".into());
        return observation;
    };
    if authority
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .is_none()
    {
        observation.failure = Some("invalid BMC loopback port".into());
        return observation;
    }
    match fetch(url) {
        Ok((status, body)) => {
            observation.service_root_status = Some(status);
            match serde_json::from_slice(&body) {
                Ok(root) => {
                    observation.service_root_valid = valid_service_root(status, &root);
                    observation.service_root = Some(root);
                }
                Err(error) => {
                    observation.failure = Some(format!("ServiceRoot is not JSON: {error}"))
                }
            }
        }
        Err(error) => {
            observation.failure = Some(error.to_string());
            return observation;
        }
    }
    if observation.service_root_valid {
        match fetch(&format!("{url}Managers")) {
            Ok((status, _)) => {
                observation.managers_status = Some(status);
                observation.unauthenticated_managers_denied = status == 401;
            }
            Err(error) => observation.failure = Some(error.to_string()),
        }
    }
    observation
}

fn valid_service_root(status: u16, body: &serde_json::Value) -> bool {
    status == 200
        && matches!(
            body["@odata.id"].as_str(),
            Some("/redfish/v1" | "/redfish/v1/")
        )
        && body["@odata.type"]
            .as_str()
            .is_some_and(|t| t.starts_with("#ServiceRoot.") && t.ends_with(".ServiceRoot"))
}

fn fetch_response(url: &str) -> Result<(u16, Vec<u8>)> {
    let body = tempfile::NamedTempFile::new()?;
    // -q must be first: ignore user curlrc. No redirects, proxies or credentials.
    // BMC firmware uses a self-signed certificate; the observation records this.
    let output = Command::new("curl")
        .args([
            "-q",
            "--silent",
            "--show-error",
            "--insecure",
            "--noproxy",
            "*",
            "--proto",
            "=https",
            "--connect-timeout",
            "1",
            "--max-time",
            "2",
            "--max-filesize",
            "65536",
            "--output",
        ])
        .arg(body.path())
        .args(["--write-out", "%{http_code}", url])
        .output()?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr)
            .trim()
            .to_string()
            .into());
    }
    let status = String::from_utf8(output.stdout)?.parse::<u16>()?;
    let mut data = Vec::new();
    File::open(body.path())?
        .take(65537)
        .read_to_end(&mut data)?;
    if data.len() > 65536 {
        return Err("BMC response exceeds 64 KiB".into());
    }
    Ok((status, data))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bmc_preparation_failures_preserve_source_and_existing_outputs() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("input.bin");
        fs::write(&source, b"firmware").unwrap();
        let plan = fat_emulate::EmulationPlan::new("bmc", "qemu-direct", vec![]).unwrap();
        let mut config = BmcBootConfig {
            machine: "romulus-bmc".into(),
            flash_offset: 0,
            flash_size: 8,
            source_sha256: "a".repeat(64),
            nic_count: 1,
            management_nic: 0,
            vendor_kernel: None,
        };
        let root = dir.path().join("staging");
        let spec = fat_emulate::bmc_runner::build_bmc_blueprint(&plan, &root, &config)
            .unwrap()
            .launch;
        assert!(materialize(&source, &spec, &config)
            .unwrap_err()
            .to_string()
            .contains("SHA-256 mismatch"));
        assert!(!root.exists());
        config.source_sha256 = digest(b"firmware");
        config.flash_size = 16;
        assert!(materialize(&source, &spec, &config).is_err());
        assert!(!root.exists());
        config.flash_size = 8;
        fs::create_dir(&root).unwrap();
        fs::write(root.join("flash.bin"), b"existing").unwrap();
        assert!(materialize(&source, &spec, &config).is_err());
        assert_eq!(fs::read(root.join("flash.bin")).unwrap(), b"existing");
        assert_eq!(fs::read(source).unwrap(), b"firmware");
    }
    #[test]
    fn bmc_retains_plain_text_protected_resource_status() {
        let observed = probe_service_with("https://127.0.0.1:24443/redfish/v1/", &mut |url| {
            if url.ends_with("Managers") {
                Ok((401, b"Unauthorized".to_vec()))
            } else {
                Ok((200, br##"{"@odata.id":"/redfish/v1/","@odata.type":"#ServiceRoot.v1_5_0.ServiceRoot"}"##.to_vec()))
            }
        });
        assert!(observed.service_root_valid);
        assert_eq!(observed.managers_status, Some(401));
        assert!(observed.unauthenticated_managers_denied);
        assert!(observed.failure.is_none());
        let observed = probe_service_with("https://127.0.0.1:24443/redfish/v1/", &mut |_| {
            Ok((200, b"login page".to_vec()))
        });
        assert_eq!(observed.service_root_status, Some(200));
        assert!(!observed.service_root_valid);
    }
    #[test]
    fn bmc_readiness_requires_actual_service_root() {
        let root = serde_json::json!({"@odata.id":"/redfish/v1/", "@odata.type":"#ServiceRoot.v1_5_0.ServiceRoot"});
        assert!(valid_service_root(200, &root));
        let mut no_slash = root.clone();
        no_slash["@odata.id"] = serde_json::json!("/redfish/v1");
        assert!(valid_service_root(200, &no_slash));
        assert!(!valid_service_root(401, &root));
        assert!(!valid_service_root(
            200,
            &serde_json::json!({"error":"not ready"})
        ));
        assert!(!valid_service_root(
            200,
            &serde_json::json!({"@odata.type":"#ServiceRoot.fake", "@odata.id":"/redfish/v1/"})
        ));
    }
    #[test]
    fn bmc_probe_rejects_external_or_injected_endpoints() {
        for url in [
            "https://example.com/redfish/v1/",
            "https://127.0.0.1:443@evil/redfish/v1/",
            "https://127.0.0.1:0/redfish/v1/",
        ] {
            assert_eq!(
                probe_service(url).failure.as_deref(),
                Some(if url.contains(":0/") || url.contains("@evil") {
                    "invalid BMC loopback port"
                } else {
                    "invalid BMC loopback endpoint"
                })
            );
        }
    }
}
