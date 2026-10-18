//! Explicit BMC boot contracts. Raw bootloader strings are never inputs.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BmcBootConfig {
    pub machine: String,
    pub flash_offset: u64,
    pub flash_size: u64,
    pub source_sha256: String,
    pub nic_count: u8,
    pub management_nic: u8,
    #[serde(default)]
    pub vendor_kernel: Option<BmcVendorKernel>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BmcVendorKernel {
    /// Offset relative to the carved flash region.
    pub fit_offset: u64,
    pub kernel_node: String,
    pub dtb_node: String,
    #[serde(default)]
    pub initrd_node: Option<String>,
    pub boot_args: String,
    #[serde(default)]
    pub disable_nodes: Vec<String>,
}

impl BmcBootConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.machine.is_empty()
            || self.machine.len() > 128
            || !self
                .machine
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.,=".contains(&b))
        {
            return Err("BMC machine must be a bounded QEMU machine specification".into());
        }
        if self.flash_size == 0
            || self.flash_size > 256 * 1024 * 1024
            || self.flash_offset.checked_add(self.flash_size).is_none()
        {
            return Err(
                "BMC flash region must be nonempty, at most 256 MiB and nonoverflowing".into(),
            );
        }
        if self.source_sha256.len() != 64
            || !self.source_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("BMC profile requires an exact source SHA-256".into());
        }
        if !(1..=4).contains(&self.nic_count) || self.management_nic >= self.nic_count {
            return Err("BMC NIC count must be 1..4 and contain the management NIC".into());
        }
        if let Some(vendor) = &self.vendor_kernel {
            if vendor.fit_offset >= self.flash_size
                || vendor.boot_args.trim().is_empty()
                || vendor.boot_args.len() > 4096
                || vendor.boot_args.contains(['\0', '\n', '\r'])
            {
                return Err("vendor-kernel boot requires an in-flash FIT offset and explicit bounded boot args".into());
            }
            for name in [&vendor.kernel_node, &vendor.dtb_node]
                .into_iter()
                .chain(vendor.initrd_node.iter())
            {
                if name.is_empty() || name.len() > 255 || name.contains(['/', '\0']) {
                    return Err("FIT image node names must be nonempty single components".into());
                }
            }
            if vendor.disable_nodes.len() > 16
                || vendor.disable_nodes.iter().any(|path| {
                    !path.starts_with('/')
                        || path.len() > 1024
                        || path.contains('\0')
                        || path
                            .split('/')
                            .skip(1)
                            .any(|part| matches!(part, "" | "." | ".."))
                })
            {
                return Err("disabled DTB nodes must be bounded absolute normalized paths".into());
            }
        }
        Ok(())
    }
    pub fn mode(&self) -> &'static str {
        if self.vendor_kernel.is_some() {
            "vendor-kernel"
        } else {
            "full-flash"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> BmcBootConfig {
        BmcBootConfig {
            machine: "romulus-bmc".into(),
            flash_offset: 0,
            flash_size: 32 * 1024 * 1024,
            source_sha256: "a".repeat(64),
            nic_count: 1,
            management_nic: 0,
            vendor_kernel: None,
        }
    }
    #[test]
    fn bmc_rejects_bad_geometry_identity_and_network() {
        let good = config();
        assert!(good.validate().is_ok());
        for bad in [
            BmcBootConfig {
                flash_size: 0,
                ..good.clone()
            },
            BmcBootConfig {
                flash_offset: u64::MAX,
                ..good.clone()
            },
            BmcBootConfig {
                source_sha256: "unknown".into(),
                ..good.clone()
            },
            BmcBootConfig {
                nic_count: 5,
                ..good.clone()
            },
            BmcBootConfig {
                management_nic: 1,
                ..good.clone()
            },
            BmcBootConfig {
                machine: "romulus-bmc,invalid=\n".into(),
                ..good
            },
        ] {
            assert!(bad.validate().is_err(), "accepted {bad:?}");
        }
    }
    #[test]
    fn bmc_rejects_implicit_or_unbounded_vendor_kernel() {
        let mut c = config();
        c.vendor_kernel = Some(BmcVendorKernel {
            fit_offset: c.flash_size,
            kernel_node: "kernel@1".into(),
            dtb_node: "fdt@board".into(),
            initrd_node: None,
            boot_args: "console=ttyS4".into(),
            disable_nodes: vec![],
        });
        assert!(c.validate().is_err());
        c.vendor_kernel.as_mut().unwrap().fit_offset = 0;
        assert!(c.validate().is_ok());
        c.vendor_kernel
            .as_mut()
            .unwrap()
            .disable_nodes
            .push("/../hace".into());
        assert!(c.validate().is_err());
    }
    #[test]
    fn bmc_rejects_unknown_fields() {
        let mut value = serde_json::to_value(config()).unwrap();
        value["vendor_kernal"] = serde_json::json!({});
        assert!(serde_json::from_value::<BmcBootConfig>(value).is_err());
    }
}
