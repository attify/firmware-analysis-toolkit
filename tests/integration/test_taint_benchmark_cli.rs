use std::process::Command;

use tempfile::tempdir;

#[test]
fn fat_benchmark_taint_reports_dataset_summary_from_fixture_findings() {
    let dir = tempdir().expect("tempdir");
    let findings_path = dir.path().join("findings.json");
    let manifest_path = dir.path().join("manifest.json");

    std::fs::write(
        &findings_path,
        serde_json::json!([
            {
                "id": "ANGR-0001",
                "title": "getenv -> system in httpd",
                "severity": "High",
                "chain": [
                    {
                        "binary": "httpd",
                        "function": "handle_apply",
                        "location": "0x1000",
                        "action": "getenv()",
                        "edge_type": "DirectFlow"
                    },
                    {
                        "binary": "httpd",
                        "function": "handle_apply",
                        "location": "0x1010",
                        "action": "system()",
                        "edge_type": "DirectFlow"
                    }
                ],
                "status": "Proven",
                "status_reason": "confirmed-rd",
                "confidence": 0.95,
                "source_class": "Primary"
            },
            {
                "id": "ANGR-0002",
                "title": "nvram_get -> system in rc",
                "severity": "Low",
                "chain": [
                    {
                        "binary": "rc",
                        "function": "apply_hostname",
                        "location": "0x2000",
                        "action": "nvram_get()",
                        "edge_type": {
                            "ConfigKeyBridge": {
                                "config_file": "/tmp/router.conf",
                                "config_key": "machine_name"
                            }
                        }
                    },
                    {
                        "binary": "rc",
                        "function": "apply_hostname",
                        "location": "0x2010",
                        "action": "system()",
                        "edge_type": "DirectFlow"
                    }
                ],
                "status": "Candidate",
                "status_reason": "cross-binary-heuristic",
                "confidence": 0.40,
                "source_class": "Secondary"
            }
        ])
        .to_string(),
    )
    .expect("write findings fixture");

    std::fs::write(
        &manifest_path,
        serde_json::json!({
            "dataset": "fixture-mini",
            "cases": [
                {
                    "id": "router-httpd",
                    "findings_fixture": findings_path,
                    "duration_ms": 42
                }
            ]
        })
        .to_string(),
    )
    .expect("write benchmark manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "benchmark",
            "taint",
            "--dataset",
            manifest_path.to_str().expect("manifest path"),
            "--json",
        ])
        .output()
        .expect("fat benchmark taint runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).expect("benchmark taint returns JSON");

    assert_eq!(report["dataset"], "fixture-mini");
    assert_eq!(report["cases"], 1);
    assert_eq!(report["total_findings"], 2);
    assert_eq!(report["total_duration_ms"], 42);
    assert_eq!(report["by_severity"]["high"], 1);
    assert_eq!(report["by_severity"]["low"], 1);
    assert_eq!(report["by_status"]["proven"], 1);
    assert_eq!(report["by_status"]["candidate"], 1);
}
