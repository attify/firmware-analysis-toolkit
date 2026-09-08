use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn write_firmware(path: &std::path::Path, words: &[u32]) {
    let mut bytes = Vec::new();
    for word in words {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    fs::write(path, bytes).expect("write firmware");
}

#[test]
fn fat_inspect_svd_rank_json_emits_ranked_candidates() {
    let dir = tempdir().expect("tempdir");
    let firmware = dir.path().join("firmware.bin");
    let corpus = dir.path().join("svds");
    fs::create_dir(&corpus).expect("corpus dir");

    write_firmware(
        &firmware,
        &[
            0x4001_1000,
            0x4001_100C,
            0x5800_1C00,
            0x5800_1C10,
            0x2000_1000,
        ],
    );
    fs::write(
        corpus.join("match.svd"),
        r#"<device><name>MATCH_DEVICE</name><peripherals>
<peripheral><name>USART1</name><baseAddress>0x40011000</baseAddress><registers>
<register><name>CR1</name><addressOffset>0x0</addressOffset></register>
<register><name>BRR</name><addressOffset>0x0c</addressOffset></register>
</registers></peripheral>
<peripheral><name>I2C4</name><baseAddress>0x58001c00</baseAddress><registers>
<register><name>CR1</name><addressOffset>0x0</addressOffset></register>
<register><name>TIMEOUTR</name><addressOffset>0x10</addressOffset></register>
</registers></peripheral>
</peripherals></device>"#,
    )
    .expect("match svd");
    fs::write(
        corpus.join("miss.svd"),
        r#"<device><name>MISS_DEVICE</name><peripherals>
<peripheral><name>UART0</name><baseAddress>0x40000000</baseAddress><registers>
<register><name>DR</name><addressOffset>0x0</addressOffset></register>
</registers></peripheral>
</peripherals></device>"#,
    )
    .expect("miss svd");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "svd-rank",
            "--file",
            firmware.to_str().expect("firmware path"),
            "--svd-corpus",
            corpus.to_str().expect("corpus path"),
            "--json",
        ])
        .output()
        .expect("fat inspect svd-rank runs");

    assert!(
        output.status.success(),
        "status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(report["schema_version"], "svd-rank/v1");
    assert_eq!(report["candidates"][0]["device"], "MATCH_DEVICE");
    assert_eq!(report["candidates"][0]["matched_register_count"], 4);
    assert_eq!(report["candidates"][1]["device"], "MISS_DEVICE");
}
