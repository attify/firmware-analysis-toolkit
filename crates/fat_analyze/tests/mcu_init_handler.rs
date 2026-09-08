//! Compressed-`.data` handler classification and toolchain fingerprint.
//!
//! `scatter-load-lz-*.bin` are real `arm-none-eabi-gcc` 16.2.0 output — see
//! `tests/fixtures/mcu/init-table/Makefile`. Their init table carries four
//! records whose handlers are, in order, a word copy, a zero fill, an LZSS
//! decompressor with a 3/4 control-byte split, and a plain byte-wise memcpy.
//! The last one is the point: it has the same byte granularity as the decoder
//! and none of the codec machinery, so it is the false positive a shape
//! classifier is most likely to produce.
//!
//! The `-os` and `-o0` variants exist because optimisation level changes how
//! the codec is compiled — GCC folds the extended-count fallback into an `it`
//! block at `-Os` and into a stack round trip at `-O0` — while the shape being
//! detected does not change.

use std::path::PathBuf;

use fat_analyze::mcu_init_handler::classify_handler;
use fat_analyze::mcu_init_table::ImageAddressing;
use fat_analyze::mcu_inspect::{
    build_address_hypotheses, classify_image_layout, inspect_file, McuInspectRequest,
};
use fat_core::mcu_inspection::{
    CompressorVariant, HandlerEvidenceKind, InitHandlerKind, InitTableReport, McuInspectionReport,
};

const LZ_OS: &str = "scatter-load-lz-os.bin";
const LZ_O0: &str = "scatter-load-lz-o0.bin";
const PLAIN: &str = "scatter-load.bin";

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/mcu/init-table")
        .join(name)
}

fn inspect(name: &str) -> McuInspectionReport {
    inspect_file(&McuInspectRequest {
        file: fixture_path(name),
        user_base: None,
        user_family: None,
        bundle_root: None,
        backend_preference: None,
    })
    .expect("mcu inspection report")
}

fn init_table(name: &str) -> InitTableReport {
    inspect(name).init_table.expect("init descriptor table")
}

/// The record whose destination is the decompressed output area, identified by
/// its position rather than by a hardcoded address so the test survives a
/// rebuild that moves the code.
fn decompress_record(table: &InitTableReport) -> &fat_core::mcu_inspection::InitRecord {
    table
        .records
        .iter()
        .find(|record| record.handler_kind == InitHandlerKind::Decompress)
        .unwrap_or_else(|| panic!("no decompressing record in {table:#?}"))
}

#[test]
fn a_packed_data_handler_is_classified_as_a_decompressor() {
    for fixture in [LZ_OS, LZ_O0] {
        let table = init_table(fixture);
        let record = decompress_record(&table);
        let classification = record
            .handler_classification
            .as_ref()
            .unwrap_or_else(|| panic!("{fixture}: no classification"));

        assert_eq!(classification.kind, InitHandlerKind::Decompress);
        assert_eq!(
            classification.compressor,
            Some(CompressorVariant::Lzss {
                literal_bits: 3,
                match_bits: 4,
            }),
            "{fixture}"
        );
        assert!(
            classification.confidence >= 0.7,
            "{fixture}: confidence {}",
            classification.confidence
        );
    }
}

#[test]
fn the_decompressor_classification_carries_its_supporting_observations() {
    let table = init_table(LZ_OS);
    let classification = decompress_record(&table)
        .handler_classification
        .as_ref()
        .expect("classification")
        .clone();

    let kinds: Vec<&HandlerEvidenceKind> = classification
        .evidence
        .iter()
        .map(|evidence| &evidence.kind)
        .collect();
    assert!(
        classification.evidence.len() >= 3,
        "expected at least three observations, got {kinds:?}"
    );
    assert!(kinds.contains(&&HandlerEvidenceKind::ControlByteSplit {
        literal_bits: 3,
        match_bits: 4,
    }));
    assert!(kinds.contains(&&HandlerEvidenceKind::LiteralCopyLoop));
    assert!(kinds.contains(&&HandlerEvidenceKind::BackReferenceLoop));
    assert!(kinds.contains(&&HandlerEvidenceKind::ExtendedCountFallback));

    for evidence in &classification.evidence {
        assert!(
            (0x0800_0000..0x0800_1000).contains(&evidence.instruction_addr),
            "evidence points outside the image: {evidence:?}"
        );
        assert!(!evidence.description.is_empty());
    }
}

#[test]
fn a_missing_observation_lowers_confidence_rather_than_the_verdict() {
    // At -O0 the extended-count fallback becomes a stack round trip that the
    // classifier does not recognise. The codec is still a codec; the report
    // must say so with less confidence, not silently drop to `custom`.
    let os = init_table(LZ_OS);
    let o0 = init_table(LZ_O0);
    let os_classification = decompress_record(&os)
        .handler_classification
        .clone()
        .expect("classification");
    let o0_classification = decompress_record(&o0)
        .handler_classification
        .clone()
        .expect("classification");

    assert_eq!(o0_classification.kind, InitHandlerKind::Decompress);
    assert!(o0_classification.evidence.len() < os_classification.evidence.len());
    assert!(o0_classification.confidence < os_classification.confidence);
}

#[test]
fn a_plain_byte_wise_memcpy_is_not_mistaken_for_a_decompressor() {
    // Same byte granularity as the decoder, none of the codec machinery. This
    // is the false positive a shape classifier is most likely to produce.
    for fixture in [LZ_OS, LZ_O0] {
        let table = init_table(fixture);
        let custom: Vec<_> = table
            .records
            .iter()
            .filter(|record| record.handler_kind == InitHandlerKind::Custom)
            .collect();
        assert_eq!(custom.len(), 1, "{fixture}: {table:#?}");

        let classification = custom[0]
            .handler_classification
            .as_ref()
            .expect("classification");
        assert_eq!(classification.kind, InitHandlerKind::Custom);
        assert_eq!(classification.compressor, None);
        assert!(
            classification.evidence.is_empty(),
            "{fixture}: an unrecognised shape must not carry evidence"
        );
        assert!(
            classification.confidence <= 0.3,
            "{fixture}: confidence {}",
            classification.confidence
        );
    }
}

#[test]
fn copy_and_fill_handlers_keep_their_classification_and_gain_evidence() {
    let table = init_table(LZ_OS);

    let copy = table
        .records
        .iter()
        .find(|record| record.handler_kind == InitHandlerKind::WordCopy)
        .expect("word copy record");
    let copy_classification = copy
        .handler_classification
        .as_ref()
        .expect("classification");
    assert!(copy_classification.confidence >= 0.9);
    assert_eq!(
        copy_classification.evidence.first().map(|e| &e.kind),
        Some(&HandlerEvidenceKind::WordCopyLoop)
    );

    let zero = table
        .records
        .iter()
        .find(|record| record.handler_kind == InitHandlerKind::ZeroInit)
        .expect("zero init record");
    let zero_classification = zero
        .handler_classification
        .as_ref()
        .expect("classification");
    assert!(zero_classification.confidence >= 0.9);
    assert_eq!(
        zero_classification.evidence.first().map(|e| &e.kind),
        Some(&HandlerEvidenceKind::ZeroInitLoop)
    );
}

#[test]
fn packed_data_produces_a_toolchain_fingerprint() {
    let table = init_table(LZ_OS);
    let fingerprint = table.toolchain_fingerprint.expect("toolchain fingerprint");

    assert_eq!(
        fingerprint.data_compression,
        Some(CompressorVariant::Lzss {
            literal_bits: 3,
            match_bits: 4,
        })
    );
    assert_eq!(fingerprint.consistent_with, vec!["iar-ewarm".to_string()]);
    // The vendor is a hint, not an identification, and the report must not
    // present it as more than that.
    assert!(fingerprint.confidence <= 0.5);
    assert!(fingerprint
        .notes
        .iter()
        .any(|note| note.contains("does not identify the vendor")));
}

#[test]
fn an_uncompressed_image_gets_no_toolchain_fingerprint() {
    let report = inspect(PLAIN);
    let table = report.init_table.clone().expect("init table");
    assert!(table
        .records
        .iter()
        .all(|record| record.handler_kind != InitHandlerKind::Decompress));
    assert!(table.toolchain_fingerprint.is_none());
    assert!(table
        .provenance
        .expect("provenance")
        .notes
        .iter()
        .any(|note| note.starts_with("data_compression=absent")));
}

#[test]
fn a_data_region_is_not_classified_as_a_handler() {
    // The vector table is data. Decoding it produces no stores, and the
    // classifier must report Unknown rather than inventing a shape.
    let bytes = std::fs::read(fixture_path(LZ_OS)).expect("read fixture");
    let hypotheses = build_address_hypotheses(&bytes);
    let layout = classify_image_layout(&bytes, &hypotheses);
    let addressing =
        ImageAddressing::from_layout(0x0800_0021, &layout, bytes.len()).expect("addressing");

    let classification = classify_handler(&bytes, 0x0800_0000, &addressing);
    assert_eq!(classification.kind, InitHandlerKind::Unknown);
    assert!(classification.evidence.is_empty());
    assert_eq!(classification.confidence, 0.0);
}

#[test]
fn the_classification_survives_a_json_round_trip() {
    let table = init_table(LZ_OS);
    let serialized = serde_json::to_string(&table).expect("serialize");
    assert!(serialized.contains("decompress"));
    assert!(serialized.contains("lzss"));
    assert!(serialized.contains("control-byte-split"));
    assert!(serialized.contains("back-reference-loop"));
    let restored: InitTableReport = serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(restored, table);
}
