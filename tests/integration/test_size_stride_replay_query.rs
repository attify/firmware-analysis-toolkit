use fat_query::adapters::source_clang_facts::maybe_analyze_source_tree;
use fat_query::derived::derive_from_fused_source;
use fat_query::fusion::fuse_source_analysis;
use fat_query::replay::rank_replay_candidates;
use std::fs;

fn write_fixture(root: &std::path::Path) {
    let sample = root.join("BufferSurface.mm");
    fs::write(
        &sample,
        r#"
int MakeBuffer(int x) { return x; }
void SaturateDepth(int) {}
void CopyBufferToSurface(int, int) {}
void CopyBytes(int, int) {}

class BufferSurface {
public:
  void uploadRegion(int sourceBytesPerImage, int depthPitch)
  {
    auto buffer = MakeBuffer(depthPitch);
    SaturateDepth(sourceBytesPerImage);
    CopyBufferToSurface(buffer, sourceBytesPerImage);
  }

  void uploadRegionVariant(int sourceBytesPerImage, int depthPitch)
  {
    auto buffer = MakeBuffer(depthPitch);
    CopyBufferToSurface(buffer, sourceBytesPerImage);
    SaturateDepth(sourceBytesPerImage);
  }

  void copyOnlyNegative(int sourceBytesPerImage)
  {
    CopyBytes(sourceBytesPerImage, sourceBytesPerImage);
  }
};
"#,
    )
    .expect("write source");

    fs::write(
        root.join("compile_commands.json"),
        format!(
            r#"[{{
  "directory": "{}",
  "file": "{}",
  "arguments": ["clang++", "-x", "objective-c++", "-std=c++17", "{}"]
}}]"#,
            root.display(),
            sample.display(),
            sample.display()
        ),
    )
    .expect("write compile commands");
}

#[test]
fn size_stride_replay_ranks_true_variant_above_negative_control() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_fixture(dir.path());

    let summary = maybe_analyze_source_tree(dir.path())
        .expect("analyze source tree")
        .expect("summary");
    let fused = fuse_source_analysis(Some(&summary));
    let derived = derive_from_fused_source(&fused);

    let replay = rank_replay_candidates(
        &["uploadRegion".into()],
        &fused,
        &derived,
        &["copyOnlyNegative".into()],
    );

    assert!(replay
        .required_roles
        .iter()
        .any(|role| role.as_str() == "allocation-size"));
    assert_eq!(
        replay
            .candidates
            .first()
            .map(|candidate| candidate.symbol.as_str()),
        Some("uploadRegionVariant")
    );
    let negative = replay
        .candidates
        .iter()
        .find(|candidate| candidate.symbol == "copyOnlyNegative")
        .expect("negative candidate present");
    let positive = replay
        .candidates
        .iter()
        .find(|candidate| candidate.symbol == "uploadRegionVariant")
        .expect("positive candidate present");
    assert!(positive.score > negative.score);
}
