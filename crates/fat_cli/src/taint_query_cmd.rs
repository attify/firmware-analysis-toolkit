use std::error::Error;
use std::path::Path;

type DynResult<T> = Result<T, Box<dyn Error>>;

pub fn run(
    fixture: Option<&Path>,
    file: Option<&Path>,
    from: &str,
    to: &str,
    json: bool,
) -> DynResult<()> {
    let graph = if let Some(fixture_path) = fixture {
        fat_taint::query::binary_adapter::from_fixture(fixture_path)
            .map_err(|e| format!("failed to load fixture: {e}"))?
    } else if let Some(binary_path) = file {
        let detected = fat_query::target_detection::detect_path(binary_path)
            .map_err(|e| format!("failed to detect target kind: {e}"))?;
        match detected.kind {
            fat_query::target_detection::TargetKind::ElfBinary
            | fat_query::target_detection::TargetKind::RawBlob => {}
            fat_query::target_detection::TargetKind::MachOBinary => {
                return Err(
                    "Mach-O taint-query is not supported yet. Use `fat identify-launcher` or `fat inspect-handoff` first."
                        .into(),
                );
            }
            other => {
                return Err(format!(
                    "taint-query does not support target kind {other:?}. Use --fixture for regression graphs or provide an ELF/raw blob."
                )
                .into());
            }
        }
        fat_taint::query::binary_adapter::from_binary(binary_path)
            .map_err(|e| format!("failed to analyze binary: {e}"))?
    } else {
        return Err("taint-query requires --fixture or --file".into());
    };
    let from_selector =
        fat_query::selectors::parse(from).map_err(|e| format!("invalid --from selector: {e}"))?;
    let to_selector =
        fat_query::selectors::parse(to).map_err(|e| format!("invalid --to selector: {e}"))?;
    let result = fat_query::eval::evaluate_path(&graph, &from_selector, &to_selector)
        .map_err(|e| format!("path evaluation failed: {e}"))?;

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        let palette = crate::style::Palette::stdout();
        let path_kind = format!("{:?}", result.path_kind);
        let styled_kind = match path_kind.as_str() {
            "ArgFlowProven" => palette.good(&path_kind),
            "ConstantSinkArg" => palette.warn(&path_kind),
            "ControlReachable" => palette.info(&path_kind),
            _ => palette.muted(&path_kind),
        };
        println!("{}", palette.kv("path_kind", &styled_kind));
        if !result.trace.is_empty() {
            println!("{}", palette.heading("Trace"));
            for step in result.trace {
                println!("  {} {}", palette.bullet("-"), palette.info(&step));
            }
        }
    }
    Ok(())
}
