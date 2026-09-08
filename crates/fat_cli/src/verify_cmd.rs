use std::error::Error;
use std::path::Path;

type DynResult<T> = Result<T, Box<dyn Error>>;

pub fn run(fixture: Option<&Path>, json: bool) -> DynResult<()> {
    let fixture_path = fixture.ok_or("verify currently requires --fixture")?;
    let adapter_note = fat_query::adapters::registry::default_registry()
        .plan(
            &fat_query::target_detection::DetectedTarget::new(
                fat_query::target_detection::TargetKind::RuntimeSession,
                fixture_path,
            ),
            &fat_query::adapters::traits::QueryRequest::new(
                fat_query::adapters::traits::QueryKind::RuntimeVerify,
            ),
        )
        .map(|plan| {
            format!(
                "adapter plan for {:?}: {}",
                plan.query_kind,
                plan.adapter_ids.join(" -> ")
            )
        })
        .unwrap_or_else(|err| format!("no dedicated runtime adapter plan: {err}"));
    let result = fat_query::adapters::runtime::confirm_fixture(fixture_path)
        .map_err(|e| format!("verify failed: {e}"))?;
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        let palette = crate::style::Palette::stdout();
        println!("{}", palette.kv("adapter", palette.muted(&adapter_note)));
        println!(
            "{}",
            palette.kv("finding", palette.accent(&result.finding_id))
        );
        let verdict = if result.verdict.eq_ignore_ascii_case("confirmed") {
            palette.good(&result.verdict)
        } else {
            palette.warn(&result.verdict)
        };
        println!("{}", palette.kv("verdict", verdict));
    }
    Ok(())
}
