use std::error::Error;
use std::path::Path;

type DynResult<T> = Result<T, Box<dyn Error>>;

pub fn run(
    fixture: Option<&Path>,
    repo: Option<&Path>,
    _find_variants: bool,
    mode: fat_query::adapters::traits::ExecutionMode,
    debug_bundle_dir: Option<&Path>,
    json: bool,
) -> DynResult<()> {
    let target = fixture
        .or(repo)
        .ok_or("patch check requires --fixture or --repo")?;
    let options = fat_query::adapters::invariant::PatchCheckOptions {
        mode,
        debug_bundle_dir: debug_bundle_dir.map(|path| path.to_path_buf()),
    };
    let result = fat_query::adapters::invariant::run_patch_check_with_options(target, &options)
        .map_err(|e| format!("patch check failed: {e}"))?;
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        let palette = crate::style::Palette::stdout();
        println!("{}", palette.kv("mode", palette.accent(&result.mode)));
        println!(
            "{}",
            palette.kv("required_call", palette.accent(&result.required_call))
        );
        println!(
            "{}",
            palette.kv(
                "reference_sites",
                if result.reference_sites.is_empty() {
                    palette.muted("<none>")
                } else {
                    palette.good(result.reference_sites.join(", "))
                }
            )
        );
        println!(
            "{}",
            palette.kv(
                "variant_candidates",
                if result.variant_candidates.is_empty() {
                    palette.muted("<none>")
                } else {
                    palette.warn(result.variant_candidates.join(", "))
                }
            )
        );
        println!(
            "{}",
            palette.kv(
                "derived_facts",
                palette.accent(result.derived.facts.len().to_string())
            )
        );
        println!(
            "{}",
            palette.kv(
                "variant_leads",
                palette.warn(result.variant_leads.len().to_string())
            )
        );
        println!(
            "{}",
            palette.kv(
                "replay_candidates",
                palette.info(result.replay.candidates.len().to_string())
            )
        );
        if let Some(top) = result.replay.candidates.first() {
            println!(
                "{}",
                palette.kv(
                    "replay_top1",
                    format!(
                        "{} ({})",
                        top.symbol,
                        top.matched_roles
                            .iter()
                            .map(|role| role.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                )
            );
        }
        println!(
            "{}",
            palette.kv("locality", format!("{:?}", result.locality.locality))
        );
    }
    Ok(())
}
