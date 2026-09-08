use std::error::Error;
use std::path::Path;

type DynResult<T> = Result<T, Box<dyn Error>>;

pub fn run(fixture: Option<&Path>, goal: &str, json: bool) -> DynResult<()> {
    let fixture_path = fixture.ok_or("chain query currently requires --fixture")?;
    let result = fat_query::eval::evaluate_chain_fixture(fixture_path, goal)
        .map_err(|e| format!("chain query failed: {e}"))?;
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        let palette = crate::style::Palette::stdout();
        println!("{}", palette.kv("goal", palette.accent(&result.goal)));
        println!("{}", palette.heading("Steps"));
        for step in result.steps {
            println!("{} {}", palette.bullet("-"), palette.info(&step));
        }
    }
    Ok(())
}
