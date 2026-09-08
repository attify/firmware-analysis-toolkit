//! `fat list` / `fat delete` — enumerate and remove FAT projects under a
//! projects root (default `.fat-projects`).

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use fat_core::database::ProjectDb;

use crate::style::Palette;

type DynResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Serialize)]
struct ProjectRow {
    name: String,
    status: String,
    firmware: String,
    path: String,
}

/// Return `true` if `dir` looks like a FAT project (has a `.fat.db`).
fn is_project_dir(dir: &Path) -> bool {
    dir.join(".fat.db").is_file()
}

fn collect_projects(projects_dir: &Path) -> DynResult<Vec<ProjectRow>> {
    let mut rows = Vec::new();
    let entries = match fs::read_dir(projects_dir) {
        Ok(entries) => entries,
        // A missing projects root just means "no projects yet".
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(rows),
        Err(err) => return Err(format!("failed to read {}: {err}", projects_dir.display()).into()),
    };

    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() || !is_project_dir(&dir) {
            continue;
        }
        let name = dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();
        let db = ProjectDb::open(&dir)?;
        let (status, firmware) = match db.get(&name)? {
            Some(project) => (
                project.status.as_str().to_string(),
                project.firmware_name.clone(),
            ),
            None => ("unknown".to_string(), String::new()),
        };
        rows.push(ProjectRow {
            name,
            status,
            firmware,
            path: dir.display().to_string(),
        });
    }
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(rows)
}

pub fn run_list(projects_dir: &Path, json: bool) -> DynResult<()> {
    let rows = collect_projects(projects_dir)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }

    let palette = Palette::stdout();
    if !palette.enabled() {
        println!(
            "{}",
            palette.heading(format!("Projects in {}", projects_dir.display()))
        );
        if rows.is_empty() {
            println!(
                "{} {}",
                palette.bullet("-"),
                palette.muted("no projects found (create one with `fat new <firmware>`)")
            );
            return Ok(());
        }
        for row in &rows {
            let firmware = if row.firmware.is_empty() {
                String::new()
            } else {
                format!("  {}", palette.muted(&row.firmware))
            };
            println!(
                "{} {}  {}{}",
                palette.bullet("-"),
                palette.good(&row.name),
                palette.info(&row.status),
                firmware
            );
        }
        return Ok(());
    }

    let mut lines = Vec::new();
    if rows.is_empty() {
        lines.push(format!(
            "{} {}",
            palette.dot_muted(),
            palette.muted("no projects yet — try `fat new <firmware>`")
        ));
    }
    let mut next_project: Option<(&ProjectRow, &str)> = None;
    for row in &rows {
        let (dot, hint) = match row.status.as_str() {
            "analyzed" => (palette.dot_ok(), None),
            "extracted" => (palette.dot_warn(), Some("fat analyze")),
            "extracting" | "analyzing" | "emulating" => (palette.dot_warn(), None),
            "error" => (palette.dot_bad(), Some("fat extract --force")),
            _ => (palette.dot_muted(), Some("fat extract")),
        };
        let mut line = format!(
            "{} {}  {}",
            dot,
            palette.good(&row.name),
            palette.info(&row.status)
        );
        if !row.firmware.is_empty() {
            line.push_str(&format!("  {}", palette.muted(&row.firmware)));
        }
        lines.push(line);
        lines.push(format!("· {}", palette.muted(&row.path)));
        if let Some(hint) = hint {
            if next_project.is_none() {
                next_project = Some((row, hint));
            }
        }
    }
    println!(
        "{}",
        palette.panel(&format!("Projects in {}", projects_dir.display()), &lines)
    );
    if let Some((row, hint)) = next_project {
        println!(
            "{}",
            palette.next_hint(&format!("{hint} {row}", row = row.name))
        );
    }
    Ok(())
}

/// Resolve a project argument to a concrete project directory: accept either a
/// direct path to a project dir or a bare name under `projects_dir`.
fn resolve_project(project: &Path, projects_dir: &Path) -> DynResult<PathBuf> {
    if project.is_dir() && is_project_dir(project) {
        return Ok(project.to_path_buf());
    }
    let under_root = projects_dir.join(project);
    if under_root.is_dir() && is_project_dir(&under_root) {
        return Ok(under_root);
    }
    Err(format!(
        "no FAT project found at '{}' or '{}'",
        project.display(),
        under_root.display()
    )
    .into())
}

pub fn run_delete(project: &Path, projects_dir: &Path, yes: bool) -> DynResult<()> {
    let dir = resolve_project(project, projects_dir)?;
    let palette = Palette::stdout();
    if !yes {
        println!(
            "{} {}",
            palette.warn("would delete project"),
            palette.code(dir.display().to_string())
        );
        println!(
            "{}",
            palette.muted("re-run with --yes to remove it permanently")
        );
        return Ok(());
    }
    fs::remove_dir_all(&dir).map_err(|err| format!("failed to delete {}: {err}", dir.display()))?;
    println!(
        "{} {}",
        palette.good("deleted project"),
        palette.code(dir.display().to_string())
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fat_core::project::Project;

    fn make_project(root: &Path, name: &str, firmware: &str) -> PathBuf {
        let dir = root.join(name);
        fs::create_dir_all(&dir).expect("project dir");
        let db = ProjectDb::open(&dir).expect("open db");
        db.save(&Project::new(name.to_string(), firmware.to_string()))
            .expect("save project");
        dir
    }

    #[test]
    fn collect_projects_finds_saved_projects_sorted() {
        let root = tempfile::tempdir().expect("tempdir");
        make_project(root.path(), "zeta", "z.bin");
        make_project(root.path(), "alpha", "a.bin");
        // A non-project directory is ignored.
        fs::create_dir_all(root.path().join("not-a-project")).unwrap();

        let rows = collect_projects(root.path()).expect("collect");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "alpha");
        assert_eq!(rows[1].name, "zeta");
        assert_eq!(rows[0].status, "created");
        assert_eq!(rows[0].firmware, "a.bin");
    }

    #[test]
    fn collect_projects_missing_root_is_empty() {
        let root = tempfile::tempdir().expect("tempdir");
        let missing = root.path().join("does-not-exist");
        assert!(collect_projects(&missing).expect("collect").is_empty());
    }

    #[test]
    fn resolve_project_accepts_path_and_bare_name() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = make_project(root.path(), "demo", "d.bin");

        assert_eq!(resolve_project(&dir, root.path()).unwrap(), dir);
        assert_eq!(
            resolve_project(Path::new("demo"), root.path()).unwrap(),
            dir
        );
        assert!(resolve_project(Path::new("missing"), root.path()).is_err());
    }
}
