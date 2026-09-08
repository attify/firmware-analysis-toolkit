use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::{params, types::Type, Connection, OptionalExtension};

use crate::fingerprint::FirmwareFingerprint;
use crate::project::{Project, ProjectStatus};
use crate::runtime_store;

#[derive(Debug)]
pub struct ProjectDb {
    conn: Connection,
}

#[derive(Debug)]
pub enum ProjectDbError {
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
}

impl fmt::Display for ProjectDbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProjectDbError::Io(err) => write!(f, "project database io error: {err}"),
            ProjectDbError::Sqlite(err) => write!(f, "project database sqlite error: {err}"),
        }
    }
}

impl Error for ProjectDbError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ProjectDbError::Io(err) => Some(err),
            ProjectDbError::Sqlite(err) => Some(err),
        }
    }
}

impl From<std::io::Error> for ProjectDbError {
    fn from(err: std::io::Error) -> Self {
        ProjectDbError::Io(err)
    }
}

impl From<rusqlite::Error> for ProjectDbError {
    fn from(err: rusqlite::Error) -> Self {
        ProjectDbError::Sqlite(err)
    }
}

impl ProjectDb {
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, ProjectDbError> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir)?;
        runtime_store::initialize_project_layout(dir)?;

        let db_path = db_path(dir);
        let conn = Connection::open(db_path)?;
        let db = Self { conn };
        db.initialize()?;
        Ok(db)
    }

    pub fn save(&self, project: &Project) -> rusqlite::Result<()> {
        let (fingerprint_sha256, fingerprint_size_bytes) = project
            .fingerprint
            .as_ref()
            .map(|fingerprint| {
                (
                    Some(fingerprint.sha256.as_str()),
                    Some(fingerprint.size_bytes as i64),
                )
            })
            .unwrap_or((None, None));

        self.conn.execute(
            r#"
            INSERT INTO projects (
                name,
                firmware_name,
                status,
                fingerprint_sha256,
                fingerprint_size_bytes
            ) VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(name) DO UPDATE SET
                firmware_name = excluded.firmware_name,
                status = excluded.status,
                fingerprint_sha256 = excluded.fingerprint_sha256,
                fingerprint_size_bytes = excluded.fingerprint_size_bytes
            "#,
            params![
                project.name,
                project.firmware_name,
                project.status.as_str(),
                fingerprint_sha256,
                fingerprint_size_bytes,
            ],
        )?;

        Ok(())
    }

    pub fn get(&self, name: &str) -> rusqlite::Result<Option<Project>> {
        self.conn
            .query_row(
                r#"
                SELECT name, firmware_name, status, fingerprint_sha256, fingerprint_size_bytes
                FROM projects
                WHERE name = ?1
                "#,
                [name],
                |row| {
                    let status = row.get::<_, String>(2)?;
                    let status = ProjectStatus::from_db_str(&status).ok_or_else(|| {
                        rusqlite::Error::InvalidColumnType(2, "status".into(), Type::Text)
                    })?;
                    let fingerprint = match (
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                    ) {
                        (Some(sha256), Some(size_bytes)) => {
                            Some(FirmwareFingerprint::new(sha256, size_bytes as u64))
                        }
                        _ => None,
                    };

                    Ok(Project {
                        name: row.get(0)?,
                        firmware_name: row.get(1)?,
                        status,
                        fingerprint,
                    })
                },
            )
            .optional()
    }

    fn initialize(&self) -> rusqlite::Result<()> {
        self.conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS projects (
                name TEXT PRIMARY KEY NOT NULL,
                firmware_name TEXT NOT NULL,
                status TEXT NOT NULL,
                fingerprint_sha256 TEXT,
                fingerprint_size_bytes INTEGER
            )
            "#,
            [],
        )?;
        Ok(())
    }
}

fn db_path(dir: &Path) -> PathBuf {
    dir.join(".fat.db")
}
