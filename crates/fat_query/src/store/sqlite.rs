use crate::ir::{EdgeRecord, NodeRecord};
use crate::result::SourceEvidenceReport;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const SCHEMA_VERSION: i64 = 1;
pub const SOURCE_FACT_CACHE_SCHEMA_VERSION: &str = "source-fact-cache-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMeta {
    pub project_id: String,
    pub target_kind: String,
    pub schema_version: i64,
}

impl SnapshotMeta {
    pub fn new(project_id: impl Into<String>, target_kind: impl Into<String>) -> Self {
        Self {
            project_id: project_id.into(),
            target_kind: target_kind.into(),
            schema_version: SCHEMA_VERSION,
        }
    }
}

pub fn init_snapshot(path: &Path, meta: &SnapshotMeta) -> Result<(), String> {
    let conn = Connection::open(path).map_err(|e| e.to_string())?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS snapshot_meta (
            project_id TEXT NOT NULL,
            target_kind TEXT NOT NULL,
            schema_version INTEGER NOT NULL
        );
        DELETE FROM snapshot_meta;
        CREATE TABLE IF NOT EXISTS nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            label TEXT NOT NULL,
            attrs_json TEXT NOT NULL,
            provenance_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS edges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            from_id INTEGER NOT NULL,
            to_id INTEGER NOT NULL,
            attrs_json TEXT NOT NULL,
            provenance_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS source_fact_cache (
            cache_key TEXT NOT NULL,
            backend_kind TEXT NOT NULL,
            backend_version TEXT NOT NULL,
            fact_schema_version TEXT NOT NULL,
            tu_spec_hash TEXT NOT NULL,
            toolchain_profile_hash TEXT NOT NULL,
            query_family_version TEXT,
            report_json TEXT NOT NULL,
            PRIMARY KEY (cache_key, backend_kind)
        );
        "#,
    )
    .map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT INTO snapshot_meta(project_id, target_kind, schema_version) VALUES (?1, ?2, ?3)",
        params![meta.project_id, meta.target_kind, meta.schema_version],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFactRecord {
    pub cache_key: String,
    pub backend_kind: String,
    pub backend_version: String,
    pub fact_schema_version: String,
    pub tu_spec_hash: String,
    pub toolchain_profile_hash: String,
    pub query_family_version: Option<String>,
    pub report: SourceEvidenceReport,
}

pub fn write_source_fact_records(path: &Path, records: &[SourceFactRecord]) -> Result<(), String> {
    let conn = Connection::open(path).map_err(|e| e.to_string())?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS source_fact_cache (
            cache_key TEXT NOT NULL,
            backend_kind TEXT NOT NULL,
            backend_version TEXT NOT NULL,
            fact_schema_version TEXT NOT NULL,
            tu_spec_hash TEXT NOT NULL,
            toolchain_profile_hash TEXT NOT NULL,
            query_family_version TEXT,
            report_json TEXT NOT NULL,
            PRIMARY KEY (cache_key, backend_kind)
        );
        "#,
    )
    .map_err(|e| e.to_string())?;
    let mut stmt = conn
        .prepare(
            "INSERT OR REPLACE INTO source_fact_cache(
                cache_key, backend_kind, backend_version, fact_schema_version,
                tu_spec_hash, toolchain_profile_hash, query_family_version, report_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .map_err(|e| e.to_string())?;
    for record in records {
        stmt.execute(params![
            record.cache_key,
            record.backend_kind,
            record.backend_version,
            record.fact_schema_version,
            record.tu_spec_hash,
            record.toolchain_profile_hash,
            record.query_family_version,
            serde_json::to_string(&record.report).map_err(|e| e.to_string())?,
        ])
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub fn load_source_fact_records(path: &Path) -> Result<Vec<SourceFactRecord>, String> {
    let conn = Connection::open(path).map_err(|e| e.to_string())?;
    let mut stmt = conn
        .prepare(
            "SELECT cache_key, backend_kind, backend_version, fact_schema_version,
                    tu_spec_hash, toolchain_profile_hash, query_family_version, report_json
             FROM source_fact_cache ORDER BY cache_key",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |row| {
            let report_json: String = row.get(7)?;
            let report: SourceEvidenceReport =
                serde_json::from_str(&report_json).map_err(map_serde_err)?;
            Ok(SourceFactRecord {
                cache_key: row.get(0)?,
                backend_kind: row.get(1)?,
                backend_version: row.get(2)?,
                fact_schema_version: row.get(3)?,
                tu_spec_hash: row.get(4)?,
                toolchain_profile_hash: row.get(5)?,
                query_family_version: row.get(6)?,
                report,
            })
        })
        .map_err(|e| e.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}

pub fn load_source_fact_records_for_cache_key(
    path: &Path,
    cache_key: &str,
) -> Result<Vec<SourceFactRecord>, String> {
    let conn = Connection::open(path).map_err(|e| e.to_string())?;
    let mut stmt = conn
        .prepare(
            "SELECT cache_key, backend_kind, backend_version, fact_schema_version,
                    tu_spec_hash, toolchain_profile_hash, query_family_version, report_json
             FROM source_fact_cache
             WHERE cache_key = ?1
             ORDER BY backend_kind",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([cache_key], |row| {
            let report_json: String = row.get(7)?;
            let report: SourceEvidenceReport =
                serde_json::from_str(&report_json).map_err(map_serde_err)?;
            Ok(SourceFactRecord {
                cache_key: row.get(0)?,
                backend_kind: row.get(1)?,
                backend_version: row.get(2)?,
                fact_schema_version: row.get(3)?,
                tu_spec_hash: row.get(4)?,
                toolchain_profile_hash: row.get(5)?,
                query_family_version: row.get(6)?,
                report,
            })
        })
        .map_err(|e| e.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}

pub fn load_snapshot_meta(path: &Path) -> Result<SnapshotMeta, String> {
    let conn = Connection::open(path).map_err(|e| e.to_string())?;
    conn.query_row(
        "SELECT project_id, target_kind, schema_version FROM snapshot_meta LIMIT 1",
        [],
        |row| {
            Ok(SnapshotMeta {
                project_id: row.get(0)?,
                target_kind: row.get(1)?,
                schema_version: row.get(2)?,
            })
        },
    )
    .map_err(|e| e.to_string())
}

pub struct GraphWriter {
    conn: Connection,
}

impl GraphWriter {
    pub fn open(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        Ok(Self { conn })
    }

    pub fn insert_node(&mut self, node: &NodeRecord) -> Result<u32, String> {
        self.conn
            .execute(
                "INSERT INTO nodes(kind, label, attrs_json, provenance_json) VALUES (?1, ?2, ?3, ?4)",
                params![
                    format!("{:?}", node.kind),
                    node.label,
                    serde_json::to_string(&node.attrs).map_err(|e| e.to_string())?,
                    serde_json::to_string(&node.provenance).map_err(|e| e.to_string())?,
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok((self.conn.last_insert_rowid() - 1) as u32)
    }

    pub fn insert_edge(&mut self, edge: &EdgeRecord) -> Result<u32, String> {
        self.conn
            .execute(
                "INSERT INTO edges(kind, from_id, to_id, attrs_json, provenance_json) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    format!("{:?}", edge.kind),
                    edge.from,
                    edge.to,
                    serde_json::to_string(&edge.attrs).map_err(|e| e.to_string())?,
                    serde_json::to_string(&edge.provenance).map_err(|e| e.to_string())?,
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok((self.conn.last_insert_rowid() - 1) as u32)
    }
}

pub struct GraphReader {
    conn: Connection,
}

impl GraphReader {
    pub fn open(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        Ok(Self { conn })
    }

    pub fn nodes(&self) -> Result<Vec<NodeRecord>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, kind, label, attrs_json, provenance_json FROM nodes ORDER BY id")
            .map_err(|e| e.to_string())?;
        let iter = stmt
            .query_map([], |row| {
                let attrs_json: String = row.get(3)?;
                let provenance_json: String = row.get(4)?;
                Ok(NodeRecord {
                    id: row.get::<_, i64>(0)? as u32,
                    kind: match row.get::<_, String>(1)?.as_str() {
                        "Source" => crate::ir::NodeKind::Source,
                        "Constant" => crate::ir::NodeKind::Constant,
                        "SinkSlot" => crate::ir::NodeKind::SinkSlot,
                        "Function" => crate::ir::NodeKind::Function,
                        "CallSite" => crate::ir::NodeKind::CallSite,
                        "Guard" => crate::ir::NodeKind::Guard,
                        "Invariant" => crate::ir::NodeKind::Invariant,
                        "InvariantSite" => crate::ir::NodeKind::InvariantSite,
                        "PatchSite" => crate::ir::NodeKind::PatchSite,
                        "StateChannel" => crate::ir::NodeKind::StateChannel,
                        "RuntimeEvent" => crate::ir::NodeKind::RuntimeEvent,
                        _ => crate::ir::NodeKind::Observation,
                    },
                    label: row.get(2)?,
                    attrs: serde_json::from_str(&attrs_json).map_err(map_serde_err)?,
                    provenance: serde_json::from_str(&provenance_json).map_err(map_serde_err)?,
                })
            })
            .map_err(|e| e.to_string())?;
        iter.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    pub fn edges(&self) -> Result<Vec<EdgeRecord>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, kind, from_id, to_id, attrs_json, provenance_json FROM edges ORDER BY id")
            .map_err(|e| e.to_string())?;
        let iter = stmt
            .query_map([], |row| {
                let attrs_json: String = row.get(4)?;
                let provenance_json: String = row.get(5)?;
                Ok(EdgeRecord {
                    id: row.get::<_, i64>(0)? as u32,
                    kind: match row.get::<_, String>(1)?.as_str() {
                        "DefUse" => crate::ir::EdgeKind::DefUse,
                        "ControlDependsOn" => crate::ir::EdgeKind::ControlDependsOn,
                        "WritesConstant" => crate::ir::EdgeKind::WritesConstant,
                        "GuardedBy" => crate::ir::EdgeKind::GuardedBy,
                        "Calls" => crate::ir::EdgeKind::Calls,
                        "DerivedFromPatch" => crate::ir::EdgeKind::DerivedFromPatch,
                        "ReadsChannel" => crate::ir::EdgeKind::ReadsChannel,
                        "WritesChannel" => crate::ir::EdgeKind::WritesChannel,
                        "SatisfiesInvariant" => crate::ir::EdgeKind::SatisfiesInvariant,
                        "ViolatesInvariant" => crate::ir::EdgeKind::ViolatesInvariant,
                        "ConfirmedByRuntime" => crate::ir::EdgeKind::ConfirmedByRuntime,
                        _ => crate::ir::EdgeKind::ContradictedByRuntime,
                    },
                    from: row.get::<_, i64>(2)? as u32,
                    to: row.get::<_, i64>(3)? as u32,
                    attrs: serde_json::from_str(&attrs_json).map_err(map_serde_err)?,
                    provenance: serde_json::from_str(&provenance_json).map_err(map_serde_err)?,
                })
            })
            .map_err(|e| e.to_string())?;
        iter.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }
}

fn map_serde_err(err: serde_json::Error) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(err))
}

#[derive(Debug, Clone)]
pub struct InMemoryGraph {
    nodes: Vec<NodeRecord>,
    edges: Vec<EdgeRecord>,
    out_adj: Vec<Vec<usize>>,
    in_adj: Vec<Vec<usize>>,
}

impl InMemoryGraph {
    pub fn from_records(mut nodes: Vec<NodeRecord>, mut edges: Vec<EdgeRecord>) -> Self {
        for (idx, node) in nodes.iter_mut().enumerate() {
            node.id = idx as u32;
        }
        for (idx, edge) in edges.iter_mut().enumerate() {
            edge.id = idx as u32;
        }
        let mut out_adj = vec![Vec::new(); nodes.len()];
        let mut in_adj = vec![Vec::new(); nodes.len()];
        for (idx, edge) in edges.iter().enumerate() {
            out_adj[edge.from as usize].push(idx);
            in_adj[edge.to as usize].push(idx);
        }
        Self {
            nodes,
            edges,
            out_adj,
            in_adj,
        }
    }

    pub fn nodes(&self) -> &[NodeRecord] {
        &self.nodes
    }

    pub fn edges(&self) -> &[EdgeRecord] {
        &self.edges
    }

    pub fn out_edges(&self, node: u32) -> &[usize] {
        &self.out_adj[node as usize]
    }

    pub fn in_edges(&self, node: u32) -> &[usize] {
        &self.in_adj[node as usize]
    }

    pub fn edge(&self, edge_idx: usize) -> &EdgeRecord {
        &self.edges[edge_idx]
    }
}
