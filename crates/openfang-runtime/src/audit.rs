//! Merkle hash chain audit trail for security-critical actions.
//!
//! Every auditable event is appended to an append-only log where each entry
//! contains the SHA-256 hash of its own contents concatenated with the hash of
//! the previous entry, forming a tamper-evident chain (similar to a blockchain).

use chrono::Utc;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Categories of auditable actions within the agent runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditAction {
    ToolInvoke,
    CapabilityCheck,
    AgentSpawn,
    AgentKill,
    AgentMessage,
    MemoryAccess,
    FileAccess,
    NetworkAccess,
    ShellExec,
    AuthAttempt,
    WireConnect,
    ConfigChange,
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// A single entry in the Merkle hash chain audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonically increasing sequence number (0-indexed).
    pub seq: u64,
    /// ISO-8601 timestamp of when this entry was recorded.
    pub timestamp: String,
    /// The agent that triggered (or is the subject of) this action.
    pub agent_id: String,
    /// The category of action being audited.
    pub action: AuditAction,
    /// Free-form detail about the action (e.g. tool name, file path).
    pub detail: String,
    /// The outcome of the action (e.g. "ok", "denied", an error message).
    pub outcome: String,
    /// SHA-256 hash of the previous entry (or all-zeros for the genesis).
    pub prev_hash: String,
    /// SHA-256 hash of this entry's content concatenated with `prev_hash`.
    pub hash: String,
}

fn action_from_str(s: &str) -> AuditAction {
    match s {
        "ToolInvoke" => AuditAction::ToolInvoke,
        "CapabilityCheck" => AuditAction::CapabilityCheck,
        "AgentSpawn" => AuditAction::AgentSpawn,
        "AgentKill" => AuditAction::AgentKill,
        "AgentMessage" => AuditAction::AgentMessage,
        "MemoryAccess" => AuditAction::MemoryAccess,
        "FileAccess" => AuditAction::FileAccess,
        "NetworkAccess" => AuditAction::NetworkAccess,
        "ShellExec" => AuditAction::ShellExec,
        "AuthAttempt" => AuditAction::AuthAttempt,
        "WireConnect" => AuditAction::WireConnect,
        "ConfigChange" => AuditAction::ConfigChange,
        _ => AuditAction::AuthAttempt,
    }
}

/// Computes the SHA-256 hash for a single audit entry from its fields.
fn compute_entry_hash(
    seq: u64,
    timestamp: &str,
    agent_id: &str,
    action: &AuditAction,
    detail: &str,
    outcome: &str,
    prev_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(seq.to_string().as_bytes());
    hasher.update(timestamp.as_bytes());
    hasher.update(agent_id.as_bytes());
    hasher.update(action.to_string().as_bytes());
    hasher.update(detail.as_bytes());
    hasher.update(outcome.as_bytes());
    hasher.update(prev_hash.as_bytes());
    hex::encode(hasher.finalize())
}

/// An append-only, tamper-evident audit log using a Merkle hash chain.
///
/// Thread-safe — all access is serialized through an internal mutex.
pub struct AuditLog {
    pub(crate) conn: Arc<Mutex<Connection>>,
}

impl AuditLog {
    /// Creates a new in-memory audit log for testing.
    pub fn new() -> Self {
        Self::open_in_memory()
    }

    /// Opens an in-memory audit log.
    pub fn open_in_memory() -> Self {
        let conn = Connection::open_in_memory().expect("Failed to open in-memory audit DB");
        Self::init_db(Arc::new(Mutex::new(conn)))
    }

    /// Opens or creates an audit log at the specified path.
    pub fn open(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let conn = Connection::open(path).expect("Failed to open audit DB");
        Self::init_db(Arc::new(Mutex::new(conn)))
    }

    /// Creates an audit log backed by a shared database connection.
    pub fn with_db(conn: Arc<Mutex<Connection>>) -> Self {
        let log = Self::init_db(conn);
        let count = log.len();
        if count > 0 {
            if let Err(e) = log.verify_integrity() {
                tracing::error!("Audit trail integrity check FAILED on boot: {e}");
            } else {
                tracing::info!("Audit trail loaded: {count} entries, chain integrity OK");
            }
        }
        log
    }

    fn init_db(conn: Arc<Mutex<Connection>>) -> Self {
        let db = conn.lock().unwrap_or_else(|e| e.into_inner());
        db.execute(
            "CREATE TABLE IF NOT EXISTS audit_entries (
                seq INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                action TEXT NOT NULL,
                detail TEXT NOT NULL,
                outcome TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                hash TEXT NOT NULL
            )",
            [],
        )
        .expect("Failed to create audit_entries table");
        drop(db);
        Self { conn }
    }

    /// Records a new auditable event and returns the SHA-256 hash of the entry.
    pub fn record(
        &self,
        agent_id: impl Into<String>,
        action: AuditAction,
        detail: impl Into<String>,
        outcome: impl Into<String>,
    ) -> String {
        let agent_id = agent_id.into();
        let detail = detail.into();
        let outcome = outcome.into();
        let timestamp = Utc::now().to_rfc3339();

        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());

        let (seq, prev_hash): (u64, String) = conn
            .query_row(
                "SELECT seq, hash FROM audit_entries ORDER BY seq DESC LIMIT 1",
                [],
                |row| Ok((row.get::<_, u64>(0)? + 1, row.get::<_, String>(1)?)),
            )
            .unwrap_or((0, "0".repeat(64)));

        let hash = compute_entry_hash(
            seq,
            &timestamp,
            &agent_id,
            &action,
            &detail,
            &outcome,
            &prev_hash,
        );

        conn.execute(
            "INSERT INTO audit_entries (seq, timestamp, agent_id, action, detail, outcome, prev_hash, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                seq,
                timestamp,
                agent_id,
                action.to_string(),
                detail,
                outcome,
                prev_hash,
                hash
            ],
        )
        .expect("Failed to insert audit entry");

        hash
    }

    /// Walks the entire chain and recomputes every hash to detect tampering.
    pub fn verify_integrity(&self) -> Result<(), String> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn
            .prepare("SELECT seq, timestamp, agent_id, action, detail, outcome, prev_hash, hash FROM audit_entries ORDER BY seq ASC")
            .map_err(|e| format!("Failed to prepare integrity check: {e}"))?;

        let mut expected_prev = "0".repeat(64);

        let rows = stmt
            .query_map([], |row| {
                Ok(AuditEntry {
                    seq: row.get::<_, u64>(0)?,
                    timestamp: row.get::<_, String>(1)?,
                    agent_id: row.get::<_, String>(2)?,
                    action: action_from_str(&row.get::<_, String>(3)?),
                    detail: row.get::<_, String>(4)?,
                    outcome: row.get::<_, String>(5)?,
                    prev_hash: row.get::<_, String>(6)?,
                    hash: row.get::<_, String>(7)?,
                })
            })
            .map_err(|e| format!("Failed to query audit entries: {e}"))?;

        for entry_res in rows {
            let entry = entry_res.map_err(|e| format!("DB row error: {e}"))?;
            if entry.prev_hash != expected_prev {
                return Err(format!(
                    "chain break at seq {}: expected prev_hash {} but found {}",
                    entry.seq, expected_prev, entry.prev_hash
                ));
            }

            let recomputed = compute_entry_hash(
                entry.seq,
                &entry.timestamp,
                &entry.agent_id,
                &entry.action,
                &entry.detail,
                &entry.outcome,
                &entry.prev_hash,
            );

            if recomputed != entry.hash {
                return Err(format!(
                    "hash mismatch at seq {}: expected {} but found {}",
                    entry.seq, recomputed, entry.hash
                ));
            }

            expected_prev = entry.hash.clone();
        }

        Ok(())
    }

    /// Returns the current tip hash.
    pub fn tip_hash(&self) -> String {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            "SELECT hash FROM audit_entries ORDER BY seq DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|_| "0".repeat(64))
    }

    /// Returns the number of entries in the log.
    pub fn len(&self) -> usize {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row("SELECT COUNT(*) FROM audit_entries", [], |row| row.get(0))
            .unwrap_or(0)
    }

    /// Returns whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns up to the most recent `n` entries (cloned).
    pub fn recent(&self, n: usize) -> Vec<AuditEntry> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn
            .prepare("SELECT seq, timestamp, agent_id, action, detail, outcome, prev_hash, hash FROM audit_entries ORDER BY seq DESC LIMIT ?1")
            .expect("Failed to prepare query");

        let rows = stmt
            .query_map(params![n], |row| {
                Ok(AuditEntry {
                    seq: row.get::<_, u64>(0)?,
                    timestamp: row.get::<_, String>(1)?,
                    agent_id: row.get::<_, String>(2)?,
                    action: action_from_str(&row.get::<_, String>(3)?),
                    detail: row.get::<_, String>(4)?,
                    outcome: row.get::<_, String>(5)?,
                    prev_hash: row.get::<_, String>(6)?,
                    hash: row.get::<_, String>(7)?,
                })
            })
            .expect("Failed to execute query");

        let mut results: Vec<_> = rows.collect::<Result<Vec<_>, _>>().expect("DB read error");
        results.reverse();
        results
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_chain_integrity() {
        let log = AuditLog::new();
        log.record(
            "agent-1",
            AuditAction::ToolInvoke,
            "read_file /etc/passwd",
            "ok",
        );
        log.record("agent-1", AuditAction::ShellExec, "ls -la", "ok");
        log.record("agent-2", AuditAction::AgentSpawn, "spawning helper", "ok");
        log.record(
            "agent-1",
            AuditAction::NetworkAccess,
            "https://example.com",
            "denied",
        );

        assert_eq!(log.len(), 4);
        assert!(log.verify_integrity().is_ok());

        // Verify the chain links are correct
        let entries = log.recent(4);
        assert_eq!(entries[0].prev_hash, "0".repeat(64));
        assert_eq!(entries[1].prev_hash, entries[0].hash);
        assert_eq!(entries[2].prev_hash, entries[1].hash);
        assert_eq!(entries[3].prev_hash, entries[2].hash);
    }

    #[test]
    fn test_audit_tamper_detection() {
        let log = AuditLog::new();
        log.record("agent-1", AuditAction::ToolInvoke, "read_file /tmp/a", "ok");
        log.record("agent-1", AuditAction::ShellExec, "rm -rf /", "denied");
        log.record("agent-1", AuditAction::MemoryAccess, "read key foo", "ok");

        // Tamper with an entry by reaching into the DB
        {
            let conn = log.conn.lock().unwrap();
            conn.execute(
                "UPDATE audit_entries SET detail = ?1 WHERE seq = 1",
                ["echo hello"],
            )
            .unwrap();
        }

        let result = log.verify_integrity();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("hash mismatch at seq 1"));
    }

    #[test]
    fn test_audit_tip_changes() {
        let log = AuditLog::new();
        let genesis_tip = log.tip_hash();
        assert_eq!(genesis_tip, "0".repeat(64));

        let h1 = log.record("a", AuditAction::AgentSpawn, "spawn", "ok");
        assert_eq!(log.tip_hash(), h1);
        assert_ne!(log.tip_hash(), genesis_tip);

        let h2 = log.record("b", AuditAction::AgentKill, "kill", "ok");
        assert_eq!(log.tip_hash(), h2);
        assert_ne!(h2, h1);
    }

    #[test]
    fn test_audit_persists_to_db() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE audit_entries (
                seq INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                action TEXT NOT NULL,
                detail TEXT NOT NULL,
                outcome TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                hash TEXT NOT NULL
            )",
        )
        .unwrap();

        let db = Arc::new(Mutex::new(conn));

        // Record entries with DB
        let log = AuditLog::with_db(Arc::clone(&db));
        log.record("agent-1", AuditAction::AgentSpawn, "spawn test", "ok");
        log.record("agent-1", AuditAction::ShellExec, "ls", "ok");
        assert_eq!(log.len(), 2);

        // Verify entries in database
        let db_conn = db.lock().unwrap();
        let count: i64 = db_conn
            .query_row("SELECT COUNT(*) FROM audit_entries", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 2);
        drop(db_conn);

        // Simulate restart: create new AuditLog from same DB
        let log2 = AuditLog::with_db(Arc::clone(&db));
        assert_eq!(log2.len(), 2);
        assert!(log2.verify_integrity().is_ok());

        // Chain continues correctly after restart
        log2.record("agent-2", AuditAction::ToolInvoke, "file_read", "ok");
        assert_eq!(log2.len(), 3);
        assert!(log2.verify_integrity().is_ok());

        // Verify tip is correct
        let entries = log2.recent(3);
        assert_eq!(entries[2].prev_hash, entries[1].hash);
    }
}
