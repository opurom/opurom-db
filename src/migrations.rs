//! Deterministic schema migration runner.
//!
//! A [`Migrator`] applies numbered versions to a database in order and records
//! each one in a `_migrations` table. Re-applying an already-applied version is
//! a no-op, an out-of-order or missing version is a typed
//! [`MigrationError::OutOfOrder`] / [`MigrationError::MissingVersion`], and each
//! migration runs inside its own transaction so a failure rolls back and leaves
//! no record behind.

use crate::{Database, DbError};
use std::fmt;

/// One numbered migration: a stable integer `version` and its SQL `up` body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Migration {
    pub version: i64,
    pub up: String,
}

impl Migration {
    pub fn new(version: i64, up: impl Into<String>) -> Migration {
        Migration {
            version,
            up: up.into(),
        }
    }
}

/// A typed migration failure distinct from a driver error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MigrationError {
    /// Versions must start at 1 and increase by exactly one.
    MissingVersion { expected: i64, found: i64 },
    /// The database has already applied a version beyond one in the input.
    AppliedAhead { recorded: i64, found: i64 },
    /// A migration that requires existing prior state was supplied none.
    DuplicateVersion { version: i64 },
    /// A migration statement or its bookkeeping failed; its transaction rolled
    /// back and recorded nothing.
    Failed { version: i64, cause: DbError },
}

impl MigrationError {
    pub fn message(&self) -> String {
        match self {
            MigrationError::MissingVersion { expected, found } => {
                format!("missing migration version {expected} before {found}")
            }
            MigrationError::AppliedAhead { recorded, found } => format!(
                "database already applied version {recorded}; cannot apply older version {found}"
            ),
            MigrationError::DuplicateVersion { version } => {
                format!("migration version {version} appears more than once")
            }
            MigrationError::Failed { version, cause } => {
                format!("migration {version} failed and rolled back: {cause}")
            }
        }
    }
}

impl fmt::Display for MigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for MigrationError {}

/// Applies [`Migration`]s against one [`Database`] and tracks applied versions
/// in the `_migrations` table.
pub struct Migrator<'a, D: Database + ?Sized> {
    db: &'a mut D,
}

impl<'a, D: Database> Migrator<'a, D> {
    /// Create the `_migrations` table if missing and return a runner over `db`.
    pub fn new(db: &'a mut D) -> Result<Migrator<'a, D>, MigrationError> {
        let m = Migrator { db };
        m.db.exec(
            "CREATE TABLE IF NOT EXISTS _migrations (\
                 version INTEGER PRIMARY KEY, \
                 applied_at TEXT NOT NULL DEFAULT '')",
        )
        .map_err(|cause| MigrationError::Failed { version: 0, cause })?;
        Ok(m)
    }

    /// The versions already applied, ascending.
    pub fn applied(&mut self) -> Result<Vec<i64>, MigrationError> {
        let rows = self
            .db
            .query("SELECT version FROM _migrations ORDER BY version ASC;")
            .map_err(|cause| MigrationError::Failed { version: 0, cause })?;
        let mut versions = Vec::with_capacity(rows.len());
        for row in &rows {
            if let Some(v) = row.get("version").and_then(crate::Value::as_i64) {
                versions.push(v);
            }
        }
        Ok(versions)
    }

    /// Apply every migration in `batch` not yet recorded, in ascending version
    /// order. Each is applied inside its own transaction together with its
    /// `_migrations` insert; a failure rolls that version back and returns a
    /// typed error, leaving earlier versions committed. Re-running with the
    /// same batch applies nothing and returns an empty list.
    pub fn apply(&mut self, batch: &[Migration]) -> Result<Vec<i64>, MigrationError> {
        let mut ordered = batch.to_vec();
        ordered.sort_by_key(|m| m.version);
        // Reject duplicates and require versions to be 1, 2, 3, ... with no gap.
        for (i, m) in ordered.iter().enumerate() {
            if i > 0 && ordered[i - 1].version == m.version {
                return Err(MigrationError::DuplicateVersion { version: m.version });
            }
            let expected = i as i64 + 1;
            if m.version != expected {
                return Err(MigrationError::MissingVersion {
                    expected,
                    found: m.version,
                });
            }
        }

        let applied = self.applied()?;
        let recorded = applied.last().copied().unwrap_or(0);
        if let Some(head) = ordered.last() {
            if head.version < recorded {
                return Err(MigrationError::AppliedAhead {
                    recorded,
                    found: head.version,
                });
            }
        }

        let mut newly = Vec::new();
        for m in &ordered {
            if applied.contains(&m.version) {
                continue;
            }
            if m.version <= recorded {
                return Err(MigrationError::AppliedAhead {
                    recorded,
                    found: m.version,
                });
            }
            let result = self.apply_one(m);
            match result {
                Ok(()) => newly.push(m.version),
                Err(cause) => {
                    return Err(MigrationError::Failed {
                        version: m.version,
                        cause,
                    })
                }
            }
        }
        Ok(newly)
    }

    fn apply_one(&mut self, m: &Migration) -> Result<(), DbError> {
        let db = &mut *self.db;
        let mut tx = db.transaction()?;
        tx.exec(&m.up)?;
        tx.exec_params(
            "INSERT INTO _migrations (version) VALUES (?);",
            &[crate::Value::Int(m.version)],
        )?;
        tx.commit()
    }
}
