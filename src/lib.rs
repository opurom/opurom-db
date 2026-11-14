//! OPUROM data layer.
//!
//! Five interchangeable [`Database`] drivers: [`Sqlite`] (direct FFI to the
//! macOS/Linux system libsqlite3), [`PgConnection`] (pure-std PostgreSQL v3
//! simple-query TCP frontend), [`MySqlConnection`] (pure-std MySQL v10
//! text-query frontend), [`Kv`] (file-backed key/value store) and [`Memory`]
//! (volatile). [`PooledDb`] shares one Mutex-serialized `Sqlite` connection
//! between threads. IR model definitions drive type-correct CRUD SQL,
//! deterministic migration files with declared indexes, a bounded filtered
//! query layer and a pure index planner, a transactional [`Migrator`] that
//! records applied versions in `_migrations`, and one-query eager loading of
//! declared foreign-key relations.

mod benchmark;
mod crud;
mod kv;
mod memory;
mod migrations;
mod model;
mod mysql;
mod mysql_crypto;
mod pg;
mod pgserver;
mod pool;
mod queries;
mod relations;
mod store;
mod transaction;

// The FFI driver links the system libsqlite3. macOS ships it in the SDK;
// Linux needs libsqlite3-dev, which CI installs before the test step.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[path = "sqlite.rs"]
mod sqlite;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
#[path = "sqlite_stub.rs"]
mod sqlite;

pub use benchmark::{
    expected_statements, filter_keys, measure_queries, percentile_ms, speedup_x100, BenchmarkPlans,
    BenchmarkReport, BenchmarkRunner, Clock, MonotonicClock, SqliteRunner, Workload,
    BENCHMARK_WORKLOAD, WORKLOAD_SEED,
};
pub use crud::{create, create_table, delete, get, list, list_paged, update, MAX_PAGE_LIMIT};
pub use kv::Kv;
pub use memory::Memory;
pub use migrations::{Migration, MigrationError, Migrator};
pub use model::{
    create_table_sql, migration_files, parse_models, parse_models_value, schema_sql, sql_literal,
    validate_ident, validate_model, write_migrations, Field, FieldType, Index, Model, Relation,
};
pub use mysql::{MySqlConnection, MySqlStatement};
pub use pg::{PgConnection, PgNotification};
pub use pgserver::{PgAuth, PgServer, PgServerOptions, PgTls};
pub use pool::PooledDb;
pub use queries::{count, explain, query, Filter, Plan, Query, Scan, Sort, MAX_COUNT_LIMIT};
pub use relations::with_related;
pub use sqlite::Sqlite;
pub use transaction::Transaction;

use std::fmt;

/// The typed category of a MySQL server error code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MySqlErrorKind {
    Syntax,
    TableNotFound,
    DuplicateEntry,
    AccessDenied,
    Other,
}

impl MySqlErrorKind {
    pub(crate) fn from_code(code: u16) -> MySqlErrorKind {
        match code {
            1064 => MySqlErrorKind::Syntax,
            1146 => MySqlErrorKind::TableNotFound,
            1062 => MySqlErrorKind::DuplicateEntry,
            1045 => MySqlErrorKind::AccessDenied,
            _ => MySqlErrorKind::Other,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            MySqlErrorKind::Syntax => "syntax error",
            MySqlErrorKind::TableNotFound => "table not found",
            MySqlErrorKind::DuplicateEntry => "duplicate entry",
            MySqlErrorKind::AccessDenied => "access denied",
            MySqlErrorKind::Other => "server error",
        }
    }
}

/// The typed category of a query-layer validation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryErrorKind {
    UnknownField,
    UnknownOperator,
    UnsupportedOperator,
    TypeMismatch,
    InvalidSortDirection,
    OutOfRange,
}

impl QueryErrorKind {
    pub(crate) fn label(self) -> &'static str {
        match self {
            QueryErrorKind::UnknownField => "unknown query field",
            QueryErrorKind::UnknownOperator => "unknown query operator",
            QueryErrorKind::UnsupportedOperator => "unsupported query operator",
            QueryErrorKind::TypeMismatch => "query value type mismatch",
            QueryErrorKind::InvalidSortDirection => "invalid query sort direction",
            QueryErrorKind::OutOfRange => "out-of-range query value",
        }
    }
}

/// The typed category of an index declaration validation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexErrorKind {
    EmptyColumns,
    UnknownColumn,
    DuplicateColumn,
    DuplicateIndex,
    InvalidIdentifier,
    InvalidDeclaration,
}

impl IndexErrorKind {
    pub(crate) fn label(self) -> &'static str {
        match self {
            IndexErrorKind::EmptyColumns => "index has no columns",
            IndexErrorKind::UnknownColumn => "unknown index column",
            IndexErrorKind::DuplicateColumn => "duplicate index column",
            IndexErrorKind::DuplicateIndex => "duplicate index",
            IndexErrorKind::InvalidIdentifier => "invalid index identifier",
            IndexErrorKind::InvalidDeclaration => "invalid index declaration",
        }
    }
}

/// A typed cell value matching the IR field types `int`, `string` and `bool`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Int(i64),
    Text(String),
    Bool(bool),
}

impl Value {
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }

    /// Bool columns are stored as INTEGER 0/1 by SQLite; both forms are accepted.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            Value::Int(0) => Some(false),
            Value::Int(1) => Some(true),
            _ => None,
        }
    }
}

impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Value::Int(v)
    }
}

impl From<i32> for Value {
    fn from(v: i32) -> Self {
        Value::Int(i64::from(v))
    }
}

impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Value::Bool(v)
    }
}

impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Value::Text(v.to_string())
    }
}

impl From<String> for Value {
    fn from(v: String) -> Self {
        Value::Text(v)
    }
}

impl From<&Value> for Value {
    fn from(v: &Value) -> Self {
        v.clone()
    }
}

/// One result row: an ordered map of column name to typed value.
///
/// SQL NULL columns are omitted, so [`Row::get`] returns `None` for them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Row {
    cells: Vec<(String, Value)>,
}

impl Row {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a cell in place.
    pub fn set(&mut self, name: impl Into<String>, value: Value) {
        let name = name.into();
        if let Some((_, current)) = self.cells.iter_mut().find(|(k, _)| *k == name) {
            *current = value;
        } else {
            self.cells.push((name, value));
        }
    }

    /// Upsert a cell and return an owned row.
    ///
    /// The returned clone lets the same method work in place
    /// (`let mut r = Row::new(); r.insert(...);`) and as a builder
    /// (`Row::new().insert(...).insert(...)`).
    pub fn insert(&mut self, name: impl Into<String>, value: Value) -> Self {
        self.set(name, value);
        self.clone()
    }

    pub fn get(&self, name: &str) -> Option<&Value> {
        self.cells.iter().find(|(k, _)| k == name).map(|(_, v)| v)
    }

    /// Iterate over `(column, value)` pairs in insertion order.
    pub fn columns(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.cells.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn len(&self) -> usize {
        self.cells.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }
}

/// A readable, non-panicking error carrying the underlying driver message,
/// an optional SQLSTATE, an optional MySQL error code and an optional typed
/// query validation or index declaration category.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DbError {
    message: String,
    sqlstate: Option<String>,
    mysql_code: Option<u16>,
    mysql_kind: Option<MySqlErrorKind>,
    query_kind: Option<QueryErrorKind>,
    index_kind: Option<IndexErrorKind>,
}

impl DbError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            sqlstate: None,
            mysql_code: None,
            mysql_kind: None,
            query_kind: None,
            index_kind: None,
        }
    }

    /// Build an error carrying the SQLSTATE reported by a PostgreSQL server.
    pub fn with_sqlstate(sqlstate: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            sqlstate: Some(sqlstate.into()),
            mysql_code: None,
            mysql_kind: None,
            query_kind: None,
            index_kind: None,
        }
    }

    /// Build a typed error carrying a MySQL error code and optional SQLSTATE.
    pub fn with_mysql_error(code: u16, sqlstate: Option<&str>, message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            sqlstate: sqlstate.map(str::to_string),
            mysql_code: Some(code),
            mysql_kind: Some(MySqlErrorKind::from_code(code)),
            query_kind: None,
            index_kind: None,
        }
    }

    pub(crate) fn with_query_error(kind: QueryErrorKind, message: impl Into<String>) -> Self {
        Self {
            message: format!("{}: {}", kind.label(), message.into()),
            sqlstate: None,
            mysql_code: None,
            mysql_kind: None,
            query_kind: Some(kind),
            index_kind: None,
        }
    }

    pub(crate) fn with_index_error(kind: IndexErrorKind, message: impl Into<String>) -> Self {
        Self {
            message: format!("{}: {}", kind.label(), message.into()),
            sqlstate: None,
            mysql_code: None,
            mysql_kind: None,
            query_kind: None,
            index_kind: Some(kind),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    /// The SQLSTATE code, when the driver reported one.
    pub fn sqlstate(&self) -> Option<&str> {
        self.sqlstate.as_deref()
    }

    /// The MySQL server error code, when this error came from an ERR packet.
    pub fn mysql_code(&self) -> Option<u16> {
        self.mysql_code
    }

    /// The typed category of a MySQL server error code.
    pub fn mysql_error_kind(&self) -> Option<MySqlErrorKind> {
        self.mysql_kind
    }

    /// The typed category of a query-layer validation failure.
    pub fn query_error_kind(&self) -> Option<QueryErrorKind> {
        self.query_kind
    }

    /// The typed category of an index declaration validation failure.
    pub fn index_error_kind(&self) -> Option<IndexErrorKind> {
        self.index_kind
    }
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DbError {}

/// The result of `PRAGMA integrity_check`: one line per problem SQLite found
/// in the database file. An empty list means the file passed the check.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IntegrityReport {
    problems: Vec<String>,
}

impl IntegrityReport {
    /// True when the check found no problem.
    pub fn is_ok(&self) -> bool {
        self.problems.is_empty()
    }

    /// One entry per problem, in the order SQLite reported them.
    pub fn problems(&self) -> &[String] {
        &self.problems
    }
}

/// One child row `PRAGMA foreign_key_check` found without a matching parent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForeignKeyViolation {
    /// The child table that holds the unmatched row.
    pub table: String,
    /// The `rowid` of that row, when the child table has one.
    pub rowid: Option<i64>,
    /// The parent table the foreign key points at.
    pub parent: String,
    /// The index of the foreign key constraint inside the child table.
    pub foreign_key: i64,
}

/// The unified data abstraction. All drivers accept plain SQL text.
pub trait Database {
    fn exec(&mut self, sql: &str) -> Result<(), DbError>;
    fn query(&mut self, sql: &str) -> Result<Vec<Row>, DbError>;

    /// Run `sql` with `?` placeholders bound to `params`. SQLite binds natively;
    /// Kv/Memory/PgConnection/MySqlConnection substitute safely quoted literals
    /// through [`sql_literal`].
    fn exec_params(&mut self, sql: &str, params: &[Value]) -> Result<(), DbError> {
        self.exec(&substitute_params(sql, params)?)
    }

    /// Query with `?` placeholders bound to `params`.
    fn query_params(&mut self, sql: &str, params: &[Value]) -> Result<Vec<Row>, DbError> {
        let sql = substitute_params(sql, params)?;
        self.query(&sql)
    }

    /// Run SQLite's `PRAGMA integrity_check` and report what it found.
    ///
    /// The default executes the pragma through [`Database::query`], so every
    /// driver answers with its own semantics: SQLite returns the typed report
    /// and a driver without SQLite pragmas returns its readable SQL error.
    fn integrity_check(&mut self) -> Result<IntegrityReport, DbError> {
        let rows = self.query("PRAGMA integrity_check")?;
        let mut problems = Vec::new();
        for row in &rows {
            // SQLite answers one row per problem, or the single row "ok".
            if let Some(Value::Text(text)) = row.columns().next().map(|(_, value)| value) {
                if text != "ok" {
                    problems.push(text.clone());
                }
            }
        }
        Ok(IntegrityReport { problems })
    }

    /// Run SQLite's `PRAGMA foreign_key_check`: one typed violation per child
    /// row that has no matching parent, and an empty list when none exist.
    fn foreign_key_check(&mut self) -> Result<Vec<ForeignKeyViolation>, DbError> {
        let rows = self.query("PRAGMA foreign_key_check")?;
        Ok(rows
            .iter()
            .map(|row| ForeignKeyViolation {
                table: text_cell(row, "table"),
                rowid: row.get("rowid").and_then(Value::as_i64),
                parent: text_cell(row, "parent"),
                foreign_key: row.get("fkid").and_then(Value::as_i64).unwrap_or_default(),
            })
            .collect())
    }

    /// Begin an explicit transaction: `BEGIN` is sent now, `COMMIT` /
    /// `ROLLBACK` run on the returned [`Transaction`] guard, and a guard
    /// dropped while still open sends `ROLLBACK`. The default works for any
    /// driver whose `exec` accepts the transaction SQL; `Kv` and `Memory`
    /// reject `BEGIN` and so fail here with a readable error.
    fn transaction(&mut self) -> Result<Transaction<'_, Self>, DbError>
    where
        Self: Sized,
    {
        Transaction::begin(self)
    }
}

/// The text cell `name` of `row`, or an empty string when the driver reports
/// no such column.
fn text_cell(row: &Row, name: &str) -> String {
    match row.get(name) {
        Some(Value::Text(text)) => text.clone(),
        _ => String::new(),
    }
}

/// Replace `?` placeholders outside string literals with quoted values.
fn substitute_params(sql: &str, params: &[Value]) -> Result<String, DbError> {
    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut used = 0usize;
    let mut in_quote = false;
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\'' {
            if in_quote && i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                out.push_str("''");
                i += 2;
                continue;
            }
            in_quote = !in_quote;
            out.push('\'');
            i += 1;
            continue;
        }
        if bytes[i] == b'?' && !in_quote {
            let value = params
                .get(used)
                .ok_or_else(|| DbError::new("not enough values for SQL placeholders"))?;
            out.push_str(&sql_literal(value));
            used += 1;
            i += 1;
            continue;
        }
        let ch = sql[i..].chars().next().unwrap_or('\u{fffd}');
        out.push(ch);
        i += ch.len_utf8();
    }
    if used != params.len() {
        return Err(DbError::new("too many values for SQL placeholders"));
    }
    Ok(out)
}

/// Open a SQLite database at `path`. Alias for [`Sqlite::open`].
pub fn open(path: &str) -> Result<Sqlite, DbError> {
    Sqlite::open(path)
}
