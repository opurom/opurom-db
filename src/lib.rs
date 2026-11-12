//! OPUROM R2 data layer.
//!
//! Three interchangeable [`Database`] drivers: [`Sqlite`] (direct FFI to the
//! macOS system libsqlite3), [`Kv`] (file-backed key/value store) and
//! [`Memory`] (volatile). IR model definitions drive type-correct CRUD SQL and
//! deterministic migration files.

mod crud;
mod kv;
mod memory;
mod model;
mod store;

#[cfg(target_os = "macos")]
#[path = "sqlite.rs"]
mod sqlite;
#[cfg(not(target_os = "macos"))]
#[path = "sqlite_stub.rs"]
mod sqlite;

pub use crud::{create, create_table, delete, get, list, update};
pub use kv::Kv;
pub use memory::Memory;
pub use model::{
    create_table_sql, migration_files, parse_models, parse_models_value, schema_sql, sql_literal,
    validate_ident, validate_model, write_migrations, Field, FieldType, Model,
};
pub use sqlite::Sqlite;

use std::fmt;

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

/// A readable, non-panicking error carrying the underlying driver message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DbError {
    message: String,
}

impl DbError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DbError {}

/// The unified data abstraction. All drivers accept plain SQL text.
pub trait Database {
    fn exec(&mut self, sql: &str) -> Result<(), DbError>;
    fn query(&mut self, sql: &str) -> Result<Vec<Row>, DbError>;

    /// Run `sql` with `?` placeholders bound to `params`. SQLite binds natively;
    /// other drivers substitute safely quoted literals through [`sql_literal`].
    fn exec_params(&mut self, sql: &str, params: &[Value]) -> Result<(), DbError> {
        self.exec(&substitute_params(sql, params)?)
    }

    /// Query with `?` placeholders bound to `params`.
    fn query_params(&mut self, sql: &str, params: &[Value]) -> Result<Vec<Row>, DbError> {
        let sql = substitute_params(sql, params)?;
        self.query(&sql)
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
