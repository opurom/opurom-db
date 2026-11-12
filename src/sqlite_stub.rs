//! Fallback for targets without a linked libsqlite3. Never fakes success.

use crate::{Database, DbError, Row, Value};

const UNAVAILABLE: &str = "SQLite FFI is unavailable on this target: opurom-db links the system libsqlite3 on macOS and Linux; use Kv or Memory instead";

pub struct Sqlite;

impl Sqlite {
    pub fn open(_path: &str) -> Result<Sqlite, DbError> {
        Err(DbError::new(UNAVAILABLE))
    }

    pub fn exec_params(&mut self, _sql: &str, _params: &[Value]) -> Result<(), DbError> {
        Err(DbError::new(UNAVAILABLE))
    }

    pub fn query_params(&mut self, _sql: &str, _params: &[Value]) -> Result<Vec<Row>, DbError> {
        Err(DbError::new(UNAVAILABLE))
    }
}

impl Database for Sqlite {
    fn exec(&mut self, _sql: &str) -> Result<(), DbError> {
        Err(DbError::new(UNAVAILABLE))
    }

    fn query(&mut self, _sql: &str) -> Result<Vec<Row>, DbError> {
        Err(DbError::new(UNAVAILABLE))
    }

    fn exec_params(&mut self, _sql: &str, _params: &[Value]) -> Result<(), DbError> {
        Err(DbError::new(UNAVAILABLE))
    }

    fn query_params(&mut self, _sql: &str, _params: &[Value]) -> Result<Vec<Row>, DbError> {
        Err(DbError::new(UNAVAILABLE))
    }
}
