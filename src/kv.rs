use crate::store::Store;
use crate::{Database, DbError, Row};
use std::path::Path;

/// Embedded file-backed key/value store. `key<TAB>value` lines, UTF-8.
///
/// Atomic writes go through a temp file plus rename. `exec`/`query` implement a
/// small SQL subset (CREATE TABLE / INSERT / SELECT / UPDATE / DELETE) so the
/// shared CRUD helpers work unchanged.
pub struct Kv {
    store: Store,
}

impl Kv {
    pub fn open(path: &str) -> Result<Kv, DbError> {
        Ok(Kv {
            store: Store::open(Path::new(path))?,
        })
    }

    pub fn put(&mut self, key: &str, value: &str) -> Result<(), DbError> {
        self.store.put(key, value)
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.store.get(key)
    }

    pub fn delete(&mut self, key: &str) -> Result<bool, DbError> {
        self.store.delete(key)
    }

    pub fn keys(&self) -> Vec<String> {
        self.store.keys()
    }
}

impl Database for Kv {
    fn exec(&mut self, sql: &str) -> Result<(), DbError> {
        self.store.exec(sql)
    }

    fn query(&mut self, sql: &str) -> Result<Vec<Row>, DbError> {
        self.store.query(sql)
    }
}
