use crate::store::Store;
use crate::{Database, DbError, Row};

/// Volatile driver with the same SQL subset and semantics as `Kv`.
pub struct Memory {
    store: Store,
}

impl Memory {
    pub fn new() -> Memory {
        Memory {
            store: Store::in_memory(),
        }
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self::new()
    }
}

impl Database for Memory {
    fn exec(&mut self, sql: &str) -> Result<(), DbError> {
        self.store.exec(sql)
    }

    fn query(&mut self, sql: &str) -> Result<Vec<Row>, DbError> {
        self.store.query(sql)
    }
}
