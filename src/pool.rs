//! One Mutex-serialized SQLite connection shared by server threads.

use std::sync::{Arc, Mutex};

use crate::{DbError, Sqlite};

/// A cloneable handle to one [`Sqlite`] connection.
///
/// `Sqlite` owns a raw `sqlite3*` pointer and is not `Send`. `PooledDb` keeps
/// that value private and permits access only through [`PooledDb::with`], which
/// holds the Mutex for the whole closure. This is one shared connection, not a
/// sized pool of independent connections.
#[derive(Clone)]
pub struct PooledDb(Arc<Mutex<Sqlite>>);

// SAFETY: `Sqlite::open` verifies that libsqlite3 is thread-safe. The raw
// pointer never escapes `PooledDb`; every safe access obtains the Mutex and
// holds it for the entire `&mut Sqlite` borrow. Safe code therefore cannot use
// the connection from two threads without that Mutex serializing the FFI calls.
#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe impl Send for PooledDb {}

// SAFETY: a shared `&PooledDb` produces only another cloned handle or a
// Mutex-guarded `&mut Sqlite`; the same serialization invariant applies.
#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe impl Sync for PooledDb {}

impl PooledDb {
    /// Open one SQLite connection and wrap it for sharing between threads.
    pub fn open(path: &str) -> Result<PooledDb, DbError> {
        Ok(PooledDb(Arc::new(Mutex::new(Sqlite::open(path)?))))
    }

    /// Run `f` with exclusive, Mutex-serialized access to the connection.
    ///
    /// A poisoned Mutex is recovered: the SQLite handle stays usable and the
    /// guard still serializes subsequent access.
    pub fn with<T>(&self, f: impl FnOnce(&mut Sqlite) -> T) -> T {
        let mut guard = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        f(&mut *guard)
    }
}
