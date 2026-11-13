//! Explicit transactions through the [`Database`] trait.

use crate::{Database, DbError};
use std::ops::{Deref, DerefMut};

/// A guard over one open transaction.
///
/// [`Database::transaction`] sends `BEGIN` and returns this guard. Statements
/// run through the deref'd driver, so the full [`Database`] API, including the
/// CRUD helpers, works inside the transaction. `commit` and `rollback` close
/// it explicitly; a guard dropped while still open sends `ROLLBACK`, so an
/// early return or unwind cannot leave writes half-applied.
pub struct Transaction<'a, D: Database + ?Sized> {
    db: &'a mut D,
    open: bool,
}

impl<D: Database + ?Sized> Transaction<'_, D> {
    pub(crate) fn begin(db: &mut D) -> Result<Transaction<'_, D>, DbError> {
        db.exec("BEGIN")?;
        Ok(Transaction { db, open: true })
    }

    /// Commit the transaction and release the driver borrow.
    ///
    /// When the driver rejects the commit the transaction may still be open,
    /// so the guard keeps its open flag and dropping it still sends
    /// `ROLLBACK`.
    pub fn commit(mut self) -> Result<(), DbError> {
        let result = self.db.exec("COMMIT");
        if result.is_ok() {
            self.open = false;
        }
        result
    }

    /// Roll the transaction back and release the driver borrow.
    pub fn rollback(mut self) -> Result<(), DbError> {
        self.open = false;
        self.db.exec("ROLLBACK")
    }
}

impl<D: Database + ?Sized> Deref for Transaction<'_, D> {
    type Target = D;

    fn deref(&self) -> &D {
        self.db
    }
}

impl<D: Database + ?Sized> DerefMut for Transaction<'_, D> {
    fn deref_mut(&mut self) -> &mut D {
        self.db
    }
}

impl<D: Database + ?Sized> Drop for Transaction<'_, D> {
    fn drop(&mut self) {
        if self.open {
            // The driver may have closed the transaction itself (for example
            // after a rejected COMMIT); a failing ROLLBACK here is best-effort.
            let _ = self.db.exec("ROLLBACK");
        }
    }
}
