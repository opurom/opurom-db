//! macOS SQLite driver: direct FFI to the system libsqlite3, no crate.

use crate::{Database, DbError, Row, Value};
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::ptr;

const SQLITE_OK: c_int = 0;
const SQLITE_ROW: c_int = 100;
const SQLITE_DONE: c_int = 101;
const SQLITE_INTEGER: c_int = 1;
const SQLITE_FLOAT: c_int = 2;
const SQLITE_TEXT: c_int = 3;
const SQLITE_BLOB: c_int = 4;
const SQLITE_NULL: c_int = 5;

#[link(name = "sqlite3")]
unsafe extern "C" {
    fn sqlite3_open(filename: *const c_char, db: *mut *mut c_void) -> c_int;
    fn sqlite3_close(db: *mut c_void) -> c_int;
    fn sqlite3_exec(
        db: *mut c_void,
        sql: *const c_char,
        callback: Option<
            unsafe extern "C" fn(*mut c_void, c_int, *mut *mut c_char, *mut *mut c_char) -> c_int,
        >,
        arg: *mut c_void,
        errmsg: *mut *mut c_char,
    ) -> c_int;
    fn sqlite3_errmsg(db: *mut c_void) -> *const c_char;
    fn sqlite3_free(ptr: *mut c_void);
    fn sqlite3_prepare_v2(
        db: *mut c_void,
        sql: *const c_char,
        nbyte: c_int,
        stmt: *mut *mut c_void,
        tail: *mut *const c_char,
    ) -> c_int;
    fn sqlite3_step(stmt: *mut c_void) -> c_int;
    fn sqlite3_finalize(stmt: *mut c_void) -> c_int;
    fn sqlite3_column_count(stmt: *mut c_void) -> c_int;
    fn sqlite3_column_name(stmt: *mut c_void, col: c_int) -> *const c_char;
    fn sqlite3_column_type(stmt: *mut c_void, col: c_int) -> c_int;
    fn sqlite3_column_int64(stmt: *mut c_void, col: c_int) -> i64;
    fn sqlite3_column_text(stmt: *mut c_void, col: c_int) -> *const u8;
    fn sqlite3_column_bytes(stmt: *mut c_void, col: c_int) -> c_int;
    fn sqlite3_bind_int64(stmt: *mut c_void, index: c_int, value: i64) -> c_int;
    fn sqlite3_bind_text(
        stmt: *mut c_void,
        index: c_int,
        value: *const c_char,
        nbyte: c_int,
        destructor: Option<unsafe extern "C" fn(*mut c_void)>,
    ) -> c_int;
}

fn errmsg(db: *mut c_void) -> String {
    if db.is_null() {
        return "sqlite3 handle unavailable".to_string();
    }
    unsafe {
        let p = sqlite3_errmsg(db);
        if p.is_null() {
            "unknown sqlite error".to_string()
        } else {
            CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    }
}

fn cstring(text: &str, what: &str) -> Result<CString, DbError> {
    CString::new(text).map_err(|_| DbError::new(format!("{what} contains a NUL byte")))
}

/// Unbound `?` parameters become SQL NULL in SQLite; count them first so a
/// mismatch is a readable error instead of a silently NULL insert.
fn count_placeholders(sql: &str) -> usize {
    let bytes = sql.as_bytes();
    let mut count = 0usize;
    let mut in_quote = false;
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\'' {
            if in_quote && i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                i += 2;
                continue;
            }
            in_quote = !in_quote;
        } else if bytes[i] == b'?' && !in_quote {
            count += 1;
        }
        i += 1;
    }
    count
}

struct Conn {
    db: *mut c_void,
}

impl Drop for Conn {
    fn drop(&mut self) {
        if !self.db.is_null() {
            unsafe { sqlite3_close(self.db) };
            self.db = ptr::null_mut();
        }
    }
}

struct Stmt(*mut c_void);

impl Drop for Stmt {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { sqlite3_finalize(self.0) };
            self.0 = ptr::null_mut();
        }
    }
}

/// Owned buffers for bound text; must outlive the prepared statement.
type BoundText = Vec<Option<CString>>;

impl Conn {
    fn open(path: &str) -> Result<Conn, DbError> {
        let cpath = cstring(path, "database path")?;
        let mut db = ptr::null_mut();
        let rc = unsafe { sqlite3_open(cpath.as_ptr(), &mut db) };
        if rc != SQLITE_OK {
            let detail = errmsg(db);
            if !db.is_null() {
                unsafe { sqlite3_close(db) };
            }
            return Err(DbError::new(format!(
                "sqlite3_open({path:?}) failed: {detail}"
            )));
        }
        if db.is_null() {
            return Err(DbError::new("sqlite3_open returned a null handle"));
        }
        Ok(Conn { db })
    }

    /// sqlite3_exec runs every statement in the string (used for schema.sql).
    fn exec(&self, sql: &str) -> Result<(), DbError> {
        let csql = cstring(sql, "SQL statement")?;
        let mut msg: *mut c_char = ptr::null_mut();
        let rc = unsafe { sqlite3_exec(self.db, csql.as_ptr(), None, ptr::null_mut(), &mut msg) };
        if rc != SQLITE_OK {
            let detail = if msg.is_null() {
                errmsg(self.db)
            } else {
                let s = unsafe { CStr::from_ptr(msg) }
                    .to_string_lossy()
                    .into_owned();
                unsafe { sqlite3_free(msg as *mut c_void) };
                s
            };
            return Err(DbError::new(format!("sqlite exec failed: {detail}")));
        }
        Ok(())
    }

    fn prepare(&self, sql: &str, params: &[Value]) -> Result<(Stmt, BoundText), DbError> {
        let expected = count_placeholders(sql);
        if expected != params.len() {
            return Err(DbError::new(format!(
                "SQL has {expected} placeholders but {} values were bound",
                params.len()
            )));
        }
        let csql = cstring(sql, "SQL statement")?;
        let mut raw: *mut c_void = ptr::null_mut();
        let rc =
            unsafe { sqlite3_prepare_v2(self.db, csql.as_ptr(), -1, &mut raw, ptr::null_mut()) };
        if rc != SQLITE_OK {
            if !raw.is_null() {
                unsafe { sqlite3_finalize(raw) };
            }
            return Err(DbError::new(format!(
                "sqlite prepare failed: {}",
                errmsg(self.db)
            )));
        }
        if raw.is_null() {
            return Err(DbError::new(format!(
                "sqlite prepare produced no statement for {sql:?}"
            )));
        }
        let stmt = Stmt(raw);
        let mut owned: BoundText = Vec::with_capacity(params.len());
        for p in params {
            match p {
                Value::Text(s) => owned.push(Some(cstring(s, "bound text")?)),
                _ => owned.push(None),
            }
        }
        for (i, p) in params.iter().enumerate() {
            let index = (i + 1) as c_int;
            let rc = match p {
                Value::Int(n) => unsafe { sqlite3_bind_int64(stmt.0, index, *n) },
                Value::Bool(b) => unsafe { sqlite3_bind_int64(stmt.0, index, i64::from(*b)) },
                Value::Text(_) => {
                    let buf = owned[i].as_ref().expect("text buffer was prepared");
                    let len = buf.as_bytes().len() as c_int;
                    // SQLITE_STATIC (null destructor): buf outlives stmt.
                    unsafe { sqlite3_bind_text(stmt.0, index, buf.as_ptr(), len, None) }
                }
            };
            if rc != SQLITE_OK {
                return Err(DbError::new(format!(
                    "sqlite bind failed: {}",
                    errmsg(self.db)
                )));
            }
        }
        Ok((stmt, owned))
    }

    fn run(&self, stmt: &Stmt) -> Result<(), DbError> {
        loop {
            let rc = unsafe { sqlite3_step(stmt.0) };
            if rc == SQLITE_DONE {
                return Ok(());
            }
            if rc != SQLITE_ROW {
                return Err(DbError::new(format!(
                    "sqlite step failed: {}",
                    errmsg(self.db)
                )));
            }
        }
    }

    fn rows(&self, stmt: &Stmt) -> Result<Vec<Row>, DbError> {
        let count = unsafe { sqlite3_column_count(stmt.0) };
        let mut names = Vec::with_capacity(count as usize);
        for i in 0..count {
            let p = unsafe { sqlite3_column_name(stmt.0, i) };
            names.push(if p.is_null() {
                format!("column{i}")
            } else {
                unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
            });
        }
        let mut rows = Vec::new();
        loop {
            let rc = unsafe { sqlite3_step(stmt.0) };
            if rc == SQLITE_DONE {
                break;
            }
            if rc != SQLITE_ROW {
                return Err(DbError::new(format!(
                    "sqlite step failed: {}",
                    errmsg(self.db)
                )));
            }
            let mut row = Row::new();
            for i in 0..count {
                let value = match unsafe { sqlite3_column_type(stmt.0, i) } {
                    SQLITE_INTEGER => Value::Int(unsafe { sqlite3_column_int64(stmt.0, i) }),
                    // FLOAT and BLOB have no Value variant; expose their text form.
                    SQLITE_TEXT | SQLITE_FLOAT | SQLITE_BLOB => {
                        let p = unsafe { sqlite3_column_text(stmt.0, i) };
                        let len = unsafe { sqlite3_column_bytes(stmt.0, i) };
                        if p.is_null() || len <= 0 {
                            Value::Text(String::new())
                        } else {
                            let bytes = unsafe { std::slice::from_raw_parts(p, len as usize) };
                            Value::Text(String::from_utf8_lossy(bytes).into_owned())
                        }
                    }
                    // Value has no NULL variant: omit the cell.
                    SQLITE_NULL => continue,
                    _ => continue,
                };
                row.set(names[i as usize].clone(), value);
            }
            rows.push(row);
        }
        Ok(rows)
    }
}

pub struct Sqlite {
    conn: Conn,
}

impl Sqlite {
    pub fn open(path: &str) -> Result<Sqlite, DbError> {
        Ok(Sqlite {
            conn: Conn::open(path)?,
        })
    }

    /// Execute `sql` with real `sqlite3_bind_*` parameter binding.
    pub fn exec_params(&mut self, sql: &str, params: &[Value]) -> Result<(), DbError> {
        let (stmt, _owned) = self.conn.prepare(sql, params)?;
        self.conn.run(&stmt)
    }

    /// Query with real `sqlite3_bind_*` parameter binding.
    pub fn query_params(&mut self, sql: &str, params: &[Value]) -> Result<Vec<Row>, DbError> {
        let (stmt, owned) = self.conn.prepare(sql, params)?;
        let result = self.conn.rows(&stmt);
        drop(stmt);
        drop(owned);
        result
    }
}

impl Database for Sqlite {
    fn exec(&mut self, sql: &str) -> Result<(), DbError> {
        self.conn.exec(sql)
    }

    fn query(&mut self, sql: &str) -> Result<Vec<Row>, DbError> {
        let (stmt, owned) = self.conn.prepare(sql, &[])?;
        let result = self.conn.rows(&stmt);
        drop(stmt);
        drop(owned);
        result
    }

    fn exec_params(&mut self, sql: &str, params: &[Value]) -> Result<(), DbError> {
        Sqlite::exec_params(self, sql, params)
    }

    fn query_params(&mut self, sql: &str, params: &[Value]) -> Result<Vec<Row>, DbError> {
        Sqlite::query_params(self, sql, params)
    }
}
