//! Shared engine for the file-backed KV and in-memory drivers.
//!
//! Raw entries are `key<TAB>value` lines. Table rows live under
//! `<table>/<sequence>` keys as compact JSON objects, so int/string/bool
//! types survive a reopen. Only a small SQL subset is interpreted.

use crate::{validate_ident, DbError, Row, Value};
use serde_json::Value as Json;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Default)]
pub struct Store {
    entries: BTreeMap<String, String>,
    file: Option<PathBuf>,
}

impl Store {
    pub fn in_memory() -> Store {
        Store::default()
    }

    pub fn open(path: &Path) -> Result<Store, DbError> {
        let mut entries = BTreeMap::new();
        match fs::read_to_string(path) {
            Ok(text) => {
                for (i, line) in text.lines().enumerate() {
                    if line.is_empty() {
                        continue;
                    }
                    let (key, value) = line.split_once('\t').ok_or_else(|| {
                        DbError::new(format!(
                            "{}: line {} has no tab separator",
                            path.display(),
                            i + 1
                        ))
                    })?;
                    entries.insert(key.to_string(), value.to_string());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(DbError::new(format!("cannot read {}: {e}", path.display()))),
        }
        Ok(Store {
            entries,
            file: Some(path.to_path_buf()),
        })
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(String::as_str)
    }

    pub fn keys(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }

    pub fn put(&mut self, key: &str, value: &str) -> Result<(), DbError> {
        if key.is_empty() || key.chars().any(|c| matches!(c, '\t' | '\n' | '\r')) {
            return Err(DbError::new(
                "KV key must be non-empty and contain no tab or newline",
            ));
        }
        if value.chars().any(|c| matches!(c, '\n' | '\r')) {
            return Err(DbError::new("KV value must not contain a newline"));
        }
        self.entries.insert(key.to_string(), value.to_string());
        self.flush()
    }

    pub fn delete(&mut self, key: &str) -> Result<bool, DbError> {
        let removed = self.entries.remove(key).is_some();
        if removed {
            self.flush()?;
        }
        Ok(removed)
    }

    /// Atomic write: sorted lines to `path.tmp`, then rename over `path`.
    fn flush(&self) -> Result<(), DbError> {
        let Some(path) = self.file.as_ref() else {
            return Ok(());
        };
        let mut buf = String::new();
        for (key, value) in &self.entries {
            buf.push_str(key);
            buf.push('\t');
            buf.push_str(value);
            buf.push('\n');
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| {
                    DbError::new(format!("cannot create {}: {e}", parent.display()))
                })?;
            }
        }
        let mut tmp_os = path.as_os_str().to_os_string();
        tmp_os.push(".tmp");
        let tmp = PathBuf::from(tmp_os);
        fs::write(&tmp, buf.as_bytes())
            .map_err(|e| DbError::new(format!("cannot write {}: {e}", tmp.display())))?;
        fs::rename(&tmp, path).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            DbError::new(format!(
                "cannot rename {} to {}: {e}",
                tmp.display(),
                path.display()
            ))
        })?;
        Ok(())
    }

    fn next_key(&self, table: &str) -> String {
        let p = table_prefix(table);
        let max = self
            .entries
            .keys()
            .filter(|k| k.starts_with(&p))
            .filter_map(|k| k[p.len()..].parse::<u64>().ok())
            .max()
            .unwrap_or(0);
        format!("{p}{:020}", max + 1)
    }

    fn table_keys(&self, table: &str) -> Vec<String> {
        let p = table_prefix(table);
        self.entries
            .keys()
            .filter(|k| k.starts_with(&p))
            .cloned()
            .collect()
    }

    fn mutate(
        &mut self,
        table: &str,
        filter: &Option<(String, Value)>,
        assignments: &[(String, Value)],
    ) -> Result<(), DbError> {
        for key in self.table_keys(table) {
            let raw = self.entries.get(&key).cloned().unwrap_or_default();
            let mut row = decode_row(&raw)?;
            if let Some((col, value)) = filter {
                if row.get(col) != Some(value) {
                    continue;
                }
            }
            for (col, value) in assignments {
                row.set(col.clone(), value.clone());
            }
            self.entries.insert(key, encode_row(&row));
        }
        self.flush()
    }

    pub fn exec(&mut self, sql: &str) -> Result<(), DbError> {
        let s = sql.trim().trim_end_matches(';').trim();
        if s.is_empty() {
            return Err(DbError::new("empty SQL statement"));
        }
        if let Some(rest) = strip_kw(s, "CREATE TABLE") {
            let rest = strip_kw(rest, "IF NOT EXISTS").unwrap_or(rest);
            let (table, tail) = take_word(rest);
            ident(table)?;
            if !tail.starts_with('(') {
                return Err(DbError::new("CREATE TABLE needs a column list"));
            }
            split_paren(tail)?;
            return Ok(());
        }
        if let Some(rest) = strip_kw(s, "INSERT INTO") {
            let (table, rest) = take_word(rest);
            ident(table)?;
            let (cols, rest) = split_paren(rest)?;
            let rest = strip_kw(rest, "VALUES")
                .ok_or_else(|| DbError::new("INSERT needs a VALUES clause"))?;
            let (vals, tail) = split_paren(rest)?;
            if !tail.is_empty() {
                return Err(DbError::new("unexpected text after INSERT VALUES"));
            }
            let cols = split_args(cols)?;
            let vals = split_args(vals)?;
            if cols.len() != vals.len() {
                return Err(DbError::new("INSERT column/value count mismatch"));
            }
            let mut row = Row::new();
            for (col, val) in cols.iter().zip(vals.iter()) {
                row.set(ident(col)?, parse_literal(val)?);
            }
            let key = self.next_key(table);
            self.entries.insert(key, encode_row(&row));
            return self.flush();
        }
        if let Some(rest) = strip_kw(s, "UPDATE") {
            let (table, rest) = take_word(rest);
            ident(table)?;
            let rest =
                strip_kw(rest, "SET").ok_or_else(|| DbError::new("UPDATE needs a SET clause"))?;
            let upper = rest.to_ascii_uppercase();
            let (set_part, where_part) = match upper.find(" WHERE ") {
                Some(i) => (&rest[..i], Some(&rest[i + 7..])),
                None => (rest, None),
            };
            let assignments = split_args(set_part)?
                .iter()
                .map(|a| parse_condition(a))
                .collect::<Result<Vec<_>, _>>()?;
            let filter = match where_part {
                Some(w) => Some(parse_condition(w)?),
                None => None,
            };
            return self.mutate(table, &filter, &assignments);
        }
        if let Some(rest) = strip_kw(s, "DELETE FROM") {
            let (table, rest) = take_word(rest);
            ident(table)?;
            let filter = if rest.is_empty() {
                None
            } else {
                let r = strip_kw(rest, "WHERE")
                    .ok_or_else(|| DbError::new("unsupported DELETE clause"))?;
                Some(parse_condition(r)?)
            };
            for key in self.table_keys(table) {
                let remove = match &filter {
                    None => true,
                    Some((col, value)) => {
                        let raw = self.entries.get(&key).cloned().unwrap_or_default();
                        decode_row(&raw)?.get(col) == Some(value)
                    }
                };
                if remove {
                    self.entries.remove(&key);
                }
            }
            return self.flush();
        }
        Err(DbError::new(format!(
            "unsupported SQL for KV/memory driver: {s}"
        )))
    }

    pub fn query(&self, sql: &str) -> Result<Vec<Row>, DbError> {
        let s = sql.trim().trim_end_matches(';').trim();
        let rest = strip_kw(s, "SELECT")
            .ok_or_else(|| DbError::new("KV/memory driver supports only SELECT queries"))?;
        let rest = rest
            .strip_prefix('*')
            .ok_or_else(|| DbError::new("KV/memory driver supports only SELECT *"))?
            .trim();
        let rest =
            strip_kw(rest, "FROM").ok_or_else(|| DbError::new("SELECT needs a FROM clause"))?;
        let (table, rest) = take_word(rest);
        ident(table)?;
        let filter = if rest.is_empty() {
            None
        } else {
            let r =
                strip_kw(rest, "WHERE").ok_or_else(|| DbError::new("unsupported SELECT clause"))?;
            Some(parse_condition(r)?)
        };
        let mut rows = Vec::new();
        for (key, raw) in &self.entries {
            if !key.starts_with(&table_prefix(table)) {
                continue;
            }
            let row = decode_row(raw)?;
            if let Some((col, value)) = &filter {
                if row.get(col) != Some(value) {
                    continue;
                }
            }
            rows.push(row);
        }
        Ok(rows)
    }
}

fn table_prefix(table: &str) -> String {
    format!("{table}/")
}

fn strip_kw<'a>(s: &'a str, kw: &str) -> Option<&'a str> {
    let head = s.get(..kw.len())?;
    if head.eq_ignore_ascii_case(kw) {
        Some(s[kw.len()..].trim())
    } else {
        None
    }
}

fn take_word(s: &str) -> (&str, &str) {
    let end = s
        .find(|c: char| c.is_whitespace() || c == '(' || c == ';')
        .unwrap_or(s.len());
    (&s[..end], s[end..].trim())
}

fn split_paren(s: &str) -> Result<(&str, &str), DbError> {
    let rest = s
        .strip_prefix('(')
        .ok_or_else(|| DbError::new("expected '(' in SQL"))?;
    let bytes = rest.as_bytes();
    let mut in_quote = false;
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\'' {
            if in_quote && i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                i += 2;
                continue;
            }
            in_quote = !in_quote;
        } else if bytes[i] == b')' && !in_quote {
            return Ok((&rest[..i], rest[i + 1..].trim()));
        }
        i += 1;
    }
    Err(DbError::new("unbalanced parentheses in SQL"))
}

fn split_args(s: &str) -> Result<Vec<String>, DbError> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                if in_quote && chars.peek() == Some(&'\'') {
                    cur.push('\'');
                    cur.push('\'');
                    chars.next();
                } else {
                    in_quote = !in_quote;
                    cur.push('\'');
                }
            }
            ',' if !in_quote => {
                parts.push(cur.trim().to_string());
                cur = String::new();
            }
            _ => cur.push(c),
        }
    }
    if in_quote {
        return Err(DbError::new("unterminated string literal in SQL"));
    }
    parts.push(cur.trim().to_string());
    if parts.iter().any(|p| p.is_empty()) {
        return Err(DbError::new("empty item in SQL list"));
    }
    Ok(parts)
}

fn ident(s: &str) -> Result<String, DbError> {
    let s = s.trim();
    validate_ident(s)?;
    Ok(s.to_string())
}

fn parse_literal(s: &str) -> Result<Value, DbError> {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('\'') && s.ends_with('\'') {
        return Ok(Value::Text(s[1..s.len() - 1].replace("''", "'")));
    }
    if let Ok(n) = s.parse::<i64>() {
        return Ok(Value::Int(n));
    }
    if s.eq_ignore_ascii_case("true") {
        return Ok(Value::Bool(true));
    }
    if s.eq_ignore_ascii_case("false") {
        return Ok(Value::Bool(false));
    }
    Err(DbError::new(format!("unsupported SQL literal: {s:?}")))
}

fn parse_condition(s: &str) -> Result<(String, Value), DbError> {
    let (left, right) = s
        .split_once('=')
        .ok_or_else(|| DbError::new("expected <column> = <literal>"))?;
    Ok((ident(left)?, parse_literal(right)?))
}

fn encode_row(row: &Row) -> String {
    let mut obj = serde_json::Map::new();
    for (key, value) in row.columns() {
        obj.insert(
            key.to_string(),
            match value {
                Value::Int(n) => Json::from(*n),
                Value::Text(s) => Json::from(s.clone()),
                Value::Bool(b) => Json::from(*b),
            },
        );
    }
    Json::Object(obj).to_string()
}

fn decode_row(raw: &str) -> Result<Row, DbError> {
    let parsed: Json = serde_json::from_str(raw)
        .map_err(|e| DbError::new(format!("corrupt KV table row: {e}")))?;
    let obj = parsed
        .as_object()
        .ok_or_else(|| DbError::new("KV table row is not a JSON object"))?;
    let mut row = Row::new();
    for (key, value) in obj {
        let cell = match value {
            Json::Number(n) => n.as_i64().map(Value::Int),
            Json::String(s) => Some(Value::Text(s.clone())),
            Json::Bool(b) => Some(Value::Bool(*b)),
            _ => None,
        };
        if let Some(cell) = cell {
            row.set(key.clone(), cell);
        }
    }
    Ok(row)
}
