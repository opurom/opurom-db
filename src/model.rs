use crate::{DbError, Value};
use serde_json::Value as Json;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// IR field types. Bool is stored as INTEGER 0/1 in SQL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldType {
    Int,
    Text,
    Bool,
}

impl FieldType {
    pub fn as_str(self) -> &'static str {
        match self {
            FieldType::Int => "int",
            FieldType::Text => "string",
            FieldType::Bool => "bool",
        }
    }

    pub fn sql_type(self) -> &'static str {
        match self {
            FieldType::Int | FieldType::Bool => "INTEGER",
            FieldType::Text => "TEXT",
        }
    }

    pub fn zero(self) -> Value {
        match self {
            FieldType::Int => Value::Int(0),
            FieldType::Text => Value::Text(String::new()),
            FieldType::Bool => Value::Bool(false),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub ty: FieldType,
    pub primary: bool,
    pub default: Option<Value>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Model {
    pub name: String,
    pub fields: Vec<Field>,
}

impl Model {
    pub fn primary(&self) -> Option<&Field> {
        self.fields.iter().find(|f| f.primary)
    }

    pub fn table(&self) -> &str {
        &self.name
    }

    pub fn from_ir(value: &Json) -> Result<Model, DbError> {
        let obj = value
            .as_object()
            .ok_or_else(|| DbError::new("model entry must be a JSON object"))?;
        let name = obj
            .get("name")
            .and_then(Json::as_str)
            .ok_or_else(|| DbError::new("model entry is missing a string 'name'"))?;
        validate_ident(name)?;
        let entries = obj
            .get("fields")
            .and_then(Json::as_array)
            .ok_or_else(|| DbError::new(format!("model {name:?} is missing a 'fields' array")))?;
        let mut fields = Vec::with_capacity(entries.len());
        for entry in entries {
            let fobj = entry.as_object().ok_or_else(|| {
                DbError::new(format!("field of model {name:?} must be a JSON object"))
            })?;
            let fname = fobj.get("name").and_then(Json::as_str).ok_or_else(|| {
                DbError::new(format!(
                    "field of model {name:?} is missing a string 'name'"
                ))
            })?;
            validate_ident(fname)?;
            let ty = match fobj.get("type").and_then(Json::as_str) {
                Some("int") => FieldType::Int,
                Some("string") => FieldType::Text,
                Some("bool") => FieldType::Bool,
                other => {
                    return Err(DbError::new(format!(
                        "field {fname:?} has unsupported type {other:?}; expected int|string|bool"
                    )))
                }
            };
            let primary = match fobj.get("primary") {
                None | Some(Json::Null) => false,
                Some(Json::Bool(b)) => *b,
                Some(_) => {
                    return Err(DbError::new(format!(
                        "field {fname:?} has a non-boolean 'primary'"
                    )))
                }
            };
            let default = match fobj.get("default") {
                None | Some(Json::Null) => None,
                Some(v) => Some(parse_default(fname, ty, v)?),
            };
            fields.push(Field {
                name: fname.to_string(),
                ty,
                primary,
                default,
            });
        }
        let model = Model {
            name: name.to_string(),
            fields,
        };
        validate_model(&model)?;
        Ok(model)
    }
}

/// Reject anything that is not `[A-Za-z_][A-Za-z0-9_]*`.
pub fn validate_ident(name: &str) -> Result<(), DbError> {
    let mut chars = name.chars();
    let ok = match chars.next() {
        Some(c) => {
            (c.is_ascii_alphabetic() || c == '_')
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    };
    if ok {
        Ok(())
    } else {
        Err(DbError::new(format!("invalid SQL identifier: {name:?}")))
    }
}

pub fn validate_model(model: &Model) -> Result<(), DbError> {
    validate_ident(&model.name)?;
    if model.fields.is_empty() {
        return Err(DbError::new(format!(
            "model {:?} has no fields",
            model.name
        )));
    }
    let mut seen = BTreeSet::new();
    let mut primaries = 0;
    for f in &model.fields {
        validate_ident(&f.name)?;
        if !seen.insert(f.name.as_str()) {
            return Err(DbError::new(format!(
                "duplicate field {:?} in model {:?}",
                f.name, model.name
            )));
        }
        if f.primary {
            primaries += 1;
        }
        if let Some(d) = &f.default {
            if !default_matches(f.ty, d) {
                return Err(DbError::new(format!(
                    "default for field {:?} does not match type {}",
                    f.name,
                    f.ty.as_str()
                )));
            }
        }
    }
    if primaries > 1 {
        return Err(DbError::new(format!(
            "model {:?} declares {primaries} primary fields; at most one is allowed",
            model.name
        )));
    }
    Ok(())
}

fn default_matches(ty: FieldType, value: &Value) -> bool {
    matches!(
        (ty, value),
        (FieldType::Int, Value::Int(_))
            | (FieldType::Text, Value::Text(_))
            | (FieldType::Bool, Value::Bool(_))
    )
}

fn parse_default(field: &str, ty: FieldType, value: &Json) -> Result<Value, DbError> {
    let parsed = match (ty, value) {
        (FieldType::Int, Json::Number(n)) => n.as_i64().map(Value::Int),
        (FieldType::Text, Json::String(s)) => Some(Value::Text(s.clone())),
        (FieldType::Bool, Json::Bool(b)) => Some(Value::Bool(*b)),
        _ => None,
    };
    parsed.ok_or_else(|| {
        DbError::new(format!(
            "default for field {field:?} must be a {} JSON value",
            ty.as_str()
        ))
    })
}

/// Quote a typed value as a SQL literal; single quotes inside text are doubled.
pub fn sql_literal(value: &Value) -> String {
    match value {
        Value::Int(n) => n.to_string(),
        Value::Text(s) => format!("'{}'", s.replace('\'', "''")),
        Value::Bool(b) => {
            if *b {
                "1".to_string()
            } else {
                "0".to_string()
            }
        }
    }
}

/// Parse the top-level `models` array from a full-stack IR JSON value.
///
/// `ir`, when present, must be `"0.1"`. Missing `models` means no models.
pub fn parse_models_value(root: &Json) -> Result<Vec<Model>, DbError> {
    let obj = root
        .as_object()
        .ok_or_else(|| DbError::new("full-stack IR must be a JSON object"))?;
    if let Some(v) = obj.get("ir") {
        match v.as_str() {
            Some("0.1") => {}
            Some(other) => {
                return Err(DbError::new(format!(
                    "unsupported IR version {other:?}; expected \"0.1\""
                )))
            }
            None => return Err(DbError::new("IR field 'ir' must be a string")),
        }
    }
    let entries = match obj.get("models") {
        None | Some(Json::Null) => return Ok(Vec::new()),
        Some(Json::Array(a)) => a,
        Some(_) => return Err(DbError::new("IR field 'models' must be an array")),
    };
    let mut models = Vec::with_capacity(entries.len());
    let mut names = BTreeSet::new();
    for entry in entries {
        let model = Model::from_ir(entry)?;
        if !names.insert(model.name.to_ascii_lowercase()) {
            return Err(DbError::new(format!(
                "duplicate model name {:?}",
                model.name
            )));
        }
        models.push(model);
    }
    Ok(models)
}

pub fn parse_models(ir_json: &str) -> Result<Vec<Model>, DbError> {
    let root: Json = serde_json::from_str(ir_json)
        .map_err(|e| DbError::new(format!("invalid full-stack IR JSON: {e}")))?;
    parse_models_value(&root)
}

/// Deterministic, idempotent `CREATE TABLE IF NOT EXISTS` statement.
pub fn create_table_sql(model: &Model) -> Result<String, DbError> {
    validate_model(model)?;
    let mut out = format!("CREATE TABLE IF NOT EXISTS {} (\n", model.name);
    for (i, f) in model.fields.iter().enumerate() {
        out.push_str("    ");
        out.push_str(&f.name);
        out.push(' ');
        out.push_str(f.ty.sql_type());
        if f.primary {
            out.push_str(" PRIMARY KEY");
        }
        if let Some(d) = &f.default {
            out.push_str(" DEFAULT ");
            out.push_str(&sql_literal(d));
        }
        if i + 1 < model.fields.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str(");\n");
    Ok(out)
}

pub fn schema_sql(models: &[Model]) -> Result<String, DbError> {
    let mut out = String::new();
    for m in models {
        out.push_str(&create_table_sql(m)?);
    }
    Ok(out)
}

/// `(filename, content)` pairs: `001_create_<lowercase model>.sql`, etc.
pub fn migration_files(models: &[Model]) -> Result<Vec<(String, String)>, DbError> {
    let mut files = Vec::with_capacity(models.len());
    for (i, m) in models.iter().enumerate() {
        validate_model(m)?;
        files.push((
            format!("{:03}_create_{}.sql", i + 1, m.name.to_ascii_lowercase()),
            create_table_sql(m)?,
        ));
    }
    Ok(files)
}

/// Write `migrations/NNN_*.sql` plus a combined `schema.sql` under `out_dir`.
/// Byte-identical on repeated runs. Returns every path written.
pub fn write_migrations(models: &[Model], out_dir: &Path) -> Result<Vec<PathBuf>, DbError> {
    let schema = schema_sql(models)?;
    let files = migration_files(models)?;
    let mut written = Vec::new();
    if !files.is_empty() {
        let dir = out_dir.join("migrations");
        fs::create_dir_all(&dir)
            .map_err(|e| DbError::new(format!("cannot create {}: {e}", dir.display())))?;
        for (name, content) in files {
            let path = dir.join(name);
            fs::write(&path, content)
                .map_err(|e| DbError::new(format!("cannot write {}: {e}", path.display())))?;
            written.push(path);
        }
    }
    fs::create_dir_all(out_dir)
        .map_err(|e| DbError::new(format!("cannot create {}: {e}", out_dir.display())))?;
    let schema_path = out_dir.join("schema.sql");
    fs::write(&schema_path, schema)
        .map_err(|e| DbError::new(format!("cannot write {}: {e}", schema_path.display())))?;
    written.push(schema_path);
    Ok(written)
}
