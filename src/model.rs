use crate::{DbError, IndexErrorKind, Value};
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

/// A declared foreign-key relation: the model field `field` holds the primary
/// key `parent` of another model. Values are validated identifiers, so a
/// relation can be turned into SQL without quoting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Relation {
    /// This model's foreign-key field, e.g. `author_id`.
    pub field: String,
    /// The related model name, e.g. `User`.
    pub parent: String,
}

/// A table index over one or more declared model columns. `name` is the SQL
/// index name and must be unique across the generated schema; `unique` adds a
/// uniqueness constraint. All names are validated before SQL generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Index {
    pub name: String,
    pub columns: Vec<String>,
    pub unique: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Model {
    pub name: String,
    pub fields: Vec<Field>,
    /// Foreign-key relations declared on this model. Empty by default; use
    /// `relation` to declare one, and [`crate::with_related`] to eager load.
    pub relations: Vec<Relation>,
    /// Indexes created with the table. Empty by default; use [`Model::index`]
    /// or the IR `indexes` array to declare them.
    pub indexes: Vec<Index>,
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
        let mut relations = Vec::new();
        if let Some(entries) = obj.get("relations").and_then(Json::as_array) {
            for entry in entries {
                let robj = entry.as_object().ok_or_else(|| {
                    DbError::new(format!("relation of model {name:?} must be a JSON object"))
                })?;
                let field = robj.get("field").and_then(Json::as_str).ok_or_else(|| {
                    DbError::new(format!(
                        "relation of model {name:?} is missing a string 'field'"
                    ))
                })?;
                let parent = robj.get("parent").and_then(Json::as_str).ok_or_else(|| {
                    DbError::new(format!(
                        "relation of model {name:?} is missing a string 'parent'"
                    ))
                })?;
                relations.push(Relation {
                    field: field.to_string(),
                    parent: parent.to_string(),
                });
            }
        }
        let mut indexes = Vec::new();
        if let Some(value) = obj.get("indexes") {
            let entries = value.as_array().ok_or_else(|| {
                index_error(
                    IndexErrorKind::InvalidDeclaration,
                    format!("model {name:?} has a non-array 'indexes' field"),
                )
            })?;
            for entry in entries {
                indexes.push(index_from_ir(name, entry)?);
            }
        }
        let model = Model {
            name: name.to_string(),
            fields,
            relations,
            indexes,
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

fn index_error(kind: IndexErrorKind, message: impl Into<String>) -> DbError {
    DbError::with_index_error(kind, message)
}

fn index_from_ir(model: &str, value: &Json) -> Result<Index, DbError> {
    let obj = value.as_object().ok_or_else(|| {
        index_error(
            IndexErrorKind::InvalidDeclaration,
            format!("index of model {model:?} must be a JSON object"),
        )
    })?;
    let name = obj.get("name").and_then(Json::as_str).ok_or_else(|| {
        index_error(
            IndexErrorKind::InvalidDeclaration,
            format!("index of model {model:?} is missing a string 'name'"),
        )
    })?;
    let columns = obj.get("columns").and_then(Json::as_array).ok_or_else(|| {
        index_error(
            IndexErrorKind::InvalidDeclaration,
            format!("index {name:?} of model {model:?} is missing a 'columns' array"),
        )
    })?;
    let mut parsed_columns = Vec::with_capacity(columns.len());
    for column in columns {
        let column = column.as_str().ok_or_else(|| {
            index_error(
                IndexErrorKind::InvalidDeclaration,
                format!("index {name:?} of model {model:?} has a non-string column"),
            )
        })?;
        parsed_columns.push(column.to_string());
    }
    let unique = match obj.get("unique") {
        None | Some(Json::Null) => false,
        Some(Json::Bool(b)) => *b,
        Some(_) => {
            return Err(index_error(
                IndexErrorKind::InvalidDeclaration,
                format!("index {name:?} of model {model:?} has a non-boolean 'unique'"),
            ))
        }
    };
    Ok(Index {
        name: name.to_string(),
        columns: parsed_columns,
        unique,
    })
}

fn validate_models(models: &[Model]) -> Result<(), DbError> {
    let mut names = BTreeSet::new();
    for model in models {
        validate_model(model)?;
        for index in &model.indexes {
            if !names.insert(index.name.to_ascii_lowercase()) {
                return Err(index_error(
                    IndexErrorKind::DuplicateIndex,
                    format!("index {:?} is declared by more than one model", index.name),
                ));
            }
        }
    }
    Ok(())
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
    let mut rel_fields = BTreeSet::new();
    for r in &model.relations {
        validate_ident(&r.field)?;
        validate_ident(&r.parent)?;
        let field = model.fields.iter().find(|f| f.name == r.field);
        match field {
            None => {
                return Err(DbError::new(format!(
                    "relation on model {:?} names field {:?}, which the model does not declare",
                    model.name, r.field
                )))
            }
            Some(f) if f.ty != FieldType::Int => {
                return Err(DbError::new(format!(
                    "relation field {:?} of model {:?} must be int to hold a foreign key",
                    r.field, model.name
                )))
            }
            Some(_) => {}
        }
        if !rel_fields.insert(r.field.as_str()) {
            return Err(DbError::new(format!(
                "model {:?} declares more than one relation on field {:?}",
                model.name, r.field
            )));
        }
    }
    let mut index_names = BTreeSet::new();
    let mut index_shapes = BTreeSet::new();
    for index in &model.indexes {
        validate_ident(&index.name)
            .map_err(|e| index_error(IndexErrorKind::InvalidIdentifier, e.to_string()))?;
        let name = index.name.to_ascii_lowercase();
        if name.starts_with("sqlite_") {
            return Err(index_error(
                IndexErrorKind::InvalidIdentifier,
                format!("index {:?} uses the reserved sqlite_ prefix", index.name),
            ));
        }
        if !index_names.insert(name) {
            return Err(index_error(
                IndexErrorKind::DuplicateIndex,
                format!(
                    "model {:?} declares index {:?} more than once",
                    model.name, index.name
                ),
            ));
        }
        if index.columns.is_empty() {
            return Err(index_error(
                IndexErrorKind::EmptyColumns,
                format!(
                    "index {:?} of model {:?} has no columns",
                    index.name, model.name
                ),
            ));
        }
        let shape = index
            .columns
            .iter()
            .map(|column| column.to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join(",");
        if !index_shapes.insert(shape) {
            return Err(index_error(
                IndexErrorKind::DuplicateIndex,
                format!(
                    "model {:?} declares duplicate columns for index {:?}",
                    model.name, index.name
                ),
            ));
        }
        let mut columns = BTreeSet::new();
        for column in &index.columns {
            validate_ident(column)
                .map_err(|e| index_error(IndexErrorKind::InvalidIdentifier, e.to_string()))?;
            if !columns.insert(column.to_ascii_lowercase()) {
                return Err(index_error(
                    IndexErrorKind::DuplicateColumn,
                    format!("index {:?} repeats column {column:?}", index.name),
                ));
            }
            if !model.fields.iter().any(|f| f.name == *column) {
                return Err(index_error(
                    IndexErrorKind::UnknownColumn,
                    format!(
                        "index {:?} of model {:?} names unknown column {column:?}",
                        index.name, model.name
                    ),
                ));
            }
        }
    }
    Ok(())
}

impl Model {
    /// Declare a foreign-key relation on `field` pointing at `parent`'s
    /// primary key and return the model for chaining.
    pub fn relation(mut self, field: &str, parent: &str) -> Model {
        self.relations.push(Relation {
            field: field.to_string(),
            parent: parent.to_string(),
        });
        self
    }

    /// Declare an index over `columns`; `unique` adds a uniqueness constraint.
    /// Names and columns are checked by [`validate_model`] before SQL is built.
    pub fn index(mut self, name: &str, columns: &[&str], unique: bool) -> Model {
        self.indexes.push(Index {
            name: name.to_string(),
            columns: columns.iter().map(|column| column.to_string()).collect(),
            unique,
        });
        self
    }
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
    validate_models(&models)?;
    Ok(models)
}

pub fn parse_models(ir_json: &str) -> Result<Vec<Model>, DbError> {
    let root: Json = serde_json::from_str(ir_json)
        .map_err(|e| DbError::new(format!("invalid full-stack IR JSON: {e}")))?;
    parse_models_value(&root)
}

/// Deterministic, idempotent `CREATE TABLE IF NOT EXISTS` plus one
/// `CREATE [UNIQUE] INDEX IF NOT EXISTS` per declared index. All identifiers
/// are validated by [`validate_model`] before SQL text is produced.
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
    for index in &model.indexes {
        out.push_str(if index.unique {
            "CREATE UNIQUE INDEX IF NOT EXISTS "
        } else {
            "CREATE INDEX IF NOT EXISTS "
        });
        out.push_str(&index.name);
        out.push_str(" ON ");
        out.push_str(&model.name);
        out.push_str(" (");
        out.push_str(&index.columns.join(", "));
        out.push_str(");\n");
    }
    Ok(out)
}

pub fn schema_sql(models: &[Model]) -> Result<String, DbError> {
    validate_models(models)?;
    let mut out = String::new();
    for m in models {
        out.push_str(&create_table_sql(m)?);
    }
    Ok(out)
}

/// `(filename, content)` pairs: `001_create_<lowercase model>.sql`, etc.
pub fn migration_files(models: &[Model]) -> Result<Vec<(String, String)>, DbError> {
    validate_models(models)?;
    let mut files = Vec::with_capacity(models.len());
    for (i, m) in models.iter().enumerate() {
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
