use crate::{
    create_table_sql, sql_literal, validate_ident, validate_model, Database, DbError, Field,
    FieldType, Model, Row, Value,
};
use std::collections::BTreeSet;

/// Create the model's table if it does not exist yet.
pub fn create_table<D: Database + ?Sized>(db: &mut D, model: &Model) -> Result<(), DbError> {
    db.exec(&create_table_sql(model)?)
}

fn coerce(value: &Value, ty: FieldType) -> Result<Value, DbError> {
    match (ty, value) {
        (FieldType::Int, Value::Int(_)) => Ok(value.clone()),
        (FieldType::Int, Value::Bool(b)) => Ok(Value::Int(i64::from(*b))),
        (FieldType::Text, Value::Text(_)) => Ok(value.clone()),
        (FieldType::Bool, Value::Bool(_)) => Ok(value.clone()),
        (FieldType::Bool, Value::Int(0)) => Ok(Value::Bool(false)),
        (FieldType::Bool, Value::Int(1)) => Ok(Value::Bool(true)),
        _ => Err(DbError::new(format!(
            "value {value:?} does not match field type {}",
            ty.as_str()
        ))),
    }
}

/// SQLite has no boolean storage class: re-map INTEGER 0/1 to Value::Bool.
fn normalize(model: &Model, mut row: Row) -> Row {
    for f in &model.fields {
        if f.ty == FieldType::Bool {
            if let Some(b) = row.get(&f.name).and_then(Value::as_bool) {
                row.set(f.name.clone(), Value::Bool(b));
            }
        }
    }
    row
}

fn next_id<D: Database + ?Sized>(db: &mut D, model: &Model, pk: &Field) -> Result<i64, DbError> {
    let rows = db.query(&format!("SELECT * FROM {};", model.name))?;
    let max = rows
        .iter()
        .filter_map(|r| r.get(&pk.name).and_then(Value::as_i64))
        .max()
        .unwrap_or(0);
    Ok(max + 1)
}

fn require_primary(model: &Model) -> Result<&Field, DbError> {
    model.primary().ok_or_else(|| {
        DbError::new(format!(
            "model {:?} has no primary field; this operation requires one",
            model.name
        ))
    })
}

/// Insert a row. Missing fields fall back to the declared default, then to the
/// type's zero value; an omitted int primary key gets `max(id) + 1`.
pub fn create<D: Database + ?Sized>(
    db: &mut D,
    model: &Model,
    fields: &[(&str, Value)],
) -> Result<Row, DbError> {
    validate_model(model)?;
    let mut seen = BTreeSet::new();
    for (name, _) in fields {
        validate_ident(name)?;
        if !seen.insert(*name) {
            return Err(DbError::new(format!("duplicate column {name:?} in create")));
        }
        if !model.fields.iter().any(|f| f.name == *name) {
            return Err(DbError::new(format!(
                "unknown column {name:?} in model {:?}",
                model.name
            )));
        }
    }
    let mut values: Vec<(&Field, Value)> = Vec::with_capacity(model.fields.len());
    for f in &model.fields {
        let supplied = fields.iter().find(|(n, _)| *n == f.name.as_str());
        let value = match supplied {
            Some((_, v)) => coerce(v, f.ty)?,
            None => match &f.default {
                Some(d) => d.clone(),
                None if f.primary && f.ty == FieldType::Int => Value::Int(next_id(db, model, f)?),
                None => f.ty.zero(),
            },
        };
        values.push((f, value));
    }
    let cols = values
        .iter()
        .map(|(f, _)| f.name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let vals = values
        .iter()
        .map(|(_, v)| sql_literal(v))
        .collect::<Vec<_>>()
        .join(", ");
    db.exec(&format!(
        "INSERT INTO {} ({}) VALUES ({});",
        model.name, cols, vals
    ))?;
    let mut row = Row::new();
    for (f, v) in &values {
        row.set(f.name.clone(), v.clone());
    }
    Ok(row)
}

pub fn list<D: Database + ?Sized>(db: &mut D, model: &Model) -> Result<Vec<Row>, DbError> {
    validate_model(model)?;
    let rows = db.query(&format!("SELECT * FROM {};", model.name))?;
    Ok(rows.into_iter().map(|r| normalize(model, r)).collect())
}

/// `id` accepts any type convertible into Value (i64, i32, &str, String, bool, Value).
pub fn get<D: Database + ?Sized, V: Into<Value>>(
    db: &mut D,
    model: &Model,
    id: V,
) -> Result<Option<Row>, DbError> {
    validate_model(model)?;
    let pk = require_primary(model)?;
    let id = coerce(&id.into(), pk.ty)?;
    let sql = format!(
        "SELECT * FROM {} WHERE {} = {};",
        model.name,
        pk.name,
        sql_literal(&id)
    );
    Ok(db
        .query(&sql)?
        .into_iter()
        .next()
        .map(|r| normalize(model, r)))
}

/// Returns true when a matching row existed and was updated.
pub fn update<D: Database + ?Sized, V: Into<Value>>(
    db: &mut D,
    model: &Model,
    id: V,
    fields: &[(&str, Value)],
) -> Result<bool, DbError> {
    validate_model(model)?;
    let pk = require_primary(model)?;
    let id = coerce(&id.into(), pk.ty)?;
    for (name, _) in fields {
        validate_ident(name)?;
    }
    if get(db, model, id.clone())?.is_none() {
        return Ok(false);
    }
    if fields.is_empty() {
        return Ok(true);
    }
    let mut sets = Vec::with_capacity(fields.len());
    for (name, value) in fields {
        let f = model
            .fields
            .iter()
            .find(|f| f.name == *name)
            .ok_or_else(|| {
                DbError::new(format!("unknown column {name:?} in model {:?}", model.name))
            })?;
        sets.push(format!(
            "{} = {}",
            f.name,
            sql_literal(&coerce(value, f.ty)?)
        ));
    }
    db.exec(&format!(
        "UPDATE {} SET {} WHERE {} = {};",
        model.name,
        sets.join(", "),
        pk.name,
        sql_literal(&id)
    ))?;
    Ok(true)
}

/// Returns true when a matching row existed and was deleted.
pub fn delete<D: Database + ?Sized, V: Into<Value>>(
    db: &mut D,
    model: &Model,
    id: V,
) -> Result<bool, DbError> {
    validate_model(model)?;
    let pk = require_primary(model)?;
    let id = coerce(&id.into(), pk.ty)?;
    if get(db, model, id.clone())?.is_none() {
        return Ok(false);
    }
    db.exec(&format!(
        "DELETE FROM {} WHERE {} = {};",
        model.name,
        pk.name,
        sql_literal(&id)
    ))?;
    Ok(true)
}
