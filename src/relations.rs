//! Eager loading of declared foreign-key relations.
//!
//! One [`with_related`] call issues a single `SELECT ... WHERE id IN (...)`
//! for all parents, so the query count is constant no matter how many parents
//! or children there are. Rows are keyed by parent primary-key value and every
//! parent gets an entry (empty when it has no children).

use crate::crud::normalize;
use crate::{
    validate_model, Database, DbError, Field, FieldType, ForeignKeyViolation, Model, Row, Value,
};
use std::collections::BTreeMap;

/// Fetch the related rows of every parent in `parents` with ONE statement.
///
/// `field` must name a declared relation on `model`, whose field type is `int`
/// (validation guarantees this). The result maps each parent's foreign-key
/// value to its related rows, fetched from the relation's parent table by
/// primary key `id`. A parent without related rows maps to an empty entry —
/// never a panic. When the parents reference a key the related table does not
/// hold, that dangling foreign key is returned as a [`ForeignKeyViolation`] so
/// the caller can report it instead of silently dropping data.
pub fn with_related<D: Database + ?Sized>(
    db: &mut D,
    model: &Model,
    parents: &[Row],
    field: &str,
) -> Result<(BTreeMap<i64, Vec<Row>>, Vec<ForeignKeyViolation>), DbError> {
    validate_model(model)?;
    let relation = model
        .relations
        .iter()
        .find(|r| r.field == field)
        .ok_or_else(|| {
            DbError::new(format!(
                "model {:?} declares no relation on field {field:?}",
                model.name
            ))
        })?;
    let key_field = model
        .fields
        .iter()
        .find(|f| f.name == relation.field)
        .ok_or_else(|| {
            DbError::new(format!(
                "model {:?} declares no field {:?}",
                model.name, relation.field
            ))
        })?;

    // Every parent gets an entry; parents with a NULL link stay empty.
    let mut groups: BTreeMap<i64, Vec<Row>> = BTreeMap::new();
    let mut keys = Vec::new();
    for parent in parents {
        match parent.get(&key_field.name).and_then(Value::as_i64) {
            Some(id) => {
                if groups.insert(id, Vec::new()).is_none() {
                    keys.push(id);
                }
            }
            None => {}
        }
    }
    if keys.is_empty() {
        return Ok((groups, Vec::new()));
    }

    let placeholders = vec!["?"; keys.len()].join(", ");
    let params = keys.iter().map(|id| Value::Int(*id)).collect::<Vec<_>>();
    let sql = format!(
        "SELECT * FROM {} WHERE id IN ({placeholders});",
        relation.parent
    );
    let mut related = db.query_params(&sql, &params)?;
    // Deterministic order, independent of the driver's row order.
    related.sort_by_key(|row| row.get("id").and_then(Value::as_i64));

    let parent_model = related_model(relation);
    let mut present = Vec::with_capacity(related.len());
    for row in related {
        let id = row.get("id").and_then(Value::as_i64).ok_or_else(|| {
            DbError::new(format!(
                "related table {:?} returned a row without an integer id",
                relation.parent
            ))
        })?;
        present.push(id);
        groups.insert(id, vec![normalize(&parent_model, row)]);
    }

    let violations = keys
        .iter()
        .filter(|id| !present.contains(id))
        .map(|id| ForeignKeyViolation {
            table: model.name.clone(),
            rowid: Some(*id),
            parent: relation.parent.clone(),
            foreign_key: 0,
        })
        .collect();

    Ok((groups, violations))
}

/// A model carrying only the related table's `id`, so [`normalize`] maps the
/// fetched rows' boolean/`int` shape consistently with the rest of the layer.
fn related_model(relation: &crate::Relation) -> Model {
    Model {
        name: relation.parent.clone(),
        fields: vec![Field {
            name: "id".to_string(),
            ty: FieldType::Int,
            primary: true,
            default: None,
        }],
        relations: Vec::new(),
    }
}
