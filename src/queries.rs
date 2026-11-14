//! Filtered, deterministically ordered model queries and a pure index planner.
//!
//! Only validated model identifiers and whitelisted SQL tokens are formatted
//! into statements. Runtime values, including paging bounds, are bound with `?`.
//! [`explain`] ranks declared indexes without opening a database connection.

use crate::crud::{coerce, normalize, require_primary, validate_page_bounds};
use crate::{
    validate_ident, validate_model, Database, DbError, Field, FieldType, Index, Model,
    QueryErrorKind, Row, Value, MAX_PAGE_LIMIT,
};
use std::collections::BTreeSet;

/// Maximum number of matching rows [`count`] will materialize.
pub const MAX_COUNT_LIMIT: i64 = MAX_PAGE_LIMIT;

/// One `WHERE` condition on a declared model field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Filter<'a> {
    pub field: &'a str,
    pub op: &'a str,
    pub value: Value,
}

/// One `ORDER BY` term; direction is `asc` or `desc` (case-insensitive).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sort<'a> {
    pub field: &'a str,
    pub direction: &'a str,
}

struct Predicate {
    where_sql: String,
    params: Vec<Value>,
}

fn query_error(kind: QueryErrorKind, message: impl Into<String>) -> DbError {
    DbError::with_query_error(kind, message)
}

fn field<'a>(model: &'a Model, name: &str) -> Result<&'a Field, DbError> {
    validate_ident(name).map_err(|e| query_error(QueryErrorKind::UnknownField, e.to_string()))?;
    model.fields.iter().find(|f| f.name == name).ok_or_else(|| {
        query_error(
            QueryErrorKind::UnknownField,
            format!("unknown field {name:?} in model {:?}", model.name),
        )
    })
}

/// The one filter predicate shared by [`query`] and [`count`].
fn predicate(model: &Model, filters: &[Filter<'_>]) -> Result<Predicate, DbError> {
    validate_model(model)?;
    let mut clauses = Vec::with_capacity(filters.len().max(1));
    let mut params = Vec::with_capacity(filters.len());
    for filter in filters {
        let f = field(model, filter.field)?;
        let op = match filter.op {
            "=" => "=",
            "!=" => "!=",
            "<" => "<",
            "<=" => "<=",
            ">" => ">",
            ">=" => ">=",
            other => {
                return Err(query_error(
                    QueryErrorKind::UnknownOperator,
                    format!("unknown operator {other:?}; expected =|!=|<|<=|>|>="),
                ))
            }
        };
        if f.ty != FieldType::Int && op != "=" && op != "!=" {
            return Err(query_error(
                QueryErrorKind::UnsupportedOperator,
                format!(
                    "operator {op} is only supported for int fields; {:?} is {}",
                    f.name,
                    f.ty.as_str()
                ),
            ));
        }
        if f.ty == FieldType::Bool {
            if let Value::Int(n) = &filter.value {
                if *n != 0 && *n != 1 {
                    return Err(query_error(
                        QueryErrorKind::OutOfRange,
                        format!("bool field {:?} accepts 0 or 1, got {n}", f.name),
                    ));
                }
            }
        }
        let value = coerce(&filter.value, f.ty)
            .map_err(|e| query_error(QueryErrorKind::TypeMismatch, e.to_string()))?;
        clauses.push(format!("{} {op} ?", f.name));
        params.push(value);
    }
    if clauses.is_empty() {
        clauses.push("1 = 1".to_string());
    }
    Ok(Predicate {
        where_sql: clauses.join(" AND "),
        params,
    })
}

/// The primary key completes every sort, so tied rows have a total order.
fn order_by(model: &Model, sorts: &[Sort<'_>]) -> Result<String, DbError> {
    validate_model(model)?;
    let pk = require_primary(model)?;
    let mut terms = Vec::with_capacity(sorts.len() + 1);
    let mut has_pk = false;
    for sort in sorts {
        let f = field(model, sort.field)?;
        let direction = if sort.direction.eq_ignore_ascii_case("asc") {
            "ASC"
        } else if sort.direction.eq_ignore_ascii_case("desc") {
            "DESC"
        } else {
            return Err(query_error(
                QueryErrorKind::InvalidSortDirection,
                format!(
                    "unknown sort direction {:?}; expected asc|desc",
                    sort.direction
                ),
            ));
        };
        if f.name.as_str() == pk.name.as_str() {
            has_pk = true;
        }
        terms.push(format!("{} {direction}", f.name));
    }
    if !has_pk {
        terms.push(format!("{} ASC", pk.name));
    }
    Ok(terms.join(", "))
}

fn validate_count_cap(cap: i64) -> Result<(), DbError> {
    if cap <= 0 {
        return Err(query_error(
            QueryErrorKind::OutOfRange,
            format!("count cap must be positive, got {cap}"),
        ));
    }
    if cap > MAX_COUNT_LIMIT {
        return Err(query_error(
            QueryErrorKind::OutOfRange,
            format!("count cap {cap} exceeds the maximum {MAX_COUNT_LIMIT}"),
        ));
    }
    Ok(())
}

/// Filter and page `model`'s rows through bound parameters.
///
/// `sorts` are applied left-to-right; the primary key is appended ascending
/// unless already present. `limit` must be `1..=MAX_PAGE_LIMIT` and `offset`
/// non-negative. Fields, operators and directions are validated before any SQL
/// reaches the driver; boolean cells are normalized from SQLite's 0/1 integers.
pub fn query<D: Database + ?Sized>(
    db: &mut D,
    model: &Model,
    filters: &[Filter<'_>],
    sorts: &[Sort<'_>],
    limit: i64,
    offset: i64,
) -> Result<Vec<Row>, DbError> {
    validate_page_bounds(limit, offset)?;
    let p = predicate(model, filters)?;
    let order = order_by(model, sorts)?;
    let mut params = p.params;
    params.push(Value::Int(limit));
    params.push(Value::Int(offset));
    let sql = format!(
        "SELECT * FROM {} WHERE {} ORDER BY {} LIMIT ? OFFSET ?;",
        model.name, p.where_sql, order
    );
    Ok(db
        .query_params(&sql, &params)?
        .into_iter()
        .map(|row| normalize(model, row))
        .collect())
}

/// Count rows matching the same predicate as [`query`], capped at `cap`.
///
/// The SQL subquery stops after `cap` rows, so the result is
/// `min(matching_rows, cap)` rather than an unbounded table scan. `cap` must be
/// `1..=MAX_COUNT_LIMIT`.
pub fn count<D: Database + ?Sized>(
    db: &mut D,
    model: &Model,
    filters: &[Filter<'_>],
    cap: i64,
) -> Result<i64, DbError> {
    validate_count_cap(cap)?;
    let p = predicate(model, filters)?;
    let mut params = p.params;
    params.push(Value::Int(cap));
    let sql = format!(
        "SELECT COUNT(*) AS n FROM (SELECT 1 FROM {} WHERE {} LIMIT ?);",
        model.name, p.where_sql
    );
    let n = db
        .query_params(&sql, &params)?
        .first()
        .and_then(|row| row.get("n"))
        .and_then(Value::as_i64)
        .ok_or_else(|| DbError::new("query count returned no numeric row"))?;
    Ok(n.min(cap))
}

/// Pure planner input: filter fields, available indexes and a caller-supplied
/// table row count. Constructing or explaining it touches no database.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query<'a> {
    pub filters: Vec<Filter<'a>>,
    pub indexes: Vec<Index>,
    pub table_rows: u64,
}

impl<'a> Query<'a> {
    /// Snapshot `model`'s declared indexes and `filters` for [`explain`].
    pub fn new(model: &Model, filters: &[Filter<'a>], table_rows: u64) -> Query<'a> {
        Query {
            filters: filters.to_vec(),
            indexes: model.indexes.clone(),
            table_rows,
        }
    }
}

/// How [`explain`] expects rows to be reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scan {
    TableScan,
    IndexScan,
}

/// A deterministic, integer-only query plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub scan: Scan,
    pub index: Option<String>,
    pub matched_columns: usize,
    pub estimated_rows: u64,
}

const PREFIX_DIVISOR: u64 = 10;

/// Choose the best declared index without touching a database.
///
/// Filter fields form a case-insensitive set; operators and values do not
/// affect ranking. A candidate matches only its leading columns, stopping at
/// the first missing one. The longest prefix wins, ties go to the
/// lexicographically smallest index name. Without a match, the plan is a table
/// scan. Each matched column divides `query.table_rows` by ten using integer
/// division (at least one row for a nonempty table); a fully matched unique
/// index estimates at most one row.
pub fn explain(query: &Query<'_>) -> Plan {
    let fields = query
        .filters
        .iter()
        .filter(|filter| validate_ident(filter.field).is_ok())
        .map(|filter| filter.field.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let mut best: Option<(&Index, usize)> = None;
    for index in &query.indexes {
        if !usable_index(index) {
            continue;
        }
        let matched = prefix_match(index, &fields);
        if matched == 0 {
            continue;
        }
        let better = best.map_or(true, |(current, current_matched)| {
            matched > current_matched
                || (matched == current_matched && index.name.as_str() < current.name.as_str())
        });
        if better {
            best = Some((index, matched));
        }
    }
    match best {
        None => Plan {
            scan: Scan::TableScan,
            index: None,
            matched_columns: 0,
            estimated_rows: query.table_rows,
        },
        Some((index, matched)) => Plan {
            scan: Scan::IndexScan,
            index: Some(index.name.clone()),
            matched_columns: matched,
            estimated_rows: estimate_rows(query.table_rows, matched, index),
        },
    }
}

fn usable_index(index: &Index) -> bool {
    if index.columns.is_empty() || validate_ident(&index.name).is_err() {
        return false;
    }
    let mut seen = BTreeSet::new();
    for column in &index.columns {
        if validate_ident(column).is_err() || !seen.insert(column.to_ascii_lowercase()) {
            return false;
        }
    }
    true
}

fn prefix_match(index: &Index, fields: &BTreeSet<String>) -> usize {
    index
        .columns
        .iter()
        .take_while(|column| {
            let key = column.to_ascii_lowercase();
            fields.contains(&key)
        })
        .count()
}

fn estimate_rows(table_rows: u64, matched: usize, index: &Index) -> u64 {
    if index.unique && matched == index.columns.len() {
        return table_rows.min(1);
    }
    // shortcut: no SQLite statistics are available; divide by 10 until ANALYZE stats exist.
    let mut estimate = table_rows;
    for _ in 0..matched {
        estimate /= PREFIX_DIVISOR;
    }
    if estimate == 0 && table_rows > 0 {
        1
    } else {
        estimate
    }
}
