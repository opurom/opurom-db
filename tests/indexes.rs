use opurom_db::*;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDb(PathBuf);

impl TempDb {
    fn new(tag: &str) -> TempDb {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "opurom-db-index-{}-{}-{}-{}.d",
            std::process::id(),
            tag,
            nanos,
            seq
        ));
        fs::create_dir_all(&dir).unwrap();
        TempDb(dir)
    }

    fn open(&self) -> Sqlite {
        let path = self.0.join("db.sqlite");
        Sqlite::open(path.to_str().unwrap()).unwrap()
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn model_ir(name: &str, indexes: &str) -> String {
    format!(
        r#"{{"ir":"0.1","models":[{{"name":"{name}","fields":[
          {{"name":"id","type":"int","primary":true}},
          {{"name":"score","type":"int"}},
          {{"name":"kind","type":"string"}},
          {{"name":"slug","type":"string"}}
        ],"indexes":[{indexes}]}}]}}"#
    )
}

fn indexed_ir() -> String {
    model_ir(
        "Item",
        r#"{"name":"by_score","columns":["score"]},
           {"name":"by_kind_slug","columns":["kind","slug"],"unique":true}"#,
    )
}

fn indexed_model() -> Model {
    parse_models(&indexed_ir()).unwrap().pop().unwrap()
}

fn index(name: &str, columns: &[&str], unique: bool) -> Index {
    Index {
        name: name.to_string(),
        columns: columns.iter().map(|column| column.to_string()).collect(),
        unique,
    }
}

fn filter(field: &'static str) -> Filter<'static> {
    Filter {
        field,
        op: "=",
        value: Value::Int(1),
    }
}

fn sqlite_index_names(db: &mut Sqlite) -> Vec<String> {
    db.query("SELECT name FROM sqlite_master WHERE type='index' ORDER BY name;")
        .unwrap()
        .iter()
        .filter_map(|row| row.get("name").and_then(Value::as_str).map(str::to_string))
        .filter(|name| !name.starts_with("sqlite_autoindex_"))
        .collect()
}

fn explain_details(db: &mut Sqlite, sql: &str) -> Vec<String> {
    db.query(&format!("EXPLAIN QUERY PLAN {sql}"))
        .unwrap()
        .iter()
        .filter_map(|row| {
            row.get("detail")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect()
}

#[test]
fn index_declarations_generate_validated_idempotent_sql() {
    let model = indexed_model();
    assert!(validate_model(&model).is_ok());
    let sql = create_table_sql(&model).unwrap();
    assert!(sql.contains("CREATE TABLE IF NOT EXISTS Item ("));
    assert!(sql.contains("CREATE INDEX IF NOT EXISTS by_score ON Item (score);\n"));
    assert!(sql.contains("CREATE UNIQUE INDEX IF NOT EXISTS by_kind_slug ON Item (kind, slug);\n"));

    let builder = indexed_model().index("by_score_kind", &["score", "kind"], true);
    assert!(validate_model(&builder).is_ok());
    assert!(create_table_sql(&builder)
        .unwrap()
        .contains("CREATE UNIQUE INDEX IF NOT EXISTS by_score_kind ON Item (score, kind);\n"));

    let schema = schema_sql(&[model.clone()]).unwrap();
    assert!(schema.contains("CREATE UNIQUE INDEX IF NOT EXISTS by_kind_slug"));
    let files = migration_files(&[model]).unwrap();
    assert_eq!(files.len(), 1);
    assert!(files[0].1.contains("CREATE INDEX IF NOT EXISTS by_score"));

    let temp = TempDb::new("ddl");
    let mut db = temp.open();
    db.exec(&sql).unwrap();
    db.exec(&sql).unwrap();
    assert_eq!(
        sqlite_index_names(&mut db),
        vec!["by_kind_slug".to_string(), "by_score".to_string()]
    );
}

#[test]
fn index_declarations_reject_bad_columns_and_duplicates_with_typed_errors() {
    let cases = [
        (
            r#"{"name":"empty","columns":[]}"#,
            IndexErrorKind::EmptyColumns,
        ),
        (
            r#"{"name":"unknown","columns":["missing"]}"#,
            IndexErrorKind::UnknownColumn,
        ),
        (
            r#"{"name":"repeated","columns":["score","score"]}"#,
            IndexErrorKind::DuplicateColumn,
        ),
        (
            r#"{"name":"bad; name","columns":["score"]}"#,
            IndexErrorKind::InvalidIdentifier,
        ),
        (
            r#"{"name":"sqlite_bad","columns":["score"]}"#,
            IndexErrorKind::InvalidIdentifier,
        ),
        (
            r#"{"name":"no_columns"}"#,
            IndexErrorKind::InvalidDeclaration,
        ),
        (
            r#"{"name":"bad_unique","columns":["score"],"unique":"yes"}"#,
            IndexErrorKind::InvalidDeclaration,
        ),
        (
            r#"{"name":"bad_column","columns":[7]}"#,
            IndexErrorKind::InvalidDeclaration,
        ),
    ];
    for (declaration, kind) in cases {
        let err = parse_models(&model_ir("Item", declaration)).unwrap_err();
        assert_eq!(err.index_error_kind(), Some(kind), "{err}");
    }

    let duplicate_name = r#"{"name":"same","columns":["score"]},
                            {"name":"same","columns":["kind"]}"#;
    let err = parse_models(&model_ir("Item", duplicate_name)).unwrap_err();
    assert_eq!(err.index_error_kind(), Some(IndexErrorKind::DuplicateIndex));

    let duplicate_shape = r#"{"name":"one","columns":["kind","slug"]},
                             {"name":"two","columns":["kind","slug"]}"#;
    let err = parse_models(&model_ir("Item", duplicate_shape)).unwrap_err();
    assert_eq!(err.index_error_kind(), Some(IndexErrorKind::DuplicateIndex));

    let global_duplicate = r#"{"ir":"0.1","models":[
        {"name":"A","fields":[{"name":"id","type":"int"}],
         "indexes":[{"name":"shared","columns":["id"]}]},
        {"name":"B","fields":[{"name":"id","type":"int"}],
         "indexes":[{"name":"shared","columns":["id"]}]}]}"#;
    let err = parse_models(global_duplicate).unwrap_err();
    assert_eq!(err.index_error_kind(), Some(IndexErrorKind::DuplicateIndex));

    let a = indexed_model();
    let b = a.clone();
    let err = schema_sql(&[a.clone(), b.clone()]).unwrap_err();
    assert_eq!(err.index_error_kind(), Some(IndexErrorKind::DuplicateIndex));
    let err = migration_files(&[a, b]).unwrap_err();
    assert_eq!(err.index_error_kind(), Some(IndexErrorKind::DuplicateIndex));

    let empty_builder = indexed_model().index("empty", &[], false);
    let err = validate_model(&empty_builder).unwrap_err();
    assert_eq!(err.index_error_kind(), Some(IndexErrorKind::EmptyColumns));
}

#[test]
fn unique_multi_column_index_is_enforced_through_migrator() {
    let temp = TempDb::new("unique");
    let mut db = temp.open();
    let model = indexed_model();
    {
        let mut mig = Migrator::new(&mut db).unwrap();
        assert_eq!(
            mig.apply(&[Migration::from_model(1, &model).unwrap()])
                .unwrap(),
            vec![1]
        );
    }

    create(
        &mut db,
        &model,
        &[
            ("id", Value::Int(1)),
            ("score", Value::Int(10)),
            ("kind", Value::Text("a".into())),
            ("slug", Value::Text("x".into())),
        ],
    )
    .unwrap();
    let err = create(
        &mut db,
        &model,
        &[
            ("id", Value::Int(2)),
            ("score", Value::Int(20)),
            ("kind", Value::Text("a".into())),
            ("slug", Value::Text("x".into())),
        ],
    )
    .unwrap_err();
    assert!(err.message().contains("UNIQUE constraint failed"), "{err}");
    create(
        &mut db,
        &model,
        &[
            ("id", Value::Int(3)),
            ("score", Value::Int(20)),
            ("kind", Value::Text("a".into())),
            ("slug", Value::Text("y".into())),
        ],
    )
    .unwrap();
    assert_eq!(
        sqlite_index_names(&mut db),
        vec!["by_kind_slug".to_string(), "by_score".to_string()]
    );
}

#[test]
fn migrator_rolls_back_table_and_index_together() {
    let temp = TempDb::new("rollback");
    let mut db = temp.open();
    let model = indexed_model();
    let mut broken = Migration::from_model(2, &model).unwrap();
    broken.up.push_str("this is not SQL;\n");
    let batch = [
        Migration::new(1, "CREATE TABLE ok (id INTEGER PRIMARY KEY);"),
        broken,
    ];
    {
        let mut mig = Migrator::new(&mut db).unwrap();
        let err = mig.apply(&batch).unwrap_err();
        assert!(matches!(err, MigrationError::Failed { version: 2, .. }));
        assert_eq!(mig.applied().unwrap(), vec![1]);
    }
    let table = db
        .query("SELECT name FROM sqlite_master WHERE type='table' AND name='Item';")
        .unwrap();
    assert!(table.is_empty(), "failed migration created its table");
    assert!(
        sqlite_index_names(&mut db).is_empty(),
        "failed migration created its indexes"
    );

    {
        let mut mig = Migrator::new(&mut db).unwrap();
        let retry = [
            Migration::new(1, "CREATE TABLE ok (id INTEGER PRIMARY KEY);"),
            Migration::from_model(2, &model).unwrap(),
        ];
        assert_eq!(mig.apply(&retry).unwrap(), vec![2]);
        assert_eq!(mig.applied().unwrap(), vec![1, 2]);
    }
    let table = db
        .query("SELECT name FROM sqlite_master WHERE type='table' AND name='Item';")
        .unwrap();
    assert_eq!(table.len(), 1);
    assert_eq!(
        sqlite_index_names(&mut db),
        vec!["by_kind_slug".to_string(), "by_score".to_string()]
    );
}

#[test]
fn planner_chooses_longest_leading_prefix() {
    let model = indexed_model();
    let filters = [filter("kind"), filter("slug"), filter("score")];
    let mut query = Query::new(&model, &filters, 10_000);
    assert_eq!(query.filters.len(), 3);
    assert_eq!(query.indexes.len(), 2);
    query
        .indexes
        .push(index("a_gap", &["score", "missing", "slug"], false));
    query
        .indexes
        .push(index("z_three", &["score", "kind", "slug"], false));
    assert_eq!(
        explain(&query),
        Plan {
            scan: Scan::IndexScan,
            index: Some("z_three".to_string()),
            matched_columns: 3,
            estimated_rows: 10,
        }
    );

    let gap = Query {
        filters: vec![filter("score"), filter("slug")],
        indexes: vec![index("gap", &["score", "missing", "slug"], false)],
        table_rows: 1_000,
    };
    assert_eq!(
        explain(&gap),
        Plan {
            scan: Scan::IndexScan,
            index: Some("gap".to_string()),
            matched_columns: 1,
            estimated_rows: 100,
        }
    );

    let unique = Query::new(&model, &[filter("kind"), filter("slug")], 10_000);
    assert_eq!(
        explain(&unique),
        Plan {
            scan: Scan::IndexScan,
            index: Some("by_kind_slug".to_string()),
            matched_columns: 2,
            estimated_rows: 1,
        }
    );
}

#[test]
fn planner_breaks_ties_by_index_name() {
    let query = Query {
        filters: vec![filter("score")],
        indexes: vec![
            index("z_single", &["score"], false),
            index("a_single", &["score"], false),
            index("b_gap", &["score", "missing"], false),
        ],
        table_rows: 500,
    };
    assert_eq!(
        explain(&query),
        Plan {
            scan: Scan::IndexScan,
            index: Some("a_single".to_string()),
            matched_columns: 1,
            estimated_rows: 50,
        }
    );
}

#[test]
fn planner_returns_table_scan_for_empty_or_unmatched_filters() {
    let valid = vec![index("by_score", &["score"], false)];
    let cases: Vec<(Vec<Filter<'static>>, Vec<Index>)> = vec![
        (vec![], valid.clone()),
        (vec![filter("kind")], valid.clone()),
        (vec![filter("score")], Vec::new()),
        (vec![filter("score")], vec![index("empty", &[], false)]),
        (
            vec![filter("score")],
            vec![index("bad; name", &["score"], false)],
        ),
    ];
    for (filters, indexes) in cases {
        let query = Query {
            filters,
            indexes,
            table_rows: 250,
        };
        assert_eq!(
            explain(&query),
            Plan {
                scan: Scan::TableScan,
                index: None,
                matched_columns: 0,
                estimated_rows: 250,
            }
        );
    }

    let zero_rows = Query {
        filters: vec![filter("score")],
        indexes: valid,
        table_rows: 0,
    };
    assert_eq!(
        explain(&zero_rows),
        Plan {
            scan: Scan::IndexScan,
            index: Some("by_score".to_string()),
            matched_columns: 1,
            estimated_rows: 0,
        }
    );
}

#[test]
fn sqlite_explain_query_plan_reports_index_use() {
    let temp = TempDb::new("eqp");
    let mut db = temp.open();
    let indexed_model = parse_models(&model_ir(
        "Indexed",
        r#"{"name":"by_score","columns":["score"]}"#,
    ))
    .unwrap()
    .pop()
    .unwrap();
    let plain_model = parse_models(&model_ir("Plain", "")).unwrap().pop().unwrap();
    let sql = format!(
        "{}{}",
        create_table_sql(&indexed_model).unwrap(),
        create_table_sql(&plain_model).unwrap()
    );
    db.exec(&sql).unwrap();
    for id in 1..=40 {
        db.exec(&format!(
            "INSERT INTO Indexed (id, score, kind, slug) VALUES ({id}, {id}, 'kind', 'slug');"
        ))
        .unwrap();
        db.exec(&format!(
            "INSERT INTO Plain (id, score, kind, slug) VALUES ({id}, {id}, 'kind', 'slug');"
        ))
        .unwrap();
    }
    db.exec("ANALYZE;").unwrap();

    // executed_statements counts statements, not visited B-tree rows; SQLite's
    // own EXPLAIN QUERY PLAN is the authoritative row-access evidence.
    let before = db.executed_statements();
    let indexed_details = explain_details(&mut db, "SELECT * FROM Indexed WHERE score = 7;");
    let plain_details = explain_details(&mut db, "SELECT * FROM Plain WHERE score = 7;");
    assert_eq!(db.executed_statements() - before, 2);
    assert_eq!(
        indexed_details,
        vec!["SEARCH Indexed USING INDEX by_score (score=?)".to_string()]
    );
    assert_eq!(plain_details, vec!["SCAN Plain".to_string()]);

    let filters = [Filter {
        field: "score",
        op: "=",
        value: Value::Int(7),
    }];
    let before = db.executed_statements();
    let indexed_rows = query(&mut db, &indexed_model, &filters, &[], 10, 0).unwrap();
    let plain_rows = query(&mut db, &plain_model, &filters, &[], 10, 0).unwrap();
    assert_eq!(db.executed_statements() - before, 2);
    assert_eq!(indexed_rows, plain_rows);
    assert_eq!(indexed_rows.len(), 1);
}
