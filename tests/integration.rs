use opurom_db::*;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

static SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "opurom-db-{}-{}-{}-{}.d",
            std::process::id(),
            tag,
            nanos,
            seq
        ));
        fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn todo_ir() -> String {
    r#"{
      "ir": "0.1",
      "app": "TodoApp",
      "models": [
        {"name": "Todo", "fields": [
          {"name": "id", "type": "int", "primary": true, "default": null},
          {"name": "title", "type": "string", "primary": false, "default": null},
          {"name": "done", "type": "bool", "primary": false, "default": false}
        ]}
      ]
    }"#
    .to_string()
}

fn two_model_ir() -> String {
    r#"{
      "ir": "0.1",
      "app": "TodoApp",
      "models": [
        {"name": "Todo", "fields": [
          {"name": "id", "type": "int", "primary": true, "default": null},
          {"name": "title", "type": "string", "primary": false, "default": null},
          {"name": "done", "type": "bool", "primary": false, "default": false}
        ]},
        {"name": "User", "fields": [
          {"name": "uid", "type": "int", "primary": true, "default": null},
          {"name": "name", "type": "string", "primary": false, "default": "anon"},
          {"name": "active", "type": "bool", "primary": false, "default": true}
        ]}
      ]
    }"#
    .to_string()
}

fn todo_model() -> Model {
    parse_models(&todo_ir()).unwrap().pop().unwrap()
}

fn note_model() -> Model {
    parse_models(
        r#"{"ir":"0.1","models":[{"name":"Note","fields":[
          {"name":"slug","type":"string","primary":true},
          {"name":"body","type":"string"}
        ]}]}"#,
    )
    .unwrap()
    .pop()
    .unwrap()
}

fn read_tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(dir: &Path, prefix: &str, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            let rel = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            if entry.path().is_dir() {
                walk(&entry.path(), &rel, out);
            } else {
                out.insert(rel, fs::read(entry.path()).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, "", &mut out);
    out
}

#[test]
fn sqlite_crud_roundtrip_on_temp_file() {
    let dir = TempDir::new("sqlite-crud");
    let db_path = dir.path().join("todo.sqlite");
    let path = db_path.to_str().unwrap();
    assert!(open(path).is_ok(), "free open() alias must work");
    let mut db = Sqlite::open(path).unwrap();
    let model = todo_model();
    create_table(&mut db, &model).unwrap();

    let tricky = "O'Reilly; DROP TABLE Todo; --";
    let row = create(
        &mut db,
        &model,
        &[
            ("title", Value::Text(tricky.to_string())),
            ("done", Value::Bool(true)),
        ],
    )
    .unwrap();
    let id = row.get("id").unwrap().as_i64().unwrap();
    assert_eq!(id, 1);

    // Raw SQL sees bool as INTEGER 0/1; as_bool() bridges it.
    let raw = db.query("SELECT done FROM Todo;").unwrap();
    assert_eq!(raw[0].get("done"), Some(&Value::Int(1)));
    assert_eq!(raw[0].get("done").unwrap().as_bool(), Some(true));

    let rows = list(&mut db, &model).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("title").unwrap().as_str(), Some(tricky));
    assert_eq!(rows[0].get("done").unwrap().as_bool(), Some(true));

    let one = get(&mut db, &model, id).unwrap().unwrap();
    assert_eq!(one.get("title").unwrap().as_str(), Some(tricky));

    assert!(update(
        &mut db,
        &model,
        id,
        &[
            ("title", Value::Text("finished".to_string())),
            ("done", Value::Bool(false)),
        ],
    )
    .unwrap());
    let one = get(&mut db, &model, id).unwrap().unwrap();
    assert_eq!(one.get("title").unwrap().as_str(), Some("finished"));
    assert_eq!(one.get("done").unwrap().as_bool(), Some(false));

    assert!(delete(&mut db, &model, id).unwrap());
    assert!(!delete(&mut db, &model, id).unwrap());
    assert!(list(&mut db, &model).unwrap().is_empty());
    assert!(get(&mut db, &model, id).unwrap().is_none());

    // Bad queries return the sqlite message instead of panicking.
    let err = db.query("SELECT * FROM missing_table").unwrap_err();
    assert!(err.to_string().contains("no such table"), "{err}");
    assert!(db.exec("this is not SQL").is_err());
}

#[test]
fn sqlite_parameter_binding_handles_quotes() {
    let dir = TempDir::new("sqlite-bind");
    let db_path = dir.path().join("bind.sqlite");
    let mut db = Sqlite::open(db_path.to_str().unwrap()).unwrap();
    db.exec("CREATE TABLE T (id INTEGER PRIMARY KEY, txt TEXT);")
        .unwrap();
    let text = "a'b \"c\" ? -- ;";
    db.exec_params(
        "INSERT INTO T (txt) VALUES (?);",
        &[Value::Text(text.to_string())],
    )
    .unwrap();
    let rows = db
        .query_params(
            "SELECT txt FROM T WHERE txt = ?;",
            &[Value::Text(text.to_string())],
        )
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("txt").unwrap().as_str(), Some(text));
    assert!(db
        .exec_params("INSERT INTO T (txt) VALUES (?);", &[])
        .is_err());
}

#[test]
fn sqlite_crud_roundtrips_hostile_text_byte_exactly() {
    let dir = TempDir::new("sqlite-bytes");
    let db_path = dir.path().join("bytes.sqlite");
    let mut db = Sqlite::open(db_path.to_str().unwrap()).unwrap();
    let model = todo_model();
    create_table(&mut db, &model).unwrap();

    let cases = [
        "single'quote",
        "double''quote and \"double quotes\"",
        "semi; DROP TABLE Todo; --",
        "line1\nline2\r\ttab;",
        "back\\slash and NUL-like \\0 \\x00 \\u0000 %00",
        "embedded\0NUL byte and another\0one",
        "question ? marks ?? and 'quoted' text",
        "non-ASCII: \u{4e2d}\u{6587} \u{65e5}\u{672c}\u{8a9e} \u{d55c}\u{ad6d}\u{c5b4} \u{627}\u{644}\u{639}\u{631}\u{628}\u{64a}\u{629} \u{e9}\u{f1}\u{fc} \u{1f9ea}\u{1f680}",
        "",
    ];
    for (i, &original) in cases.iter().enumerate() {
        let value = Value::Text(original.to_string());
        let done = Value::Bool(i % 2 == 0);
        let row = create(
            &mut db,
            &model,
            &[("title", value.clone()), ("done", done.clone())],
        )
        .unwrap();
        let id = row.get("id").unwrap().as_i64().unwrap();
        assert_eq!(row.get("title"), Some(&value), "case {i} create");

        let fetched = get(&mut db, &model, id).unwrap().unwrap();
        assert_eq!(
            fetched.get("title").unwrap().as_str().unwrap().as_bytes(),
            original.as_bytes(),
            "case {i} get"
        );
        assert_eq!(fetched.get("done"), Some(&done), "case {i} bool");

        let rows = list(&mut db, &model).unwrap();
        assert_eq!(rows.len(), 1, "case {i} list");
        assert_eq!(
            rows[0].get("title").unwrap().as_str().unwrap().as_bytes(),
            original.as_bytes(),
            "case {i} list"
        );

        let updated = format!("{original}\nupdated; 'x' --");
        let updated_value = Value::Text(updated.clone());
        assert!(update(&mut db, &model, id, &[("title", updated_value.clone())]).unwrap());
        let fetched = get(&mut db, &model, id).unwrap().unwrap();
        assert_eq!(
            fetched.get("title"),
            Some(&updated_value),
            "case {i} update"
        );
        assert_eq!(
            fetched.get("title").unwrap().as_str().unwrap().as_bytes(),
            updated.as_bytes(),
            "case {i} update"
        );

        assert!(delete(&mut db, &model, id).unwrap());
        assert!(list(&mut db, &model).unwrap().is_empty(), "case {i} delete");
    }
}

#[test]
fn sqlite_crud_binding_blocks_query_structure_injection() {
    let dir = TempDir::new("sqlite-inject");
    let db_path = dir.path().join("inject.sqlite");
    let mut db = Sqlite::open(db_path.to_str().unwrap()).unwrap();
    let model = note_model();
    create_table(&mut db, &model).unwrap();
    create(
        &mut db,
        &model,
        &[
            ("slug", Value::Text("a".to_string())),
            ("body", Value::Text("alpha".to_string())),
        ],
    )
    .unwrap();
    create(
        &mut db,
        &model,
        &[
            ("slug", Value::Text("b".to_string())),
            ("body", Value::Text("beta".to_string())),
        ],
    )
    .unwrap();

    // The crafted key and body are stored as data: neither INSERT nor SELECT
    // may gain a WHERE clause, a second statement, or a widened OR condition.
    let attack = "x' OR 1=1; DROP TABLE Note; --";
    let body_attack = "'); DROP TABLE Note; --";
    create(
        &mut db,
        &model,
        &[
            ("slug", Value::Text(attack.to_string())),
            ("body", Value::Text(body_attack.to_string())),
        ],
    )
    .unwrap();
    assert_eq!(list(&mut db, &model).unwrap().len(), 3);
    let found = get(&mut db, &model, attack.to_string()).unwrap().unwrap();
    assert_eq!(found.get("slug").unwrap().as_str(), Some(attack));
    assert_eq!(found.get("body").unwrap().as_str(), Some(body_attack));

    assert!(update(
        &mut db,
        &model,
        attack.to_string(),
        &[("body", Value::Text("changed".to_string()))]
    )
    .unwrap());
    assert_eq!(list(&mut db, &model).unwrap().len(), 3);
    assert_eq!(
        get(&mut db, &model, "a")
            .unwrap()
            .unwrap()
            .get("body")
            .unwrap()
            .as_str(),
        Some("alpha")
    );
    assert_eq!(
        get(&mut db, &model, "b")
            .unwrap()
            .unwrap()
            .get("body")
            .unwrap()
            .as_str(),
        Some("beta")
    );
    assert!(delete(&mut db, &model, attack.to_string()).unwrap());

    // A payload that is not a stored key matches nothing and cannot mutate or
    // drop anything, even though it contains a quote, a semicolon and OR 1=1.
    let payload = "' OR 1=1; DROP TABLE Note; --";
    assert!(get(&mut db, &model, payload.to_string()).unwrap().is_none());
    assert!(!update(
        &mut db,
        &model,
        payload.to_string(),
        &[("body", Value::Text("pwned".to_string()))]
    )
    .unwrap());
    assert!(!delete(&mut db, &model, payload.to_string()).unwrap());

    let rows = list(&mut db, &model).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get("slug").unwrap().as_str(), Some("a"));
    assert_eq!(rows[0].get("body").unwrap().as_str(), Some("alpha"));
    assert_eq!(rows[1].get("slug").unwrap().as_str(), Some("b"));
    assert_eq!(rows[1].get("body").unwrap().as_str(), Some("beta"));
    let tables = db
        .query("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'Note';")
        .unwrap();
    assert_eq!(tables.len(), 1, "the table must survive every attempt");
}

fn paged_todo_ids<D: Database + ?Sized>(db: &mut D, model: &Model, page: i64) -> Vec<i64> {
    list_paged(db, model, 10, page * 10)
        .unwrap()
        .iter()
        .map(|r| r.get("id").unwrap().as_i64().unwrap())
        .collect()
}

#[test]
fn list_paged_paginates_identically_across_runs() {
    let model = todo_model();
    let dir = TempDir::new("list-paged");
    let db_path = dir.path().join("a.sqlite");
    let mut db = Sqlite::open(db_path.to_str().unwrap()).unwrap();
    create_table(&mut db, &model).unwrap();
    // Descending ids: page order must come from the primary key, not insertion.
    for i in (1..=25).rev() {
        create(
            &mut db,
            &model,
            &[
                ("id", Value::Int(i)),
                ("title", Value::Text(format!("task {i}"))),
            ],
        )
        .unwrap();
    }

    let expected: Vec<i64> = (1..=25).collect();
    let first: Vec<i64> = (0..3)
        .flat_map(|p| paged_todo_ids(&mut db, &model, p))
        .collect();
    assert_eq!(first, expected, "25 rows at limit 10 cover ids in pk order");
    // A repeated walk over the same database returns the identical sequence.
    let again: Vec<i64> = (0..3)
        .flat_map(|p| paged_todo_ids(&mut db, &model, p))
        .collect();
    assert_eq!(again, expected, "pagination must be identical across runs");

    assert_eq!(
        paged_todo_ids(&mut db, &model, 2),
        vec![21, 22, 23, 24, 25],
        "final page is partial"
    );
    assert!(
        list_paged(&mut db, &model, 10, 25).unwrap().is_empty(),
        "offset one past the end yields an empty page"
    );
    // limit/offset bounds return readable errors.
    for (limit, offset, mention) in [
        (0, 0, "positive integer"),
        (-3, 0, "positive integer"),
        (MAX_PAGE_LIMIT + 1, 0, "maximum page size"),
        (10, -1, "non-negative"),
    ] {
        let err = list_paged(&mut db, &model, limit, offset).unwrap_err();
        assert!(
            err.message().contains(mention),
            "unexpected error for ({limit}, {offset}): {err}"
        );
    }
    assert_eq!(
        list_paged(&mut db, &model, MAX_PAGE_LIMIT, 0)
            .unwrap()
            .len(),
        25,
        "the page-size cap itself is usable"
    );
    // Stable ordering needs a primary field, like get/update/delete.
    let no_pk = Model {
        name: "Blob".to_string(),
        fields: vec![Field {
            name: "note".to_string(),
            ty: FieldType::Text,
            primary: false,
            default: None,
        }],
    };
    let err = list_paged(&mut db, &no_pk, 10, 0).unwrap_err();
    assert!(
        err.message().contains("no primary field"),
        "unexpected error: {err}"
    );

    // A second temp database with a different insertion order paginates the same.
    let dir2 = TempDir::new("list-paged-odd-even");
    let db_path2 = dir2.path().join("b.sqlite");
    let mut db2 = Sqlite::open(db_path2.to_str().unwrap()).unwrap();
    create_table(&mut db2, &model).unwrap();
    for i in (1..=25).step_by(2) {
        create(
            &mut db2,
            &model,
            &[
                ("id", Value::Int(i)),
                ("title", Value::Text(format!("task {i}"))),
            ],
        )
        .unwrap();
    }
    for i in (2..=24).rev().step_by(2) {
        create(
            &mut db2,
            &model,
            &[
                ("id", Value::Int(i)),
                ("title", Value::Text(format!("task {i}"))),
            ],
        )
        .unwrap();
    }
    let shuffled: Vec<i64> = (0..3)
        .flat_map(|p| paged_todo_ids(&mut db2, &model, p))
        .collect();
    assert_eq!(shuffled, expected, "insertion timing must not change pages");
}

#[test]
fn kv_persistence_across_two_opens() {
    let dir = TempDir::new("kv-persist");
    let path = dir.path().join("store.kv");
    let p = path.to_str().unwrap();
    {
        let mut kv = Kv::open(p).unwrap();
        kv.put("alpha", "1").unwrap();
        kv.put("beta", "two").unwrap();
        assert_eq!(kv.get("alpha"), Some("1"));
    }
    assert_eq!(fs::read_to_string(&path).unwrap(), "alpha\t1\nbeta\ttwo\n");
    {
        let mut kv = Kv::open(p).unwrap();
        assert_eq!(kv.get("alpha"), Some("1"));
        assert_eq!(kv.get("beta"), Some("two"));
        assert_eq!(kv.keys(), vec!["alpha".to_string(), "beta".to_string()]);
        assert!(kv.delete("alpha").unwrap());
        assert!(!kv.delete("alpha").unwrap());
    }
    let mut kv = Kv::open(p).unwrap();
    assert_eq!(kv.get("alpha"), None);
    assert_eq!(kv.get("beta"), Some("two"));
    assert!(kv.put("tab\tkey", "x").is_err());
    assert!(kv.put("ok", "line\nbreak").is_err());
}

#[test]
fn kv_crud_through_the_database_trait() {
    let dir = TempDir::new("kv-crud");
    let path = dir.path().join("rows.kv");
    let mut kv = Kv::open(path.to_str().unwrap()).unwrap();
    let model = todo_model();
    create_table(&mut kv, &model).unwrap();
    create(&mut kv, &model, &[("title", Value::Text("kv".to_string()))]).unwrap();
    assert_eq!(list(&mut kv, &model).unwrap().len(), 1);
    assert_eq!(
        get(&mut kv, &model, 1).unwrap().unwrap().get("done"),
        Some(&Value::Bool(false))
    );
    assert!(update(&mut kv, &model, 1, &[("done", Value::Bool(true))]).unwrap());
    assert_eq!(
        get(&mut kv, &model, 1).unwrap().unwrap().get("done"),
        Some(&Value::Bool(true))
    );
    assert!(delete(&mut kv, &model, 1).unwrap());
    assert!(list(&mut kv, &model).unwrap().is_empty());
    // Reopen: the SQL CRUD rows are persisted with their JSON-typed values.
    let mut kv2 = Kv::open(path.to_str().unwrap()).unwrap();
    assert!(list(&mut kv2, &model).unwrap().is_empty());
}

#[test]
fn memory_crud_and_default_param_substitution() {
    let mut db = Memory::new();
    let model = todo_model();
    create_table(&mut db, &model).unwrap();
    let row = create(
        &mut db,
        &model,
        &[("title", Value::Text("mem".to_string()))],
    )
    .unwrap();
    assert_eq!(row.get("id").unwrap().as_i64(), Some(1));
    assert_eq!(list(&mut db, &model).unwrap().len(), 1);
    assert!(get(&mut db, &model, 1).unwrap().is_some());
    assert!(update(
        &mut db,
        &model,
        1,
        &[("title", Value::Text("updated".to_string()))]
    )
    .unwrap());
    assert_eq!(
        get(&mut db, &model, 1)
            .unwrap()
            .unwrap()
            .get("title")
            .unwrap()
            .as_str(),
        Some("updated")
    );
    assert!(delete(&mut db, &model, 1).unwrap());
    assert!(!delete(&mut db, &model, 1).unwrap());

    // Trait-default exec_params/query_params use safe literal substitution.
    let mut mem = Memory::default();
    mem.exec("CREATE TABLE T (id INTEGER PRIMARY KEY, txt TEXT);")
        .unwrap();
    mem.exec_params(
        "INSERT INTO T (txt) VALUES (?);",
        &[Value::Text("a'b".to_string())],
    )
    .unwrap();
    let rows = mem
        .query_params(
            "SELECT * FROM T WHERE txt = ?;",
            &[Value::Text("a'b".to_string())],
        )
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("txt").unwrap().as_str(), Some("a'b"));
}

#[test]
fn migration_sql_content_and_idempotency() {
    let models = parse_models(&two_model_ir()).unwrap();
    assert_eq!(models.len(), 2);
    let a = TempDir::new("mig-a");
    let b = TempDir::new("mig-b");
    let first = write_migrations(&models, a.path()).unwrap();
    assert_eq!(first.len(), 3);
    let before = read_tree(a.path());
    let second = write_migrations(&models, a.path()).unwrap();
    assert_eq!(first, second);
    assert_eq!(before, read_tree(a.path()));
    write_migrations(&models, b.path()).unwrap();
    assert_eq!(read_tree(a.path()), read_tree(b.path()));

    let sql = fs::read_to_string(a.path().join("schema.sql")).unwrap();
    assert!(sql.contains("CREATE TABLE IF NOT EXISTS Todo ("));
    assert!(sql.contains("id INTEGER PRIMARY KEY"));
    assert!(sql.contains("title TEXT"));
    assert!(sql.contains("done INTEGER DEFAULT 0"));
    assert!(sql.contains("CREATE TABLE IF NOT EXISTS User ("));
    assert!(sql.contains("name TEXT DEFAULT 'anon'"));
    assert!(sql.contains("active INTEGER DEFAULT 1"));
    let todo = fs::read_to_string(a.path().join("migrations/001_create_todo.sql")).unwrap();
    assert_eq!(
        todo.lines().next().unwrap(),
        "CREATE TABLE IF NOT EXISTS Todo ("
    );
    assert!(a.path().join("migrations/002_create_user.sql").exists());

    // The combined schema is valid SQL and can be applied twice.
    let db_path = a.path().join("verify.sqlite");
    let mut db = Sqlite::open(db_path.to_str().unwrap()).unwrap();
    db.exec(&sql).unwrap();
    db.exec(&sql).unwrap();
    let tables = db
        .query("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name;")
        .unwrap();
    assert_eq!(tables.len(), 2);
}

#[test]
fn malformed_ir_is_rejected_readably() {
    let cases = [
        "not json",
        r#"{"ir":"9.9","models":[]}"#,
        r#"{"ir":"0.1","models":"nope"}"#,
        r#"{"ir":"0.1","models":[{"name":"Todo","fields":[{"name":"id","type":"float"}]}]}"#,
        r#"{"ir":"0.1","models":[{"name":"Todo","fields":[{"name":"id","type":"int","primary":true},{"name":"x","type":"string","primary":true}]}]}"#,
        r#"{"ir":"0.1","models":[{"name":"Todo; DROP TABLE x","fields":[{"name":"id","type":"int"}]}]}"#,
        r#"{"ir":"0.1","models":[{"name":"Todo","fields":[{"name":"id","type":"int","default":"oops"}]}]}"#,
        r#"{"ir":"0.1","models":[{"name":"Todo","fields":[]}]}"#,
        r#"{"ir":"0.1","models":[{"name":"Todo","fields":[{"name":"id","type":"int"},{"name":"id","type":"int"}]}]}"#,
        r#"{"ir":"0.1","models":[{"name":"Todo","fields":[{"name":"id","type":"int"}]},{"name":"todo","fields":[{"name":"id","type":"int"}]}]}"#,
    ];
    for case in cases {
        let err = parse_models(case).unwrap_err();
        assert!(!err.to_string().is_empty(), "empty error for {case}");
    }
}

#[test]
fn sql_injection_on_identifiers_is_rejected() {
    assert!(validate_ident("Todo").is_ok());
    for bad in [
        "Todo; DROP TABLE x",
        "a'b",
        "1abc",
        "",
        "a b",
        "a-b",
        "a.b",
        "x\n",
        "a\u{4e2d}",
    ] {
        assert!(validate_ident(bad).is_err(), "accepted {bad:?}");
    }
    let mut db = Memory::new();
    let model = todo_model();
    create_table(&mut db, &model).unwrap();
    let err = create(
        &mut db,
        &model,
        &[(
            "title) VALUES (1); DROP TABLE Todo; --",
            Value::Text("x".to_string()),
        )],
    )
    .unwrap_err();
    assert!(err.to_string().contains("invalid SQL identifier"), "{err}");
    assert!(
        list(&mut db, &model).is_ok(),
        "table must survive the attempt"
    );
    assert!(parse_models(
        r#"{"ir":"0.1","models":[{"name":"Todo; DROP TABLE x","fields":[{"name":"id","type":"int"}]}]}"#
    )
    .is_err());
}

#[test]
fn empty_models_produce_no_migration_files() {
    let models = parse_models(r#"{"ir":"0.1","app":"Empty","models":[]}"#).unwrap();
    assert!(models.is_empty());
    let dir = TempDir::new("empty-mig");
    let paths = write_migrations(&models, dir.path()).unwrap();
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].file_name().unwrap(), "schema.sql");
    assert_eq!(fs::read_to_string(&paths[0]).unwrap(), "");
    let tree = read_tree(dir.path());
    assert!(!tree.keys().any(|k| k.contains("create_")), "{tree:?}");
}

#[test]
fn migrate_binary_writes_files_and_prints_paths() {
    let dir = TempDir::new("migrate-bin");
    let ir_path = dir.path().join("ir.json");
    fs::write(&ir_path, two_model_ir()).unwrap();
    let bin = env!("CARGO_BIN_EXE_opurom-migrate");
    let out = Command::new(bin)
        .arg(&ir_path)
        .args(["-o"])
        .arg(dir.path().join("out"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("001_create_todo.sql"), "{stdout}");
    assert!(stdout.contains("002_create_user.sql"), "{stdout}");
    assert!(stdout.contains("schema.sql"), "{stdout}");
    assert!(dir
        .path()
        .join("out/migrations/001_create_todo.sql")
        .exists());
    assert!(dir.path().join("out/schema.sql").exists());

    // Passing the migrations directory itself also normalizes to the same base.
    let out2 = Command::new(bin)
        .arg(&ir_path)
        .args(["-o"])
        .arg(dir.path().join("out/migrations"))
        .output()
        .unwrap();
    assert!(out2.status.success());
    assert!(dir
        .path()
        .join("out/migrations/001_create_todo.sql")
        .exists());
    assert!(!dir.path().join("out/migrations/migrations").exists());

    let bad = Command::new(bin).arg(&ir_path).output().unwrap();
    assert!(!bad.status.success());
}

#[test]
fn row_builder_and_value_helpers() {
    let row = Row::new()
        .insert("id", Value::Int(7))
        .insert("done", Value::Bool(false));
    assert_eq!(row.get("id").unwrap().as_i64(), Some(7));
    assert_eq!(row.get("done").unwrap().as_bool(), Some(false));
    assert_eq!(row.len(), 2);
    assert!(row.get("missing").is_none());

    let mut in_place = Row::new();
    in_place.insert("id", Value::Int(8));
    assert_eq!(in_place.get("id").unwrap().as_i64(), Some(8));
    assert_eq!(
        in_place
            .insert("id", Value::Int(9))
            .get("id")
            .unwrap()
            .as_i64(),
        Some(9)
    );
    assert_eq!(in_place.get("id").unwrap().as_i64(), Some(9));

    assert_eq!(Value::Int(1).as_bool(), Some(true));
    assert_eq!(Value::Int(0).as_bool(), Some(false));
    assert_eq!(Value::Text("x".to_string()).as_str(), Some("x"));
    assert_eq!(Value::Bool(true).as_i64(), None);
    assert_eq!(sql_literal(&Value::Text("a'b".to_string())), "'a''b'");

    fn assert_std_error<T: std::error::Error + std::fmt::Debug>() {}
    assert_std_error::<DbError>();
    assert!(format!("{}", DbError::new("oops")).contains("oops"));
}

#[test]
fn pooled_db_serializes_crud_across_threads() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PooledDb>();

    let dir = TempDir::new("pooled-crud");
    let db_path = dir.path().join("pool.sqlite");
    let pool = PooledDb::open(db_path.to_str().unwrap()).unwrap();
    pool.with(|db| {
        db.exec("CREATE TABLE T (id INTEGER PRIMARY KEY, title TEXT);")
            .unwrap()
    });

    const THREADS: i64 = 8;
    let barrier = Arc::new(Barrier::new(THREADS as usize));
    let mut handles = Vec::new();
    for id in 1..=THREADS {
        let pool = pool.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            pool.with(|db| {
                let created = format!("t{id}");
                let updated = format!("u{id}");
                db.exec_params(
                    "INSERT INTO T (id, title) VALUES (?, ?);",
                    &[Value::Int(id), Value::Text(created.clone())],
                )
                .unwrap();
                let rows = db
                    .query_params("SELECT title FROM T WHERE id = ?;", &[Value::Int(id)])
                    .unwrap();
                assert_eq!(
                    rows[0].get("title").unwrap().as_str(),
                    Some(created.as_str())
                );

                db.exec_params(
                    "UPDATE T SET title = ? WHERE id = ?;",
                    &[Value::Text(updated.clone()), Value::Int(id)],
                )
                .unwrap();
                let rows = db
                    .query_params("SELECT title FROM T WHERE id = ?;", &[Value::Int(id)])
                    .unwrap();
                assert_eq!(
                    rows[0].get("title").unwrap().as_str(),
                    Some(updated.as_str())
                );

                db.exec_params("DELETE FROM T WHERE id = ?;", &[Value::Int(id)])
                    .unwrap();
                let rows = db
                    .query_params("SELECT title FROM T WHERE id = ?;", &[Value::Int(id)])
                    .unwrap();
                assert!(rows.is_empty());
            });
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }

    let rows = pool.with(|db| db.query("SELECT COUNT(*) AS n FROM T;").unwrap());
    assert_eq!(rows[0].get("n"), Some(&Value::Int(0)));
}

#[test]
fn sqlite_transaction_commit_keeps_rows() {
    let dir = TempDir::new("tx-commit");
    let path = dir.path().join("tx.sqlite").to_str().unwrap().to_string();
    let mut db = Sqlite::open(&path).unwrap();
    let model = todo_model();
    create_table(&mut db, &model).unwrap();

    let mut tx = db.transaction().unwrap();
    let row = create(&mut *tx, &model, &[("title", Value::Text("kept".into()))]).unwrap();
    let id = row.get("id").unwrap().as_i64().unwrap();
    assert_eq!(id, 1);
    assert_eq!(list(&mut *tx, &model).unwrap().len(), 1);
    tx.commit().unwrap();

    let rows = list(&mut db, &model).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("title"), Some(&Value::Text("kept".into())));
}

#[test]
fn sqlite_transaction_rollback_discards_rows() {
    let dir = TempDir::new("tx-rollback");
    let path = dir.path().join("tx.sqlite").to_str().unwrap().to_string();
    let mut db = Sqlite::open(&path).unwrap();
    let model = todo_model();
    create_table(&mut db, &model).unwrap();

    let mut tx = db.transaction().unwrap();
    create(&mut *tx, &model, &[("title", Value::Text("gone".into()))]).unwrap();
    assert_eq!(list(&mut *tx, &model).unwrap().len(), 1);
    tx.rollback().unwrap();

    assert!(list(&mut db, &model).unwrap().is_empty());
}

#[test]
fn sqlite_transaction_drop_rolls_back_and_keeps_the_driver_usable() {
    let dir = TempDir::new("tx-drop");
    let path = dir.path().join("tx.sqlite").to_str().unwrap().to_string();
    let mut db = Sqlite::open(&path).unwrap();
    let model = todo_model();
    create_table(&mut db, &model).unwrap();

    {
        let mut tx = db.transaction().unwrap();
        tx.exec("INSERT INTO Todo (id, title, done) VALUES (7, 'abandoned', 0);")
            .unwrap();
        assert_eq!(list(&mut *tx, &model).unwrap().len(), 1);
        // No commit: the guard drop must roll the insert back.
    }

    assert!(list(&mut db, &model).unwrap().is_empty());
    // The driver still works after the implicit rollback.
    let mut tx = db.transaction().unwrap();
    tx.exec("INSERT INTO Todo (id, title, done) VALUES (7, 'kept', 0);")
        .unwrap();
    tx.commit().unwrap();
    let rows = list(&mut db, &model).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("title"), Some(&Value::Text("kept".into())));
}

#[test]
fn sqlite_transaction_failed_commit_still_rolls_back_on_drop() {
    let dir = TempDir::new("tx-failed-commit");
    let path = dir.path().join("tx.sqlite").to_str().unwrap().to_string();
    let mut db = Sqlite::open(&path).unwrap();
    db.exec("CREATE TABLE T (id INTEGER);").unwrap();

    let mut tx = db.transaction().unwrap();
    tx.exec("INSERT INTO T (id) VALUES (1);").unwrap();
    tx.exec("ROLLBACK;").unwrap();
    // COMMIT now fails because the transaction is no longer active.
    assert!(tx.commit().is_err());

    let rows = db.query("SELECT * FROM T;").unwrap();
    assert!(rows.is_empty());
    // The driver accepts a new transaction afterwards.
    db.transaction().unwrap().commit().unwrap();
}

#[test]
fn sqlite_nested_transaction_begin_is_a_readable_error() {
    let dir = TempDir::new("tx-nested");
    let path = dir.path().join("tx.sqlite").to_str().unwrap().to_string();
    let mut db = Sqlite::open(&path).unwrap();
    db.exec("CREATE TABLE T (id INTEGER);").unwrap();

    let mut tx = db.transaction().unwrap();
    let nested_error = match tx.transaction() {
        Err(e) => e,
        Ok(_) => panic!("nested BEGIN must fail"),
    };
    assert!(
        nested_error.message().contains("within a transaction"),
        "expected the driver's nested-BEGIN message"
    );
    tx.rollback().unwrap();
    db.transaction().unwrap().commit().unwrap();
}
