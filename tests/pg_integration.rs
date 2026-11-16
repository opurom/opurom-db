//! Real PostgreSQL integration: migrations, CRUD, transactions and eager
//! relations through the v3 wire client against a live server.
//!
//! These tests are env-gated and honest: without a real server they SKIP and
//! print why, they never fake a pass. Run them with:
//!
//! ```sh
//! OPUROM_TEST_PG=1 \
//! OPUROM_TEST_PG_HOST=127.0.0.1 OPUROM_TEST_PG_PORT=5432 \
//! OPUROM_TEST_PG_USER=postgres OPUROM_TEST_PG_DB=opurom_test \
//! cargo test --test pg_integration
//! ```
//!
//! The wire client implements `AuthenticationOk` only, so the target server
//! must accept trust authentication for the test address (for example a
//! `host all all 127.0.0.1/32 trust` line in `pg_hba.conf`). The tests drop
//! and recreate their tables, so point them at a dedicated database.

use opurom_db::{
    create, create_table, delete, get, list_paged, parse_models, update, with_related, Database,
    Migration, Migrator, Model, PgConnection, Value,
};

const ENABLE_ENV: &str = "OPUROM_TEST_PG";

/// The tests share one database and each drops/recreates its tables, so they
/// must not overlap. This mutex serializes them within the process regardless
/// of `--test-threads`; the guard is held for a test's whole lifetime.
static DB_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Open one real PostgreSQL connection, or `None` when the environment does
/// not opt into live-server testing. `None` makes every test print a SKIP
/// line and pass without touching the result: the harness stays honest about
/// what actually ran.
fn pg() -> Option<(std::sync::MutexGuard<'static, ()>, PgConnection)> {
    if std::env::var(ENABLE_ENV).as_deref() != Ok("1") {
        eprintln!(
            "SKIP: real PostgreSQL integration disabled; set {ENABLE_ENV}=1 with \
             OPUROM_TEST_PG_HOST/PORT/USER/DB pointing at a trust-auth server"
        );
        return None;
    }
    let host = std::env::var("OPUROM_TEST_PG_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = std::env::var("OPUROM_TEST_PG_PORT")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(5432);
    let user = std::env::var("OPUROM_TEST_PG_USER").unwrap_or_else(|_| "postgres".into());
    let database = std::env::var("OPUROM_TEST_PG_DB").unwrap_or_else(|_| "opurom_test".into());
    // Serialize before connecting so the whole test body owns the database.
    let lock = DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match PgConnection::connect(&host, port, &user, &database) {
        Ok(connection) => Some((lock, connection)),
        Err(error) => {
            eprintln!(
                "SKIP: cannot reach PostgreSQL at {host}:{port}/{database} ({error}); \
                 start a server with trust authentication to run this suite"
            );
            None
        }
    }
}

fn user_model() -> Model {
    parse_models(
        r#"{"ir":"0.1.0","models":[{"name":"ForumUser","fields":[
          {"name":"id","type":"int","primary":true},
          {"name":"username","type":"string"},
          {"name":"role","type":"string","default":"member"}
        ]}]}"#,
    )
    .unwrap()
    .pop()
    .unwrap()
}

fn post_model() -> Model {
    parse_models(
        r#"{"ir":"0.1.0","models":[{"name":"Post","fields":[
          {"name":"id","type":"int","primary":true},
          {"name":"user_id","type":"int"},
          {"name":"title","type":"string"},
          {"name":"pinned","type":"bool","default":false}
        ]}]}"#,
    )
    .unwrap()
    .pop()
    .unwrap()
}

fn comment_model() -> Model {
    parse_models(
        r#"{"ir":"0.1.0","models":[{"name":"Comment","fields":[
          {"name":"id","type":"int","primary":true},
          {"name":"post_id","type":"int"},
          {"name":"body","type":"string"}
        ],"relations":[{"field":"post_id","parent":"Post"}]}]}"#,
    )
    .unwrap()
    .pop()
    .unwrap()
}

/// Drop every table the suite creates, including the migration bookkeeping
/// table, so each test starts from an empty schema.
fn reset(db: &mut PgConnection) {
    for table in ["Comment", "Post", "ForumUser", "_migrations"] {
        db.exec(&format!("DROP TABLE IF EXISTS {table};"))
            .expect("drop table");
    }
}

#[test]
fn real_pg_applies_migrations_and_records_versions() {
    let Some((_lock, mut db)) = pg() else { return };
    reset(&mut db);
    let models = [user_model(), post_model(), comment_model()];
    let batch: Vec<Migration> = models
        .iter()
        .enumerate()
        .map(|(i, model)| Migration::from_model(i as i64 + 1, model).unwrap())
        .collect();
    let mut migrator = Migrator::new(&mut db).unwrap();
    let applied = migrator.apply(&batch).unwrap();
    assert_eq!(applied, vec![1, 2, 3], "all three versions applied once");
    assert_eq!(migrator.applied().unwrap(), vec![1, 2, 3]);
    // Re-applying the same batch is a no-op.
    migrator.apply(&batch).unwrap();
    assert_eq!(migrator.applied().unwrap(), vec![1, 2, 3]);
    // Unquoted DDL folds to lowercase on PostgreSQL, so compare folded names.
    let rows = db
        .query(
            "SELECT table_name FROM information_schema.tables \
             WHERE lower(table_name) IN ('forumuser', 'post', 'comment') ORDER BY table_name;",
        )
        .unwrap();
    let names: Vec<String> = rows
        .iter()
        .map(|row| match row.columns().next().map(|(_, v)| v) {
            Some(Value::Text(name)) => name.to_ascii_lowercase(),
            other => panic!("unexpected table_name cell: {other:?}"),
        })
        .collect();
    assert_eq!(names, vec!["comment", "forumuser", "post"]);
}

#[test]
fn real_pg_round_trips_the_framework_crud_helpers() {
    let Some((_lock, mut db)) = pg() else { return };
    reset(&mut db);
    let user = user_model();
    let post = post_model();
    create_table_rows(&mut db, &[&user, &post]);

    create(&mut db, &user, &[("username", Value::Text("ada".into()))]).unwrap();
    let created = create(
        &mut db,
        &post,
        &[
            ("user_id", Value::Int(1)),
            ("title", Value::Text("first post".into())),
            ("pinned", Value::Bool(true)),
        ],
    )
    .unwrap();
    let id = created.get("id").and_then(Value::as_i64).unwrap();
    let fetched = get(&mut db, &post, id)
        .unwrap()
        .expect("created row is readable");
    assert_eq!(
        fetched.get("title"),
        Some(&Value::Text("first post".into()))
    );
    assert_eq!(fetched.get("pinned"), Some(&Value::Bool(true)));

    assert!(
        update(
            &mut db,
            &post,
            id,
            &[("title", Value::Text("edited".into()))]
        )
        .unwrap(),
        "updating an existing row reports success"
    );
    let edited = get(&mut db, &post, id).unwrap().unwrap();
    assert_eq!(edited.get("title"), Some(&Value::Text("edited".into())));
    let page = list_paged(&mut db, &post, 10, 0).unwrap();
    assert_eq!(page.len(), 1, "one row after update");
    let empty_page = list_paged(&mut db, &post, 10, 1).unwrap();
    assert!(empty_page.is_empty(), "offset past the end yields no rows");

    assert!(
        delete(&mut db, &post, id).unwrap(),
        "delete reports the row"
    );
    assert!(
        get(&mut db, &post, id).unwrap().is_none(),
        "deleted row is gone"
    );
}

#[test]
fn real_pg_transactions_keep_multi_row_writes_atomic() {
    let Some((_lock, mut db)) = pg() else { return };
    reset(&mut db);
    let post = post_model();
    create_table_rows(&mut db, &[&post]);

    // Rollback discards both writes; the guard also covers early returns.
    let mut rolled_back = db.transaction().unwrap();
    create(
        &mut *rolled_back,
        &post,
        &[("title", Value::Text("never committed".into()))],
    )
    .unwrap();
    create(
        &mut *rolled_back,
        &post,
        &[("title", Value::Text("also never".into()))],
    )
    .unwrap();
    rolled_back.rollback().unwrap();
    assert!(
        list_paged(&mut db, &post, 100, 0).unwrap().is_empty(),
        "a rolled-back transaction leaves no rows"
    );

    // Commit applies both writes as one unit.
    let mut committed = db.transaction().unwrap();
    let first = create(
        &mut *committed,
        &post,
        &[("title", Value::Text("kept one".into()))],
    )
    .unwrap();
    create(
        &mut *committed,
        &post,
        &[("title", Value::Text("kept two".into()))],
    )
    .unwrap();
    committed.commit().unwrap();
    let rows = list_paged(&mut db, &post, 100, 0).unwrap();
    assert_eq!(rows.len(), 2, "a committed transaction keeps every row");
    assert_eq!(rows[0].get("id"), first.get("id"), "primary keys preserved");
}

#[test]
fn real_pg_eager_loads_comments_and_reports_dangling_keys() {
    let Some((_lock, mut db)) = pg() else { return };
    reset(&mut db);
    let post = post_model();
    let comment = comment_model();
    create_table_rows(&mut db, &[&post, &comment]);

    let one = create(&mut db, &post, &[("title", Value::Text("one".into()))]).unwrap();
    let two = create(&mut db, &post, &[("title", Value::Text("two".into()))]).unwrap();
    let one_id = one.get("id").and_then(Value::as_i64).unwrap();
    let two_id = two.get("id").and_then(Value::as_i64).unwrap();
    for (post_id, body) in [(one_id, "nice"), (one_id, "agreed"), (two_id, "welcome")] {
        create(
            &mut db,
            &comment,
            &[
                ("post_id", Value::Int(post_id)),
                ("body", Value::Text(body.into())),
            ],
        )
        .unwrap();
    }
    let comments = list_paged(&mut db, &comment, 100, 0).unwrap();
    assert_eq!(comments.len(), 3, "three comments inserted");
    // with_related(child_model, child_rows, fk) maps each child's foreign-key
    // value to the parent row it points at; every child key is present.
    let (groups, violations) = with_related(&mut db, &comment, &comments, "post_id").unwrap();
    assert!(
        violations.is_empty(),
        "no dangling keys after clean inserts"
    );
    assert_eq!(groups.len(), 2, "two distinct posts referenced");
    let one_posts = groups.get(&one_id).expect("post one referenced");
    assert_eq!(one_posts.len(), 1, "one parent row per key");
    assert_eq!(one_posts[0].get("title"), Some(&Value::Text("one".into())));
    assert_eq!(
        groups
            .get(&two_id)
            .and_then(|rows| rows.first())
            .and_then(|r| r.get("title")),
        Some(&Value::Text("two".into()))
    );

    // A comment pointing at a missing post comes back as a typed violation,
    // not a silently dropped row.
    let orphan = create(
        &mut db,
        &comment,
        &[
            ("post_id", Value::Int(999_999)),
            ("body", Value::Text("dangling".into())),
        ],
    )
    .unwrap();
    let comments = list_paged(&mut db, &comment, 100, 0).unwrap();
    let (_, violations) = with_related(&mut db, &comment, &comments, "post_id").unwrap();
    assert_eq!(violations.len(), 1, "the dangling foreign key is reported");
    assert_eq!(violations[0].table, "Comment");
    assert_eq!(violations[0].parent, "Post");
    // The violation carries the unmatched foreign-key value (the post id), not
    // the child row id: that is the key the eager load could not resolve.
    assert_eq!(violations[0].rowid, Some(999_999));
    let _ = orphan;
}

/// Create the tables for `models` through the framework helper, keeping the
/// DDL identical to what the migration generator emits.
fn create_table_rows(db: &mut PgConnection, models: &[&Model]) {
    for model in models {
        create_table(db, model).unwrap();
    }
}
