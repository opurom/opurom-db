# opurom-db

R2 data layer for OPUROM: one `Database` trait over three drivers, typed
IR-driven CRUD helpers, and deterministic SQL migrations. Rust 1.99.1,
`std` + `serde_json` only. SQLite is reached through direct FFI to the
system `libsqlite3` (`#[link(name = "sqlite3")]`), with no SQLite crate.

## Public API

```rust
pub trait Database {
    fn exec(&mut self, sql: &str) -> Result<(), DbError>;
    fn query(&mut self, sql: &str) -> Result<Vec<Row>, DbError>;

    // Default methods. SQLite overrides these with real sqlite3_bind_* calls;
    // Kv/Memory substitute safely quoted literals.
    fn exec_params(&mut self, sql: &str, params: &[Value]) -> Result<(), DbError>;
    fn query_params(&mut self, sql: &str, params: &[Value]) -> Result<Vec<Row>, DbError>;
}
```

| Item | Notes |
| --- | --- |
| `open(path) -> Result<Sqlite, DbError>` | free function; identical to `Sqlite::open(path)` |
| `Sqlite::open(path)` | associated form, same behaviour |
| `Sqlite::exec_params` / `Sqlite::query_params` | native `?` parameter binding |
| `Kv::open(path)` | file-backed store; `put` / `get` / `delete` / `keys` |
| `Memory::new()` | volatile store, `Default` implemented |
| `Value::{Int(i64), Text(String), Bool(bool)}` | `as_i64` / `as_str` / `as_bool` |
| `Row::get(&str) -> Option<&Value>` | plus `Row::new()`, `insert`, `set`, `columns`, `len`, `is_empty` |
| `DbError` | `Display`, `Debug`, `std::error::Error`; carries the sqlite errmsg |

`Row::insert(name, value)` works both in place (`let mut r = Row::new();
r.insert(...);`) and as a builder (`Row::new().insert(...).insert(...)`);
it returns an owned row and replaces an existing cell with the same name.

`id` arguments to `get` / `update` / `delete` accept anything convertible to
`Value`: `i64`, `i32`, `&str`, `String`, `bool`, `Value`, `&Value`.

Model and IR helpers:

```rust
let models = parse_models(&ir_json)?;          // full-stack IR text
let model = Model::from_ir(&ir_value)?;        // one model entry
create_table(&mut db, &model)?;                // CREATE TABLE IF NOT EXISTS
let row = create(&mut db, &model, &[("title", Value::Text("x".into()))])?;
let rows = list(&mut db, &model)?;
let one = get(&mut db, &model, 1)?;           // Result<Option<Row>, DbError>
let ok = update(&mut db, &model, 1, &[("done", Value::Bool(true))])?;
let ok = delete(&mut db, &model, 1)?;         // bool: a row existed
```

`create` fills missing columns with the declared IR default, then with the
type zero value (`0` / `""` / `false`). An omitted `int` primary key is
auto-assigned as `max(id) + 1`. Supplied column names are validated against
the model and the identifier rule `[A-Za-z_][A-Za-z0-9_]*`.

### Type and quoting rules

- IR `int` -> SQL `INTEGER`, `string` -> `TEXT`, `bool` -> `INTEGER` holding
  `0` / `1`. Raw `query()` therefore returns `Value::Int(0|1)` for boolean
  columns; `Value::as_bool()` accepts both that and `Value::Bool`, and the
  `list` / `get` helpers re-map boolean fields to `Value::Bool` using IR
  metadata.
- All generated identifiers are validated; text literals use single quotes
  with doubled interior quotes (`O'Reilly` becomes `'O''Reilly'`). Bound
  parameters (`?`) are preferred where values are supplied directly.
- SQL `NULL` is omitted from `Row` (there is no null variant in `Value`);
  `Row::get` then returns `None`. SQLite `FLOAT` and `BLOB` columns are
  exposed as their text representation.
- Malformed IR, bad queries, and invalid identifiers produce a readable
  `DbError`; nothing panics on a bad query.

## Drivers

### SQLite (`Sqlite`)

Direct FFI: `sqlite3_open`, `sqlite3_close`, `sqlite3_exec`,
`sqlite3_prepare_v2`, `sqlite3_step`, `sqlite3_column_*`,
`sqlite3_finalize`, `sqlite3_errmsg`, `sqlite3_free`, `sqlite3_bind_int64`,
`sqlite3_bind_text`. `exec` uses `sqlite3_exec` so a whole `schema.sql`
string can be applied in one call. Prepared statements are finalized on
every path, including errors.

The `#[link(name = "sqlite3")]` extern block is compiled only on macOS,
where the system library is present. On other targets a stub is compiled:
`Sqlite::open` returns a documented "SQLite FFI is unavailable" `DbError`
instead of pretending success; use `Kv` or `Memory` there. Verified on this
host: `/usr/lib/libsqlite3.dylib` is provided through the macOS SDK stub
(`libsqlite3.tbd`), and tests link and pass with no external crate.

### Embedded KV (`Kv`)

A UTF-8 file of newline-delimited `key<TAB>value` lines. `put` performs an
atomic write: sorted lines go to `<path>.tmp`, then `rename` over `<path>`.
`get` / `delete` / `keys` operate on the loaded map.

`exec` / `query` interpret a small SQL subset so the same CRUD helpers work:
`CREATE TABLE ...`, `INSERT INTO t (cols) VALUES (vals)`, `SELECT * FROM t
[WHERE col = literal]`, `UPDATE t SET ... [WHERE ...]`, `DELETE FROM t
[WHERE ...]`. Table rows are stored as compact JSON objects under
`<table>/<sequence>` keys (the `<table>/` namespace is reserved), which
preserves `int` / `string` / `bool` across reopens.

### In-memory (`Memory`)

Same SQL subset and semantics as `Kv`, with no file. Useful for tests and
generated code.

## Migrations

```sh
cargo run --bin opurom-migrate -- fullstack-ir.json -o ./build/out
```

Output (deterministic, byte-identical when run twice):

```
build/out/migrations/001_create_<model_lowercase>.sql
build/out/migrations/002_create_<model_lowercase>.sql
...
build/out/schema.sql          # all CREATE TABLE statements combined
```

Each file contains `CREATE TABLE IF NOT EXISTS ...;` so applying it twice is
safe. Every written path is printed to stdout, one per line. `-o <out>` is
the base directory; `-o <out>/migrations` is also accepted and normalizes to
`<out>`. Field names, field types (`int|string|bool`), duplicate model names
and duplicate primary keys are validated before anything is written. An
empty `models` array produces no numbered migration files (only an empty
`schema.sql`).

The generated server needs no env var and no startup step from this crate.
It can apply migrations with `db.exec(&schema_sql)` or call
`create_table(&mut db, &model)` per model at startup.

## Build and tests

```sh
cargo fmt
cargo test
```

Tests cover: SQLite CRUD round-trip against a temp file, native parameter
binding with quotes, KV persistence across two opens, KV and Memory CRUD,
migration SQL content and idempotency, malformed IR rejection, SQL injection
on identifiers, empty-model migrations, the `opurom-migrate` binary, and the
`Row` / `Value` helpers.

## Honest status (R2)

Verified: SQLite via FFI, embedded file-backed KV, in-memory store, typed
CRUD helpers, deterministic/idempotent migration SQL, identifier validation,
parameter binding, `opurom-db` library and `opurom-migrate` binary.

Not implemented (R3+): PostgreSQL / MySQL drivers, connection pooling,
transactions, authentication, TLS, migration rollback, and ORM relations.
The SQLite FFI driver is macOS-only in R2; other platforms get a documented
unavailable error. `Kv` / `Memory` support only the small SQL subset listed
above, not arbitrary SQL. `get` / `update` / `delete` require a declared
primary field; models with zero primary fields are parsed but cannot be
addressed by id yet.
