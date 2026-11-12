# opurom-db

R2/R4/R5/R7 data layer for OPUROM: one `Database` trait over four drivers,
typed IR-driven CRUD helpers, deterministic SQL migrations, an R4 shared SQLite
handle, an R5 pure-std PostgreSQL v3 frontend and an R7 TLS client plus a
bundled PostgreSQL-protocol conformance server. Rust 1.99.1; PostgreSQL uses
`std::net::TcpStream` and, since R7, the pinned pure-Rust `rustls` 0.23.46
(no OpenSSL, no C toolchain: the `ring` provider is selected explicitly).
SQLite is reached through direct FFI to the system `libsqlite3`
(`#[link(name = "sqlite3")]`), with no SQLite crate.

## Public API

```rust
pub trait Database {
    fn exec(&mut self, sql: &str) -> Result<(), DbError>;
    fn query(&mut self, sql: &str) -> Result<Vec<Row>, DbError>;

    // Default methods. SQLite overrides these with real sqlite3_bind_* calls;
    // Kv/Memory/PgConnection substitute safely quoted literals.
    fn exec_params(&mut self, sql: &str, params: &[Value]) -> Result<(), DbError>;
    fn query_params(&mut self, sql: &str, params: &[Value]) -> Result<Vec<Row>, DbError>;
}
```

| Item | Notes |
| --- | --- |
| `PgConnection::connect(host, port, user, database)` | plain TCP v3 startup; requires `AuthenticationOk` |
| `PgConnection::connect_tls(host, port, user, database, server_name, trust)` | TLS 1.2/1.3 before the startup message; `trust` is an explicit DER trust anchor |
| `PgConnection::exec` / `query` | simple `Query`; implements `Database` for CRUD routing |
| `PgConnection::parameter(name)` / `backend_key()` | parsed startup `ParameterStatus` / `BackendKeyData` |
| `PgConnection::tls_version()` | negotiated TLS version (`Some("TLSv1.3")`), `None` on a plain connection |
| `PgServer::start(PgServerOptions)` | bundled v3 protocol server on an ephemeral loopback port |
| `PgServer::address()` / `port()` | the bound loopback address |
| `PgServerOptions { auth, tls }` | `PgAuth::Trust` / `PgAuth::Cleartext`, optional `PgTls` certificate and key |
| `open(path) -> Result<Sqlite, DbError>` | free function; identical to `Sqlite::open(path)` |
| `Sqlite::open(path)` | associated form, same behaviour |
| `Sqlite::exec_params` / `Sqlite::query_params` | native `?` parameter binding |
| `PooledDb::open(path) -> Result<PooledDb, DbError>` | one Mutex-serialized SQLite connection |
| `PooledDb::with(f)` | `f: FnOnce(&mut Sqlite) -> T`, lock held for the whole call |
| `PooledDb: Clone + Send + Sync` | clones share the same connection |
| `Kv::open(path)` | file-backed store; `put` / `get` / `delete` / `keys` |
| `Memory::new()` | volatile store, `Default` implemented |
| `Value::{Int(i64), Text(String), Bool(bool)}` | `as_i64` / `as_str` / `as_bool` |
| `Row::get(&str) -> Option<&Value>` | plus `Row::new()`, `insert`, `set`, `columns`, `len`, `is_empty` |
| `DbError` | `Display`, `Debug`, `std::error::Error`; driver message plus optional `sqlstate()` |

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

## R4 pooled SQLite handle

```rust
let pool = PooledDb::open("./opurom.db")?;
let clone = pool.clone();
pool.with(|db| db.exec("CREATE TABLE IF NOT EXISTS T (id INTEGER);"))?;
clone.with(|db| db.query("SELECT * FROM T;"))?;
```

`Sqlite` owns a raw `sqlite3*` and is deliberately not `Send`. `PooledDb` is
`Arc<Mutex<Sqlite>>`; it never exposes the owned `Sqlite`, and `with` holds the
Mutex for the entire `&mut Sqlite` borrow. `Sqlite::open` calls
`sqlite3_threadsafe()` and rejects a libsqlite3 built without thread-safety.
On macOS and Linux, `unsafe impl Send` and `unsafe impl Sync` are therefore
justified by one invariant: all FFI access to the connection is serialized by
the Mutex. A poisoned Mutex is recovered because the SQLite handle remains
usable and later calls still hold the same guard.

This is one shared connection, not a sized pool of independent connections. It
does not add transactions, authentication, TLS, connection pool sizing, or
distributed coordination. The R4 server-side rate limit and structured request
log live in `opurom-server` (`OPR_RATE_LIMIT` and `OPR_LOG_JSON`); this crate
only supplies the shared handle.

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

Direct FFI: `sqlite3_open`, `sqlite3_threadsafe`, `sqlite3_close`,
`sqlite3_exec`, `sqlite3_prepare_v2`, `sqlite3_step`, `sqlite3_column_*`,
`sqlite3_finalize`, `sqlite3_errmsg`, `sqlite3_free`, `sqlite3_bind_int64`,
`sqlite3_bind_text`. `exec` uses `sqlite3_exec` so a whole `schema.sql`
string can be applied in one call. Prepared statements are finalized on
every path, including errors.

The `#[link(name = "sqlite3")]` extern block is compiled on macOS and Linux.
macOS ships the library in the SDK (`libsqlite3.tbd`); on Linux the system
package `libsqlite3-dev` is required, and CI installs it before the tests.
On other targets a stub is compiled: `Sqlite::open` returns a documented
"SQLite FFI is unavailable" `DbError` instead of pretending success; use `Kv`
or `Memory` there. Verified on this host: `/usr/lib/libsqlite3.dylib` is
provided through the macOS SDK stub, and tests link and pass with no external
crate.

### PostgreSQL v3 (`PgConnection`)

`PgConnection::connect("127.0.0.1", 5432, "user", "database")` sends a
protocol-196608 startup message (`user`, `database`) over plain TCP, parses
`AuthenticationOk`, `ParameterStatus`, `BackendKeyData` and `ReadyForQuery`,
and rejects `ErrorResponse` as a readable `DbError`. Cleartext, MD5 and
SASL/SCRAM authentication requests return an `UNSUPPORTED` error; no
credentials are sent and success is never faked.

`query(sql)` sends one simple `Query` message and parses
`RowDescription`, `DataRow`, `CommandComplete` and `ReadyForQuery` until the
connection is ready. Repeated command sequences in one simple-query string
are accepted; rows from every result set are appended. `exec(sql)` discards
the rows. Both implement `Database`, so `create_table`, `create`, `list`,
`get`, `update` and `delete` route to PostgreSQL when their generated SQL is
compatible. Generated `INTEGER`/`TEXT`/`INTEGER DEFAULT 0|1` columns and
client-assigned integer primary keys are compatible; PostgreSQL's
`INTEGER PRIMARY KEY` does not auto-increment, so callers must use the CRUD
helpers or supply an id. Trait-default `?` placeholders are substituted as
safely quoted literals, not native PostgreSQL `$1` parameters.

Text-format int OIDs become `Value::Int`, PostgreSQL bool `t`/`f` becomes
`Value::Bool`, and other types become `Value::Text`; SQL NULL is omitted.
Binary-format columns are rejected. Duplicate column names collapse in
`Row`. Floats, numerics, dates, arrays and JSON have no dedicated `Value`
variant and are returned as text. There is no password or SCRAM/MD5
authentication, no prepared statements, no connection pooling, no
transaction API, no COPY protocol and no binary result decoding. A 500 ms
per-address connect timeout, write deadline and response deadline, a 16 MiB
frame and cumulative response budget, a 65,536-row cap and a 1,600-column
cap bound memory and waiting.

### TLS client (`PgConnection::connect_tls`)

```rust
let mut db = PgConnection::connect_tls(
    "127.0.0.1",
    5432,
    "user",
    "database",
    "db.example.com",
    Some(anchor_der),
)?;
```

`connect_tls` sends the eight-byte `SSLRequest` frame, requires the server to
answer `S`, then negotiates TLS 1.2/1.3 with `rustls` before the startup
message. Every protocol byte afterwards travels inside the encrypted stream;
the plain `connect` path is unchanged and still byte-identical.

Certificate verification is real. `server_name` is the name the certificate
must be valid for, and `trust` is the explicit trust anchor as DER bytes.
Without a trust anchor no anchor is trusted, so every certificate is rejected
with a certificate error; with one, only certificates chaining to that anchor
are accepted. There is no "trust everything" mode and no way to skip
verification.

Honest scope: no client-certificate mTLS, no OCSP or CRL, no revocation
checking, no HSM, and no cipher-suite tuning beyond the library defaults.

### Bundled conformance server (`PgServer`)

```rust
let server = PgServer::start(PgServerOptions {
    auth: PgAuth::Trust,
    tls: None,
})?;
let mut db = PgConnection::connect("127.0.0.1", server.port(), "alice", "opurom")?;
```

The bundled server speaks the PostgreSQL v3 protocol over a real TCP socket on
an ephemeral loopback port: startup with trust or cleartext authentication,
`ParameterStatus`, `BackendKeyData`, `ReadyForQuery`, simple `Query` with
`RowDescription` / `DataRow` / `CommandComplete`, real `BEGIN` / `COMMIT` /
`ROLLBACK` transactions with uncommitted rows invisible outside their
transaction, and `ErrorResponse` with real SQLSTATEs (`42P01`
undefined_table, `23505` unique_violation, `42601` syntax_error, `28P01`
invalid_password, `25P02` in_failed_transaction). The client maps a
SQLSTATE to a typed `DbError`: the message carries the code, for example
`postgres ERROR [SQLSTATE 42P01]: relation "Missing" does not exist`, and
`DbError::sqlstate()` returns `Some("42P01")` (`None` for errors without a
code).

It is a conformance harness for the framework's SQL subset, not a PostgreSQL
replacement: it implements `CREATE TABLE`, `INSERT`, `SELECT`, `UPDATE` and
`DELETE` over plain rows, not arbitrary SQL, types, joins, indexes or the
full type system. No server process is left running: the server runs on
background threads of the calling process and the tests never spawn a
process.

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
`create_table(&mut db, &model)` per model at startup. In R4 the generated
service opens one `PooledDb` at startup and runs migrations through `with`.

## Build and tests

```sh
cargo fmt --all
cargo test
```

All 12 R4 integration tests remain green: SQLite CRUD round-trip against a
temp file, native parameter binding with quotes, KV persistence across two
opens, KV and Memory CRUD, migration SQL content and idempotency, malformed
IR rejection, SQL injection on identifiers, empty-model migrations, the
`opurom-migrate` binary, the `Row` / `Value` helpers, and eight threads
sharing one `PooledDb` for insert/read/update/delete.

Six R5 tests in `tests/pg_protocol.rs` cover a loopback mock server: startup
and `Query` framing, `ParameterStatus` / `BackendKeyData` parsing, a two-row
result with typed values and SQL NULL omission, CRUD routing through the
`Database` trait, query/startup `ErrorResponse` rejection, startup/query
truncation, invalid and oversized frame lengths, read timeout, and
unsupported cleartext/MD5/SASL authentication.

Eleven R7 tests in `tests/pgserver.rs` run the client against the bundled
server over real sockets: a multi-statement `BEGIN` / `INSERT` / `SELECT` /
`COMMIT` transaction whose committed row survives (both as separate round
trips and as one Query message), a `ROLLBACK` transaction whose row does not,
SQLSTATE mapping to a typed error (`42P01` and `23505`), the framework's
`create_table` / `create` / `list` / `get` / `update` / `delete` helpers
routed over a real socket, cleartext authentication offered by the server
and refused by the client, a TLS session with a trusted self-signed
certificate that runs a full transaction over the encrypted stream, the
rejection of an untrusted self-signed certificate, the rejection of a
certificate that does not chain to the supplied anchor, a plaintext server
that refuses TLS, and a session that stays usable after a failed statement.

`cargo test` therefore runs 29 integration tests (0 unit tests, 0 doc tests).
Sockets bind to `127.0.0.1` on ephemeral ports and every server runs on
background threads of the test process, so no external PostgreSQL server is
contacted and no server process is left running.

## Honest status (R7)

Verified: SQLite via FFI on macOS/Linux, embedded file-backed KV, in-memory
store, typed CRUD helpers, deterministic/idempotent migration SQL, identifier
validation, parameter binding, a Mutex-serialized shared SQLite handle with a
threaded CRUD test, `opurom-db` library and `opurom-migrate` binary. Also
verified against a local TCP mock: PostgreSQL v3 startup and simple-query
framing, typed text rows, readable errors, unsupported-auth rejection,
size/time bounds, and `Database` trait routing. Since R7, additionally
verified against the bundled PostgreSQL-protocol server over real sockets:
TLS 1.3 negotiation before the startup message with real certificate
verification and rejection of an untrusted certificate, a real multi-statement
transaction with commit and rollback, and SQLSTATE-to-`DbError` mapping.
`cargo fmt --all` and `cargo test` pass with zero warnings.

Still R8+: SCRAM/MD5/cleartext password authentication in the client,
prepared statements, binary result decoding, PostgreSQL connection pooling,
MySQL, migration rollback, ORM relations, real connection pool sizing,
distributed rate limiting, and a distributed connection coordinator. The
bundled server is a conformance harness for a small SQL subset, not a
PostgreSQL replacement; no third-party PostgreSQL server was tested. The TLS
client has no mTLS, no OCSP/CRL and no revocation checking. `Kv` / `Memory`
support only the small SQL subset listed above, not arbitrary SQL. `get` /
`update` / `delete` require a declared primary field; models with zero primary
fields are parsed but cannot be addressed by id yet. On targets other than
macOS/Linux the SQLite driver is a documented unavailable stub. MySQL remains
R8+.
