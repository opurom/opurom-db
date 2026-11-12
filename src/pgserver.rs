//! A bundled PostgreSQL v3 protocol server used as a conformance harness.
//!
//! The server speaks the subset of the PostgreSQL wire protocol the framework
//! needs: startup with trust or cleartext authentication, parameter status,
//! backend key data, simple queries with real row descriptions, real
//! transactions and SQLSTATE error responses. It is a conformance harness for
//! the client, not a PostgreSQL replacement.

use crate::DbError;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const SSL_REQUEST_CODE: i32 = 80_877_103;
const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

const SQLSTATE_UNDEFINED_TABLE: &str = "42P01";
const SQLSTATE_UNDEFINED_COLUMN: &str = "42703";
const SQLSTATE_UNIQUE_VIOLATION: &str = "23505";
const SQLSTATE_SYNTAX_ERROR: &str = "42601";
const SQLSTATE_INVALID_PASSWORD: &str = "28P01";
const SQLSTATE_IN_FAILED_TRANSACTION: &str = "25P02";

const OID_BOOL: i32 = 16;
const OID_INT8: i32 = 20;
const OID_INT2: i32 = 21;
const OID_INT4: i32 = 23;
const OID_TEXT: i32 = 25;

/// How the bundled server authenticates an incoming connection.
#[derive(Clone, Debug)]
pub enum PgAuth {
    /// Accept the connection without asking for a password.
    Trust,
    /// Ask for a cleartext password and compare it with the expected one.
    Cleartext(String),
}

impl Default for PgAuth {
    fn default() -> Self {
        PgAuth::Trust
    }
}

/// A DER-encoded certificate and private key enabling the TLS listener.
#[derive(Clone, Debug)]
pub struct PgTls {
    /// DER bytes of the server certificate.
    pub certificate: Vec<u8>,
    /// DER bytes of the matching private key (PKCS#8, PKCS#1 or SEC1).
    pub private_key: Vec<u8>,
}

/// Configuration for [`PgServer::start`].
#[derive(Clone, Debug, Default)]
pub struct PgServerOptions {
    /// Authentication mode. Defaults to trust.
    pub auth: PgAuth,
    /// Optional TLS listener configuration. `None` serves plaintext only.
    pub tls: Option<PgTls>,
}

/// A running bundled PostgreSQL protocol server.
#[derive(Clone, Copy, Debug)]
pub struct PgServer {
    address: SocketAddr,
}

impl PgServer {
    /// Bind an ephemeral loopback port and serve it in background threads.
    pub fn start(options: PgServerOptions) -> Result<PgServer, DbError> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|error| {
            DbError::new(format!("bundled postgres server bind failed: {error}"))
        })?;
        let address = listener.local_addr().map_err(|error| {
            DbError::new(format!(
                "bundled postgres server address lookup failed: {error}"
            ))
        })?;
        let tables = Arc::new(Mutex::new(BTreeMap::new()));
        let tls = match &options.tls {
            Some(tls) => Some(server_config(tls)?),
            None => None,
        };
        let auth = options.auth.clone();
        thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(stream) = incoming else { continue };
                let tables = Arc::clone(&tables);
                let auth = auth.clone();
                let tls = tls.clone();
                thread::spawn(move || {
                    let _ = serve(stream, tables, auth, tls);
                });
            }
        });
        Ok(PgServer { address })
    }

    /// The loopback address the server listens on.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// The ephemeral port the server listens on.
    pub fn port(&self) -> u16 {
        self.address.port()
    }
}

fn server_config(tls: &PgTls) -> Result<Arc<ServerConfig>, DbError> {
    let certificate = CertificateDer::from(tls.certificate.clone());
    let key: PrivateKeyDer<'static> =
        PrivateKeyDer::try_from(tls.private_key.clone()).map_err(|error| {
            DbError::new(format!(
                "bundled postgres server TLS private key is unusable: {error}"
            ))
        })?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .map_err(|error| {
            DbError::new(format!("bundled postgres server TLS setup failed: {error}"))
        })?;
    Ok(Arc::new(config))
}

fn serve(
    stream: TcpStream,
    tables: Arc<Mutex<Tables>>,
    auth: PgAuth,
    tls: Option<Arc<ServerConfig>>,
) -> Result<(), DbError> {
    stream.set_read_timeout(Some(IO_TIMEOUT)).map_err(|error| {
        DbError::new(format!(
            "bundled postgres server read timeout failed: {error}"
        ))
    })?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| {
            DbError::new(format!(
                "bundled postgres server write timeout failed: {error}"
            ))
        })?;

    let mut stream = stream;
    let first = read_startup_frame(&mut stream)?;
    if is_ssl_request(&first) {
        let Some(config) = tls else {
            stream.write_all(b"N").map_err(|error| {
                DbError::new(format!(
                    "bundled postgres server TLS refusal failed: {error}"
                ))
            })?;
            return Ok(());
        };
        stream.write_all(b"S").map_err(|error| {
            DbError::new(format!(
                "bundled postgres server TLS accept failed: {error}"
            ))
        })?;
        let mut tls_stream = tls_handshake(stream, config)?;
        let startup = read_startup_frame(&mut tls_stream)?;
        return session(&mut tls_stream, startup, tables, auth);
    }
    session(&mut stream, first, tables, auth)
}

fn is_ssl_request(body: &[u8]) -> bool {
    body.len() == 4 && i32::from_be_bytes([body[0], body[1], body[2], body[3]]) == SSL_REQUEST_CODE
}

/// Drive the server side of a TLS handshake over a plain socket.
fn tls_handshake(
    stream: TcpStream,
    config: Arc<ServerConfig>,
) -> Result<StreamOwned<ServerConnection, TcpStream>, DbError> {
    let connection = ServerConnection::new(config).map_err(|error| {
        DbError::new(format!(
            "bundled postgres server TLS connection failed: {error}"
        ))
    })?;
    let mut connection = connection;
    let mut socket = stream;
    while connection.is_handshaking() {
        connection.complete_io(&mut socket).map_err(|error| {
            DbError::new(format!(
                "bundled postgres server TLS handshake failed: {error}"
            ))
        })?;
    }
    Ok(StreamOwned::new(connection, socket))
}

fn read_startup_frame(stream: &mut dyn Wire) -> Result<Vec<u8>, DbError> {
    let length = read_length(stream)?;
    let mut body = vec![0u8; (length - 4) as usize];
    read_exact(stream, &mut body)?;
    Ok(body)
}

fn read_message(stream: &mut dyn Wire) -> Result<(u8, Vec<u8>), DbError> {
    let mut tag = [0u8; 1];
    read_exact(stream, &mut tag)?;
    let length = read_length(stream)?;
    let mut body = vec![0u8; (length - 4) as usize];
    read_exact(stream, &mut body)?;
    Ok((tag[0], body))
}

trait Wire: Read + Write {}
impl<T: Read + Write + ?Sized> Wire for T {}

fn read_length(stream: &mut dyn Wire) -> Result<i32, DbError> {
    let mut header = [0u8; 4];
    read_exact(stream, &mut header)?;
    let length = i32::from_be_bytes(header);
    if length < 4 || length as usize > MAX_FRAME_LEN {
        return Err(DbError::new(format!(
            "bundled postgres server rejected a frame length of {length} bytes"
        )));
    }
    Ok(length)
}

fn read_exact(stream: &mut dyn Wire, buffer: &mut [u8]) -> Result<(), DbError> {
    let mut filled = 0;
    while filled < buffer.len() {
        match stream.read(&mut buffer[filled..]) {
            Ok(0) => {
                return Err(DbError::new(
                    "bundled postgres server connection closed mid-message",
                ))
            }
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(DbError::new(format!(
                    "bundled postgres server read failed: {error}"
                )))
            }
        }
    }
    Ok(())
}

fn write_frame(stream: &mut dyn Wire, tag: u8, body: &[u8]) -> Result<(), DbError> {
    let mut frame = Vec::with_capacity(5 + body.len());
    frame.push(tag);
    frame.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
    frame.extend_from_slice(body);
    stream
        .write_all(&frame)
        .map_err(|error| DbError::new(format!("bundled postgres server write failed: {error}")))
}

fn session(
    stream: &mut dyn Wire,
    startup: Vec<u8>,
    tables: Arc<Mutex<Tables>>,
    auth: PgAuth,
) -> Result<(), DbError> {
    let parameters = parse_startup(&startup)?;
    if !parameters.iter().any(|(name, _)| name == "user") {
        return Err(DbError::new(
            "bundled postgres server got a startup message without a user parameter",
        ));
    }

    match &auth {
        PgAuth::Trust => write_frame(stream, b'R', &0i32.to_be_bytes())?,
        PgAuth::Cleartext(expected) => {
            write_frame(stream, b'R', &3i32.to_be_bytes())?;
            let (tag, body) = read_message(stream)?;
            if tag != b'p' {
                return Err(DbError::new(
                    "bundled postgres server expected a password message",
                ));
            }
            let password = match body.split_last() {
                Some((0, head)) => String::from_utf8_lossy(head).into_owned(),
                _ => String::from_utf8_lossy(&body).into_owned(),
            };
            if password != *expected {
                write_error(
                    stream,
                    &SqlError::new(SQLSTATE_INVALID_PASSWORD, "password authentication failed"),
                )?;
                return Ok(());
            }
            write_frame(stream, b'R', &0i32.to_be_bytes())?;
        }
    }

    for (name, value) in [
        ("server_version", "15.0"),
        ("server_encoding", "UTF8"),
        ("client_encoding", "UTF8"),
        ("DateStyle", "ISO, MDY"),
        ("integer_datetimes", "on"),
        ("standard_conforming_strings", "on"),
    ] {
        let mut body = Vec::new();
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
        write_frame(stream, b'S', &body)?;
    }
    let mut key = Vec::with_capacity(8);
    key.extend_from_slice(&4242i32.to_be_bytes());
    key.extend_from_slice(&99i32.to_be_bytes());
    write_frame(stream, b'K', &key)?;
    write_frame(stream, b'Z', b"I")?;

    let mut state = Session::new(tables);
    loop {
        let (tag, body) = match read_message(stream) {
            Ok(message) => message,
            Err(_) => return Ok(()),
        };
        match tag {
            b'Q' => {
                let sql = match body.split_last() {
                    Some((0, head)) => String::from_utf8_lossy(head).into_owned(),
                    _ => String::from_utf8_lossy(&body).into_owned(),
                };
                run_query(stream, &mut state, &sql)?;
            }
            b'X' => return Ok(()),
            other => {
                return Err(DbError::new(format!(
                    "bundled postgres server received an unsupported message tag 0x{other:02x}"
                )))
            }
        }
    }
}

fn parse_startup(body: &[u8]) -> Result<Vec<(String, String)>, DbError> {
    if body.len() < 4 {
        return Err(DbError::new(
            "bundled postgres server got a short startup message",
        ));
    }
    let version = i32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    if version >> 16 != 3 {
        return Err(DbError::new(format!(
            "bundled postgres server rejected protocol version {version}"
        )));
    }
    let mut parameters = Vec::new();
    let mut rest = &body[4..];
    while let Some(end) = rest.iter().position(|byte| *byte == 0) {
        let name = String::from_utf8_lossy(&rest[..end]).into_owned();
        rest = &rest[end + 1..];
        if name.is_empty() {
            break;
        }
        let Some(value_end) = rest.iter().position(|byte| *byte == 0) else {
            return Err(DbError::new(
                "bundled postgres server got an unterminated startup parameter",
            ));
        };
        let value = String::from_utf8_lossy(&rest[..value_end]).into_owned();
        rest = &rest[value_end + 1..];
        parameters.push((name, value));
    }
    Ok(parameters)
}

fn write_error(stream: &mut dyn Wire, error: &SqlError) -> Result<(), DbError> {
    let mut body = Vec::new();
    for (code, text) in [
        (b'S', "ERROR"),
        (b'V', "ERROR"),
        (b'C', error.code),
        (b'M', error.message.as_str()),
    ] {
        body.push(code);
        body.extend_from_slice(text.as_bytes());
        body.push(0);
    }
    body.push(0);
    write_frame(stream, b'E', &body)
}

fn run_query(stream: &mut dyn Wire, state: &mut Session, sql: &str) -> Result<(), DbError> {
    let statements = split_statements(sql);
    if statements.is_empty() {
        write_frame(stream, b'I', &[])?;
    }
    for statement in statements {
        let outcome = state.execute(statement.trim());
        match outcome {
            Ok(reply) => write_reply(stream, &reply)?,
            Err(error) => {
                write_error(stream, &error)?;
                break;
            }
        }
    }
    write_frame(stream, b'Z', state.status().as_bytes())
}

fn write_reply(stream: &mut dyn Wire, reply: &Reply) -> Result<(), DbError> {
    match reply {
        Reply::Empty => write_frame(stream, b'I', &[]),
        Reply::Tag(tag) => {
            let mut body = tag.as_bytes().to_vec();
            body.push(0);
            write_frame(stream, b'C', &body)
        }
        Reply::Rows { columns, rows } => {
            let mut description = Vec::new();
            description.extend_from_slice(&(columns.len() as i16).to_be_bytes());
            for (index, column) in columns.iter().enumerate() {
                description.extend_from_slice(column.name.as_bytes());
                description.push(0);
                description.extend_from_slice(&0i32.to_be_bytes());
                description.extend_from_slice(&((index + 1) as i16).to_be_bytes());
                description.extend_from_slice(&column.type_oid.to_be_bytes());
                description.extend_from_slice(&(-1i16).to_be_bytes());
                description.extend_from_slice(&(-1i32).to_be_bytes());
                description.extend_from_slice(&0i16.to_be_bytes());
            }
            write_frame(stream, b'T', &description)?;
            for row in rows {
                let mut data = Vec::new();
                data.extend_from_slice(&(row.len() as i16).to_be_bytes());
                for cell in row {
                    match cell {
                        Some(text) => {
                            data.extend_from_slice(&(text.len() as i32).to_be_bytes());
                            data.extend_from_slice(text.as_bytes());
                        }
                        None => data.extend_from_slice(&(-1i32).to_be_bytes()),
                    }
                }
                write_frame(stream, b'D', &data)?;
            }
            let mut body = format!("SELECT {}", rows.len()).into_bytes();
            body.push(0);
            write_frame(stream, b'C', &body)
        }
    }
}

#[derive(Clone, Debug)]
struct Column {
    name: String,
    type_oid: i32,
}

#[derive(Clone, Debug)]
struct Table {
    columns: Vec<Column>,
    rows: Vec<Vec<Option<String>>>,
    primary_key: Option<usize>,
}

type Tables = BTreeMap<String, Table>;

struct Session {
    committed: Arc<Mutex<Tables>>,
    pending: Option<Tables>,
    failed: bool,
}

enum Reply {
    Empty,
    Tag(String),
    Rows {
        columns: Vec<Column>,
        rows: Vec<Vec<Option<String>>>,
    },
}

struct SqlError {
    code: &'static str,
    message: String,
}

impl SqlError {
    fn new(code: &'static str, message: impl Into<String>) -> SqlError {
        SqlError {
            code,
            message: message.into(),
        }
    }
}

impl Session {
    fn new(committed: Arc<Mutex<Tables>>) -> Session {
        Session {
            committed,
            pending: None,
            failed: false,
        }
    }

    fn status(&self) -> &'static str {
        if self.failed {
            "E"
        } else if self.pending.is_some() {
            "T"
        } else {
            "I"
        }
    }

    /// The tables a statement must read: the transaction copy when open, else
    /// the committed copy.
    fn snapshot(&self) -> Tables {
        match &self.pending {
            Some(pending) => pending.clone(),
            None => self
                .committed
                .lock()
                .map(|tables| tables.clone())
                .unwrap_or_default(),
        }
    }

    /// Write the tables back into the transaction copy or into the committed
    /// copy when no transaction is open.
    fn store(&mut self, tables: Tables) {
        match &mut self.pending {
            Some(pending) => *pending = tables,
            None => {
                if let Ok(mut committed) = self.committed.lock() {
                    *committed = tables;
                }
            }
        }
    }

    fn execute(&mut self, sql: &str) -> Result<Reply, SqlError> {
        let keyword = keyword_of(sql);
        if keyword == "COMMIT" || keyword == "END" {
            if self.failed {
                self.pending = None;
                self.failed = false;
                return Ok(Reply::Tag("ROLLBACK".to_string()));
            }
            if let Some(pending) = self.pending.take() {
                if let Ok(mut committed) = self.committed.lock() {
                    *committed = pending;
                }
            }
            return Ok(Reply::Tag("COMMIT".to_string()));
        }
        if keyword == "ROLLBACK" || keyword == "ABORT" {
            self.pending = None;
            self.failed = false;
            return Ok(Reply::Tag("ROLLBACK".to_string()));
        }
        if self.failed {
            return Err(SqlError::new(
                SQLSTATE_IN_FAILED_TRANSACTION,
                "current transaction is aborted, commands ignored until end of transaction block",
            ));
        }
        let result = match keyword.as_str() {
            "BEGIN" | "START" => {
                if self.pending.is_none() {
                    self.pending = Some(self.snapshot());
                }
                Ok(Reply::Tag("BEGIN".to_string()))
            }
            "CREATE" => self.create_table(sql),
            "INSERT" => self.insert(sql),
            "SELECT" => self.select(sql),
            "DELETE" => self.delete(sql),
            "UPDATE" => self.update(sql),
            "" => Ok(Reply::Empty),
            other => Err(SqlError::new(
                SQLSTATE_SYNTAX_ERROR,
                format!("unsupported statement {other:?} in the bundled postgres server"),
            )),
        };
        if result.is_err() && self.pending.is_some() {
            // Only a transaction block enters the aborted state; a failed
            // statement outside one leaves the session usable.
            self.failed = true;
        }
        result
    }

    fn create_table(&mut self, sql: &str) -> Result<Reply, SqlError> {
        let rest = strip_keyword(sql, "CREATE")
            .ok_or_else(|| SqlError::new(SQLSTATE_SYNTAX_ERROR, "CREATE without TABLE"))?;
        let rest = strip_keyword(rest.trim_start(), "TABLE").ok_or_else(|| {
            SqlError::new(SQLSTATE_SYNTAX_ERROR, "only CREATE TABLE is supported")
        })?;
        let mut rest = rest.trim_start();
        if let Some(after_if) = strip_keyword(rest, "IF") {
            rest = strip_keyword(after_if.trim_start(), "NOT")
                .ok_or_else(|| {
                    SqlError::new(
                        SQLSTATE_SYNTAX_ERROR,
                        "CREATE TABLE IF must be followed by NOT EXISTS",
                    )
                })?
                .trim_start();
            rest = strip_keyword(rest, "EXISTS")
                .ok_or_else(|| {
                    SqlError::new(
                        SQLSTATE_SYNTAX_ERROR,
                        "CREATE TABLE IF must be followed by NOT EXISTS",
                    )
                })?
                .trim_start();
        }
        let (name, rest) = take_identifier(rest);
        if name.is_empty() {
            return Err(SqlError::new(
                SQLSTATE_SYNTAX_ERROR,
                "CREATE TABLE without a name",
            ));
        }
        let (definitions, _) = take_parenthesised(rest.trim_start())?;
        let mut columns = Vec::new();
        let mut primary_key = None;
        for definition in split_top_level(&definitions, ',') {
            let definition = definition.trim();
            if definition.is_empty() {
                continue;
            }
            let parts: Vec<&str> = definition.split_whitespace().collect();
            let type_oid = parts.get(1).map(|ty| type_oid_of(ty)).unwrap_or(OID_TEXT);
            if parts.windows(2).any(|pair| {
                pair[0].eq_ignore_ascii_case("PRIMARY") && pair[1].eq_ignore_ascii_case("KEY")
            }) {
                primary_key = Some(columns.len());
            }
            columns.push(Column {
                name: parts[0].to_string(),
                type_oid,
            });
        }
        if columns.is_empty() {
            return Err(SqlError::new(
                SQLSTATE_SYNTAX_ERROR,
                "CREATE TABLE without columns",
            ));
        }
        let mut tables = self.snapshot();
        tables.insert(
            name,
            Table {
                columns,
                rows: Vec::new(),
                primary_key,
            },
        );
        self.store(tables);
        Ok(Reply::Tag("CREATE TABLE".to_string()))
    }

    fn insert(&mut self, sql: &str) -> Result<Reply, SqlError> {
        let rest = strip_keyword(sql, "INSERT")
            .ok_or_else(|| SqlError::new(SQLSTATE_SYNTAX_ERROR, "INSERT without INTO"))?;
        let rest = strip_keyword(rest.trim_start(), "INTO")
            .ok_or_else(|| SqlError::new(SQLSTATE_SYNTAX_ERROR, "INSERT without INTO"))?;
        let (name, rest) = take_identifier(rest.trim_start());
        let rest = rest.trim_start();
        let (column_names, rest) = if rest.starts_with('(') {
            let (inner, rest) = take_parenthesised(rest)?;
            (
                inner
                    .split(',')
                    .map(|part| part.trim().to_string())
                    .filter(|part| !part.is_empty())
                    .collect::<Vec<String>>(),
                rest,
            )
        } else {
            (Vec::new(), rest)
        };
        let rest = strip_keyword(rest.trim_start(), "VALUES")
            .ok_or_else(|| SqlError::new(SQLSTATE_SYNTAX_ERROR, "INSERT without VALUES"))?;
        let (values, _) = take_parenthesised(rest.trim_start())?;
        let mut cells = Vec::new();
        for value in split_top_level(&values, ',') {
            cells.push(parse_literal(value.trim()).ok_or_else(|| {
                SqlError::new(
                    SQLSTATE_SYNTAX_ERROR,
                    format!("unsupported literal {value:?} in the bundled postgres server"),
                )
            })?);
        }

        let mut tables = self.snapshot();
        let table = tables.get_mut(&name).ok_or_else(|| {
            SqlError::new(
                SQLSTATE_UNDEFINED_TABLE,
                format!("relation {name:?} does not exist"),
            )
        })?;
        let row = build_row(table, &column_names, &cells)?;
        if let Some(primary) = table.primary_key {
            let key = row.get(primary).cloned().unwrap_or(None);
            if table
                .rows
                .iter()
                .any(|existing| existing.get(primary).cloned().unwrap_or(None) == key)
            {
                return Err(SqlError::new(
                    SQLSTATE_UNIQUE_VIOLATION,
                    format!("duplicate key value violates unique constraint on {name:?}"),
                ));
            }
        }
        table.rows.push(row);
        self.store(tables);
        Ok(Reply::Tag("INSERT 0 1".to_string()))
    }

    fn select(&mut self, sql: &str) -> Result<Reply, SqlError> {
        let rest = strip_keyword(sql, "SELECT")
            .ok_or_else(|| SqlError::new(SQLSTATE_SYNTAX_ERROR, "malformed SELECT"))?;
        let rest = rest.trim_start();
        let from = find_keyword(rest, "FROM")
            .ok_or_else(|| SqlError::new(SQLSTATE_SYNTAX_ERROR, "SELECT without FROM"))?;
        let requested = rest[..from].trim();
        let rest = rest[from + 4..].trim_start();
        let (name, rest) = take_identifier(rest);
        let condition = parse_condition(rest)?;
        let tables = self.snapshot();
        let table = tables.get(&name).ok_or_else(|| {
            SqlError::new(
                SQLSTATE_UNDEFINED_TABLE,
                format!("relation {name:?} does not exist"),
            )
        })?;
        let (columns, indexes) = select_columns(table, requested)?;
        let mut rows = Vec::new();
        for row in &table.rows {
            if !condition.matches(row, &table.columns) {
                continue;
            }
            rows.push(indexes.iter().map(|index| row[*index].clone()).collect());
        }
        Ok(Reply::Rows { columns, rows })
    }

    fn delete(&mut self, sql: &str) -> Result<Reply, SqlError> {
        let rest = strip_keyword(sql, "DELETE")
            .ok_or_else(|| SqlError::new(SQLSTATE_SYNTAX_ERROR, "malformed DELETE statement"))?;
        let rest = strip_keyword(rest.trim_start(), "FROM")
            .ok_or_else(|| SqlError::new(SQLSTATE_SYNTAX_ERROR, "DELETE without FROM"))?;
        let (name, rest) = take_identifier(rest.trim_start());
        let condition = parse_condition(rest)?;
        let mut tables = self.snapshot();
        let table = tables.get_mut(&name).ok_or_else(|| {
            SqlError::new(
                SQLSTATE_UNDEFINED_TABLE,
                format!("relation {name:?} does not exist"),
            )
        })?;
        let before = table.rows.len();
        table
            .rows
            .retain(|row| !condition.matches(row, &table.columns));
        let deleted = before - table.rows.len();
        self.store(tables);
        Ok(Reply::Tag(format!("DELETE {deleted}")))
    }

    fn update(&mut self, sql: &str) -> Result<Reply, SqlError> {
        let rest = strip_keyword(sql, "UPDATE")
            .ok_or_else(|| SqlError::new(SQLSTATE_SYNTAX_ERROR, "malformed UPDATE statement"))?;
        let (name, rest) = take_identifier(rest.trim_start());
        let rest = strip_keyword(rest.trim_start(), "SET")
            .ok_or_else(|| SqlError::new(SQLSTATE_SYNTAX_ERROR, "UPDATE without SET"))?;
        let (assignments, rest) = take_until_keyword(rest.trim_start(), "WHERE");
        let condition = parse_condition(rest)?;
        let mut tables = self.snapshot();
        let table = tables.get_mut(&name).ok_or_else(|| {
            SqlError::new(
                SQLSTATE_UNDEFINED_TABLE,
                format!("relation {name:?} does not exist"),
            )
        })?;
        let mut updates = Vec::new();
        for assignment in split_top_level(&assignments, ',') {
            let Some((column, value)) = assignment.split_once('=') else {
                return Err(SqlError::new(
                    SQLSTATE_SYNTAX_ERROR,
                    format!("malformed assignment {assignment:?}"),
                ));
            };
            let column = column.trim();
            let Some(index) = table
                .columns
                .iter()
                .position(|item| item.name.eq_ignore_ascii_case(column))
            else {
                return Err(SqlError::new(
                    SQLSTATE_UNDEFINED_COLUMN,
                    format!("column {column:?} of relation {name:?} does not exist"),
                ));
            };
            let value = parse_literal(value.trim()).ok_or_else(|| {
                SqlError::new(
                    SQLSTATE_SYNTAX_ERROR,
                    format!("unsupported literal {value:?} in the bundled postgres server"),
                )
            })?;
            updates.push((index, value));
        }
        let mut updated = 0;
        for row in &mut table.rows {
            if condition.matches(row, &table.columns) {
                for (index, value) in &updates {
                    row[*index] = value.clone();
                }
                updated += 1;
            }
        }
        self.store(tables);
        Ok(Reply::Tag(format!("UPDATE {updated}")))
    }
}

fn type_oid_of(declared: &str) -> i32 {
    let base = declared.split('(').next().unwrap_or(declared).trim();
    match base.to_ascii_uppercase().as_str() {
        "BOOL" | "BOOLEAN" => OID_BOOL,
        "INT2" | "SMALLINT" => OID_INT2,
        "INT8" | "BIGINT" => OID_INT8,
        "INT" | "INT4" | "INTEGER" => OID_INT4,
        _ => OID_TEXT,
    }
}

fn select_columns(table: &Table, requested: &str) -> Result<(Vec<Column>, Vec<usize>), SqlError> {
    if requested == "*" || requested.is_empty() {
        let indexes = (0..table.columns.len()).collect();
        return Ok((table.columns.clone(), indexes));
    }
    let mut columns = Vec::new();
    let mut indexes = Vec::new();
    for name in requested.split(',') {
        let name = name.trim();
        let Some(index) = table
            .columns
            .iter()
            .position(|column| column.name.eq_ignore_ascii_case(name))
        else {
            return Err(SqlError::new(
                SQLSTATE_UNDEFINED_COLUMN,
                format!("column {name:?} does not exist"),
            ));
        };
        columns.push(table.columns[index].clone());
        indexes.push(index);
    }
    Ok((columns, indexes))
}

fn build_row(
    table: &Table,
    column_names: &[String],
    cells: &[Option<String>],
) -> Result<Vec<Option<String>>, SqlError> {
    let mut row = vec![None; table.columns.len()];
    if column_names.is_empty() {
        if cells.len() != row.len() {
            return Err(SqlError::new(
                SQLSTATE_SYNTAX_ERROR,
                "INSERT column count does not match the table",
            ));
        }
        for (position, cell) in cells.iter().enumerate() {
            row[position] = cell.clone();
        }
        return Ok(row);
    }
    if cells.len() != column_names.len() {
        return Err(SqlError::new(
            SQLSTATE_SYNTAX_ERROR,
            "INSERT column count does not match the value count",
        ));
    }
    for (position, name) in column_names.iter().enumerate() {
        let Some(index) = table
            .columns
            .iter()
            .position(|column| column.name.eq_ignore_ascii_case(name))
        else {
            return Err(SqlError::new(
                SQLSTATE_UNDEFINED_COLUMN,
                format!("column {name:?} does not exist"),
            ));
        };
        row[index] = cells[position].clone();
    }
    Ok(row)
}

#[derive(Default)]
struct Condition {
    column: Option<String>,
    value: Option<String>,
}

impl Condition {
    fn matches(&self, row: &[Option<String>], columns: &[Column]) -> bool {
        let (Some(column), Some(value)) = (self.column.as_deref(), self.value.as_deref()) else {
            return true;
        };
        let Some(index) = columns
            .iter()
            .position(|item| item.name.eq_ignore_ascii_case(column))
        else {
            return false;
        };
        row.get(index)
            .and_then(|cell| cell.as_deref())
            .unwrap_or("")
            == value
    }
}

fn parse_condition(rest: &str) -> Result<Condition, SqlError> {
    let rest = rest.trim();
    if rest.is_empty() {
        return Ok(Condition::default());
    }
    let rest = strip_keyword(rest, "WHERE")
        .ok_or_else(|| SqlError::new(SQLSTATE_SYNTAX_ERROR, "malformed WHERE clause"))?;
    let (column, value) = rest
        .split_once('=')
        .ok_or_else(|| SqlError::new(SQLSTATE_SYNTAX_ERROR, "WHERE clause without an equality"))?;
    let value = parse_literal(value.trim()).ok_or_else(|| {
        SqlError::new(
            SQLSTATE_SYNTAX_ERROR,
            "WHERE clause with an unsupported literal",
        )
    })?;
    Ok(Condition {
        column: Some(column.trim().to_string()),
        value,
    })
}

fn parse_literal(text: &str) -> Option<Option<String>> {
    let text = text.trim();
    if text.eq_ignore_ascii_case("NULL") {
        return Some(None);
    }
    if text.len() >= 2 && text.starts_with('\'') && text.ends_with('\'') {
        return Some(Some(text[1..text.len() - 1].replace("''", "'")));
    }
    if text.eq_ignore_ascii_case("TRUE") {
        return Some(Some("true".to_string()));
    }
    if text.eq_ignore_ascii_case("FALSE") {
        return Some(Some("false".to_string()));
    }
    if text.parse::<i64>().is_ok() {
        return Some(Some(text.to_string()));
    }
    None
}

fn keyword_of(sql: &str) -> String {
    sql.trim()
        .trim_end_matches(';')
        .trim()
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_uppercase()
}

fn strip_keyword<'a>(text: &'a str, keyword: &str) -> Option<&'a str> {
    let head = text.get(..keyword.len())?;
    if !head.eq_ignore_ascii_case(keyword) {
        return None;
    }
    let rest = &text[keyword.len()..];
    if rest.is_empty() || rest.starts_with(|c: char| c.is_whitespace() || c == '(') {
        Some(rest)
    } else {
        None
    }
}

fn find_keyword(text: &str, keyword: &str) -> Option<usize> {
    let lower = text.to_ascii_lowercase();
    let needle = keyword.to_ascii_lowercase();
    let bytes = text.as_bytes();
    let mut start = 0;
    while let Some(offset) = lower[start..].find(&needle) {
        let position = start + offset;
        let before = position == 0 || !is_identifier_byte(bytes[position - 1]);
        let after = position + keyword.len();
        let after_ok = after >= bytes.len() || !is_identifier_byte(bytes[after]);
        if before && after_ok {
            return Some(position);
        }
        start = position + keyword.len();
    }
    None
}

fn take_until_keyword<'a>(text: &'a str, keyword: &str) -> (String, &'a str) {
    match find_keyword(text, keyword) {
        Some(position) => (text[..position].trim().to_string(), &text[position..]),
        None => (text.trim().to_string(), ""),
    }
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn take_identifier(text: &str) -> (String, &str) {
    let mut end = 0;
    for (index, byte) in text.bytes().enumerate() {
        if is_identifier_byte(byte) || byte == b'.' {
            end = index + 1;
        } else {
            break;
        }
    }
    (text[..end].to_string(), &text[end..])
}

fn take_parenthesised(text: &str) -> Result<(String, &str), SqlError> {
    let text = text.trim_start();
    if !text.starts_with('(') {
        return Err(SqlError::new(
            SQLSTATE_SYNTAX_ERROR,
            "expected a parenthesised list",
        ));
    }
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut in_quote = false;
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_quote {
            if byte == b'\'' {
                if index + 1 < bytes.len() && bytes[index + 1] == b'\'' {
                    index += 2;
                    continue;
                }
                in_quote = false;
            }
            index += 1;
            continue;
        }
        match byte {
            b'\'' => in_quote = true,
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Ok((text[1..index].to_string(), &text[index + 1..]));
                }
            }
            _ => {}
        }
        index += 1;
    }
    Err(SqlError::new(
        SQLSTATE_SYNTAX_ERROR,
        "unbalanced parentheses",
    ))
}

fn split_top_level(text: &str, separator: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;
    let mut in_quote = false;
    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        if in_quote {
            current.push(character);
            if character == '\'' {
                if chars.peek() == Some(&'\'') {
                    current.push('\'');
                    chars.next();
                } else {
                    in_quote = false;
                }
            }
            continue;
        }
        match character {
            '\'' => {
                in_quote = true;
                current.push(character);
            }
            '(' => {
                depth += 1;
                current.push(character);
            }
            ')' => {
                depth = depth.saturating_sub(1);
                current.push(character);
            }
            character if character == separator && depth == 0 => {
                parts.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(character),
        }
    }
    parts.push(current.trim().to_string());
    parts
}

fn split_statements(sql: &str) -> Vec<String> {
    split_top_level(sql, ';')
        .into_iter()
        .filter(|statement| !statement.trim().is_empty())
        .collect()
}
