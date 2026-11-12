//! Pure-std PostgreSQL v3 frontend.
//!
//! This driver speaks plain TCP startup and simple `Query` messages only. It
//! accepts `AuthenticationOk` and rejects any other authentication request,
//! binary result columns, oversized frames and slow or truncated responses.

use crate::{Database, DbError, Row, Value};
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

const PROTOCOL_VERSION: i32 = 196608;
const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_ROWS: usize = 65_536;
const MAX_COLUMNS: usize = 1_600;
const IO_TIMEOUT: Duration = Duration::from_millis(500);

const AUTH_OK: i32 = 0;
const AUTH_CLEARTEXT_PASSWORD: i32 = 3;
const AUTH_MD5_PASSWORD: i32 = 5;
const AUTH_SASL: i32 = 10;
const AUTH_SASL_CONTINUE: i32 = 11;
const AUTH_SASL_FINAL: i32 = 12;

const OID_BOOL: i32 = 16;
const OID_INT8: i32 = 20;
const OID_INT2: i32 = 21;
const OID_INT4: i32 = 23;
const OID_OID: i32 = 26;

/// A plain-TCP PostgreSQL v3 connection using the simple query protocol.
#[derive(Debug)]
pub struct PgConnection {
    stream: TcpStream,
    parameters: BTreeMap<String, String>,
    backend_key: Option<(i32, i32)>,
    broken: bool,
}

impl PgConnection {
    /// Connect to a server that returns `AuthenticationOk` without TLS.
    pub fn connect(
        host: &str,
        port: u16,
        user: &str,
        database: &str,
    ) -> Result<PgConnection, DbError> {
        let startup = startup_message(user, database)?;
        let stream = connect_stream(host, port)?;
        let mut connection = PgConnection {
            stream,
            parameters: BTreeMap::new(),
            backend_key: None,
            broken: false,
        };
        connection.write_all_deadline(&startup, Instant::now() + IO_TIMEOUT)?;
        connection.read_startup(Instant::now() + IO_TIMEOUT)?;
        Ok(connection)
    }

    /// Return a `ParameterStatus` value received during startup.
    pub fn parameter(&self, name: &str) -> Option<&str> {
        self.parameters.get(name).map(String::as_str)
    }

    /// Return the `(process id, secret key)` from `BackendKeyData`.
    pub fn backend_key(&self) -> Option<(i32, i32)> {
        self.backend_key
    }

    /// Run a simple query and expose its text-format rows.
    pub fn query(&mut self, sql: &str) -> Result<Vec<Row>, DbError> {
        if self.broken {
            return Err(DbError::new(
                "postgres connection is unusable after a protocol error",
            ));
        }
        self.run_query(sql)
    }

    /// Run a simple query, discarding any returned rows.
    pub fn exec(&mut self, sql: &str) -> Result<(), DbError> {
        self.query(sql).map(|_| ())
    }

    fn read_startup(&mut self, deadline: Instant) -> Result<(), DbError> {
        let mut budget = Budget::default();
        let mut authenticated = false;
        loop {
            let message = self.read_message(&mut budget, deadline)?;
            match message.tag {
                b'R' => {
                    let mut cursor = Cursor::new(&message.body, "Authentication");
                    let code = match cursor.i32() {
                        Ok(code) => code,
                        Err(error) => return self.fail(error.to_string()),
                    };
                    if code != AUTH_OK {
                        return self.fail(unsupported_auth(code));
                    }
                    if let Err(error) = cursor.done() {
                        return self.fail(error.to_string());
                    }
                    authenticated = true;
                }
                b'S' => {
                    let (name, value) = match parse_parameter_status(&message.body) {
                        Ok(pair) => pair,
                        Err(error) => return self.fail(error.to_string()),
                    };
                    self.parameters.insert(name, value);
                }
                b'K' => match parse_backend_key(&message.body) {
                    Ok(key) => self.backend_key = Some(key),
                    Err(error) => return self.fail(error.to_string()),
                },
                b'E' => {
                    let error = match parse_error_response(&message.body) {
                        Ok(error) => error,
                        Err(error) => return self.fail(error.to_string()),
                    };
                    return self.fail(error.to_string());
                }
                b'N' => {
                    if let Err(error) = parse_fields(&message.body, "NoticeResponse") {
                        return self.fail(error.to_string());
                    }
                }
                b'Z' => {
                    if let Err(error) = parse_ready(&message.body) {
                        return self.fail(error.to_string());
                    }
                    if !authenticated {
                        return self
                            .fail("postgres reached ReadyForQuery without AuthenticationOk");
                    }
                    return Ok(());
                }
                tag => {
                    return self.fail(format!(
                        "unsupported postgres startup message tag 0x{tag:02x}"
                    ));
                }
            }
        }
    }

    fn run_query(&mut self, sql: &str) -> Result<Vec<Row>, DbError> {
        let frame = query_message(sql)?;
        self.write_all_deadline(&frame, Instant::now() + IO_TIMEOUT)?;
        let deadline = Instant::now() + IO_TIMEOUT;
        let mut budget = Budget::default();
        let mut rows = Vec::new();
        let mut columns: Option<Vec<Column>> = None;
        let mut completed = false;
        let mut query_error: Option<DbError> = None;

        loop {
            let message = match self.read_message(&mut budget, deadline) {
                Ok(message) => message,
                Err(error) => {
                    // Keep the server's first ErrorResponse even if it closes before ReadyForQuery.
                    return match query_error {
                        Some(first) => Err(first),
                        None => Err(error),
                    };
                }
            };
            match message.tag {
                b'T' => {
                    let parsed = match parse_row_description(&message.body) {
                        Ok(columns) => columns,
                        Err(error) => return self.fail(error.to_string()),
                    };
                    columns = Some(parsed);
                }
                b'D' => {
                    let current = match columns.as_ref() {
                        Some(columns) => columns,
                        None => {
                            return self.fail("postgres DataRow arrived before RowDescription");
                        }
                    };
                    if let Err(error) = budget.row() {
                        return self.fail(error.to_string());
                    }
                    let row = match parse_data_row(&message.body, current) {
                        Ok(row) => row,
                        Err(error) => return self.fail(error.to_string()),
                    };
                    rows.push(row);
                }
                b'C' => {
                    if let Err(error) = parse_command_complete(&message.body) {
                        return self.fail(error.to_string());
                    }
                    completed = true;
                    columns = None;
                }
                b'I' => {
                    if !message.body.is_empty() {
                        return self.fail("postgres EmptyQueryResponse has a non-empty body");
                    }
                    completed = true;
                }
                b'E' => {
                    let error = match parse_error_response(&message.body) {
                        Ok(error) => error,
                        Err(error) => return self.fail(error.to_string()),
                    };
                    if query_error.is_none() {
                        query_error = Some(error);
                    }
                }
                b'N' => {
                    if let Err(error) = parse_fields(&message.body, "NoticeResponse") {
                        return self.fail(error.to_string());
                    }
                }
                b'Z' => {
                    if let Err(error) = parse_ready(&message.body) {
                        return self.fail(error.to_string());
                    }
                    return match query_error {
                        Some(error) => Err(error),
                        None if completed => Ok(rows),
                        None => self.fail("postgres reached ReadyForQuery before CommandComplete"),
                    };
                }
                tag => {
                    return self.fail(format!(
                        "unsupported postgres query message tag 0x{tag:02x}"
                    ));
                }
            }
        }
    }

    fn write_all_deadline(&mut self, bytes: &[u8], deadline: Instant) -> Result<(), DbError> {
        let mut sent = 0;
        while sent < bytes.len() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return self.fail(io_timeout("write").to_string());
            }
            if let Err(error) = self.stream.set_write_timeout(Some(remaining)) {
                return self.fail(io_failure("write timeout setup", error).to_string());
            }
            match self.stream.write(&bytes[sent..]) {
                Ok(0) => return self.fail("postgres write accepted zero bytes"),
                Ok(count) => sent += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    return self.fail(io_timeout("write").to_string());
                }
                Err(error) => return self.fail(io_failure("write", error).to_string()),
            }
        }
        Ok(())
    }

    fn read_exact_deadline(&mut self, buffer: &mut [u8], deadline: Instant) -> Result<(), DbError> {
        let mut filled = 0;
        while filled < buffer.len() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return self.fail(io_timeout("read").to_string());
            }
            if let Err(error) = self.stream.set_read_timeout(Some(remaining)) {
                return self.fail(io_failure("read timeout setup", error).to_string());
            }
            match self.stream.read(&mut buffer[filled..]) {
                Ok(0) => {
                    return self.fail(
                        "postgres connection closed while reading a message (truncated frame)",
                    );
                }
                Ok(count) => filled += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    return self.fail(io_timeout("read").to_string());
                }
                Err(error) => return self.fail(io_failure("read", error).to_string()),
            }
        }
        Ok(())
    }

    fn read_message(&mut self, budget: &mut Budget, deadline: Instant) -> Result<Message, DbError> {
        let mut header = [0u8; 5];
        self.read_exact_deadline(&mut header, deadline)?;
        let length = i32::from_be_bytes([header[1], header[2], header[3], header[4]]);
        if length < 4 {
            return self.fail(format!("invalid postgres message length {length}"));
        }
        if length as usize > MAX_FRAME_LEN {
            return self.fail(format!(
                "postgres message length {length} exceeds {MAX_FRAME_LEN}-byte limit"
            ));
        }
        let body_len = length as usize - 4;
        if let Err(error) = budget.account(5 + body_len) {
            return self.fail(error.to_string());
        }
        let mut body = vec![0u8; body_len];
        self.read_exact_deadline(&mut body, deadline)?;
        Ok(Message {
            tag: header[0],
            body,
        })
    }

    fn fail<T>(&mut self, message: impl Into<String>) -> Result<T, DbError> {
        self.broken = true;
        Err(DbError::new(message))
    }
}

impl Database for PgConnection {
    fn exec(&mut self, sql: &str) -> Result<(), DbError> {
        PgConnection::exec(self, sql)
    }

    fn query(&mut self, sql: &str) -> Result<Vec<Row>, DbError> {
        PgConnection::query(self, sql)
    }
}

struct Message {
    tag: u8,
    body: Vec<u8>,
}

#[derive(Default)]
struct Budget {
    bytes: usize,
    rows: usize,
}

impl Budget {
    fn account(&mut self, bytes: usize) -> Result<(), DbError> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| DbError::new("postgres response byte budget overflow"))?;
        if self.bytes > MAX_RESPONSE_BYTES {
            return Err(DbError::new(format!(
                "postgres response exceeds {MAX_RESPONSE_BYTES} bytes"
            )));
        }
        Ok(())
    }

    fn row(&mut self) -> Result<(), DbError> {
        if self.rows >= MAX_ROWS {
            return Err(DbError::new(format!(
                "postgres query exceeds {MAX_ROWS} rows"
            )));
        }
        self.rows += 1;
        Ok(())
    }
}

struct Column {
    name: String,
    type_oid: i32,
}

struct Cursor<'a> {
    data: &'a [u8],
    position: usize,
    what: &'static str,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8], what: &'static str) -> Cursor<'a> {
        Cursor {
            data,
            position: 0,
            what,
        }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], DbError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or_else(|| malformed(self.what, "length overflow"))?;
        let bytes = self
            .data
            .get(self.position..end)
            .ok_or_else(|| malformed(self.what, "truncated body"))?;
        self.position = end;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, DbError> {
        Ok(self.take(1)?[0])
    }

    fn i16(&mut self) -> Result<i16, DbError> {
        let bytes = self.take(2)?;
        Ok(i16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn i32(&mut self) -> Result<i32, DbError> {
        let bytes = self.take(4)?;
        Ok(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn cstring(&mut self) -> Result<String, DbError> {
        let rest = self
            .data
            .get(self.position..)
            .ok_or_else(|| malformed(self.what, "truncated body"))?;
        let end = rest
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| malformed(self.what, "missing NUL terminator"))?;
        let text = String::from_utf8_lossy(&rest[..end]).into_owned();
        self.position += end + 1;
        Ok(text)
    }

    fn done(&self) -> Result<(), DbError> {
        if self.position == self.data.len() {
            Ok(())
        } else {
            Err(malformed(self.what, "trailing bytes"))
        }
    }
}

fn malformed(what: &str, detail: &str) -> DbError {
    DbError::new(format!("malformed postgres {what} message: {detail}"))
}

fn io_timeout(operation: &str) -> DbError {
    DbError::new(format!(
        "postgres {operation} timed out after {} ms",
        IO_TIMEOUT.as_millis()
    ))
}

fn io_failure(operation: &str, error: io::Error) -> DbError {
    DbError::new(format!("postgres {operation} failed: {error}"))
}

fn unsupported_auth(code: i32) -> String {
    let kind = match code {
        AUTH_CLEARTEXT_PASSWORD => "cleartext password",
        AUTH_MD5_PASSWORD => "MD5 password",
        AUTH_SASL => "SASL/SCRAM",
        AUTH_SASL_CONTINUE => "SASL continuation",
        AUTH_SASL_FINAL => "SASL final",
        _ => "unknown",
    };
    format!(
        "UNSUPPORTED: PostgreSQL {kind} authentication (code {code}) is not implemented; no credentials are sent"
    )
}

fn frame_length(payload_len: usize, what: &str) -> Result<i32, DbError> {
    let length = 4usize
        .checked_add(payload_len)
        .ok_or_else(|| DbError::new(format!("postgres {what} is too long")))?;
    if length > MAX_FRAME_LEN {
        return Err(DbError::new(format!(
            "postgres {what} exceeds {MAX_FRAME_LEN}-byte limit"
        )));
    }
    Ok(length as i32)
}

fn startup_message(user: &str, database: &str) -> Result<Vec<u8>, DbError> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    for (name, value) in [("user", user), ("database", database)] {
        if value.as_bytes().contains(&0) {
            return Err(DbError::new(format!(
                "postgres startup parameter {name} contains a NUL byte"
            )));
        }
        payload.extend_from_slice(name.as_bytes());
        payload.push(0);
        payload.extend_from_slice(value.as_bytes());
        payload.push(0);
    }
    payload.push(0);
    let length = frame_length(payload.len(), "startup message")?;
    let mut frame = Vec::with_capacity(length as usize);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn query_message(sql: &str) -> Result<Vec<u8>, DbError> {
    if sql.as_bytes().contains(&0) {
        return Err(DbError::new("postgres SQL contains a NUL byte"));
    }
    let mut payload = Vec::with_capacity(sql.len() + 1);
    payload.extend_from_slice(sql.as_bytes());
    payload.push(0);
    let length = frame_length(payload.len(), "query message")?;
    let mut frame = Vec::with_capacity(1 + length as usize);
    frame.push(b'Q');
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn connect_stream(host: &str, port: u16) -> Result<TcpStream, DbError> {
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|error| DbError::new(format!("postgres address {host}:{port}: {error}")))?;
    let mut last_error = "no addresses resolved".to_string();
    for address in addresses {
        match TcpStream::connect_timeout(&address, IO_TIMEOUT) {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(IO_TIMEOUT))
                    .map_err(|error| io_failure("read timeout setup", error))?;
                stream
                    .set_write_timeout(Some(IO_TIMEOUT))
                    .map_err(|error| io_failure("write timeout setup", error))?;
                return Ok(stream);
            }
            Err(error) => last_error = format!("{address}: {error}"),
        }
    }
    Err(DbError::new(format!(
        "postgres connect to {host}:{port} failed: {last_error}"
    )))
}

fn parse_parameter_status(body: &[u8]) -> Result<(String, String), DbError> {
    let mut cursor = Cursor::new(body, "ParameterStatus");
    let name = cursor.cstring()?;
    let value = cursor.cstring()?;
    cursor.done()?;
    Ok((name, value))
}

fn parse_backend_key(body: &[u8]) -> Result<(i32, i32), DbError> {
    let mut cursor = Cursor::new(body, "BackendKeyData");
    let process_id = cursor.i32()?;
    let secret_key = cursor.i32()?;
    cursor.done()?;
    Ok((process_id, secret_key))
}

fn parse_ready(body: &[u8]) -> Result<(), DbError> {
    let mut cursor = Cursor::new(body, "ReadyForQuery");
    let status = cursor.u8()?;
    cursor.done()?;
    if matches!(status, b'I' | b'T' | b'E') {
        Ok(())
    } else {
        Err(malformed("ReadyForQuery", "invalid transaction status"))
    }
}

fn parse_command_complete(body: &[u8]) -> Result<(), DbError> {
    let mut cursor = Cursor::new(body, "CommandComplete");
    let _tag = cursor.cstring()?;
    cursor.done()?;
    Ok(())
}

fn parse_fields(body: &[u8], what: &'static str) -> Result<Vec<(u8, String)>, DbError> {
    let mut cursor = Cursor::new(body, what);
    let mut fields = Vec::new();
    loop {
        let code = cursor.u8()?;
        if code == 0 {
            break;
        }
        fields.push((code, cursor.cstring()?));
    }
    cursor.done()?;
    Ok(fields)
}

fn parse_error_response(body: &[u8]) -> Result<DbError, DbError> {
    let fields = parse_fields(body, "ErrorResponse")?;
    let field = |code| {
        fields
            .iter()
            .find(|(key, _)| *key == code)
            .map(|(_, value)| value.as_str())
    };
    let severity = field(b'V').or_else(|| field(b'S')).unwrap_or("ERROR");
    let message = field(b'M').unwrap_or("no message supplied");
    let mut text = format!("postgres {severity}");
    if let Some(sqlstate) = field(b'C') {
        text.push_str(&format!(" [SQLSTATE {sqlstate}]"));
    }
    text.push_str(&format!(": {message}"));
    for (code, label) in [(b'D', "detail"), (b'H', "hint"), (b'P', "position")] {
        if let Some(value) = field(code) {
            text.push_str(&format!("; {label}: {value}"));
        }
    }
    Ok(DbError::new(text))
}

fn parse_row_description(body: &[u8]) -> Result<Vec<Column>, DbError> {
    let mut cursor = Cursor::new(body, "RowDescription");
    let count = cursor.i16()?;
    if count < 0 || count as usize > MAX_COLUMNS {
        return Err(malformed("RowDescription", "invalid field count"));
    }
    let mut columns = Vec::with_capacity(count as usize);
    for index in 0..count as usize {
        let name = cursor.cstring()?;
        let _table_oid = cursor.i32()?;
        let _attribute_number = cursor.i16()?;
        let type_oid = cursor.i32()?;
        let _type_size = cursor.i16()?;
        let _type_modifier = cursor.i32()?;
        let format = cursor.i16()?;
        if format != 0 {
            // shortcut: binary results are rejected; add typed binary decoding with prepared statements.
            return Err(malformed(
                "RowDescription",
                "binary result format is unsupported",
            ));
        }
        let name = if name.is_empty() {
            format!("column{index}")
        } else {
            name
        };
        columns.push(Column { name, type_oid });
    }
    cursor.done()?;
    Ok(columns)
}

fn parse_data_row(body: &[u8], columns: &[Column]) -> Result<Row, DbError> {
    let mut cursor = Cursor::new(body, "DataRow");
    let count = cursor.i16()?;
    if count < 0 || count as usize != columns.len() {
        return Err(malformed(
            "DataRow",
            "column count does not match RowDescription",
        ));
    }
    let mut row = Row::new();
    for column in columns {
        let length = cursor.i32()?;
        if length == -1 {
            continue;
        }
        if length < 0 {
            return Err(malformed("DataRow", "invalid column length"));
        }
        let text = String::from_utf8_lossy(cursor.take(length as usize)?).into_owned();
        // shortcut: other types stay text; extend Value before adding typed float/date/array support.
        let value = match column.type_oid {
            OID_BOOL => match parse_bool(&text) {
                Some(value) => Value::Bool(value),
                None => {
                    return Err(malformed(
                        "DataRow",
                        &format!("invalid boolean value {text:?}"),
                    ));
                }
            },
            OID_INT2 | OID_INT4 | OID_INT8 | OID_OID => match text.parse::<i64>() {
                Ok(value) => Value::Int(value),
                Err(_) => {
                    return Err(malformed(
                        "DataRow",
                        &format!("invalid integer value {text:?}"),
                    ));
                }
            },
            _ => Value::Text(text),
        };
        row.set(column.name.clone(), value);
    }
    cursor.done()?;
    Ok(row)
}

fn parse_bool(text: &str) -> Option<bool> {
    match text.to_ascii_lowercase().as_str() {
        "t" | "true" | "1" => Some(true),
        "f" | "false" | "0" => Some(false),
        _ => None,
    }
}
