//! Pure-std MySQL protocol v10 frontend.
//!
//! This driver speaks plain TCP protocol 10, `mysql_native_password`,
//! `COM_QUERY` and text result sets. It rejects authentication plugin switches,
//! TLS negotiation, binary/prepared statements and oversized or out-of-sequence
//! packets instead of guessing.

use crate::{Database, DbError, MySqlErrorKind, Row, Value};
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

const PROTOCOL_10: u8 = 10;
const COM_QUERY: u8 = 0x03;
const NATIVE_PLUGIN: &str = "mysql_native_password";
const SCRAMBLE_LEN: usize = 20;

const CLIENT_LONG_PASSWORD: u32 = 0x0000_0001;
const CLIENT_LONG_FLAG: u32 = 0x0000_0004;
const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const CLIENT_TRANSACTIONS: u32 = 0x0000_2000;
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
const CLIENT_DEPRECATE_EOF: u32 = 0x0100_0000;
const HANDSHAKE_REQUIRED: u32 = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH;
const REQUIRED_CAPABILITIES: u32 = CLIENT_LONG_PASSWORD
    | CLIENT_LONG_FLAG
    | CLIENT_CONNECT_WITH_DB
    | CLIENT_PROTOCOL_41
    | CLIENT_TRANSACTIONS
    | CLIENT_SECURE_CONNECTION
    | CLIENT_PLUGIN_AUTH;

const MYSQL_TYPE_TINY: u8 = 1;
const MYSQL_TYPE_SHORT: u8 = 2;
const MYSQL_TYPE_LONG: u8 = 3;
const MYSQL_TYPE_LONGLONG: u8 = 8;
const MYSQL_TYPE_INT24: u8 = 9;
const MYSQL_TYPE_YEAR: u8 = 13;

const MAX_PACKET_LEN: usize = 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_ROWS: usize = 65_536;
const MAX_COLUMNS: usize = 1_600;
const MIN_OK_LEN: usize = 7;
const DEPRECATED_OK_LIMIT: usize = 9;
const EOF_LEN: usize = 5;
const IO_TIMEOUT: Duration = Duration::from_millis(500);

/// A MySQL v10 connection using `COM_QUERY` and text result rows.
#[derive(Debug)]
pub struct MySqlConnection {
    stream: TcpStream,
    handshake: Handshake,
    capabilities: u32,
    sequence: u8,
    broken: bool,
}

#[derive(Debug)]
struct Handshake {
    server_version: String,
    connection_id: u32,
    capabilities: u32,
    charset: u8,
    status: u16,
    plugin: String,
    nonce: [u8; SCRAMBLE_LEN],
}

impl MySqlConnection {
    /// Connect with a `mysql_native_password` HandshakeResponse41.
    pub fn connect(
        host: &str,
        port: u16,
        user: &str,
        password: &str,
        database: &str,
    ) -> Result<MySqlConnection, DbError> {
        let mut stream = connect_stream(host, port)?;
        let deadline = Instant::now() + IO_TIMEOUT;
        let mut sequence = 0u8;
        let mut budget = Budget::default();
        let payload = read_packet(&mut stream, &mut sequence, &mut budget, deadline)?;
        let handshake = parse_handshake(&payload)?;
        let (capabilities, response) = handshake_response(user, password, database, &handshake)?;
        write_packet(&mut stream, &mut sequence, &response, deadline)?;
        let mut connection = MySqlConnection {
            stream,
            handshake,
            capabilities,
            sequence,
            broken: false,
        };
        connection.read_auth_result(&mut budget, deadline)?;
        Ok(connection)
    }

    /// The server version string from the initial handshake.
    pub fn server_version(&self) -> &str {
        &self.handshake.server_version
    }

    /// The connection id from the initial handshake.
    pub fn connection_id(&self) -> u32 {
        self.handshake.connection_id
    }

    /// The capability flags advertised by the server.
    pub fn server_capabilities(&self) -> u32 {
        self.handshake.capabilities
    }

    /// The capability flags this client negotiated.
    pub fn negotiated_capabilities(&self) -> u32 {
        self.capabilities
    }

    /// The character set from the initial handshake.
    pub fn charset(&self) -> u8 {
        self.handshake.charset
    }

    /// The status flags from the initial handshake.
    pub fn status_flags(&self) -> u16 {
        self.handshake.status
    }

    /// The authentication plugin from the initial handshake.
    pub fn auth_plugin(&self) -> &str {
        &self.handshake.plugin
    }

    /// Run `COM_QUERY` and expose its text-format rows.
    pub fn query(&mut self, sql: &str) -> Result<Vec<Row>, DbError> {
        if self.broken {
            return Err(DbError::new(
                "mysql connection is unusable after a protocol error",
            ));
        }
        self.run_query(sql)
    }

    /// Run `COM_QUERY`, discarding any returned rows.
    pub fn exec(&mut self, sql: &str) -> Result<(), DbError> {
        self.query(sql).map(|_| ())
    }

    fn deprecate_eof(&self) -> bool {
        self.capabilities & CLIENT_DEPRECATE_EOF != 0
    }

    fn read_auth_result(&mut self, budget: &mut Budget, deadline: Instant) -> Result<(), DbError> {
        let payload = self.read_packet(budget, deadline)?;
        if is_err(&payload) {
            return self.typed_error(&payload);
        }
        if is_ok(&payload, self.deprecate_eof()) {
            return match parse_ok(&payload, self.deprecate_eof()) {
                Ok(()) => Ok(()),
                Err(error) => self.fail(error.to_string()),
            };
        }
        if is_eof(&payload) {
            return self.fail("mysql server sent EOF before authentication OK");
        }
        if let Some(plugin) = auth_switch_plugin(&payload) {
            return self.fail(format!(
                "UNSUPPORTED: MySQL authentication switch to {plugin:?} is not implemented"
            ));
        }
        self.fail("mysql server did not send OK after authentication")
    }

    fn run_query(&mut self, sql: &str) -> Result<Vec<Row>, DbError> {
        if sql.as_bytes().contains(&0) {
            return Err(DbError::new("mysql SQL contains a NUL byte"));
        }
        let mut payload = Vec::with_capacity(sql.len() + 1);
        payload.push(COM_QUERY);
        payload.extend_from_slice(sql.as_bytes());
        self.sequence = 0;
        let deadline = Instant::now() + IO_TIMEOUT;
        self.write_packet(&payload, deadline)?;
        let mut budget = Budget::default();
        let first = self.read_packet(&mut budget, deadline)?;
        if is_err(&first) {
            return self.typed_error(&first);
        }
        if is_ok(&first, self.deprecate_eof()) {
            return match parse_ok(&first, self.deprecate_eof()) {
                Ok(()) => Ok(Vec::new()),
                Err(error) => self.fail(error.to_string()),
            };
        }
        if is_eof(&first) {
            return self.fail("mysql server sent EOF instead of a COM_QUERY response");
        }
        if auth_switch_plugin(&first).is_some() {
            return self.fail(
                "UNSUPPORTED: MySQL authentication switches during COM_QUERY are not implemented",
            );
        }
        let column_count = match parse_column_count(&first) {
            Ok(count) => count,
            Err(error) => return self.fail(error.to_string()),
        };
        let mut columns = Vec::with_capacity(column_count);
        for _ in 0..column_count {
            let packet = self.read_packet(&mut budget, deadline)?;
            if is_err(&packet) {
                return self.typed_error(&packet);
            }
            if is_eof(&packet) || is_deprecated_ok(&packet, self.deprecate_eof()) {
                return self.fail("mysql result set ended before all column definitions");
            }
            let column = match parse_column_definition(&packet) {
                Ok(column) => column,
                Err(error) => return self.fail(error.to_string()),
            };
            columns.push(column);
        }
        let mut rows = Vec::new();
        loop {
            let packet = self.read_packet(&mut budget, deadline)?;
            if is_err(&packet) {
                return self.typed_error(&packet);
            }
            if is_eof(&packet) {
                if let Err(error) = parse_eof(&packet) {
                    return self.fail(error.to_string());
                }
                break;
            }
            if is_deprecated_ok(&packet, self.deprecate_eof()) {
                if let Err(error) = parse_ok(&packet, self.deprecate_eof()) {
                    return self.fail(error.to_string());
                }
                break;
            }
            if let Err(error) = budget.row() {
                return self.fail(error.to_string());
            }
            let row = match parse_text_row(&packet, &columns) {
                Ok(row) => row,
                Err(error) => return self.fail(error.to_string()),
            };
            rows.push(row);
        }
        Ok(rows)
    }

    fn read_packet(&mut self, budget: &mut Budget, deadline: Instant) -> Result<Vec<u8>, DbError> {
        match read_packet(&mut self.stream, &mut self.sequence, budget, deadline) {
            Ok(payload) => Ok(payload),
            Err(error) => self.fail(error.to_string()),
        }
    }

    fn write_packet(&mut self, payload: &[u8], deadline: Instant) -> Result<(), DbError> {
        match write_packet(&mut self.stream, &mut self.sequence, payload, deadline) {
            Ok(()) => Ok(()),
            Err(error) => self.fail(error.to_string()),
        }
    }

    fn typed_error<T>(&mut self, payload: &[u8]) -> Result<T, DbError> {
        match parse_err(payload, self.capabilities) {
            Ok(error) => Err(error),
            Err(error) => self.fail(error.to_string()),
        }
    }

    fn fail<T>(&mut self, message: impl Into<String>) -> Result<T, DbError> {
        self.broken = true;
        Err(DbError::new(message))
    }
}

impl Database for MySqlConnection {
    fn exec(&mut self, sql: &str) -> Result<(), DbError> {
        MySqlConnection::exec(self, sql)
    }

    fn query(&mut self, sql: &str) -> Result<Vec<Row>, DbError> {
        MySqlConnection::query(self, sql)
    }
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
            .ok_or_else(|| DbError::new("mysql response byte budget overflow"))?;
        if self.bytes > MAX_RESPONSE_BYTES {
            return Err(DbError::new(format!(
                "mysql response exceeds {MAX_RESPONSE_BYTES} bytes"
            )));
        }
        Ok(())
    }

    fn row(&mut self) -> Result<(), DbError> {
        if self.rows >= MAX_ROWS {
            return Err(DbError::new(format!("mysql query exceeds {MAX_ROWS} rows")));
        }
        self.rows += 1;
        Ok(())
    }
}

struct Column {
    name: String,
    type_code: u8,
    column_length: u32,
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

    fn peek(&self) -> Option<u8> {
        self.data.get(self.position).copied()
    }

    fn rest(&mut self) -> Result<&'a [u8], DbError> {
        let bytes = self
            .data
            .get(self.position..)
            .ok_or_else(|| malformed(self.what, "truncated body"))?;
        self.position = self.data.len();
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, DbError> {
        Ok(self.take(1)?[0])
    }

    fn u16_le(&mut self) -> Result<u16, DbError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u32_le(&mut self) -> Result<u32, DbError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
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

    fn lenenc_int(&mut self) -> Result<u64, DbError> {
        let marker = self.u8()?;
        match marker {
            0xfc => {
                let bytes = self.take(2)?;
                Ok(u64::from(u16::from_le_bytes([bytes[0], bytes[1]])))
            }
            0xfd => {
                let bytes = self.take(3)?;
                Ok(u64::from(u32::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], 0,
                ])))
            }
            0xfe => {
                let bytes = self.take(8)?;
                Ok(u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]))
            }
            0xfb | 0xff => Err(malformed(self.what, "invalid length-encoded integer")),
            value => Ok(u64::from(value)),
        }
    }

    fn lenenc_bytes(&mut self) -> Result<Option<&'a [u8]>, DbError> {
        let marker = self.u8()?;
        let length = match marker {
            0xfb => return Ok(None),
            0xfc => {
                let bytes = self.take(2)?;
                usize::from(u16::from_le_bytes([bytes[0], bytes[1]]))
            }
            0xfd => {
                let bytes = self.take(3)?;
                u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]) as usize
            }
            0xfe => {
                let bytes = self.take(8)?;
                let count = u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                if count > MAX_PACKET_LEN as u64 {
                    return Err(malformed(self.what, "length exceeds packet limit"));
                }
                usize::try_from(count)
                    .map_err(|_| malformed(self.what, "length does not fit usize"))?
            }
            0xff => return Err(malformed(self.what, "invalid length-encoded string")),
            value => usize::from(value),
        };
        if length > MAX_PACKET_LEN {
            return Err(malformed(self.what, "length exceeds packet limit"));
        }
        Ok(Some(self.take(length)?))
    }

    fn lenenc_string(&mut self) -> Result<String, DbError> {
        match self.lenenc_bytes()? {
            Some(bytes) => Ok(String::from_utf8_lossy(bytes).into_owned()),
            None => Err(malformed(self.what, "unexpected NULL string")),
        }
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
    DbError::new(format!("malformed mysql {what} packet: {detail}"))
}

fn io_timeout(operation: &str) -> DbError {
    DbError::new(format!(
        "mysql {operation} timed out after {} ms",
        IO_TIMEOUT.as_millis()
    ))
}

fn io_failure(operation: &str, error: io::Error) -> DbError {
    DbError::new(format!("mysql {operation} failed: {error}"))
}

fn read_packet(
    stream: &mut TcpStream,
    sequence: &mut u8,
    budget: &mut Budget,
    deadline: Instant,
) -> Result<Vec<u8>, DbError> {
    let mut header = [0u8; 4];
    read_exact_deadline(stream, &mut header, deadline)?;
    let length =
        usize::from(header[0]) | (usize::from(header[1]) << 8) | (usize::from(header[2]) << 16);
    let seen = header[3];
    if seen != *sequence {
        return Err(DbError::new(format!(
            "mysql packet sequence id {seen} does not match expected {}",
            *sequence
        )));
    }
    *sequence = sequence.wrapping_add(1);
    if length == 0 {
        return Err(DbError::new("mysql packet has an empty payload"));
    }
    if length > MAX_PACKET_LEN {
        return Err(DbError::new(format!(
            "mysql packet length {length} exceeds {MAX_PACKET_LEN}-byte limit"
        )));
    }
    budget.account(4 + length)?;
    let mut payload = vec![0u8; length];
    read_exact_deadline(stream, &mut payload, deadline)?;
    Ok(payload)
}

fn write_packet(
    stream: &mut TcpStream,
    sequence: &mut u8,
    payload: &[u8],
    deadline: Instant,
) -> Result<(), DbError> {
    if payload.is_empty() {
        return Err(DbError::new("mysql command packet has an empty payload"));
    }
    if payload.len() > MAX_PACKET_LEN {
        return Err(DbError::new(format!(
            "mysql command packet exceeds {MAX_PACKET_LEN}-byte limit"
        )));
    }
    let length = payload.len();
    let mut frame = Vec::with_capacity(4 + length);
    frame.push(length as u8);
    frame.push((length >> 8) as u8);
    frame.push((length >> 16) as u8);
    frame.push(*sequence);
    frame.extend_from_slice(payload);
    write_all_deadline(stream, &frame, deadline)?;
    *sequence = sequence.wrapping_add(1);
    Ok(())
}

fn read_exact_deadline(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), DbError> {
    let mut filled = 0;
    while filled < buffer.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io_timeout("read"));
        }
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|error| io_failure("read timeout setup", error))?;
        match stream.read(&mut buffer[filled..]) {
            Ok(0) => {
                return Err(DbError::new(
                    "mysql connection closed while reading a packet (truncated frame)",
                ));
            }
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(io_timeout("read"));
            }
            Err(error) => return Err(io_failure("read", error)),
        }
    }
    Ok(())
}

fn write_all_deadline(
    stream: &mut TcpStream,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), DbError> {
    let mut sent = 0;
    while sent < bytes.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io_timeout("write"));
        }
        stream
            .set_write_timeout(Some(remaining))
            .map_err(|error| io_failure("write timeout setup", error))?;
        match stream.write(&bytes[sent..]) {
            Ok(0) => return Err(DbError::new("mysql write accepted zero bytes")),
            Ok(count) => sent += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(io_timeout("write"));
            }
            Err(error) => return Err(io_failure("write", error)),
        }
    }
    Ok(())
}

fn connect_stream(host: &str, port: u16) -> Result<TcpStream, DbError> {
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|error| DbError::new(format!("mysql address {host}:{port}: {error}")))?;
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
        "mysql connect to {host}:{port} failed: {last_error}"
    )))
}

fn parse_handshake(payload: &[u8]) -> Result<Handshake, DbError> {
    let mut cursor = Cursor::new(payload, "initial handshake");
    let protocol = cursor.u8()?;
    if protocol != PROTOCOL_10 {
        return Err(malformed(
            "initial handshake",
            &format!("protocol {protocol} is not 10"),
        ));
    }
    let server_version = cursor.cstring()?;
    let connection_id = cursor.u32_le()?;
    let part1 = cursor.take(8)?;
    cursor.take(1)?;
    let lower = u32::from(cursor.u16_le()?);
    let charset = cursor.u8()?;
    let status = cursor.u16_le()?;
    let upper = u32::from(cursor.u16_le()?);
    let capabilities = lower | (upper << 16);
    let auth_data_len = cursor.u8()?;
    cursor.take(10)?;
    if capabilities & HANDSHAKE_REQUIRED != HANDSHAKE_REQUIRED {
        return Err(DbError::new(format!(
            "mysql server lacks required capabilities 0x{HANDSHAKE_REQUIRED:08x} (has 0x{capabilities:08x})"
        )));
    }
    let part2_len = usize::from(auth_data_len.saturating_sub(8)).max(13);
    let part2 = cursor.take(part2_len)?;
    let end = part2
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(part2.len());
    let needed = SCRAMBLE_LEN - part1.len();
    if end < needed {
        return Err(malformed("initial handshake", "short auth-plugin-data"));
    }
    let mut nonce = [0u8; SCRAMBLE_LEN];
    nonce[..part1.len()].copy_from_slice(part1);
    nonce[part1.len()..].copy_from_slice(&part2[..needed]);
    let plugin = cursor.cstring()?;
    cursor.done()?;
    if plugin != NATIVE_PLUGIN {
        return Err(DbError::new(format!(
            "UNSUPPORTED: MySQL authentication plugin {plugin:?} is not implemented; only {NATIVE_PLUGIN} is supported"
        )));
    }
    Ok(Handshake {
        server_version,
        connection_id,
        capabilities,
        charset,
        status,
        plugin,
        nonce,
    })
}

fn handshake_response(
    user: &str,
    password: &str,
    database: &str,
    handshake: &Handshake,
) -> Result<(u32, Vec<u8>), DbError> {
    for (name, value) in [
        ("username", user),
        ("password", password),
        ("database", database),
    ] {
        if value.as_bytes().contains(&0) {
            return Err(DbError::new(format!("mysql {name} contains a NUL byte")));
        }
    }
    let mut capabilities = REQUIRED_CAPABILITIES;
    if handshake.capabilities & CLIENT_DEPRECATE_EOF != 0 {
        capabilities |= CLIENT_DEPRECATE_EOF;
    }
    let missing = capabilities & !handshake.capabilities;
    if missing != 0 {
        return Err(DbError::new(format!(
            "mysql server lacks required capabilities 0x{missing:08x}"
        )));
    }
    let scramble = native_password_scramble(password, &handshake.nonce);
    let mut payload = Vec::new();
    payload.extend_from_slice(&capabilities.to_le_bytes());
    payload.extend_from_slice(&(MAX_PACKET_LEN as u32).to_le_bytes());
    payload.push(handshake.charset);
    payload.extend_from_slice(&[0u8; 23]);
    payload.extend_from_slice(user.as_bytes());
    payload.push(0);
    payload.push(scramble.len() as u8);
    payload.extend_from_slice(&scramble);
    payload.extend_from_slice(database.as_bytes());
    payload.push(0);
    payload.extend_from_slice(NATIVE_PLUGIN.as_bytes());
    payload.push(0);
    // shortcut: no TLS negotiation; CLIENT_SSL is never set, add TLS in R9+.
    Ok((capabilities, payload))
}

fn native_password_scramble(password: &str, nonce: &[u8; SCRAMBLE_LEN]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let stage1 = sha1(password.as_bytes());
    let stage2 = sha1(&stage1);
    let mut combined = Vec::with_capacity(nonce.len() + stage2.len());
    combined.extend_from_slice(nonce);
    combined.extend_from_slice(&stage2);
    let stage3 = sha1(&combined);
    stage1
        .iter()
        .zip(stage3.iter())
        .map(|(left, right)| *left ^ *right)
        .collect()
}

fn sha1(data: &[u8]) -> [u8; SCRAMBLE_LEN] {
    let mut state = [
        0x6745_2301u32,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let bit_len = (data.len() as u64) * 8;
    let mut padded = Vec::with_capacity(((data.len() + 9 + 63) / 64) * 64);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for block in padded.chunks_exact(64) {
        let mut words = [0u32; 80];
        for (index, word) in words.iter_mut().enumerate().take(16) {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
            ]);
        }
        for index in 16..80 {
            words[index] =
                (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                    .rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) =
            (state[0], state[1], state[2], state[3], state[4]);
        for (index, word) in words.iter().enumerate() {
            let (function, constant) = match index {
                0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(function)
                .wrapping_add(e)
                .wrapping_add(constant)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }
    let mut digest = [0u8; SCRAMBLE_LEN];
    for (index, word) in state.iter().enumerate() {
        let offset = index * 4;
        digest[offset..offset + 4].copy_from_slice(&(*word).to_be_bytes());
    }
    digest
}

fn is_err(payload: &[u8]) -> bool {
    payload.first() == Some(&0xff)
}

fn is_eof(payload: &[u8]) -> bool {
    payload.len() == EOF_LEN && payload.first() == Some(&0xfe)
}

fn is_deprecated_ok(payload: &[u8], deprecate_eof: bool) -> bool {
    deprecate_eof
        && payload.first() == Some(&0xfe)
        && payload.len() >= MIN_OK_LEN
        && payload.len() < DEPRECATED_OK_LIMIT
}

fn is_ok(payload: &[u8], deprecate_eof: bool) -> bool {
    (payload.first() == Some(&0x00) && payload.len() >= MIN_OK_LEN)
        || is_deprecated_ok(payload, deprecate_eof)
}

fn parse_ok(payload: &[u8], deprecate_eof: bool) -> Result<(), DbError> {
    if payload.len() < MIN_OK_LEN {
        return Err(malformed("OK", "short body"));
    }
    let header = payload[0];
    let deprecated = header == 0xfe
        && deprecate_eof
        && payload.len() >= MIN_OK_LEN
        && payload.len() < DEPRECATED_OK_LIMIT;
    if header != 0x00 && !deprecated {
        return Err(malformed("OK", "invalid header"));
    }
    let mut cursor = Cursor::new(payload, "OK");
    let _header = cursor.u8()?;
    let _affected_rows = cursor.lenenc_int()?;
    let _last_insert_id = cursor.lenenc_int()?;
    let _status = cursor.u16_le()?;
    let _warnings = cursor.u16_le()?;
    Ok(())
}

fn parse_eof(payload: &[u8]) -> Result<(), DbError> {
    if payload.len() != EOF_LEN {
        return Err(malformed("EOF", "invalid body length"));
    }
    let mut cursor = Cursor::new(payload, "EOF");
    if cursor.u8()? != 0xfe {
        return Err(malformed("EOF", "invalid header"));
    }
    let _warnings = cursor.u16_le()?;
    let _status = cursor.u16_le()?;
    cursor.done()?;
    Ok(())
}

fn parse_err(payload: &[u8], capabilities: u32) -> Result<DbError, DbError> {
    let mut cursor = Cursor::new(payload, "ERR");
    if cursor.u8()? != 0xff {
        return Err(malformed("ERR", "invalid header"));
    }
    let code = cursor.u16_le()?;
    let mut sqlstate = None;
    if capabilities & CLIENT_PROTOCOL_41 != 0 && cursor.peek() == Some(b'#') {
        cursor.take(1)?;
        let state = cursor.take(5)?;
        sqlstate = Some(String::from_utf8_lossy(state).into_owned());
    }
    let message = String::from_utf8_lossy(cursor.rest()?).into_owned();
    let mut text = format!("mysql ERROR {code}");
    if let Some(state) = sqlstate.as_deref() {
        text.push_str(&format!(" [SQLSTATE {state}]"));
    }
    text.push_str(&format!(
        " {}: {message}",
        MySqlErrorKind::from_code(code).label()
    ));
    Ok(DbError::with_mysql_error(code, sqlstate.as_deref(), text))
}

fn auth_switch_plugin(payload: &[u8]) -> Option<String> {
    if payload.first() != Some(&0xfe) || payload.len() < DEPRECATED_OK_LIMIT {
        return None;
    }
    let rest = &payload[1..];
    let end = rest
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(rest.len());
    Some(String::from_utf8_lossy(&rest[..end]).into_owned())
}

fn parse_column_count(payload: &[u8]) -> Result<usize, DbError> {
    let mut cursor = Cursor::new(payload, "column count");
    let count = cursor.lenenc_int()?;
    cursor.done()?;
    if count == 0 || count > MAX_COLUMNS as u64 {
        return Err(malformed(
            "column count",
            &format!("count {count} exceeds the 1..{MAX_COLUMNS} limit"),
        ));
    }
    Ok(count as usize)
}

fn parse_column_definition(payload: &[u8]) -> Result<Column, DbError> {
    let mut cursor = Cursor::new(payload, "column definition");
    let _catalog = cursor.lenenc_string()?;
    let _schema = cursor.lenenc_string()?;
    let _table = cursor.lenenc_string()?;
    let _org_table = cursor.lenenc_string()?;
    let name = cursor.lenenc_string()?;
    let org_name = cursor.lenenc_string()?;
    let fixed_len = cursor.lenenc_int()?;
    if fixed_len != 0x0c {
        return Err(malformed("column definition", "invalid fixed-field length"));
    }
    let _charset = cursor.u16_le()?;
    let column_length = cursor.u32_le()?;
    let type_code = cursor.u8()?;
    let _flags = cursor.u16_le()?;
    let _decimals = cursor.u8()?;
    cursor.take(2)?;
    cursor.done()?;
    let name = if name.is_empty() { org_name } else { name };
    Ok(Column {
        name,
        type_code,
        column_length,
    })
}

fn parse_text_row(payload: &[u8], columns: &[Column]) -> Result<Row, DbError> {
    let mut cursor = Cursor::new(payload, "text row");
    let mut row = Row::new();
    for (index, column) in columns.iter().enumerate() {
        let Some(bytes) = cursor.lenenc_bytes()? else {
            continue;
        };
        let text = String::from_utf8_lossy(bytes).into_owned();
        let value = text_value(column, &text);
        let name = if column.name.is_empty() {
            format!("column{index}")
        } else {
            column.name.clone()
        };
        row.set(name, value);
    }
    cursor.done()?;
    Ok(row)
}

fn text_value(column: &Column, text: &str) -> Value {
    match column.type_code {
        MYSQL_TYPE_TINY if column.column_length == 1 => match text {
            "1" => Value::Bool(true),
            "0" => Value::Bool(false),
            _ => Value::Text(text.to_string()),
        },
        MYSQL_TYPE_TINY | MYSQL_TYPE_SHORT | MYSQL_TYPE_LONG | MYSQL_TYPE_LONGLONG
        | MYSQL_TYPE_INT24 | MYSQL_TYPE_YEAR => text
            .parse::<i64>()
            .map(Value::Int)
            .unwrap_or_else(|_| Value::Text(text.to_string())),
        _ => Value::Text(text.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn sha1_known_answer_vectors() {
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(&sha1(b"The quick brown fox jumps over the lazy dog")),
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        );
    }

    #[test]
    fn sha1_pads_multiblock_inputs() {
        let boundary = vec![b'a'; 64];
        let million = vec![b'a'; 1_000_000];
        assert_eq!(
            hex(&sha1(&boundary)),
            "0098ba824b5c16427bd7a1122a5a442a25ec644d"
        );
        assert_eq!(
            hex(&sha1(&million)),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }

    #[test]
    fn native_password_scramble_uses_standard_xor() {
        let nonce = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ];
        assert_eq!(
            hex(&native_password_scramble("secret", &nonce)),
            "b32bb3a583e1340c0a1108d58b1be49781ad8c2f"
        );
        assert!(native_password_scramble("", &nonce).is_empty());
    }

    #[test]
    fn mysql_error_kinds_map_known_codes() {
        assert_eq!(MySqlErrorKind::from_code(1064), MySqlErrorKind::Syntax);
        assert_eq!(
            MySqlErrorKind::from_code(1146),
            MySqlErrorKind::TableNotFound
        );
        assert_eq!(
            MySqlErrorKind::from_code(1062),
            MySqlErrorKind::DuplicateEntry
        );
        assert_eq!(
            MySqlErrorKind::from_code(1045),
            MySqlErrorKind::AccessDenied
        );
        assert_eq!(MySqlErrorKind::from_code(9999), MySqlErrorKind::Other);
        assert_eq!(MySqlErrorKind::Syntax.label(), "syntax error");
    }
}
