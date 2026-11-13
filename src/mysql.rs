//! Pure-std MySQL protocol v10 frontend.
//!
//! This driver speaks plain TCP protocol 10, `mysql_native_password`,
//! `caching_sha2_password`, `COM_QUERY`, `COM_STMT_PREPARE` and
//! `COM_STMT_EXECUTE`. It rejects TLS negotiation, binary result decoding,
//! connection pooling and oversized or out-of-sequence packets instead of
//! guessing.

use crate::mysql_crypto::{encrypt_oaep_sha1, parse_spki_pem, sha1, sha256};
use crate::{Database, DbError, MySqlErrorKind, Row, Value};
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

const PROTOCOL_10: u8 = 10;
const COM_QUERY: u8 = 0x03;
const COM_STMT_PREPARE: u8 = 0x16;
const COM_STMT_EXECUTE: u8 = 0x17;
const NATIVE_PLUGIN: &str = "mysql_native_password";
const CACHING_PLUGIN: &str = "caching_sha2_password";
const SCRAMBLE_LEN: usize = 20;
const AUTH_MORE_DATA: u8 = 0x01;
const REQUEST_PUBLIC_KEY: u8 = 0x02;
const FAST_AUTH_SUCCESS: u8 = 0x03;
const PERFORM_FULL_AUTH: u8 = 0x04;

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
const MYSQL_TYPE_STRING: u8 = 0xfe;

const MAX_PACKET_LEN: usize = 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_ROWS: usize = 65_536;
const MAX_COLUMNS: usize = 1_600;
const MAX_STMT_PARAMS: usize = 1_024;
const MAX_STMT_VALUE_BYTES: usize = 64 * 1024;
const MAX_AUTH_PACKETS: usize = 8;
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

/// The identifiers and counts from a `COM_STMT_PREPARE` OK packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MySqlStatement {
    id: u32,
    column_count: u16,
    param_count: u16,
    warning_count: u16,
}

impl MySqlStatement {
    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn column_count(&self) -> u16 {
        self.column_count
    }

    pub fn param_count(&self) -> u16 {
        self.param_count
    }

    pub fn warning_count(&self) -> u16 {
        self.warning_count
    }
}

impl MySqlConnection {
    /// Connect with a HandshakeResponse41 for either supported auth plugin.
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
        connection.read_auth_result(&mut budget, password)?;
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

    /// Send `COM_STMT_PREPARE` and parse its bounded prepare-OK metadata.
    pub fn prepare(&mut self, sql: &str) -> Result<MySqlStatement, DbError> {
        if self.broken {
            return Err(DbError::new(
                "mysql connection is unusable after a protocol error",
            ));
        }
        self.run_prepare(sql)
    }

    /// Send `COM_STMT_EXECUTE`; binary result rows are consumed but not decoded.
    pub fn execute_stmt(
        &mut self,
        statement: MySqlStatement,
        params: &[Value],
    ) -> Result<(), DbError> {
        if self.broken {
            return Err(DbError::new(
                "mysql connection is unusable after a protocol error",
            ));
        }
        self.run_stmt_execute(statement, params)
    }

    fn deprecate_eof(&self) -> bool {
        self.capabilities & CLIENT_DEPRECATE_EOF != 0
    }

    fn read_auth_result(&mut self, budget: &mut Budget, password: &str) -> Result<(), DbError> {
        for _ in 0..MAX_AUTH_PACKETS {
            let payload = self.read_packet(budget, Instant::now() + IO_TIMEOUT)?;
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
            if let Some(status) = auth_more_status(&payload) {
                match status {
                    FAST_AUTH_SUCCESS => continue,
                    PERFORM_FULL_AUTH => {
                        if self.handshake.plugin != CACHING_PLUGIN {
                            return self.fail(
                                "UNSUPPORTED: MySQL full authentication is only valid for caching_sha2_password",
                            );
                        }
                        let nonce = self.handshake.nonce;
                        self.full_auth(password, &nonce, budget)?;
                        continue;
                    }
                    other => {
                        return self.fail(format!(
                            "UNSUPPORTED: MySQL AuthMoreData status 0x{other:02x} is not implemented"
                        ));
                    }
                }
            }
            if let Some(switch) = parse_auth_switch(&payload)? {
                let response = match auth_response(&switch.plugin, password, &switch.nonce) {
                    Ok(response) => response,
                    Err(error) => return self.fail(error.to_string()),
                };
                self.handshake.plugin = switch.plugin;
                self.handshake.nonce = switch.nonce;
                self.write_packet(&response, Instant::now() + IO_TIMEOUT)?;
                continue;
            }
            return self.fail("mysql server did not send OK after authentication");
        }
        self.fail("mysql authentication exceeded the bounded packet exchange")
    }

    fn full_auth(
        &mut self,
        password: &str,
        nonce: &[u8; SCRAMBLE_LEN],
        budget: &mut Budget,
    ) -> Result<(), DbError> {
        if password.is_empty() {
            return self.fail(
                "UNSUPPORTED: MySQL caching_sha2_password full authentication with an empty password is not implemented",
            );
        }
        self.write_packet(&[REQUEST_PUBLIC_KEY], Instant::now() + IO_TIMEOUT)?;
        let key_packet = self.read_packet(budget, Instant::now() + IO_TIMEOUT)?;
        if is_err(&key_packet) {
            return self.typed_error(&key_packet);
        }
        let mut pem = if key_packet.starts_with(b"-----BEGIN") {
            key_packet
        } else if key_packet.first() == Some(&AUTH_MORE_DATA) && key_packet.len() > 1 {
            key_packet[1..].to_vec()
        } else {
            return self.fail("mysql server did not send an AuthMoreData RSA public-key PEM");
        };
        while pem.last() == Some(&0) {
            pem.pop();
        }
        let key = match parse_spki_pem(&pem) {
            Ok(key) => key,
            Err(error) => return self.fail(rsa_error(error)),
        };
        let message = full_auth_message(password, nonce);
        let ciphertext = match encrypt_oaep_sha1(&key, &message) {
            Ok(ciphertext) => ciphertext,
            Err(error) => return self.fail(rsa_error(error)),
        };
        self.write_packet(&ciphertext, Instant::now() + IO_TIMEOUT)?;
        Ok(())
    }

    fn start_command(&mut self, payload: &[u8], deadline: Instant) -> Result<Budget, DbError> {
        self.sequence = 0;
        self.write_packet(payload, deadline)?;
        Ok(Budget::default())
    }

    fn run_prepare(&mut self, sql: &str) -> Result<MySqlStatement, DbError> {
        if sql.as_bytes().contains(&0) {
            return Err(DbError::new("mysql SQL contains a NUL byte"));
        }
        let mut payload = Vec::with_capacity(sql.len() + 1);
        payload.push(COM_STMT_PREPARE);
        payload.extend_from_slice(sql.as_bytes());
        let deadline = Instant::now() + IO_TIMEOUT;
        let mut budget = self.start_command(&payload, deadline)?;
        let first = self.read_packet(&mut budget, deadline)?;
        if is_err(&first) {
            return self.typed_error(&first);
        }
        let statement = match parse_prepare_ok(&first) {
            Ok(statement) => statement,
            Err(error) => return self.fail(error.to_string()),
        };
        self.read_metadata(
            usize::from(statement.param_count),
            "parameter",
            &mut budget,
            deadline,
        )?;
        self.read_metadata(
            usize::from(statement.column_count),
            "column",
            &mut budget,
            deadline,
        )?;
        Ok(statement)
    }

    fn run_stmt_execute(
        &mut self,
        statement: MySqlStatement,
        params: &[Value],
    ) -> Result<(), DbError> {
        let payload = build_stmt_execute(statement, params)?;
        let deadline = Instant::now() + IO_TIMEOUT;
        let mut budget = self.start_command(&payload, deadline)?;
        let first = self.read_packet(&mut budget, deadline)?;
        if is_err(&first) {
            return self.typed_error(&first);
        }
        if is_ok(&first, self.deprecate_eof()) {
            return match parse_ok(&first, self.deprecate_eof()) {
                Ok(()) => Ok(()),
                Err(error) => self.fail(error.to_string()),
            };
        }
        if is_eof(&first) {
            return self.fail("mysql server sent EOF instead of a COM_STMT_EXECUTE response");
        }
        if auth_switch_plugin(&first).is_some() {
            return self.fail(
                "UNSUPPORTED: MySQL authentication switches during COM_STMT_EXECUTE are not implemented",
            );
        }
        let columns = self.read_result_columns(&first, &mut budget, deadline)?;
        let null_bitmap_len = columns
            .len()
            .checked_add(9)
            .ok_or_else(|| DbError::new("mysql binary row column count overflow"))?
            / 8;
        let mut saw_binary_row = false;
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
            if packet.first() != Some(&0x00) || packet.len() <= 1 + null_bitmap_len {
                return self.fail("malformed mysql binary result row packet: invalid header");
            }
            if let Err(error) = budget.row() {
                return self.fail(error.to_string());
            }
            saw_binary_row = true;
        }
        if saw_binary_row {
            Err(DbError::new(
                "UNSUPPORTED: MySQL binary protocol result decoding is not implemented",
            ))
        } else {
            Ok(())
        }
    }

    fn read_metadata(
        &mut self,
        count: usize,
        what: &'static str,
        budget: &mut Budget,
        deadline: Instant,
    ) -> Result<(), DbError> {
        if count == 0 {
            return Ok(());
        }
        for _ in 0..count {
            let packet = self.read_packet(budget, deadline)?;
            if is_err(&packet) {
                return self.typed_error(&packet);
            }
            if is_eof(&packet) || is_deprecated_ok(&packet, self.deprecate_eof()) {
                return self.fail(format!(
                    "mysql {what} metadata ended before all definitions"
                ));
            }
            if let Err(error) = parse_column_definition(&packet) {
                return self.fail(error.to_string());
            }
        }
        self.read_metadata_end(budget, deadline, what)
    }

    fn read_metadata_end(
        &mut self,
        budget: &mut Budget,
        deadline: Instant,
        what: &'static str,
    ) -> Result<(), DbError> {
        let packet = self.read_packet(budget, deadline)?;
        if is_err(&packet) {
            return self.typed_error(&packet);
        }
        if is_eof(&packet) {
            if let Err(error) = parse_eof(&packet) {
                return self.fail(error.to_string());
            }
            return Ok(());
        }
        if is_deprecated_ok(&packet, self.deprecate_eof()) {
            if let Err(error) = parse_ok(&packet, self.deprecate_eof()) {
                return self.fail(error.to_string());
            }
            return Ok(());
        }
        self.fail(format!("mysql {what} metadata did not end with EOF/OK"))
    }

    fn read_result_columns(
        &mut self,
        first: &[u8],
        budget: &mut Budget,
        deadline: Instant,
    ) -> Result<Vec<Column>, DbError> {
        let count = match parse_column_count(first) {
            Ok(count) => count,
            Err(error) => return self.fail(error.to_string()),
        };
        let mut columns = Vec::with_capacity(count);
        for _ in 0..count {
            let packet = self.read_packet(budget, deadline)?;
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
        self.read_metadata_end(budget, deadline, "result column")?;
        Ok(columns)
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
    if plugin != NATIVE_PLUGIN && plugin != CACHING_PLUGIN {
        return Err(DbError::new(format!(
            "UNSUPPORTED: MySQL authentication plugin {plugin:?} is not implemented; only {NATIVE_PLUGIN} and {CACHING_PLUGIN} are supported"
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
    let scramble = auth_response(&handshake.plugin, password, &handshake.nonce)?;
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
    payload.extend_from_slice(handshake.plugin.as_bytes());
    payload.push(0);
    // shortcut: no TLS negotiation; CLIENT_SSL is never set, add TLS in R11+.
    Ok((capabilities, payload))
}

fn auth_response(
    plugin: &str,
    password: &str,
    nonce: &[u8; SCRAMBLE_LEN],
) -> Result<Vec<u8>, DbError> {
    match plugin {
        NATIVE_PLUGIN => Ok(native_password_scramble(password, nonce)),
        CACHING_PLUGIN => Ok(caching_sha2_scramble(password, nonce)),
        other => Err(DbError::new(format!(
            "UNSUPPORTED: MySQL authentication plugin {other:?} is not implemented"
        ))),
    }
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

/// MySQL 8.0 fast auth: `XOR(SHA256(p), SHA256(SHA256(SHA256(p)) || nonce))`.
fn caching_sha2_scramble(password: &str, nonce: &[u8; SCRAMBLE_LEN]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let stage1 = sha256(password.as_bytes());
    let stage2 = sha256(&stage1);
    let stage3 = sha256(&stage2);
    let mut combined = Vec::with_capacity(stage3.len() + nonce.len());
    combined.extend_from_slice(&stage3);
    combined.extend_from_slice(nonce);
    let response = sha256(&combined);
    stage1
        .iter()
        .zip(response.iter())
        .map(|(left, right)| left ^ right)
        .collect()
}

/// Full auth encrypts a NUL-terminated password whose bytes are XORed with the nonce.
fn full_auth_message(password: &str, nonce: &[u8; SCRAMBLE_LEN]) -> Vec<u8> {
    let mut message = Vec::with_capacity(password.len() + 1);
    for (index, byte) in password.as_bytes().iter().enumerate() {
        message.push(*byte ^ nonce[index % SCRAMBLE_LEN]);
    }
    message.push(0);
    message
}

fn rsa_error(error: String) -> String {
    if error.starts_with("UNSUPPORTED:") {
        error
    } else {
        format!("mysql RSA full authentication failed: {error}")
    }
}

fn auth_more_status(payload: &[u8]) -> Option<u8> {
    (payload.len() == 2 && payload[0] == AUTH_MORE_DATA).then_some(payload[1])
}

struct AuthSwitch {
    plugin: String,
    nonce: [u8; SCRAMBLE_LEN],
}

fn parse_auth_switch(payload: &[u8]) -> Result<Option<AuthSwitch>, DbError> {
    if payload.first() != Some(&0xfe) || payload.len() < DEPRECATED_OK_LIMIT {
        return Ok(None);
    }
    let mut cursor = Cursor::new(payload, "AuthSwitchRequest");
    let _status = cursor.u8()?;
    let plugin = cursor.cstring()?;
    let rest = cursor.rest()?;
    let nonce_bytes = if rest.last() == Some(&0) {
        &rest[..rest.len() - 1]
    } else {
        rest
    };
    if nonce_bytes.len() != SCRAMBLE_LEN {
        return Err(malformed(
            "AuthSwitchRequest",
            "auth data is not a 20-byte nonce",
        ));
    }
    let mut nonce = [0u8; SCRAMBLE_LEN];
    nonce.copy_from_slice(nonce_bytes);
    Ok(Some(AuthSwitch { plugin, nonce }))
}

fn parse_prepare_ok(payload: &[u8]) -> Result<MySqlStatement, DbError> {
    let mut cursor = Cursor::new(payload, "prepare OK");
    if cursor.u8()? != 0x00 {
        return Err(malformed("prepare OK", "invalid header"));
    }
    let id = cursor.u32_le()?;
    let column_count = cursor.u16_le()?;
    let param_count = cursor.u16_le()?;
    if cursor.u8()? != 0 {
        return Err(malformed("prepare OK", "nonzero filler"));
    }
    let warning_count = cursor.u16_le()?;
    cursor.done()?;
    if usize::from(column_count) > MAX_COLUMNS {
        return Err(malformed(
            "prepare OK",
            &format!("column count exceeds {MAX_COLUMNS}"),
        ));
    }
    if usize::from(param_count) > MAX_STMT_PARAMS {
        return Err(malformed(
            "prepare OK",
            &format!("parameter count exceeds {MAX_STMT_PARAMS}"),
        ));
    }
    Ok(MySqlStatement {
        id,
        column_count,
        param_count,
        warning_count,
    })
}

fn build_stmt_execute(statement: MySqlStatement, params: &[Value]) -> Result<Vec<u8>, DbError> {
    let count = usize::from(statement.param_count);
    if count != params.len() {
        return Err(DbError::new(format!(
            "mysql statement expects {} parameters but received {}",
            count,
            params.len()
        )));
    }
    if count > MAX_STMT_PARAMS {
        return Err(DbError::new(format!(
            "mysql statement parameter count exceeds {MAX_STMT_PARAMS}"
        )));
    }
    let mut encoded = Vec::with_capacity(count);
    for param in params {
        let item = match param {
            Value::Int(number) => (MYSQL_TYPE_LONGLONG, 0u8, number.to_le_bytes().to_vec()),
            Value::Bool(flag) => (MYSQL_TYPE_TINY, 0u8, vec![u8::from(*flag)]),
            Value::Text(text) => {
                let bytes = text.as_bytes();
                if bytes.len() > MAX_STMT_VALUE_BYTES {
                    return Err(DbError::new(format!(
                        "mysql statement value exceeds {MAX_STMT_VALUE_BYTES} bytes"
                    )));
                }
                let mut value = Vec::with_capacity(bytes.len() + 3);
                push_lenenc_int(&mut value, bytes.len())?;
                value.extend_from_slice(bytes);
                (MYSQL_TYPE_STRING, 0u8, value)
            }
        };
        encoded.push(item);
    }
    let null_bitmap_len = count.saturating_add(7) / 8;
    let mut total = 1usize + 4 + 1 + 4;
    if count > 0 {
        total = total
            .checked_add(null_bitmap_len)
            .and_then(|total| total.checked_add(1))
            .and_then(|total| total.checked_add(count.saturating_mul(2)))
            .ok_or_else(|| DbError::new("mysql statement execute length overflow"))?;
        for (_, _, value) in &encoded {
            total = total
                .checked_add(value.len())
                .ok_or_else(|| DbError::new("mysql statement execute length overflow"))?;
        }
    }
    if total > MAX_PACKET_LEN {
        return Err(DbError::new(format!(
            "mysql command packet exceeds {MAX_PACKET_LEN}-byte limit"
        )));
    }
    let mut payload = Vec::with_capacity(total);
    payload.push(COM_STMT_EXECUTE);
    payload.extend_from_slice(&statement.id.to_le_bytes());
    payload.push(0);
    payload.extend_from_slice(&1u32.to_le_bytes());
    if count > 0 {
        payload.extend(std::iter::repeat_n(0u8, null_bitmap_len));
        payload.push(1);
        for (type_code, flags, _) in &encoded {
            payload.push(*type_code);
            payload.push(*flags);
        }
        for (_, _, value) in &encoded {
            payload.extend_from_slice(value);
        }
    }
    Ok(payload)
}

fn push_lenenc_int(output: &mut Vec<u8>, value: usize) -> Result<(), DbError> {
    if value < 0xfb {
        output.push(value as u8);
    } else if value <= 0xffff {
        output.push(0xfc);
        output.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xff_ffff {
        output.push(0xfd);
        output.extend_from_slice(&(value as u32).to_le_bytes()[..3]);
    } else {
        return Err(DbError::new(
            "mysql statement value length exceeds the length-encoded integer bound",
        ));
    }
    Ok(())
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
    use crate::mysql_crypto::{
        decrypt_oaep_sha1, encrypt_oaep_sha1_with_seed, TEST_MODULUS_HEX, TEST_OAEP_CIPHERTEXT_HEX,
        TEST_OAEP_SEED, TEST_PRIVATE_EXPONENT_HEX, TEST_PUBLIC_KEY_PEM,
    };

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn hex_bytes(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }

    fn nonce() -> [u8; SCRAMBLE_LEN] {
        [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ]
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

    #[test]
    fn caching_sha2_sha256_known_answer_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(b"The quick brown fox jumps over the lazy dog")),
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        );
        assert_eq!(
            hex(&sha256(&vec![b'a'; 64])),
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
        );
        assert_eq!(
            hex(&sha256(&vec![b'a'; 1_000_000])),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn caching_sha2_fast_scramble_known_answer_vectors() {
        assert_eq!(
            hex(&caching_sha2_scramble("secret", &nonce())),
            "33f3676ed12f11181e3898714922b5fc3aea77f11729a61eaf781b56a306b82b"
        );
        assert!(caching_sha2_scramble("", &nonce()).is_empty());
    }

    #[test]
    fn caching_sha2_oaep_sha1_known_answer_vector() {
        let key = parse_spki_pem(TEST_PUBLIC_KEY_PEM.as_bytes())
            .expect("test SPKI RSA public key must parse");
        let message = full_auth_message("secret", &nonce());
        assert_eq!(hex(&message), "72676076607200");
        let ciphertext = encrypt_oaep_sha1_with_seed(&key, &message, &TEST_OAEP_SEED)
            .expect("fixed-seed RSA-OAEP encryption must succeed");
        assert_eq!(hex(&ciphertext), TEST_OAEP_CIPHERTEXT_HEX);
        let decrypted = decrypt_oaep_sha1(
            &ciphertext,
            &hex_bytes(TEST_MODULUS_HEX),
            &hex_bytes(TEST_PRIVATE_EXPONENT_HEX),
        )
        .expect("RSA-OAEP private-key decryption must succeed");
        assert_eq!(decrypted, message);
    }

    #[test]
    fn stmt_prepare_execute_framing_is_bounded() {
        let statement = MySqlStatement {
            id: 7,
            column_count: 0,
            param_count: 2,
            warning_count: 0,
        };
        let payload = build_stmt_execute(statement, &[Value::Int(7), Value::Text("x".to_string())])
            .expect("bounded statement execute frame must build");
        let mut expected = vec![COM_STMT_EXECUTE];
        expected.extend_from_slice(&7u32.to_le_bytes());
        expected.push(0);
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(&[0, 1, MYSQL_TYPE_LONGLONG, 0, MYSQL_TYPE_STRING, 0]);
        expected.extend_from_slice(&7i64.to_le_bytes());
        expected.extend_from_slice(&[1, b'x']);
        assert_eq!(payload, expected);

        let mismatch = build_stmt_execute(statement, &[Value::Int(7)]).unwrap_err();
        assert!(
            mismatch.to_string().contains("expects 2 parameters"),
            "{mismatch}"
        );
        let oversized = build_stmt_execute(
            statement,
            &[
                Value::Int(7),
                Value::Text("x".repeat(MAX_STMT_VALUE_BYTES + 1)),
            ],
        )
        .unwrap_err();
        assert!(oversized.to_string().contains("exceeds"), "{oversized}");
        let too_many = MySqlStatement {
            param_count: (MAX_STMT_PARAMS + 1) as u16,
            ..statement
        };
        let params = vec![Value::Int(1); MAX_STMT_PARAMS + 1];
        let count_error = build_stmt_execute(too_many, &params).unwrap_err();
        assert!(count_error.to_string().contains("exceeds"), "{count_error}");
    }
}
