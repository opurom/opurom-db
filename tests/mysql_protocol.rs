#[path = "../src/mysql_crypto.rs"]
mod mysql_crypto;

use opurom_db::{Database, MySqlConnection, MySqlErrorKind, Row, Value};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAX_PACKET_LEN: usize = 1024 * 1024;
const MAX_WIRE_PACKET: usize = 0xff_ffff;
const MAX_TEST_FRAME: usize = 16 * 1024 * 1024;
const NATIVE_PLUGIN: &str = "mysql_native_password";
const CACHING_PLUGIN: &str = "caching_sha2_password";
const UNSUPPORTED_PLUGIN: &str = "unknown_auth_plugin";
const COM_STMT_PREPARE: u8 = 0x16;
const COM_STMT_EXECUTE: u8 = 0x17;
const EXPECTED_SCRAMBLE: &str = "b32bb3a583e1340c0a1108d58b1be49781ad8c2f";
const EXPECTED_CACHING_SCRAMBLE: &str =
    "33f3676ed12f11181e3898714922b5fc3aea77f11729a61eaf781b56a306b82b";
const NONCE: [u8; 20] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
];

const CLIENT_LONG_PASSWORD: u32 = 0x0000_0001;
const CLIENT_LONG_FLAG: u32 = 0x0000_0004;
const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const CLIENT_TRANSACTIONS: u32 = 0x0000_2000;
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
const CLIENT_DEPRECATE_EOF: u32 = 0x0100_0000;
const REQUIRED_CLIENT_CAPS: u32 = CLIENT_LONG_PASSWORD
    | CLIENT_LONG_FLAG
    | CLIENT_CONNECT_WITH_DB
    | CLIENT_PROTOCOL_41
    | CLIENT_TRANSACTIONS
    | CLIENT_SECURE_CONNECTION
    | CLIENT_PLUGIN_AUTH;
const SERVER_CAPS: u32 = REQUIRED_CLIENT_CAPS;
const SERVER_CAPS_DEPRECATED: u32 = SERVER_CAPS | CLIENT_DEPRECATE_EOF;

const TYPE_TINY: u8 = 1;
const TYPE_LONG: u8 = 3;
const TYPE_LONGLONG: u8 = 8;
const TYPE_VARCHAR: u8 = 253;
const TYPE_STRING: u8 = 0xfe;

#[derive(Default)]
struct Captured {
    handshake_response: Vec<u8>,
    queries: Vec<Vec<u8>>,
}

struct Scenario {
    initial: Vec<u8>,
    auth_reply: Vec<u8>,
    query_replies: Vec<Vec<u8>>,
    read_response: bool,
}

fn scenario(initial: Vec<u8>, auth_reply: Vec<u8>, query_replies: Vec<Vec<u8>>) -> Scenario {
    Scenario {
        initial,
        auth_reply,
        query_replies,
        read_response: true,
    }
}

fn one_shot(initial: Vec<u8>) -> Scenario {
    Scenario {
        initial,
        auth_reply: Vec::new(),
        query_replies: Vec::new(),
        read_response: false,
    }
}

struct MockServer {
    address: SocketAddr,
    handle: Option<JoinHandle<Captured>>,
}

impl MockServer {
    fn spawn(scenario: Scenario) -> MockServer {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let accept_deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        break stream;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if Instant::now() >= accept_deadline {
                            return Captured::default();
                        }
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => return Captured::default(),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut captured = Captured::default();
            if stream.write_all(&scenario.initial).is_err() {
                return captured;
            }
            if !scenario.read_response {
                return captured;
            }
            match read_frame(&mut stream) {
                Ok(frame) => captured.handshake_response = frame,
                Err(_) => return captured,
            }
            if !scenario.auth_reply.is_empty() && stream.write_all(&scenario.auth_reply).is_err() {
                return captured;
            }
            for reply in scenario.query_replies {
                match read_frame(&mut stream) {
                    Ok(frame) => captured.queries.push(frame),
                    Err(_) => break,
                }
                if stream.write_all(&reply).is_err() {
                    break;
                }
            }
            captured
        });
        MockServer {
            address,
            handle: Some(handle),
        }
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn finish(mut self) -> Captured {
        let handle = self.handle.take().expect("mock server handle is present");
        handle.join().expect("mock server thread panicked")
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

enum Step {
    Send(Vec<u8>),
    Receive(Option<Vec<u8>>),
}

struct ScriptedServer {
    address: SocketAddr,
    handle: Option<JoinHandle<Vec<Vec<u8>>>>,
}

impl ScriptedServer {
    fn spawn(steps: Vec<Step>) -> ScriptedServer {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let accept_deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        break stream;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if Instant::now() >= accept_deadline {
                            return Vec::new();
                        }
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => return Vec::new(),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut frames = Vec::new();
            for step in steps {
                match step {
                    Step::Send(bytes) => {
                        if stream.write_all(&bytes).is_err() {
                            break;
                        }
                    }
                    Step::Receive(reply) => {
                        match read_frame(&mut stream) {
                            Ok(frame) => frames.push(frame),
                            Err(_) => break,
                        }
                        if let Some(reply) = reply {
                            if stream.write_all(&reply).is_err() {
                                break;
                            }
                        }
                    }
                }
            }
            frames
        });
        ScriptedServer {
            address,
            handle: Some(handle),
        }
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn finish(mut self) -> Vec<Vec<u8>> {
        let handle = self
            .handle
            .take()
            .expect("scripted server handle is present");
        handle.join().expect("scripted server thread panicked")
    }
}

impl Drop for ScriptedServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn read_frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let length =
        usize::from(header[0]) | (usize::from(header[1]) << 8) | (usize::from(header[2]) << 16);
    if length == 0 || length > MAX_TEST_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid MySQL test frame length",
        ));
    }
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body)?;
    let mut frame = header.to_vec();
    frame.extend_from_slice(&body);
    Ok(frame)
}

fn bounded<T: Send + 'static>(label: &str, task: impl FnOnce() -> T + Send + 'static) -> T {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let outcome = catch_unwind(AssertUnwindSafe(task));
        let _ = sender.send(outcome);
    });
    match receiver.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(value)) => value,
        Ok(Err(payload)) => resume_unwind(payload),
        Err(_) => panic!("{label} hung"),
    }
}

fn packet(sequence: u8, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= MAX_WIRE_PACKET, "wire packet is too long");
    let length = payload.len();
    let mut frame = vec![
        length as u8,
        (length >> 8) as u8,
        (length >> 16) as u8,
        sequence,
    ];
    frame.extend_from_slice(payload);
    frame
}

fn cstr(text: &str) -> Vec<u8> {
    let mut bytes = text.as_bytes().to_vec();
    bytes.push(0);
    bytes
}

fn lenenc_str(text: &str) -> Vec<u8> {
    assert!(text.len() < 0xfb, "test string must use a one-byte length");
    let mut bytes = vec![text.len() as u8];
    bytes.extend_from_slice(text.as_bytes());
    bytes
}

fn handshake(sequence: u8, capabilities: u32, plugin: &str, nonce: &[u8; 20]) -> Vec<u8> {
    let mut body = vec![10];
    body.extend_from_slice(&cstr("8.0.36-mock"));
    body.extend_from_slice(&424_242u32.to_le_bytes());
    body.extend_from_slice(&nonce[..8]);
    body.push(0);
    body.extend_from_slice(&(capabilities as u16).to_le_bytes());
    body.push(45);
    body.extend_from_slice(&2u16.to_le_bytes());
    body.extend_from_slice(&((capabilities >> 16) as u16).to_le_bytes());
    body.push(21);
    body.extend_from_slice(&[0u8; 10]);
    body.extend_from_slice(&nonce[8..20]);
    body.push(0);
    if capabilities & CLIENT_PLUGIN_AUTH != 0 {
        body.extend_from_slice(&cstr(plugin));
    }
    packet(sequence, &body)
}

fn ok_packet(sequence: u8, header: u8, status: u16) -> Vec<u8> {
    let mut body = vec![header, 0, 0];
    body.extend_from_slice(&status.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    packet(sequence, &body)
}

fn eof_packet(sequence: u8, status: u16) -> Vec<u8> {
    let mut body = vec![0xfe];
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&status.to_le_bytes());
    packet(sequence, &body)
}

fn err_packet(sequence: u8, code: u16, sqlstate: &str, message: &str) -> Vec<u8> {
    assert_eq!(sqlstate.len(), 5, "SQLSTATE must be five bytes");
    let mut body = vec![0xff];
    body.extend_from_slice(&code.to_le_bytes());
    body.push(b'#');
    body.extend_from_slice(sqlstate.as_bytes());
    body.extend_from_slice(message.as_bytes());
    packet(sequence, &body)
}

fn column_definition(sequence: u8, name: &str, type_code: u8, column_length: u32) -> Vec<u8> {
    let mut body = Vec::new();
    for text in ["def", "opurom", "todo", "todo", name, name] {
        body.extend_from_slice(&lenenc_str(text));
    }
    body.push(0x0c);
    body.extend_from_slice(&45u16.to_le_bytes());
    body.extend_from_slice(&column_length.to_le_bytes());
    body.push(type_code);
    body.extend_from_slice(&0u16.to_le_bytes());
    body.push(0);
    body.extend_from_slice(&[0, 0]);
    packet(sequence, &body)
}

fn text_row(sequence: u8, values: &[Option<&str>]) -> Vec<u8> {
    let mut body = Vec::new();
    for value in values {
        match value {
            None => body.push(0xfb),
            Some(text) => {
                assert!(text.len() < 0xfb, "test cell must use a one-byte length");
                body.push(text.len() as u8);
                body.extend_from_slice(text.as_bytes());
            }
        }
    }
    packet(sequence, &body)
}

fn classic_result_set(
    start_sequence: u8,
    columns: &[(&str, u8, u32)],
    rows: &[Vec<Option<&str>>],
) -> Vec<u8> {
    let mut sequence = start_sequence;
    let mut bytes = packet(sequence, &[columns.len() as u8]);
    sequence = sequence.wrapping_add(1);
    for (name, type_code, column_length) in columns {
        bytes.extend_from_slice(&column_definition(
            sequence,
            name,
            *type_code,
            *column_length,
        ));
        sequence = sequence.wrapping_add(1);
    }
    for row in rows {
        bytes.extend_from_slice(&text_row(sequence, row.as_slice()));
        sequence = sequence.wrapping_add(1);
    }
    bytes.extend_from_slice(&eof_packet(sequence, 2));
    bytes
}

fn deprecated_result_set(
    start_sequence: u8,
    columns: &[(&str, u8, u32)],
    rows: &[Vec<Option<&str>>],
) -> Vec<u8> {
    let mut sequence = start_sequence;
    let mut bytes = packet(sequence, &[columns.len() as u8]);
    sequence = sequence.wrapping_add(1);
    for (name, type_code, column_length) in columns {
        bytes.extend_from_slice(&column_definition(
            sequence,
            name,
            *type_code,
            *column_length,
        ));
        sequence = sequence.wrapping_add(1);
    }
    for row in rows {
        bytes.extend_from_slice(&text_row(sequence, row.as_slice()));
        sequence = sequence.wrapping_add(1);
    }
    bytes.extend_from_slice(&ok_packet(sequence, 0xfe, 2));
    bytes
}

fn auth_switch_packet(sequence: u8, plugin: &str, nonce: &[u8; 20]) -> Vec<u8> {
    let mut body = vec![0xfe];
    body.extend_from_slice(&cstr(plugin));
    body.extend_from_slice(nonce);
    body.push(0);
    packet(sequence, &body)
}

fn auth_more_data(sequence: u8, data: &[u8]) -> Vec<u8> {
    let mut body = vec![0x01];
    body.extend_from_slice(data);
    packet(sequence, &body)
}

fn prepare_ok_packet(sequence: u8, id: u32, columns: u16, params: u16, warnings: u16) -> Vec<u8> {
    let mut body = vec![0x00];
    body.extend_from_slice(&id.to_le_bytes());
    body.extend_from_slice(&columns.to_le_bytes());
    body.extend_from_slice(&params.to_le_bytes());
    body.push(0);
    body.extend_from_slice(&warnings.to_le_bytes());
    packet(sequence, &body)
}

fn binary_row(sequence: u8) -> Vec<u8> {
    packet(sequence, &[0x00, 0x00, 7, 0, 0, 0])
}

fn expected_full_auth_message() -> Vec<u8> {
    let mut message = Vec::with_capacity(7);
    for (index, byte) in b"secret".iter().enumerate() {
        message.push(*byte ^ NONCE[index % NONCE.len()]);
    }
    message.push(0);
    message
}

fn oversized_header(sequence: u8) -> Vec<u8> {
    let length = MAX_PACKET_LEN + 1;
    vec![
        length as u8,
        (length >> 8) as u8,
        (length >> 16) as u8,
        sequence,
    ]
}

fn column_count_over_limit(sequence: u8) -> Vec<u8> {
    let count = 1_601u16.to_le_bytes();
    packet(sequence, &[0xfc, count[0], count[1]])
}

fn negotiated(server_caps: u32) -> u32 {
    REQUIRED_CLIENT_CAPS | (server_caps & CLIENT_DEPRECATE_EOF)
}

fn query_sql(frame: &[u8]) -> String {
    assert_eq!(frame[3], 0, "COM_QUERY sequence id");
    let length =
        usize::from(frame[0]) | (usize::from(frame[1]) << 8) | (usize::from(frame[2]) << 16);
    assert_eq!(
        length + 4,
        frame.len(),
        "COM_QUERY length excludes its header"
    );
    assert_eq!(frame[4], 0x03, "COM_QUERY command byte");
    String::from_utf8(frame[5..].to_vec()).unwrap()
}

fn read_cstring(bytes: &[u8], position: &mut usize) -> String {
    let start = *position;
    while bytes[*position] != 0 {
        *position += 1;
    }
    let text = String::from_utf8(bytes[start..*position].to_vec()).unwrap();
    *position += 1;
    text
}

fn hex_bytes(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "hex string must have an even length");
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn packet_body(frame: &[u8]) -> &[u8] {
    let length =
        usize::from(frame[0]) | (usize::from(frame[1]) << 8) | (usize::from(frame[2]) << 16);
    assert_eq!(length + 4, frame.len(), "packet length excludes its header");
    &frame[4..]
}

fn command_body(frame: &[u8], command: u8) -> &[u8] {
    assert_eq!(frame[3], 0, "command packet sequence id");
    let body = packet_body(frame);
    assert_eq!(body.first(), Some(&command), "command byte");
    &body[1..]
}

fn assert_handshake_response(frame: &[u8], expected_capabilities: u32) {
    assert_handshake_response_with(
        frame,
        expected_capabilities,
        NATIVE_PLUGIN,
        EXPECTED_SCRAMBLE,
    );
}

fn assert_caching_handshake_response(frame: &[u8], expected_capabilities: u32) {
    assert_handshake_response_with(
        frame,
        expected_capabilities,
        CACHING_PLUGIN,
        EXPECTED_CACHING_SCRAMBLE,
    );
}

fn assert_handshake_response_with(
    frame: &[u8],
    expected_capabilities: u32,
    expected_plugin: &str,
    expected_scramble: &str,
) {
    assert!(
        frame.len() > 36,
        "HandshakeResponse41 must have a 32-byte prefix"
    );
    assert_eq!(frame[3], 1, "HandshakeResponse41 sequence id");
    let length =
        usize::from(frame[0]) | (usize::from(frame[1]) << 8) | (usize::from(frame[2]) << 16);
    assert_eq!(length + 4, frame.len(), "packet length excludes its header");
    let body = &frame[4..];
    let capabilities = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    let max_packet = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
    assert_eq!(capabilities, expected_capabilities);
    assert_eq!(max_packet, MAX_PACKET_LEN as u32);
    assert_eq!(body[8], 45, "utf8mb4_general_ci charset");
    assert!(
        body[9..32].iter().all(|byte| *byte == 0),
        "HandshakeResponse41 reserved bytes must be zero"
    );
    let mut position = 32;
    assert_eq!(read_cstring(body, &mut position), "alice");
    let auth_len = usize::from(body[position]);
    let auth = &body[position + 1..position + 1 + auth_len];
    let expected = hex_bytes(expected_scramble);
    assert_eq!(auth, expected.as_slice(), "authentication scramble");
    position += 1 + auth_len;
    assert_eq!(read_cstring(body, &mut position), "opurom");
    assert_eq!(read_cstring(body, &mut position), expected_plugin);
    assert_eq!(
        position,
        body.len(),
        "HandshakeResponse41 must end after the plugin"
    );
}

#[test]
fn mysql_mock_conformance_handshake_query_and_two_rows() {
    let initial = handshake(0, SERVER_CAPS, NATIVE_PLUGIN, &NONCE);
    let auth_ok = ok_packet(2, 0x00, 2);
    let exec_ok = ok_packet(1, 0x00, 2);
    let columns = [
        ("id", TYPE_LONG, 11),
        ("title", TYPE_VARCHAR, 64),
        ("done", TYPE_TINY, 1),
    ];
    let sample_rows = vec![
        vec![Some("1"), Some("O'Reilly"), Some("1")],
        vec![Some("2"), None, Some("0")],
    ];
    let result_reply = classic_result_set(1, &columns, &sample_rows);
    let server = MockServer::spawn(scenario(initial, auth_ok, vec![exec_ok, result_reply]));
    let address = server.address();
    let rows = bounded("mysql conformance client", move || {
        let mut db =
            MySqlConnection::connect("127.0.0.1", address.port(), "alice", "secret", "opurom")
                .expect("handshake must succeed");
        assert_eq!(db.server_version(), "8.0.36-mock");
        assert_eq!(db.connection_id(), 424_242);
        assert_eq!(db.server_capabilities(), SERVER_CAPS);
        assert_eq!(db.negotiated_capabilities(), negotiated(SERVER_CAPS));
        assert_eq!(db.charset(), 45);
        assert_eq!(db.status_flags(), 2);
        assert_eq!(db.auth_plugin(), NATIVE_PLUGIN);
        Database::exec(&mut db, "CREATE TABLE Todo (id INT);")
            .expect("Database::exec must parse an OK packet");
        Database::query(&mut db, "SELECT * FROM Todo;")
            .expect("Database::query must parse a COM_QUERY result set")
    });
    let captured = server.finish();
    assert_handshake_response(&captured.handshake_response, negotiated(SERVER_CAPS));
    assert_eq!(captured.queries.len(), 2);
    assert_eq!(
        query_sql(&captured.queries[0]),
        "CREATE TABLE Todo (id INT);"
    );
    assert_eq!(query_sql(&captured.queries[1]), "SELECT * FROM Todo;");
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[0],
        Row::new()
            .insert("id", Value::Int(1))
            .insert("title", Value::Text("O'Reilly".to_string()))
            .insert("done", Value::Bool(true))
    );
    assert_eq!(
        rows[1],
        Row::new()
            .insert("id", Value::Int(2))
            .insert("done", Value::Bool(false))
    );
}

#[test]
fn mysql_err_packet_maps_typed_errors() {
    for (code, sqlstate, message, kind, label) in [
        (
            1064u16,
            "42000",
            "You have an error in your SQL syntax",
            MySqlErrorKind::Syntax,
            "syntax error",
        ),
        (
            1146,
            "42S02",
            "Table 'opurom.Missing' doesn't exist",
            MySqlErrorKind::TableNotFound,
            "table not found",
        ),
        (
            1062,
            "23000",
            "Duplicate entry '1' for key 'PRIMARY'",
            MySqlErrorKind::DuplicateEntry,
            "duplicate entry",
        ),
    ] {
        let initial = handshake(0, SERVER_CAPS, NATIVE_PLUGIN, &NONCE);
        let auth_ok = ok_packet(2, 0x00, 2);
        let err_reply = err_packet(1, code, sqlstate, message);
        let server = MockServer::spawn(scenario(initial, auth_ok, vec![err_reply]));
        let address = server.address();
        let error = bounded("mysql typed error client", move || {
            let mut db =
                MySqlConnection::connect("127.0.0.1", address.port(), "alice", "secret", "opurom")
                    .expect("handshake must succeed");
            Database::query(&mut db, "SELECT BOGUS;").unwrap_err()
        });
        assert_eq!(error.mysql_code(), Some(code));
        assert_eq!(error.mysql_error_kind(), Some(kind));
        assert_eq!(error.sqlstate(), Some(sqlstate));
        let text = error.to_string();
        let code_text = code.to_string();
        assert!(text.contains(code_text.as_str()), "{text}");
        assert!(text.contains(sqlstate), "{text}");
        assert!(text.contains(label), "{text}");
        assert!(text.contains(message), "{text}");
        server.finish();
    }
}

#[test]
fn mysql_auth_failure_is_typed() {
    let initial = handshake(0, SERVER_CAPS, NATIVE_PLUGIN, &NONCE);
    let auth_error = err_packet(2, 1045, "28000", "Access denied for user 'alice'");
    let server = MockServer::spawn(scenario(initial, auth_error, Vec::new()));
    let address = server.address();
    let error = bounded("mysql auth failure client", move || {
        MySqlConnection::connect("127.0.0.1", address.port(), "alice", "secret", "opurom")
            .unwrap_err()
    });
    assert_eq!(error.mysql_code(), Some(1045));
    assert_eq!(error.mysql_error_kind(), Some(MySqlErrorKind::AccessDenied));
    assert_eq!(error.sqlstate(), Some("28000"));
    assert!(error.to_string().contains("access denied"), "{error}");
    let captured = server.finish();
    assert_handshake_response(&captured.handshake_response, negotiated(SERVER_CAPS));
}

#[test]
fn mysql_truncated_and_malformed_packets_are_rejected() {
    let full_handshake = handshake(0, SERVER_CAPS, NATIVE_PLUGIN, &NONCE);
    let truncated_handshake = full_handshake[..12].to_vec();
    let server = MockServer::spawn(one_shot(truncated_handshake));
    let address = server.address();
    let error = bounded("mysql truncated handshake client", move || {
        MySqlConnection::connect("127.0.0.1", address.port(), "alice", "secret", "opurom")
            .unwrap_err()
    });
    assert!(error.to_string().contains("truncated"), "{error}");
    server.finish();

    let mut bad_handshake = handshake(0, SERVER_CAPS, NATIVE_PLUGIN, &NONCE);
    bad_handshake[4] = 9;
    let server = MockServer::spawn(one_shot(bad_handshake));
    let address = server.address();
    let error = bounded("mysql malformed handshake client", move || {
        MySqlConnection::connect("127.0.0.1", address.port(), "alice", "secret", "opurom")
            .unwrap_err()
    });
    assert!(error.to_string().contains("protocol 9"), "{error}");
    server.finish();

    let columns = [
        ("id", TYPE_LONG, 11),
        ("title", TYPE_VARCHAR, 64),
        ("done", TYPE_TINY, 1),
    ];
    let sample_rows = vec![vec![Some("1"), Some("x"), Some("1")]];
    let full_reply = classic_result_set(1, &columns, &sample_rows);
    let truncated_reply = full_reply[..10].to_vec();
    let server = MockServer::spawn(scenario(
        handshake(0, SERVER_CAPS, NATIVE_PLUGIN, &NONCE),
        ok_packet(2, 0x00, 2),
        vec![truncated_reply],
    ));
    let address = server.address();
    let error = bounded("mysql truncated query client", move || {
        let mut db =
            MySqlConnection::connect("127.0.0.1", address.port(), "alice", "secret", "opurom")
                .expect("handshake must succeed");
        Database::query(&mut db, "SELECT * FROM Todo;").unwrap_err()
    });
    assert!(error.to_string().contains("truncated"), "{error}");
    server.finish();

    let mut malformed_reply = packet(1, &[1]);
    malformed_reply.extend_from_slice(&packet(2, &[0x00]));
    let server = MockServer::spawn(scenario(
        handshake(0, SERVER_CAPS, NATIVE_PLUGIN, &NONCE),
        ok_packet(2, 0x00, 2),
        vec![malformed_reply],
    ));
    let address = server.address();
    let error = bounded("mysql malformed column client", move || {
        let mut db =
            MySqlConnection::connect("127.0.0.1", address.port(), "alice", "secret", "opurom")
                .expect("handshake must succeed");
        Database::query(&mut db, "SELECT * FROM Todo;").unwrap_err()
    });
    assert!(error.to_string().contains("column definition"), "{error}");
    server.finish();
}

#[test]
fn mysql_packet_size_bounds_are_enforced() {
    let server = MockServer::spawn(scenario(
        handshake(0, SERVER_CAPS, NATIVE_PLUGIN, &NONCE),
        oversized_header(2),
        Vec::new(),
    ));
    let address = server.address();
    let error = bounded("mysql oversized packet client", move || {
        MySqlConnection::connect("127.0.0.1", address.port(), "alice", "secret", "opurom")
            .unwrap_err()
    });
    assert!(error.to_string().contains("exceeds"), "{error}");
    server.finish();

    let server = MockServer::spawn(scenario(
        handshake(0, SERVER_CAPS, NATIVE_PLUGIN, &NONCE),
        ok_packet(2, 0x00, 2),
        vec![column_count_over_limit(1)],
    ));
    let address = server.address();
    let error = bounded("mysql column bound client", move || {
        let mut db =
            MySqlConnection::connect("127.0.0.1", address.port(), "alice", "secret", "opurom")
                .expect("handshake must succeed");
        Database::query(&mut db, "SELECT * FROM Todo;").unwrap_err()
    });
    assert!(error.to_string().contains("1600"), "{error}");
    server.finish();
}

#[test]
fn mysql_sequence_id_mismatch_is_rejected() {
    let server = MockServer::spawn(one_shot(handshake(1, SERVER_CAPS, NATIVE_PLUGIN, &NONCE)));
    let address = server.address();
    let error = bounded("mysql handshake sequence client", move || {
        MySqlConnection::connect("127.0.0.1", address.port(), "alice", "secret", "opurom")
            .unwrap_err()
    });
    assert!(error.to_string().contains("sequence id"), "{error}");
    server.finish();

    let server = MockServer::spawn(scenario(
        handshake(0, SERVER_CAPS, NATIVE_PLUGIN, &NONCE),
        ok_packet(9, 0x00, 2),
        Vec::new(),
    ));
    let address = server.address();
    let error = bounded("mysql auth sequence client", move || {
        MySqlConnection::connect("127.0.0.1", address.port(), "alice", "secret", "opurom")
            .unwrap_err()
    });
    assert!(error.to_string().contains("sequence id"), "{error}");
    server.finish();

    let server = MockServer::spawn(scenario(
        handshake(0, SERVER_CAPS, NATIVE_PLUGIN, &NONCE),
        ok_packet(2, 0x00, 2),
        vec![packet(9, &[1])],
    ));
    let address = server.address();
    let error = bounded("mysql query sequence client", move || {
        let mut db =
            MySqlConnection::connect("127.0.0.1", address.port(), "alice", "secret", "opurom")
                .expect("handshake must succeed");
        Database::query(&mut db, "SELECT * FROM Todo;").unwrap_err()
    });
    assert!(error.to_string().contains("sequence id"), "{error}");
    server.finish();
}

#[test]
fn mysql_unsupported_auth_plugins_are_rejected() {
    let server = MockServer::spawn(one_shot(handshake(
        0,
        SERVER_CAPS,
        UNSUPPORTED_PLUGIN,
        &NONCE,
    )));
    let address = server.address();
    let error = bounded("mysql unsupported plugin client", move || {
        MySqlConnection::connect("127.0.0.1", address.port(), "alice", "secret", "opurom")
            .unwrap_err()
    });
    let text = error.to_string();
    assert!(text.contains("UNSUPPORTED"), "{text}");
    assert!(text.contains(UNSUPPORTED_PLUGIN), "{text}");
    let captured = server.finish();
    assert!(
        captured.handshake_response.is_empty(),
        "no credentials are sent for an unsupported plugin"
    );

    let server = MockServer::spawn(scenario(
        handshake(0, SERVER_CAPS, NATIVE_PLUGIN, &NONCE),
        auth_switch_packet(2, UNSUPPORTED_PLUGIN, &NONCE),
        Vec::new(),
    ));
    let address = server.address();
    let error = bounded("mysql auth switch client", move || {
        MySqlConnection::connect("127.0.0.1", address.port(), "alice", "secret", "opurom")
            .unwrap_err()
    });
    let text = error.to_string();
    assert!(text.contains("UNSUPPORTED"), "{text}");
    assert!(text.contains(UNSUPPORTED_PLUGIN), "{text}");
    let captured = server.finish();
    assert_handshake_response(&captured.handshake_response, negotiated(SERVER_CAPS));
    assert!(
        captured.queries.is_empty(),
        "no credentials are sent for an unsupported auth switch"
    );
}

#[test]
fn mysql_deprecated_eof_ok_packets_are_parsed() {
    let initial = handshake(0, SERVER_CAPS_DEPRECATED, NATIVE_PLUGIN, &NONCE);
    let auth_ok = ok_packet(2, 0xfe, 2);
    let exec_ok = ok_packet(1, 0xfe, 2);
    let columns = [
        ("id", TYPE_LONG, 11),
        ("title", TYPE_VARCHAR, 64),
        ("done", TYPE_TINY, 1),
    ];
    let sample_rows = vec![vec![Some("7"), Some("x"), Some("0")]];
    let result_reply = deprecated_result_set(1, &columns, &sample_rows);
    let server = MockServer::spawn(scenario(initial, auth_ok, vec![exec_ok, result_reply]));
    let address = server.address();
    let rows = bounded("mysql deprecated EOF client", move || {
        let mut db =
            MySqlConnection::connect("127.0.0.1", address.port(), "alice", "secret", "opurom")
                .expect("handshake must succeed");
        assert_ne!(
            db.negotiated_capabilities() & CLIENT_DEPRECATE_EOF,
            0,
            "CLIENT_DEPRECATE_EOF must be negotiated"
        );
        Database::exec(&mut db, "SET autocommit=1;")
            .expect("deprecated OK packet must be parsed by exec");
        Database::query(&mut db, "SELECT * FROM Todo;")
            .expect("deprecated OK packet must terminate a result set")
    });
    let captured = server.finish();
    assert_handshake_response(
        &captured.handshake_response,
        negotiated(SERVER_CAPS_DEPRECATED),
    );
    assert_eq!(captured.queries.len(), 2);
    assert_eq!(query_sql(&captured.queries[0]), "SET autocommit=1;");
    assert_eq!(query_sql(&captured.queries[1]), "SELECT * FROM Todo;");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0],
        Row::new()
            .insert("id", Value::Int(7))
            .insert("title", Value::Text("x".to_string()))
            .insert("done", Value::Bool(false))
    );
}

#[test]
fn mysql_caching_sha2_fast_auth_conformance() {
    let mut auth_success = auth_more_data(2, &[0x03]);
    auth_success.extend_from_slice(&ok_packet(3, 0x00, 2));
    let server = ScriptedServer::spawn(vec![
        Step::Send(handshake(0, SERVER_CAPS, CACHING_PLUGIN, &NONCE)),
        Step::Receive(Some(auth_success)),
        Step::Receive(Some(ok_packet(1, 0x00, 2))),
    ]);
    let address = server.address();
    let plugin = bounded("mysql caching_sha2 fast auth client", move || {
        let mut db =
            MySqlConnection::connect("127.0.0.1", address.port(), "alice", "secret", "opurom")
                .expect("caching_sha2_password fast auth must succeed");
        assert_eq!(db.auth_plugin(), CACHING_PLUGIN);
        Database::exec(&mut db, "SELECT 1;").expect("connection must enter command phase");
        db.auth_plugin().to_string()
    });
    assert_eq!(plugin, CACHING_PLUGIN);
    let frames = server.finish();
    assert_eq!(frames.len(), 2);
    assert_caching_handshake_response(&frames[0], negotiated(SERVER_CAPS));
    assert_eq!(query_sql(&frames[1]), "SELECT 1;");
}

#[test]
fn mysql_caching_sha2_auth_switch_conformance() {
    let mut auth_success = auth_more_data(4, &[0x03]);
    auth_success.extend_from_slice(&ok_packet(5, 0x00, 2));
    let server = ScriptedServer::spawn(vec![
        Step::Send(handshake(0, SERVER_CAPS, NATIVE_PLUGIN, &NONCE)),
        Step::Receive(Some(auth_switch_packet(2, CACHING_PLUGIN, &NONCE))),
        Step::Receive(Some(auth_success)),
        Step::Receive(Some(ok_packet(1, 0x00, 2))),
    ]);
    let address = server.address();
    let plugin = bounded("mysql caching_sha2 auth switch client", move || {
        let mut db =
            MySqlConnection::connect("127.0.0.1", address.port(), "alice", "secret", "opurom")
                .expect("auth switch to caching_sha2_password must succeed");
        assert_eq!(db.auth_plugin(), CACHING_PLUGIN);
        Database::exec(&mut db, "SELECT 1;").expect("connection must enter command phase");
        db.auth_plugin().to_string()
    });
    assert_eq!(plugin, CACHING_PLUGIN);
    let frames = server.finish();
    assert_eq!(frames.len(), 3);
    assert_handshake_response(&frames[0], negotiated(SERVER_CAPS));
    assert_eq!(frames[1][3], 3, "AuthSwitchResponse sequence id");
    assert_eq!(
        packet_body(&frames[1]),
        hex_bytes(EXPECTED_CACHING_SCRAMBLE).as_slice()
    );
    assert_eq!(query_sql(&frames[2]), "SELECT 1;");
}

#[test]
fn mysql_caching_sha2_full_auth_rsa_oaep_conformance() {
    let server = ScriptedServer::spawn(vec![
        Step::Send(handshake(0, SERVER_CAPS, CACHING_PLUGIN, &NONCE)),
        Step::Receive(Some(auth_more_data(2, &[0x04]))),
        Step::Receive(Some(auth_more_data(
            4,
            mysql_crypto::TEST_PUBLIC_KEY_PEM.as_bytes(),
        ))),
        Step::Receive(Some(ok_packet(6, 0x00, 2))),
        Step::Receive(Some(ok_packet(1, 0x00, 2))),
    ]);
    let address = server.address();
    bounded("mysql caching_sha2 full auth client", move || {
        let mut db =
            MySqlConnection::connect("127.0.0.1", address.port(), "alice", "secret", "opurom")
                .expect("caching_sha2_password RSA-OAEP full auth must succeed");
        assert_eq!(db.auth_plugin(), CACHING_PLUGIN);
        Database::exec(&mut db, "SELECT 1;").expect("connection must enter command phase");
    });
    let frames = server.finish();
    assert_eq!(frames.len(), 4);
    assert_caching_handshake_response(&frames[0], negotiated(SERVER_CAPS));
    assert_eq!(frames[1][3], 3, "public-key request sequence id");
    assert_eq!(packet_body(&frames[1]), &[0x02]);
    assert_eq!(frames[2][3], 5, "encrypted password sequence id");
    let ciphertext = packet_body(&frames[2]);
    assert_eq!(ciphertext.len(), 64, "512-bit RSA ciphertext length");
    let plaintext = mysql_crypto::decrypt_oaep_sha1(
        ciphertext,
        &hex_bytes(mysql_crypto::TEST_MODULUS_HEX),
        &hex_bytes(mysql_crypto::TEST_PRIVATE_EXPONENT_HEX),
    )
    .expect("RSA-OAEP ciphertext must decrypt with the test private key");
    assert_eq!(plaintext, expected_full_auth_message());
    assert_eq!(query_sql(&frames[3]), "SELECT 1;");
}

#[test]
fn mysql_stmt_prepare_execute_conformance() {
    let sql = "SELECT id FROM Todo WHERE id = ? AND title = ?";
    let mut prepare_reply = prepare_ok_packet(1, 7, 0, 2, 0);
    prepare_reply.extend_from_slice(&column_definition(2, "?", TYPE_LONG, 11));
    prepare_reply.extend_from_slice(&column_definition(3, "?", TYPE_VARCHAR, 64));
    prepare_reply.extend_from_slice(&eof_packet(4, 2));
    let server = ScriptedServer::spawn(vec![
        Step::Send(handshake(0, SERVER_CAPS, NATIVE_PLUGIN, &NONCE)),
        Step::Receive(Some(ok_packet(2, 0x00, 2))),
        Step::Receive(Some(prepare_reply)),
        Step::Receive(Some(ok_packet(1, 0x00, 2))),
    ]);
    let address = server.address();
    let statement = bounded("mysql stmt prepare client", move || {
        let mut db =
            MySqlConnection::connect("127.0.0.1", address.port(), "alice", "secret", "opurom")
                .expect("handshake must succeed");
        let statement = db.prepare(sql).expect("COM_STMT_PREPARE OK must parse");
        db.execute_stmt(statement, &[Value::Int(7), Value::Text("x".to_string())])
            .expect("COM_STMT_EXECUTE OK must parse");
        statement
    });
    assert_eq!(statement.id(), 7);
    assert_eq!(statement.column_count(), 0);
    assert_eq!(statement.param_count(), 2);
    assert_eq!(statement.warning_count(), 0);
    let frames = server.finish();
    assert_eq!(frames.len(), 3);
    assert_handshake_response(&frames[0], negotiated(SERVER_CAPS));
    assert_eq!(command_body(&frames[1], COM_STMT_PREPARE), sql.as_bytes());
    let mut expected = vec![7, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1];
    expected.extend_from_slice(&[TYPE_LONGLONG, 0, TYPE_STRING, 0]);
    expected.extend_from_slice(&7i64.to_le_bytes());
    expected.extend_from_slice(&[1, b'x']);
    assert_eq!(
        command_body(&frames[2], COM_STMT_EXECUTE),
        expected.as_slice()
    );
}

#[test]
fn mysql_stmt_prepare_err_and_truncated_packets_are_rejected() {
    let server = ScriptedServer::spawn(vec![
        Step::Send(handshake(0, SERVER_CAPS, NATIVE_PLUGIN, &NONCE)),
        Step::Receive(Some(ok_packet(2, 0x00, 2))),
        Step::Receive(Some(err_packet(1, 1064, "42000", "prepare failed"))),
    ]);
    let address = server.address();
    let error = bounded("mysql prepare ERR client", move || {
        let mut db =
            MySqlConnection::connect("127.0.0.1", address.port(), "alice", "secret", "opurom")
                .expect("handshake must succeed");
        db.prepare("SELECT ?").unwrap_err()
    });
    assert_eq!(error.mysql_code(), Some(1064));
    assert_eq!(error.sqlstate(), Some("42000"));
    assert_eq!(error.mysql_error_kind(), Some(MySqlErrorKind::Syntax));
    server.finish();

    let full_reply = prepare_ok_packet(1, 7, 0, 0, 0);
    let truncated_reply = full_reply[..6].to_vec();
    let server = ScriptedServer::spawn(vec![
        Step::Send(handshake(0, SERVER_CAPS, NATIVE_PLUGIN, &NONCE)),
        Step::Receive(Some(ok_packet(2, 0x00, 2))),
        Step::Receive(Some(truncated_reply)),
    ]);
    let address = server.address();
    let error = bounded("mysql truncated prepare client", move || {
        let mut db =
            MySqlConnection::connect("127.0.0.1", address.port(), "alice", "secret", "opurom")
                .expect("handshake must succeed");
        db.prepare("SELECT 1").unwrap_err()
    });
    assert!(error.to_string().contains("truncated"), "{error}");
    server.finish();
}

#[test]
fn mysql_stmt_execute_binary_result_is_typed_unsupported() {
    let mut prepare_reply = prepare_ok_packet(1, 9, 1, 0, 0);
    prepare_reply.extend_from_slice(&column_definition(2, "id", TYPE_LONG, 11));
    prepare_reply.extend_from_slice(&eof_packet(3, 2));
    let mut binary_result = packet(1, &[1]);
    binary_result.extend_from_slice(&column_definition(2, "id", TYPE_LONG, 11));
    binary_result.extend_from_slice(&eof_packet(3, 2));
    binary_result.extend_from_slice(&binary_row(4));
    binary_result.extend_from_slice(&eof_packet(5, 2));
    let server = ScriptedServer::spawn(vec![
        Step::Send(handshake(0, SERVER_CAPS, NATIVE_PLUGIN, &NONCE)),
        Step::Receive(Some(ok_packet(2, 0x00, 2))),
        Step::Receive(Some(prepare_reply)),
        Step::Receive(Some(binary_result)),
        Step::Receive(Some(ok_packet(1, 0x00, 2))),
    ]);
    let address = server.address();
    let error = bounded("mysql binary result client", move || {
        let mut db =
            MySqlConnection::connect("127.0.0.1", address.port(), "alice", "secret", "opurom")
                .expect("handshake must succeed");
        let statement = db
            .prepare("SELECT id FROM Todo")
            .expect("COM_STMT_PREPARE OK must parse");
        let error = db.execute_stmt(statement, &[]).unwrap_err();
        Database::exec(&mut db, "SELECT 1;").expect("connection remains usable after UNSUPPORTED");
        error
    });
    let text = error.to_string();
    assert!(text.contains("UNSUPPORTED"), "{text}");
    assert!(text.contains("binary"), "{text}");
    let frames = server.finish();
    assert_eq!(frames.len(), 4);
    assert_eq!(query_sql(&frames[3]), "SELECT 1;");
}
