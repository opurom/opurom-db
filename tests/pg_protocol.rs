use opurom_db::{create_table, list, parse_models, Model, PgConnection, Row, Value};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAX_TEST_FRAME: usize = 16 * 1024 * 1024;

#[derive(Default)]
struct Captured {
    startup: Vec<u8>,
    queries: Vec<Vec<u8>>,
}

struct QueryReply {
    bytes: Vec<u8>,
    hold: Duration,
}

fn reply(bytes: Vec<u8>) -> QueryReply {
    QueryReply {
        bytes,
        hold: Duration::ZERO,
    }
}

fn stall(bytes: Vec<u8>, hold: Duration) -> QueryReply {
    QueryReply { bytes, hold }
}

struct MockServer {
    address: SocketAddr,
    handle: Option<JoinHandle<Captured>>,
}

impl MockServer {
    fn spawn(startup: Vec<u8>, replies: Vec<QueryReply>) -> MockServer {
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
            match read_startup_frame(&mut stream) {
                Ok(frame) => captured.startup = frame,
                Err(_) => return captured,
            }
            if stream.write_all(&startup).is_err() {
                return captured;
            }
            for response in replies {
                match read_query_frame(&mut stream) {
                    Ok(frame) => captured.queries.push(frame),
                    Err(_) => break,
                }
                if stream.write_all(&response.bytes).is_err() {
                    break;
                }
                if !response.hold.is_zero() {
                    thread::sleep(response.hold);
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

fn read_startup_frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length < 8 || length > MAX_TEST_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid startup frame length",
        ));
    }
    let mut body = vec![0u8; length - 4];
    stream.read_exact(&mut body)?;
    let mut frame = header.to_vec();
    frame.extend_from_slice(&body);
    Ok(frame)
}

fn read_query_frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header)?;
    let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if length < 4 || length > MAX_TEST_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid query frame length",
        ));
    }
    let mut body = vec![0u8; length - 4];
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

fn msg(tag: u8, body: &[u8]) -> Vec<u8> {
    let length = (4 + body.len()) as i32;
    let mut frame = Vec::with_capacity(5 + body.len());
    frame.push(tag);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(body);
    frame
}

fn frame_header(tag: u8, length: i32) -> Vec<u8> {
    let mut frame = vec![tag];
    frame.extend_from_slice(&length.to_be_bytes());
    frame
}

fn cstr(text: &str) -> Vec<u8> {
    let mut bytes = text.as_bytes().to_vec();
    bytes.push(0);
    bytes
}

fn join(parts: Vec<Vec<u8>>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for part in parts {
        bytes.extend_from_slice(&part);
    }
    bytes
}

fn parameter_body(name: &str, value: &str) -> Vec<u8> {
    let mut body = cstr(name);
    body.extend_from_slice(&cstr(value));
    body
}

fn startup_success() -> Vec<u8> {
    let mut key = Vec::new();
    key.extend_from_slice(&4242i32.to_be_bytes());
    key.extend_from_slice(&99i32.to_be_bytes());
    join(vec![
        msg(b'R', &0i32.to_be_bytes()),
        msg(b'S', &parameter_body("server_version", "15.0")),
        msg(b'S', &parameter_body("client_encoding", "UTF8")),
        msg(b'K', &key),
        msg(b'Z', b"I"),
    ])
}

fn row_description() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&3i16.to_be_bytes());
    for (name, type_oid, type_size) in [
        ("id", 23i32, 4i16),
        ("title", 25i32, -1i16),
        ("done", 16i32, 1i16),
    ] {
        body.extend_from_slice(&cstr(name));
        body.extend_from_slice(&0i32.to_be_bytes());
        body.extend_from_slice(&0i16.to_be_bytes());
        body.extend_from_slice(&type_oid.to_be_bytes());
        body.extend_from_slice(&type_size.to_be_bytes());
        body.extend_from_slice(&(-1i32).to_be_bytes());
        body.extend_from_slice(&0i16.to_be_bytes());
    }
    msg(b'T', &body)
}

fn data_row(values: &[Option<&str>]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(values.len() as i16).to_be_bytes());
    for value in values {
        match value {
            Some(text) => {
                let bytes = text.as_bytes();
                body.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
                body.extend_from_slice(bytes);
            }
            None => body.extend_from_slice(&(-1i32).to_be_bytes()),
        }
    }
    msg(b'D', &body)
}

fn command_complete(tag: &str) -> Vec<u8> {
    msg(b'C', &cstr(tag))
}

fn ready() -> Vec<u8> {
    msg(b'Z', b"I")
}

fn error_response() -> Vec<u8> {
    let mut body = Vec::new();
    for (code, value) in [
        (b'S', "ERROR"),
        (b'V', "ERROR"),
        (b'C', "42601"),
        (b'M', "syntax error at or near \"BOGUS\""),
        (b'P', "1"),
    ] {
        body.push(code);
        body.extend_from_slice(&cstr(value));
    }
    body.push(0);
    msg(b'E', &body)
}

fn exec_reply() -> Vec<u8> {
    join(vec![command_complete("CREATE TABLE"), ready()])
}

fn row_reply() -> Vec<u8> {
    join(vec![
        row_description(),
        data_row(&[Some("1"), Some("O'Reilly"), Some("t")]),
        data_row(&[Some("2"), None, Some("f")]),
        command_complete("SELECT 2"),
        ready(),
    ])
}

fn todo_model() -> Model {
    let ir = r#"{
      "ir": "0.1",
      "models": [
        {"name": "Todo", "fields": [
          {"name": "id", "type": "int", "primary": true, "default": null},
          {"name": "title", "type": "string", "primary": false, "default": null},
          {"name": "done", "type": "bool", "primary": false, "default": false}
        ]}
      ]
    }"#;
    parse_models(ir).unwrap().pop().unwrap()
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

fn startup_parameters(frame: &[u8]) -> Vec<(String, String)> {
    let length = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    assert_eq!(length, frame.len(), "startup length must include itself");
    assert_eq!(
        u32::from_be_bytes([frame[4], frame[5], frame[6], frame[7]]),
        196608,
        "startup must use protocol v3"
    );
    let mut position = 8;
    let mut parameters = Vec::new();
    loop {
        let name = read_cstring(frame, &mut position);
        if name.is_empty() {
            break;
        }
        parameters.push((name, read_cstring(frame, &mut position)));
    }
    assert_eq!(position, frame.len(), "startup must end with one NUL byte");
    parameters
}

fn query_sql(frame: &[u8]) -> String {
    assert_eq!(frame[0], b'Q', "query message tag");
    let length = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
    assert_eq!(length + 1, frame.len(), "query length excludes the tag");
    assert_eq!(*frame.last().unwrap(), 0, "query must be NUL-terminated");
    String::from_utf8(frame[5..frame.len() - 1].to_vec()).unwrap()
}

#[test]
fn postgres_mock_conformance_routes_crud_and_parses_frames() {
    let server = MockServer::spawn(
        startup_success(),
        vec![reply(exec_reply()), reply(row_reply())],
    );
    let address = server.address();
    let rows = bounded("postgres conformance client", move || {
        let mut db = PgConnection::connect("127.0.0.1", address.port(), "alice", "opurom")
            .expect("startup must succeed");
        assert_eq!(db.parameter("server_version"), Some("15.0"));
        assert_eq!(db.parameter("client_encoding"), Some("UTF8"));
        assert_eq!(db.backend_key(), Some((4242, 99)));
        let model = todo_model();
        create_table(&mut db, &model).expect("Database::exec must route to PostgreSQL");
        list(&mut db, &model).expect("Database::query must route to PostgreSQL")
    });
    let captured = server.finish();

    assert_eq!(
        startup_parameters(&captured.startup),
        vec![
            ("user".to_string(), "alice".to_string()),
            ("database".to_string(), "opurom".to_string()),
        ]
    );
    assert_eq!(captured.queries.len(), 2);
    assert!(query_sql(&captured.queries[0]).starts_with("CREATE TABLE IF NOT EXISTS Todo"));
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
fn postgres_error_response_is_rejected_readably() {
    let query_server = MockServer::spawn(
        startup_success(),
        vec![reply(join(vec![error_response(), ready()]))],
    );
    let address = query_server.address();
    let error = bounded("postgres query error client", move || {
        let mut db = PgConnection::connect("127.0.0.1", address.port(), "alice", "opurom")
            .expect("startup must succeed");
        db.query("SELECT BOGUS;").unwrap_err()
    });
    let message = error.to_string();
    assert!(message.contains("postgres ERROR"), "{message}");
    assert!(message.contains("42601"), "{message}");
    assert!(message.contains("syntax error"), "{message}");
    query_server.finish();

    let query_eof_server = MockServer::spawn(startup_success(), vec![reply(error_response())]);
    let address = query_eof_server.address();
    let error = bounded("postgres query error before close client", move || {
        let mut db = PgConnection::connect("127.0.0.1", address.port(), "alice", "opurom")
            .expect("startup must succeed");
        db.query("SELECT BOGUS;").unwrap_err()
    });
    assert!(error.to_string().contains("42601"), "{error}");
    query_eof_server.finish();

    let startup_server = MockServer::spawn(error_response(), Vec::new());
    let address = startup_server.address();
    let error = bounded("postgres startup error client", move || {
        PgConnection::connect("127.0.0.1", address.port(), "alice", "opurom").unwrap_err()
    });
    assert!(error.to_string().contains("42601"), "{error}");
    startup_server.finish();
}

#[test]
fn postgres_truncated_message_never_hangs() {
    let full_reply = row_reply();
    let query_server = MockServer::spawn(startup_success(), vec![reply(full_reply[..12].to_vec())]);
    let address = query_server.address();
    let error = bounded("postgres truncated query client", move || {
        let mut db = PgConnection::connect("127.0.0.1", address.port(), "alice", "opurom")
            .expect("startup must succeed");
        db.query("SELECT * FROM Todo;").unwrap_err()
    });
    assert!(error.to_string().contains("truncated"), "{error}");
    query_server.finish();

    let startup_server = MockServer::spawn(startup_success()[..10].to_vec(), Vec::new());
    let address = startup_server.address();
    let error = bounded("postgres truncated startup client", move || {
        PgConnection::connect("127.0.0.1", address.port(), "alice", "opurom").unwrap_err()
    });
    assert!(error.to_string().contains("truncated"), "{error}");
    startup_server.finish();
}

#[test]
fn postgres_message_framing_and_size_bounds() {
    for (length, expected) in [
        (-1i32, "invalid postgres message length"),
        (16 * 1024 * 1024 + 1, "exceeds"),
    ] {
        let server = MockServer::spawn(frame_header(b'S', length), Vec::new());
        let address = server.address();
        let error = bounded("postgres frame bound client", move || {
            PgConnection::connect("127.0.0.1", address.port(), "alice", "opurom").unwrap_err()
        });
        assert!(error.to_string().contains(expected), "{error}");
        server.finish();
    }

    let error = PgConnection::connect("127.0.0.1", 1, "bad\0user", "opurom").unwrap_err();
    assert!(error.to_string().contains("NUL byte"), "{error}");
}

#[test]
fn postgres_read_timeout_never_hangs() {
    let mut partial = vec![b'T'];
    partial.extend_from_slice(&((4 + 64) as i32).to_be_bytes());
    partial.extend_from_slice(&[0, 0]);
    let server = MockServer::spawn(
        startup_success(),
        vec![stall(partial, Duration::from_millis(900))],
    );
    let address = server.address();
    let started = Instant::now();
    let error = bounded("postgres timeout client", move || {
        let mut db = PgConnection::connect("127.0.0.1", address.port(), "alice", "opurom")
            .expect("startup must succeed");
        db.query("SELECT * FROM Todo;").unwrap_err()
    });
    assert!(error.to_string().contains("timed out"), "{error}");
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "client must not hang"
    );
    server.finish();
}

#[test]
fn postgres_cleartext_md5_and_sasl_auth_are_unsupported() {
    for (code, extra, expected) in [
        (3i32, vec![], "cleartext password"),
        (5i32, vec![1, 2, 3, 4], "MD5 password"),
        (10i32, vec![], "SASL/SCRAM"),
    ] {
        let mut body = code.to_be_bytes().to_vec();
        body.extend_from_slice(&extra);
        let server = MockServer::spawn(msg(b'R', &body), Vec::new());
        let address = server.address();
        let error = bounded("postgres auth client", move || {
            PgConnection::connect("127.0.0.1", address.port(), "alice", "opurom").unwrap_err()
        });
        let message = error.to_string();
        assert!(message.contains("UNSUPPORTED"), "{message}");
        assert!(message.contains(expected), "{message}");
        server.finish();
    }
}
