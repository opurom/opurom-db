//! Conformance of the PostgreSQL client against the bundled v3 protocol
//! server over real TCP sockets, with and without TLS.

use opurom_db::{
    create, create_table, delete, get, list, parse_models, update, PgAuth, PgConnection, PgServer,
    PgServerOptions, PgTls, Value,
};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair};
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Run a closure with a panic-timeout so a hung socket fails the test.
fn bounded<T: Send + 'static>(what: &str, body: impl FnOnce() -> T + Send + 'static) -> T {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let outcome = catch_unwind(AssertUnwindSafe(body));
        let _ = sender.send(outcome);
    });
    match receiver.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(value)) => value,
        Ok(Err(payload)) => resume_unwind(payload),
        Err(_) => panic!("{what} hung"),
    }
}

/// A self-signed certificate for `localhost` plus its private key, as DER.
fn self_signed() -> (Vec<u8>, Vec<u8>) {
    let key = KeyPair::generate().expect("test key pair");
    let mut params =
        CertificateParams::new(vec!["localhost".to_string()]).expect("test certificate parameters");
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    let certificate = params.self_signed(&key).expect("test certificate");
    (certificate.der().to_vec(), key.serialize_der())
}

fn plain_server() -> PgServer {
    PgServer::start(PgServerOptions {
        auth: PgAuth::Trust,
        tls: None,
    })
    .expect("bundled postgres server")
}

#[test]
fn bundled_server_handles_a_real_multi_statement_transaction() {
    let server = plain_server();
    let port = server.port();
    bounded("transaction client", move || {
        let mut db = PgConnection::connect("127.0.0.1", port, "alice", "opurom")
            .expect("plain connection to the bundled server");
        assert_eq!(db.parameter("server_version"), Some("15.0"));
        assert_eq!(db.parameter("client_encoding"), Some("UTF8"));
        assert_eq!(db.backend_key(), Some((4242, 99)));

        db.exec("CREATE TABLE Todo (id INTEGER PRIMARY KEY, title TEXT);")
            .expect("create table");
        db.exec("BEGIN;").expect("begin");
        db.exec("INSERT INTO Todo (id, title) VALUES (1, 'write the docs');")
            .expect("insert");
        let rows = db
            .query("SELECT * FROM Todo;")
            .expect("select inside the transaction");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("id"), Some(&Value::Int(1)));
        assert_eq!(
            rows[0].get("title"),
            Some(&Value::Text("write the docs".to_string()))
        );
        db.exec("COMMIT;").expect("commit");

        let rows = db
            .query("SELECT * FROM Todo;")
            .expect("select after the commit");
        assert_eq!(
            rows.len(),
            1,
            "the committed row must survive the transaction"
        );
    });
}

#[test]
fn bundled_server_runs_a_multi_statement_query_in_one_message() {
    let server = plain_server();
    let port = server.port();
    bounded("multi-statement client", move || {
        let mut db = PgConnection::connect("127.0.0.1", port, "alice", "opurom")
            .expect("plain connection to the bundled server");
        db.exec("CREATE TABLE Todo (id INTEGER PRIMARY KEY, title TEXT);")
            .expect("create table");
        // One Query message carrying several statements: the client must read
        // every CommandComplete before ReadyForQuery.
        db.exec("BEGIN; INSERT INTO Todo (id, title) VALUES (1, 'one'); COMMIT;")
            .expect("a multi-statement transaction in one message");
        let rows = db.query("SELECT * FROM Todo;").expect("select");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("id"), Some(&Value::Int(1)));
    });
}

#[test]
fn bundled_server_rolls_back_a_transaction() {
    let server = plain_server();
    let port = server.port();
    bounded("rollback client", move || {
        let mut db = PgConnection::connect("127.0.0.1", port, "alice", "opurom")
            .expect("plain connection to the bundled server");
        db.exec("CREATE TABLE Todo (id INTEGER PRIMARY KEY, title TEXT);")
            .expect("create table");
        db.exec("BEGIN;").expect("begin");
        db.exec("INSERT INTO Todo (id, title) VALUES (7, 'discarded');")
            .expect("insert");
        let rows = db
            .query("SELECT * FROM Todo;")
            .expect("select inside the transaction");
        assert_eq!(
            rows.len(),
            1,
            "the pending row is visible inside the transaction"
        );
        db.exec("ROLLBACK;").expect("rollback");

        let rows = db
            .query("SELECT * FROM Todo;")
            .expect("select after the rollback");
        assert!(rows.is_empty(), "the rolled back row must not survive");
    });
}

#[test]
fn bundled_server_maps_sqlstate_to_a_typed_error() {
    let server = plain_server();
    let port = server.port();
    bounded("sqlstate client", move || {
        let mut db = PgConnection::connect("127.0.0.1", port, "alice", "opurom")
            .expect("plain connection to the bundled server");
        let error = db
            .query("SELECT * FROM Missing;")
            .expect_err("an unknown relation must fail");
        let message = error.to_string();
        assert!(message.contains("42P01"), "{message}");
        assert!(message.contains("postgres ERROR"), "{message}");
        assert_eq!(
            error.sqlstate(),
            Some("42P01"),
            "the SQLSTATE must be available as a typed field"
        );

        db.exec("CREATE TABLE Todo (id INTEGER PRIMARY KEY);")
            .expect("create table");
        db.exec("INSERT INTO Todo (id) VALUES (1);")
            .expect("insert");
        let error = db
            .exec("INSERT INTO Todo (id) VALUES (1);")
            .expect_err("a duplicate primary key must fail");
        let message = error.to_string();
        assert!(message.contains("23505"), "{message}");
        assert_eq!(error.sqlstate(), Some("23505"));
    });
}

#[test]
fn bundled_server_routes_the_framework_crud_helpers() {
    let server = plain_server();
    let port = server.port();
    let ir = serde_json::json!({
        "version": "0.1",
        "models": [{
            "name": "Todo",
            "fields": [
                {"name": "id", "type": "int", "primary": true},
                {"name": "title", "type": "string"},
                {"name": "done", "type": "bool", "default": false}
            ]
        }]
    });
    let models = parse_models(&ir.to_string()).expect("test IR");
    let model = models[0].clone();
    bounded("crud client", move || {
        let mut db = PgConnection::connect("127.0.0.1", port, "alice", "opurom")
            .expect("plain connection to the bundled server");
        create_table(&mut db, &model).expect("create table");
        create(
            &mut db,
            &model,
            &[("title", Value::Text("write tests".into()))],
        )
        .expect("create a row");
        let rows = list(&mut db, &model).expect("list");
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].get("title"),
            Some(&Value::Text("write tests".to_string()))
        );
        let found = get(&mut db, &model, 1i64).expect("get").expect("a row");
        assert_eq!(found.get("id"), Some(&Value::Int(1)));
        assert!(update(&mut db, &model, 1i64, &[("done", Value::Bool(true))]).expect("update"));
        assert!(delete(&mut db, &model, 1i64).expect("delete"));
        assert!(list(&mut db, &model).expect("list").is_empty());
    });
}

#[test]
fn bundled_server_serves_cleartext_authentication() {
    let server = PgServer::start(PgServerOptions {
        auth: PgAuth::Cleartext("secret".to_string()),
        tls: None,
    })
    .expect("bundled postgres server");
    let port = server.port();
    bounded("cleartext auth client", move || {
        // The bundled server offers cleartext authentication; the client
        // refuses to send a password, so the startup must fail loudly.
        let error = PgConnection::connect("127.0.0.1", port, "alice", "opurom")
            .expect_err("the client must not answer a cleartext password request");
        let message = error.to_string();
        assert!(message.contains("UNSUPPORTED"), "{message}");
        assert!(message.contains("cleartext password"), "{message}");
    });
}

#[test]
fn tls_client_accepts_a_trusted_self_signed_certificate() {
    let (certificate, private_key) = self_signed();
    let anchor = certificate.clone();
    let server = PgServer::start(PgServerOptions {
        auth: PgAuth::Trust,
        tls: Some(PgTls {
            certificate,
            private_key,
        }),
    })
    .expect("bundled postgres server");
    let port = server.port();
    bounded("tls client", move || {
        let mut db = PgConnection::connect_tls(
            "127.0.0.1",
            port,
            "alice",
            "opurom",
            "localhost",
            Some(&anchor),
        )
        .expect("a trusted certificate must be accepted");
        assert_eq!(db.parameter("server_version"), Some("15.0"));
        assert_eq!(
            db.tls_version(),
            Some("TLSv1.3"),
            "the bundled server must negotiate TLS 1.3"
        );
        db.exec("CREATE TABLE Todo (id INTEGER PRIMARY KEY, title TEXT);")
            .expect("create table over TLS");
        db.exec("BEGIN;").expect("begin over TLS");
        db.exec("INSERT INTO Todo (id, title) VALUES (3, 'encrypted');")
            .expect("insert over TLS");
        db.exec("COMMIT;").expect("commit over TLS");
        let rows = db.query("SELECT * FROM Todo;").expect("select over TLS");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("id"), Some(&Value::Int(3)));
        assert_eq!(
            rows[0].get("title"),
            Some(&Value::Text("encrypted".to_string()))
        );
    });
}

#[test]
fn tls_client_rejects_an_untrusted_self_signed_certificate() {
    let (certificate, private_key) = self_signed();
    let server = PgServer::start(PgServerOptions {
        auth: PgAuth::Trust,
        tls: Some(PgTls {
            certificate,
            private_key,
        }),
    })
    .expect("bundled postgres server");
    let port = server.port();
    bounded("tls rejection client", move || {
        let error =
            PgConnection::connect_tls("127.0.0.1", port, "alice", "opurom", "localhost", None)
                .expect_err("an untrusted certificate must be rejected");
        let message = error.to_string();
        assert!(message.contains("certificate"), "{message}");
        assert!(
            message.contains("invalid peer certificate"),
            "the error must name the certificate failure: {message}"
        );
    });
}

#[test]
fn tls_client_rejects_a_certificate_signed_by_another_anchor() {
    let (certificate, private_key) = self_signed();
    let server = PgServer::start(PgServerOptions {
        auth: PgAuth::Trust,
        tls: Some(PgTls {
            certificate,
            private_key,
        }),
    })
    .expect("bundled postgres server");
    let port = server.port();
    // A different self-signed certificate is a valid anchor on its own but
    // does not chain to the server's certificate.
    let other_anchor = self_signed().0;
    bounded("tls wrong anchor client", move || {
        let error = PgConnection::connect_tls(
            "127.0.0.1",
            port,
            "alice",
            "opurom",
            "localhost",
            Some(&other_anchor),
        )
        .expect_err("a certificate from another issuer must be rejected");
        let message = error.to_string();
        assert!(message.contains("certificate"), "{message}");
        assert!(
            message.contains("invalid peer certificate"),
            "the error must name the certificate failure: {message}"
        );
    });
}

#[test]
fn tls_client_refuses_a_server_without_tls_support() {
    let server = plain_server();
    let port = server.port();
    bounded("tls refusal client", move || {
        let error =
            PgConnection::connect_tls("127.0.0.1", port, "alice", "opurom", "localhost", None)
                .expect_err("a plaintext server must not accept TLS");
        let message = error.to_string();
        assert!(message.contains("TLS"), "{message}");
    });
}

#[test]
fn bundled_server_keeps_the_connection_usable_after_an_error() {
    let server = plain_server();
    let port = server.port();
    bounded("bounded client", move || {
        let mut db = PgConnection::connect("127.0.0.1", port, "alice", "opurom")
            .expect("plain connection to the bundled server");
        let error = db
            .query("SELECT * FROM Missing;")
            .expect_err("an unknown relation must fail");
        assert!(error.to_string().contains("42P01"));
        db.exec("CREATE TABLE Todo (id INTEGER PRIMARY KEY);")
            .expect("create table after an error");
    });
}
