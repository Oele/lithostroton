//! Secrets are stored as digests and never logged. In a test binary of its own, so that
//! the log subscriber is the global one and sees every event.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::{
    io::Write,
    sync::{Arc, Mutex},
};

use common::*;
use http::StatusCode;

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn secrets_are_neither_stored_nor_logged() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    // global, not per thread: this binary runs this one test
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let mut secrets: Vec<String> = vec![PASSWORD.to_owned()];

    // the authorization code flow, with a failed sign-in first
    let pkce = Pkce::new();
    let mut b = lab.browser();
    let r = b
        .get(&AuthParams::new(&client_id, "DEV1", &pkce).url())
        .await;
    let r2 = b.login(&r.location(), "alice", "wrong-password-xyz").await;
    assert_eq!(r2.status, StatusCode::BAD_REQUEST);
    secrets.push("wrong-password-xyz".into());
    let code = b
        .authorize_and_allow(&AuthParams::new(&client_id, "DEV1", &pkce))
        .await;
    secrets.push(code.clone());
    secrets.push(pkce.verifier.clone());
    secrets.extend(b.cookies.values().cloned());
    let r = exchange(&lab, &code, &client_id, WEB_REDIRECT, &pkce.verifier).await;
    let t = r.json();
    // a refresh, a code replay, a revocation
    let r = lab
        .token(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", t["refresh_token"].as_str().unwrap()),
            ("client_id", &client_id),
        ])
        .await;
    let t2 = r.json();
    for tok in [&t, &t2] {
        secrets.push(tok["access_token"].as_str().unwrap().to_owned());
        secrets.push(tok["refresh_token"].as_str().unwrap().to_owned());
    }
    lab.post_form(
        "oauth2/revoke",
        &[("token", t2["access_token"].as_str().unwrap())],
    )
    .await;
    exchange(&lab, &code, &client_id, WEB_REDIRECT, &pkce.verifier).await;

    // the device grant
    let d = lab
        .post_form(
            "oauth2/device",
            &[("client_id", &client_id), ("scope", &scope("DEV2"))],
        )
        .await
        .json();
    let device_code = d["device_code"].as_str().unwrap().to_owned();
    secrets.push(device_code.clone());
    let store_dump_before = lab.store.dump();

    // the store holds digests, not the secrets
    for (kind, key, value) in store_dump_before.iter().chain(lab.store.dump().iter()) {
        let value = String::from_utf8_lossy(value);
        for s in &secrets {
            assert!(!key.contains(s.as_str()), "{kind} key holds a secret");
            assert!(!value.contains(s.as_str()), "{kind} value holds a secret");
        }
    }

    // and nothing secret was logged, though something was
    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("code issued"), "{logs}");
    assert!(logs.contains("session revoked"), "{logs}");
    assert!(logs.contains("used twice"), "{logs}");
    for s in &secrets {
        assert!(!logs.contains(s.as_str()), "a secret in the logs: {logs}");
    }
}
