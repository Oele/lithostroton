//! The rendezvous of sign-in with a QR code: MSC4388 and the 2024 revision of MSC4108.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::*;
use http::StatusCode;
use lithostroton::RendezvousCreate;
use serde_json::json;

const V1: &str = "/_matrix/client/v1/rendezvous";
const UNSTABLE: &str = "/_matrix/client/unstable/io.element.msc4388/rendezvous";
const MSC4108: &str = "/_matrix/client/unstable/org.matrix.msc4108/rendezvous";

fn matrix_error(r: &Resp, status: StatusCode, errcode: &str) {
    assert_eq!(r.status, status, "{}", r.body);
    assert_eq!(r.json()["errcode"], errcode, "{}", r.body);
}

async fn create(lab: &Lab, base: &str, data: &str) -> (String, String) {
    let r = lab.post_json(base, &json!({ "data": data })).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let b = r.json();
    assert_eq!(b["sequence_token"], "1");
    assert_eq!(b["expires_in_ms"], 300_000);
    (b["id"].as_str().unwrap().to_owned(), "1".to_owned())
}

async fn put(lab: &Lab, base: &str, id: &str, txn: &str, seq: &str, data: &str) -> Resp {
    lab.send(
        "PUT",
        &format!("{base}/{id}/{txn}"),
        &[("content-type", "application/json")],
        &json!({ "sequence_token": seq, "data": data }).to_string(),
    )
    .await
}

#[tokio::test]
async fn msc4388_exchange() {
    let lab = Lab::new().await;
    for (base, concurrent) in [
        (V1, "M_CONCURRENT_WRITE"),
        (UNSTABLE, "IO_ELEMENT_MSC4388_CONCURRENT_WRITE"),
    ] {
        let r = lab.get(base).await;
        assert_eq!(r.json(), json!({ "create_available": true }));

        let (id, _) = create(&lab, base, "hello from A").await;
        assert!(id.len() >= 16);
        let r = lab.get(&format!("{base}/{id}")).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.json()["data"], "hello from A");
        assert_eq!(r.json()["sequence_token"], "1");
        assert_eq!(r.header("cache-control").as_deref(), Some("no-store"));

        // B answers
        let r = put(
            &lab,
            base,
            &id,
            "txnB1aaaaaaaaaaaaaaaaaaaa",
            "1",
            "hello from B",
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        assert_eq!(r.json()["sequence_token"], "2");
        let r = lab.get(&format!("{base}/{id}")).await;
        assert_eq!(r.json()["data"], "hello from B");

        // A writes with the token it had: refused
        let r = put(&lab, base, &id, "txnA1aaaaaaaaaaaaaaaaaaaa", "1", "stale").await;
        matrix_error(&r, StatusCode::CONFLICT, concurrent);

        // B repeats its send (the answer was lost): the same answer, nothing changes
        let r = put(
            &lab,
            base,
            &id,
            "txnB1aaaaaaaaaaaaaaaaaaaa",
            "1",
            "hello from B",
        )
        .await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.json()["sequence_token"], "2");
        // even with a body that would be refused
        let r = lab
            .send(
                "PUT",
                &format!("{base}/{id}/txnB1aaaaaaaaaaaaaaaaaaaa"),
                &[],
                "not json",
            )
            .await;
        assert_eq!(r.json()["sequence_token"], "2");
        assert_eq!(
            lab.get(&format!("{base}/{id}")).await.json()["data"],
            "hello from B"
        );

        // A with the current token
        let r = put(
            &lab,
            base,
            &id,
            "txnA2aaaaaaaaaaaaaaaaaaaa",
            "2",
            "again from A",
        )
        .await;
        assert_eq!(r.json()["sequence_token"], "3");

        let r = lab.send("DELETE", &format!("{base}/{id}"), &[], "").await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.json(), json!({}));
        matrix_error(
            &lab.get(&format!("{base}/{id}")).await,
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
        );
        matrix_error(
            &lab.send("DELETE", &format!("{base}/{id}"), &[], "").await,
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
        );
    }
}

#[tokio::test]
async fn msc4388_refusals() {
    let lab = Lab::new().await;
    let (id, _) = create(&lab, V1, "x").await;
    matrix_error(
        &lab.send("POST", V1, &[], "not json").await,
        StatusCode::BAD_REQUEST,
        "M_NOT_JSON",
    );
    matrix_error(
        &lab.post_json(V1, &json!({ "data": 7 })).await,
        StatusCode::BAD_REQUEST,
        "M_BAD_JSON",
    );
    let big = "a".repeat(4097);
    matrix_error(
        &lab.post_json(V1, &json!({ "data": big })).await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "M_TOO_LARGE",
    );
    assert_eq!(
        lab.post_json(V1, &json!({ "data": "a".repeat(4096) }))
            .await
            .status,
        StatusCode::OK
    );
    matrix_error(
        &put(&lab, V1, &id, "bad!txn", "1", "x").await,
        StatusCode::BAD_REQUEST,
        "M_INVALID_PARAM",
    );
    matrix_error(
        &put(&lab, V1, &id, "txn1", "1", &big).await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "M_TOO_LARGE",
    );
    matrix_error(
        &lab.send("PUT", &format!("{V1}/{id}/txn2"), &[], "{\"data\": \"x\"}")
            .await,
        StatusCode::BAD_REQUEST,
        "M_BAD_JSON",
    );
    matrix_error(
        &put(&lab, V1, "nosuchsession", "txn3", "1", "x").await,
        StatusCode::NOT_FOUND,
        "M_NOT_FOUND",
    );
    // a browser navigating to it (a link someone was sent) does not see the payload
    let r = lab
        .send(
            "GET",
            &format!("{V1}/{id}"),
            &[
                ("sec-fetch-mode", "navigate"),
                ("sec-fetch-dest", "document"),
            ],
            "",
        )
        .await;
    matrix_error(&r, StatusCode::FORBIDDEN, "M_FORBIDDEN");
}

#[tokio::test]
async fn sessions_expire() {
    let lab = Lab::new().await;
    let (id, _) = create(&lab, V1, "x").await;
    lab.clock.advance(Duration::from_secs(299));
    let r = lab.get(&format!("{V1}/{id}")).await;
    assert_eq!(r.json()["expires_in_ms"], 1000);
    lab.clock.advance(Duration::from_secs(1));
    matrix_error(
        &lab.get(&format!("{V1}/{id}")).await,
        StatusCode::NOT_FOUND,
        "M_NOT_FOUND",
    );
    matrix_error(
        &put(&lab, V1, &id, "txn", "1", "x").await,
        StatusCode::NOT_FOUND,
        "M_NOT_FOUND",
    );
}

#[tokio::test]
async fn creation_policy_and_tokens() {
    let lab = Lab::with(|c| c.rendezvous.create = RendezvousCreate::SignedIn).await;
    assert_eq!(
        lab.get(V1).await.json(),
        json!({ "create_available": false })
    );
    matrix_error(
        &lab.post_json(V1, &json!({ "data": "x" })).await,
        StatusCode::FORBIDDEN,
        "M_FORBIDDEN",
    );
    // a token that does not work is a 401, never a request without a token
    let r = lab
        .send("GET", V1, &[("authorization", "Bearer nonsense")], "")
        .await;
    matrix_error(&r, StatusCode::UNAUTHORIZED, "M_UNKNOWN_TOKEN");

    let client_id = lab.register_web().await;
    let t = lab.sign_in(&client_id, "QRDEV").await;
    let bearer = format!("Bearer {}", t["access_token"].as_str().unwrap());
    let r = lab.send("GET", V1, &[("authorization", &bearer)], "").await;
    assert_eq!(r.json(), json!({ "create_available": true }));
    let r = lab
        .send(
            "POST",
            V1,
            &[
                ("authorization", &bearer),
                ("content-type", "application/json"),
            ],
            "{\"data\": \"x\"}",
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    // sending and receiving need no token
    let id = r.json()["id"].as_str().unwrap().to_owned();
    assert_eq!(lab.get(&format!("{V1}/{id}")).await.status, StatusCode::OK);
}

#[tokio::test]
async fn rendezvous_can_be_off() {
    let lab = Lab::with(|c| c.rendezvous.enabled = false).await;
    for r in [
        lab.get(V1).await,
        lab.post_json(V1, &json!({ "data": "x" })).await,
        lab.send("POST", MSC4108, &[("content-type", "text/plain")], "")
            .await,
    ] {
        matrix_error(&r, StatusCode::NOT_FOUND, "M_UNRECOGNIZED");
    }
}

#[tokio::test]
async fn creation_is_rate_limited_and_capped() {
    let lab = Lab::new().await;
    for _ in 0..10 {
        create(&lab, V1, "x").await;
    }
    let r = lab.post_json(V1, &json!({ "data": "x" })).await;
    matrix_error(&r, StatusCode::TOO_MANY_REQUESTS, "M_LIMIT_EXCEEDED");
    assert!(r.json()["retry_after_ms"].as_u64().unwrap() > 0);

    let lab = Lab::with(|c| c.rendezvous.max_sessions = 2).await;
    create(&lab, V1, "x").await;
    create(&lab, V1, "x").await;
    let r = lab.post_json(V1, &json!({ "data": "x" })).await;
    matrix_error(&r, StatusCode::TOO_MANY_REQUESTS, "M_LIMIT_EXCEEDED");
    // expired sessions make room
    lab.clock.advance(Duration::from_secs(300));
    create(&lab, V1, "x").await;
}

// ---- MSC4108, 2024 revision ----

fn common_headers(r: &Resp) -> String {
    for h in ["etag", "expires", "last-modified"] {
        assert!(r.header(h).is_some(), "{h} missing");
    }
    assert!(r.header("expires").unwrap().ends_with(" GMT"));
    assert_eq!(r.header("cache-control").as_deref(), Some("no-store"));
    assert_eq!(r.header("pragma").as_deref(), Some("no-cache"));
    assert!(
        r.header("access-control-expose-headers")
            .unwrap()
            .contains("ETag")
    );
    r.header("etag").unwrap()
}

#[tokio::test]
async fn msc4108_exchange() {
    let lab = Lab::new().await;
    let r = lab
        .send("POST", MSC4108, &[("content-type", "text/plain")], "")
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    let etag1 = common_headers(&r);
    let url = r.json()["url"].as_str().unwrap().to_owned();
    assert!(url.starts_with(&format!("{ISSUER}rendezvous/")), "{url}");

    // the other device reads the initial (empty) payload
    let r = lab.get(&url).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("content-type").as_deref(), Some("text/plain"));
    assert_eq!(common_headers(&r), etag1);
    assert_eq!(r.body, "");
    let r = lab
        .send("GET", &url, &[("if-none-match", &etag1)], "")
        .await;
    assert_eq!(r.status, StatusCode::NOT_MODIFIED);
    common_headers(&r);

    // and writes
    let r = lab
        .send(
            "PUT",
            &url,
            &[("content-type", "text/plain"), ("if-match", &etag1)],
            "message one",
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{}", r.body);
    let etag2 = common_headers(&r);
    assert_ne!(etag1, etag2);
    let r = lab
        .send("GET", &url, &[("if-none-match", &etag1)], "")
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body, "message one");
    assert_eq!(r.header("etag").unwrap(), etag2);

    // a write with an old ETag
    let r = lab
        .send(
            "PUT",
            &url,
            &[("content-type", "text/plain"), ("if-match", &etag1)],
            "stale",
        )
        .await;
    assert_eq!(r.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(r.json()["errcode"], "M_UNKNOWN");
    assert_eq!(r.json()["org.matrix.msc4108.errcode"], "M_CONCURRENT_WRITE");
    assert_eq!(common_headers(&r), etag2);

    // malformed writes
    let r = lab
        .send("PUT", &url, &[("content-type", "text/plain")], "x")
        .await;
    matrix_error(&r, StatusCode::BAD_REQUEST, "M_MISSING_PARAM");
    let r = lab
        .send(
            "PUT",
            &url,
            &[("content-type", "application/json"), ("if-match", &etag2)],
            "{}",
        )
        .await;
    matrix_error(&r, StatusCode::BAD_REQUEST, "M_INVALID_PARAM");
    let r = lab
        .send(
            "PUT",
            &url,
            &[("content-type", "text/plain"), ("if-match", "W/\"weak\"")],
            "x",
        )
        .await;
    matrix_error(&r, StatusCode::BAD_REQUEST, "M_INVALID_PARAM");
    let r = lab
        .send(
            "PUT",
            &url,
            &[("content-type", "text/plain"), ("if-match", &etag2)],
            &"a".repeat(4097),
        )
        .await;
    matrix_error(&r, StatusCode::PAYLOAD_TOO_LARGE, "M_TOO_LARGE");

    // not reachable as an MSC4388 session
    let id = url.rsplit('/').next().unwrap();
    matrix_error(
        &lab.get(&format!("{V1}/{id}")).await,
        StatusCode::NOT_FOUND,
        "M_NOT_FOUND",
    );

    let r = lab.send("DELETE", &url, &[], "").await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    matrix_error(&lab.get(&url).await, StatusCode::NOT_FOUND, "M_NOT_FOUND");
}

#[tokio::test]
async fn msc4108_creation_needs_text_plain() {
    let lab = Lab::new().await;
    matrix_error(
        &lab.send("POST", MSC4108, &[], "").await,
        StatusCode::BAD_REQUEST,
        "M_MISSING_PARAM",
    );
    matrix_error(
        &lab.send(
            "POST",
            MSC4108,
            &[("content-type", "application/json")],
            "{}",
        )
        .await,
        StatusCode::BAD_REQUEST,
        "M_INVALID_PARAM",
    );
    matrix_error(
        &lab.send(
            "POST",
            MSC4108,
            &[("content-type", "text/plain")],
            &"a".repeat(4097),
        )
        .await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "M_TOO_LARGE",
    );
}

#[tokio::test]
async fn msc4108_session_url_cors() {
    let lab = Lab::new().await;
    let r = lab
        .send("POST", MSC4108, &[("content-type", "text/plain")], "")
        .await;
    let url = r.json()["url"].as_str().unwrap().to_owned();
    let r = lab
        .send(
            "OPTIONS",
            &url,
            &[
                ("origin", "https://app.example.com"),
                ("access-control-request-method", "PUT"),
                ("access-control-request-headers", "if-match, content-type"),
            ],
            "",
        )
        .await;
    assert!(r.status.is_success());
    assert_eq!(
        r.header("access-control-allow-origin").as_deref(),
        Some("*")
    );
    let methods = r.header("access-control-allow-methods").unwrap();
    for m in ["GET", "PUT", "DELETE"] {
        assert!(methods.contains(m));
    }
    let headers = r.header("access-control-allow-headers").unwrap();
    assert!(headers.contains("If-Match") && headers.contains("If-None-Match"));
    let r = lab.get(&url).await;
    assert_eq!(
        r.header("access-control-allow-origin").as_deref(),
        Some("*")
    );
}

#[tokio::test]
async fn client_router_stops_with_the_rest() {
    let lab = Lab::new().await;
    let app = lab.app.clone();
    lab.embedded.shutdown().await;
    use tower::ServiceExt;
    let r = app
        .oneshot(
            http::Request::get(V1)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
}
