//! The rendezvous of sign-in with a QR code: a short-lived, unauthenticated place on the
//! homeserver where two devices swap messages to set up the secure channel of MSC4108.
//!
//! Two protocols are served:
//!
//! - MSC4388 (merged into the specification's proposals in November 2026): JSON, with
//!   `sequence_token` for compare-and-swap and transaction IDs for idempotent sends, at
//!   `/_matrix/client/v1/rendezvous` and its unstable form
//!   `/_matrix/client/unstable/io.element.msc4388/rendezvous`;
//! - the 2024 revision of MSC4108, which released matrix-rust-sdk versions still speak:
//!   `text/plain` bodies with `ETag`, `If-Match` and `If-None-Match`, created at
//!   `/_matrix/client/unstable/org.matrix.msc4108/rendezvous`, the session itself at
//!   `<issuer>/rendezvous/<id>`.
//!
//! Sessions live in memory, at most [`crate::RendezvousConfig::lifetime`], with payloads of
//! at most 4096 bytes, rate limits per address and a cap on how many exist at once.

// `Err` is the response to send, as axum handlers return it.
#![allow(clippy::result_large_err)]

use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
    time::{Duration, SystemTime},
};

use axum::{
    Json,
    body::Bytes,
    extract::{Path, State},
    response::{IntoResponse, Response},
};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde_json::{Value, json};

use crate::{
    config::RendezvousCreate,
    crypto,
    error::retry_after,
    host::HostError,
    http_util::{Peer, http_date, matrix_error},
    state::AppState,
};

/// The largest payload, in bytes (MSC4388, MSC4108).
pub(crate) const MAX_PAYLOAD: usize = 4096;
/// How many transaction IDs a session remembers; a normal exchange needs a handful.
const MAX_TXNS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Protocol {
    Msc4108,
    Msc4388,
}

/// Which path an MSC4388 request came in on: the error code for a concurrent write differs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Prefix {
    Stable,
    Unstable,
}

impl Prefix {
    fn concurrent_write(self) -> &'static str {
        match self {
            Prefix::Stable => "M_CONCURRENT_WRITE",
            Prefix::Unstable => "IO_ELEMENT_MSC4388_CONCURRENT_WRITE",
        }
    }
}

struct Session {
    protocol: Protocol,
    data: Vec<u8>,
    /// The revision: the MSC4388 `sequence_token`.
    seq: u64,
    /// The MSC4108 `ETag` of the revision: unique to the session and the revision.
    etag: String,
    modified: SystemTime,
    expires: SystemTime,
    /// MSC4388: the `sequence_token` each successful send answered, by transaction ID.
    txns: HashMap<String, String>,
    txn_order: VecDeque<String>,
}

/// The rendezvous sessions of this process.
#[derive(Default)]
pub(crate) struct Sessions(Mutex<HashMap<String, Session>>);

impl Sessions {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Session>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn prune(&self, now: SystemTime) {
        self.lock().retain(|_, s| s.expires > now);
    }
}

fn new_etag() -> String {
    format!("\"{}\"", crypto::random_id())
}

/// Whether `s` follows the opaque identifier grammar: 1 to 255 of `[0-9A-Za-z-._~]`.
fn is_opaque_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

fn not_found() -> Response {
    matrix_error(
        StatusCode::NOT_FOUND,
        "M_NOT_FOUND",
        "No such rendezvous session, or it has expired.",
    )
}

fn unrecognized() -> Response {
    matrix_error(
        StatusCode::NOT_FOUND,
        "M_UNRECOGNIZED",
        "The rendezvous API is not enabled.",
    )
}

fn limited(wait: Duration) -> Response {
    let body = json!({
        "errcode": "M_LIMIT_EXCEEDED",
        "error": "Too many requests.",
        "retry_after_ms": wait.as_millis() as u64,
    });
    let mut resp = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
    resp.headers_mut()
        .insert(header::RETRY_AFTER, retry_after(wait));
    resp
}

fn ms_left(expires: SystemTime, now: SystemTime) -> u64 {
    expires
        .duration_since(now)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

/// Whether the request is a browser navigating to the URL (a link someone was sent): the
/// payload is not shown then (MSC4388 "Unsafe content").
fn is_navigation(headers: &HeaderMap) -> bool {
    let get = |name: &str| headers.get(name).map(|v| v.as_bytes().to_ascii_lowercase());
    get("sec-fetch-mode").as_deref() == Some(b"navigate")
        || matches!(
            get("sec-fetch-dest").as_deref(),
            Some(b"document" | b"iframe" | b"frame" | b"embed" | b"object")
        )
}

/// Checks the limits that every rendezvous request is held to. `Err` is the answer.
fn admit(state: &AppState, peer: &Peer) -> Result<(), Response> {
    if !state.config.rendezvous.enabled {
        return Err(unrecognized());
    }
    state.limits.rendezvous.check(&peer.0).map_err(limited)
}

/// Whether the requester may create a session, by the server's policy. A request with an
/// access token that does not work is answered 401, never taken as one without a token
/// (MSC4388 "Authentication").
async fn may_create(state: &AppState, headers: &HeaderMap) -> Result<bool, Response> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty());
    let signed_in = match token {
        None => false,
        Some(token) => match state.host.authenticate(token).await {
            Ok(Some(_)) => true,
            Ok(None) | Err(HostError::Refused(_)) => {
                let body = json!({
                    "errcode": "M_UNKNOWN_TOKEN",
                    "error": "Unknown or expired access token.",
                    "soft_logout": false,
                });
                return Err((StatusCode::UNAUTHORIZED, Json(body)).into_response());
            }
            Err(HostError::Unsupported) => false,
            Err(e) => {
                tracing::error!(error = %e, "the homeserver failed to check an access token");
                return Err(matrix_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "M_UNKNOWN",
                    "Could not check the access token.",
                ));
            }
        },
    };
    Ok(match state.config.rendezvous.create {
        RendezvousCreate::Anyone => true,
        RendezvousCreate::SignedIn => signed_in,
    })
}

/// Creates a session with its first payload; `Err` is the answer.
fn create(
    state: &AppState,
    protocol: Protocol,
    data: Vec<u8>,
) -> Result<(String, SystemTime, SystemTime, String), Response> {
    let now = state.now();
    let expires = now + state.config.rendezvous.lifetime;
    let mut sessions = state.rendezvous.lock();
    if sessions.len() >= state.config.rendezvous.max_sessions {
        sessions.retain(|_, s| s.expires > now);
        if sessions.len() >= state.config.rendezvous.max_sessions {
            tracing::warn!("rendezvous sessions at their cap");
            return Err(limited(Duration::from_secs(10)));
        }
    }
    let id = crypto::random_id();
    let etag = new_etag();
    sessions.insert(
        id.clone(),
        Session {
            protocol,
            data,
            seq: 1,
            etag: etag.clone(),
            modified: now,
            expires,
            txns: HashMap::new(),
            txn_order: VecDeque::new(),
        },
    );
    Ok((id, now, expires, etag))
}

// ---- MSC4388 ----

/// `GET /_matrix/client/v1/rendezvous`: whether the requester may create a session.
pub(crate) async fn discover(
    State(state): State<AppState>,
    peer: Peer,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = admit(&state, &peer) {
        return r;
    }
    match may_create(&state, &headers).await {
        Ok(ok) => Json(json!({ "create_available": ok })).into_response(),
        Err(r) => r,
    }
}

/// `POST /_matrix/client/v1/rendezvous`
pub(crate) async fn create_4388(
    State(state): State<AppState>,
    peer: Peer,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = admit(&state, &peer) {
        return r;
    }
    if let Err(wait) = state.limits.rendezvous_create.check(&peer.0) {
        return limited(wait);
    }
    match may_create(&state, &headers).await {
        Ok(true) => {}
        Ok(false) => {
            return matrix_error(
                StatusCode::FORBIDDEN,
                "M_FORBIDDEN",
                "Sign in to create a rendezvous session on this server.",
            );
        }
        Err(r) => return r,
    }
    let Ok(value) = serde_json::from_slice::<Value>(&body) else {
        return matrix_error(
            StatusCode::BAD_REQUEST,
            "M_NOT_JSON",
            "The body is not JSON.",
        );
    };
    let Some(data) = value.get("data").and_then(Value::as_str) else {
        return matrix_error(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            "data must be a string.",
        );
    };
    if data.len() > MAX_PAYLOAD {
        return too_large();
    }
    match create(&state, Protocol::Msc4388, data.as_bytes().to_vec()) {
        Ok((id, now, expires, _)) => Json(json!({
            "id": id,
            "sequence_token": "1",
            "expires_in_ms": ms_left(expires, now),
        }))
        .into_response(),
        Err(r) => r,
    }
}

fn too_large() -> Response {
    matrix_error(
        StatusCode::PAYLOAD_TOO_LARGE,
        "M_TOO_LARGE",
        "The payload is larger than 4096 bytes.",
    )
}

/// `PUT /_matrix/client/v1/rendezvous/{id}/{txnId}`
pub(crate) async fn send_4388(
    state: AppState,
    prefix: Prefix,
    peer: Peer,
    id: String,
    txn: String,
    body: Bytes,
) -> Response {
    if let Err(r) = admit(&state, &peer) {
        return r;
    }
    let now = state.now();
    let mut sessions = state.rendezvous.lock();
    let Some(session) = sessions
        .get_mut(&id)
        .filter(|s| s.protocol == Protocol::Msc4388 && s.expires > now)
    else {
        return not_found();
    };
    // a retry of a send that succeeded gets the same answer, before anything is checked
    if let Some(seq) = session.txns.get(&txn) {
        return Json(json!({ "sequence_token": seq })).into_response();
    }
    if !is_opaque_id(&txn) {
        return matrix_error(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "The transaction ID is not an opaque identifier.",
        );
    }
    let Ok(value) = serde_json::from_slice::<Value>(&body) else {
        return matrix_error(
            StatusCode::BAD_REQUEST,
            "M_NOT_JSON",
            "The body is not JSON.",
        );
    };
    let (Some(seq), Some(data)) = (
        value.get("sequence_token").and_then(Value::as_str),
        value.get("data").and_then(Value::as_str),
    ) else {
        return matrix_error(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            "sequence_token and data must be strings.",
        );
    };
    if seq != session.seq.to_string() {
        return matrix_error(
            StatusCode::CONFLICT,
            prefix.concurrent_write(),
            "The payload has changed since that sequence token.",
        );
    }
    if data.len() > MAX_PAYLOAD {
        return too_large();
    }
    session.seq += 1;
    session.data = data.as_bytes().to_vec();
    session.etag = new_etag();
    session.modified = now;
    let token = session.seq.to_string();
    if session.txn_order.len() >= MAX_TXNS
        && let Some(oldest) = session.txn_order.pop_front()
    {
        session.txns.remove(&oldest);
    }
    session.txns.insert(txn.clone(), token.clone());
    session.txn_order.push_back(txn);
    Json(json!({ "sequence_token": token })).into_response()
}

/// `GET /_matrix/client/v1/rendezvous/{id}`
pub(crate) async fn receive_4388(
    state: AppState,
    peer: Peer,
    headers: HeaderMap,
    id: String,
) -> Response {
    if let Err(r) = admit(&state, &peer) {
        return r;
    }
    if is_navigation(&headers) {
        return matrix_error(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            "A rendezvous session is not a page.",
        );
    }
    let now = state.now();
    let sessions = state.rendezvous.lock();
    match sessions
        .get(&id)
        .filter(|s| s.protocol == Protocol::Msc4388 && s.expires > now)
    {
        Some(s) => Json(json!({
            "data": String::from_utf8_lossy(&s.data),
            "sequence_token": s.seq.to_string(),
            "expires_in_ms": ms_left(s.expires, now),
        }))
        .into_response(),
        None => not_found(),
    }
}

/// `DELETE /_matrix/client/v1/rendezvous/{id}`
pub(crate) async fn cancel_4388(state: AppState, peer: Peer, id: String) -> Response {
    if let Err(r) = admit(&state, &peer) {
        return r;
    }
    let now = state.now();
    let mut sessions = state.rendezvous.lock();
    match sessions.get(&id) {
        Some(s) if s.protocol == Protocol::Msc4388 && s.expires > now => {
            sessions.remove(&id);
            Json(json!({})).into_response()
        }
        _ => not_found(),
    }
}

// ---- MSC4108, 2024 revision ----

/// The headers every MSC4108 response of a session carries.
fn common_headers(h: &mut HeaderMap, etag: &str, expires: SystemTime, modified: SystemTime) {
    let set = |h: &mut HeaderMap, name: header::HeaderName, v: &str| {
        if let Ok(v) = HeaderValue::from_str(v) {
            h.insert(name, v);
        }
    };
    set(h, header::ETAG, etag);
    set(h, header::EXPIRES, &http_date(expires));
    set(h, header::LAST_MODIFIED, &http_date(modified));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    h.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static("ETag"),
    );
}

/// An MSC4108 error: a new error code goes in `org.matrix.msc4108.errcode`, under
/// `M_UNKNOWN`.
fn error_4108(status: StatusCode, errcode: &str, error: &str) -> Response {
    let body = if errcode == "M_CONCURRENT_WRITE" {
        json!({ "errcode": "M_UNKNOWN", "org.matrix.msc4108.errcode": errcode, "error": error })
    } else {
        json!({ "errcode": errcode, "error": error })
    };
    let mut resp = (status, Json(body)).into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// The payload of an MSC4108 request: a `text/plain` body of at most 4096 bytes.
fn text_body(headers: &HeaderMap, body: &[u8]) -> Result<Vec<u8>, Response> {
    let Some(ct) = headers.get(header::CONTENT_TYPE) else {
        return Err(error_4108(
            StatusCode::BAD_REQUEST,
            "M_MISSING_PARAM",
            "Content-Type is required.",
        ));
    };
    let media = ct
        .to_str()
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    if !media.eq_ignore_ascii_case("text/plain") {
        return Err(error_4108(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "Content-Type must be text/plain.",
        ));
    }
    if body.len() > MAX_PAYLOAD {
        return Err(error_4108(
            StatusCode::PAYLOAD_TOO_LARGE,
            "M_TOO_LARGE",
            "The payload is larger than 4096 bytes.",
        ));
    }
    Ok(body.to_vec())
}

/// `POST /_matrix/client/unstable/org.matrix.msc4108/rendezvous`
pub(crate) async fn create_4108(
    State(state): State<AppState>,
    peer: Peer,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = admit(&state, &peer) {
        return r;
    }
    if let Err(wait) = state.limits.rendezvous_create.check(&peer.0) {
        return limited(wait);
    }
    match may_create(&state, &headers).await {
        Ok(true) => {}
        Ok(false) => {
            return error_4108(
                StatusCode::FORBIDDEN,
                "M_FORBIDDEN",
                "Sign in to create a rendezvous session on this server.",
            );
        }
        Err(r) => return r,
    }
    let data = match text_body(&headers, &body) {
        Ok(d) => d,
        Err(r) => return r,
    };
    match create(&state, Protocol::Msc4108, data) {
        Ok((id, now, expires, etag)) => {
            let url = state.url(&format!("rendezvous/{id}"));
            let mut resp = (StatusCode::CREATED, Json(json!({ "url": url }))).into_response();
            common_headers(resp.headers_mut(), &etag, expires, now);
            resp
        }
        Err(r) => r,
    }
}

/// An `ETag` as sent back in `If-Match` or `If-None-Match`: strong and single.
fn etag_matches(sent: &HeaderValue, current: &str) -> Option<bool> {
    let s = sent.to_str().ok()?.trim();
    if s.starts_with("W/") || s.contains(',') || s == "*" {
        return None;
    }
    let bare = |e: &str| e.trim_matches('"').to_owned();
    Some(crypto::ct_eq(bare(s).as_bytes(), bare(current).as_bytes()))
}

/// `GET <issuer>/rendezvous/{id}`
pub(crate) async fn receive_4108(
    State(state): State<AppState>,
    peer: Peer,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = admit(&state, &peer) {
        return r;
    }
    if is_navigation(&headers) {
        return error_4108(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            "A rendezvous session is not a page.",
        );
    }
    let now = state.now();
    let sessions = state.rendezvous.lock();
    let Some(s) = sessions
        .get(&id)
        .filter(|s| s.protocol == Protocol::Msc4108 && s.expires > now)
    else {
        return error_4108(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "No such rendezvous session.",
        );
    };
    let unchanged = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| etag_matches(v, &s.etag))
        .unwrap_or(false);
    let mut resp = if unchanged {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        let mut r = (StatusCode::OK, s.data.clone()).into_response();
        r.headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        r
    };
    common_headers(resp.headers_mut(), &s.etag, s.expires, s.modified);
    resp
}

/// `PUT <issuer>/rendezvous/{id}`
pub(crate) async fn send_4108(
    State(state): State<AppState>,
    peer: Peer,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    if let Err(r) = admit(&state, &peer) {
        return r;
    }
    let Some(if_match) = headers.get(header::IF_MATCH).cloned() else {
        return error_4108(
            StatusCode::BAD_REQUEST,
            "M_MISSING_PARAM",
            "If-Match is required.",
        );
    };
    let data = match text_body(&headers, &body) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let now = state.now();
    let mut sessions = state.rendezvous.lock();
    let Some(s) = sessions
        .get_mut(&id)
        .filter(|s| s.protocol == Protocol::Msc4108 && s.expires > now)
    else {
        return error_4108(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "No such rendezvous session.",
        );
    };
    match etag_matches(&if_match, &s.etag) {
        None => {
            return error_4108(
                StatusCode::BAD_REQUEST,
                "M_INVALID_PARAM",
                "If-Match must be one strong ETag.",
            );
        }
        Some(false) => {
            let mut resp = error_4108(
                StatusCode::PRECONDITION_FAILED,
                "M_CONCURRENT_WRITE",
                "The payload has changed since that ETag.",
            );
            common_headers(resp.headers_mut(), &s.etag, s.expires, s.modified);
            return resp;
        }
        Some(true) => {}
    }
    s.data = data;
    s.seq += 1;
    s.etag = new_etag();
    s.modified = now;
    let mut resp = StatusCode::ACCEPTED.into_response();
    common_headers(resp.headers_mut(), &s.etag, s.expires, s.modified);
    resp
}

/// `DELETE <issuer>/rendezvous/{id}`
pub(crate) async fn cancel_4108(
    State(state): State<AppState>,
    peer: Peer,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = admit(&state, &peer) {
        return r;
    }
    let now = state.now();
    let mut sessions = state.rendezvous.lock();
    match sessions.get(&id) {
        Some(s) if s.protocol == Protocol::Msc4108 && s.expires > now => {
            sessions.remove(&id);
            StatusCode::NO_CONTENT.into_response()
        }
        _ => error_4108(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "No such rendezvous session.",
        ),
    }
}

/// CORS of the MSC4108 session URL: any origin, and the headers its protocol needs.
pub(crate) async fn cors_4108(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let preflight = req.method() == http::Method::OPTIONS;
    let mut resp = if preflight {
        StatusCode::NO_CONTENT.into_response()
    } else {
        next.run(req).await
    };
    if state.config.cors {
        let h = resp.headers_mut();
        h.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        );
        h.insert(
            header::ACCESS_CONTROL_EXPOSE_HEADERS,
            HeaderValue::from_static("ETag"),
        );
        if preflight {
            h.insert(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                HeaderValue::from_static("GET, PUT, DELETE"),
            );
            h.insert(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                HeaderValue::from_static("Content-Type, If-Match, If-None-Match"),
            );
            h.insert(
                header::ACCESS_CONTROL_MAX_AGE,
                HeaderValue::from_static("86400"),
            );
        }
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_ids() {
        assert!(is_opaque_id("mLDVAsAqLnzUonKnmnzUyC7B"));
        assert!(is_opaque_id("a.b-c_d~e"));
        assert!(!is_opaque_id(""));
        assert!(!is_opaque_id("a/b"));
        assert!(!is_opaque_id(&"a".repeat(256)));
    }

    #[test]
    fn etags() {
        let cur = "\"abc\"";
        assert_eq!(
            etag_matches(&HeaderValue::from_static("\"abc\""), cur),
            Some(true)
        );
        assert_eq!(
            etag_matches(&HeaderValue::from_static("abc"), cur),
            Some(true)
        );
        assert_eq!(
            etag_matches(&HeaderValue::from_static("\"abd\""), cur),
            Some(false)
        );
        assert_eq!(
            etag_matches(&HeaderValue::from_static("W/\"abc\""), cur),
            None
        );
        assert_eq!(
            etag_matches(&HeaderValue::from_static("\"a\", \"b\""), cur),
            None
        );
    }

    #[test]
    fn navigations() {
        let mut h = HeaderMap::new();
        assert!(!is_navigation(&h));
        h.insert("sec-fetch-mode", HeaderValue::from_static("cors"));
        h.insert("sec-fetch-dest", HeaderValue::from_static("empty"));
        assert!(!is_navigation(&h));
        h.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        assert!(is_navigation(&h));
    }
}
