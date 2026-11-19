//! The device authorization grant (RFC 8628; the specification's "Device authorisation
//! flow"): the device authorization endpoint, the verification pages where the user enters
//! or confirms the user code, and the device code grant of the token endpoint.

use std::time::Duration;

use axum::{
    Json,
    body::Bytes,
    extract::{Query, State},
    response::{IntoResponse, Response},
};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    client::{self, Client, GRANT_DEVICE_CODE},
    crypto,
    error::OAuthError,
    form::{Params, is_form},
    host::Tokens,
    http_util::{Csrf, Peer, check_form, see_other},
    login::{Next, bad_form, host_failed, unavailable},
    pages::{self, Page, alert, esc, hidden},
    scope, session,
    state::{AppState, Poll},
    token::{authenticate_client, start_session},
};

const KIND_GRANT: &str = "device_grant";
const KIND_USER_CODE: &str = "user_code";

/// The letters of user codes: no vowels (no words), nothing that looks like a digit
/// (RFC 8628 section 6.1). 20 letters, 8 of them: about 34.6 bits.
const USER_CODE_ALPHABET: &[u8; 20] = b"BCDFGHJKLMNPQRSTVWXZ";
const USER_CODE_LEN: usize = 8;

/// How long a device grant is kept after it expired, to answer `expired_token` rather than
/// `invalid_grant`.
const EXPIRED_GRACE: Duration = Duration::from_secs(600);

/// A poll that comes this much earlier than the interval still counts as on time: network
/// delays move requests.
const POLL_LENIENCY: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum GrantStatus {
    Pending,
    Approved { user_id: String },
    Denied,
}

/// A device authorization request, stored under the digest of its device code.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct DeviceGrant {
    pub client_id: String,
    pub scope: String,
    pub device_id: String,
    pub user_code: String,
    /// Unix seconds.
    pub expires_at: u64,
    #[serde(flatten)]
    pub status: GrantStatus,
}

fn new_user_code() -> String {
    (0..USER_CODE_LEN)
        .map(|_| {
            USER_CODE_ALPHABET[crypto::random_below(USER_CODE_ALPHABET.len() as u32) as usize]
                as char
        })
        .collect()
}

/// A user code as typed: upper case, without dashes, spaces or other punctuation. `None` if
/// it cannot be one.
pub(crate) fn normalize_user_code(typed: &str) -> Option<String> {
    let code: String = typed
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    (code.len() == USER_CODE_LEN && code.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)))
        .then_some(code)
}

/// A user code for people: `WDJB-MJHT`.
fn display_user_code(code: &str) -> String {
    let (a, b) = code.split_at(code.len() / 2);
    format!("{a}-{b}")
}

/// `POST device_authorization_endpoint` (RFC 8628 section 3.1)
pub(crate) async fn device_authorization_endpoint(
    State(state): State<AppState>,
    peer: Peer,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match device_authorization(&state, &peer, &headers, &body).await {
        Ok(resp) => resp,
        Err(e) => e.into_response(),
    }
}

async fn device_authorization(
    state: &AppState,
    peer: &Peer,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, OAuthError> {
    if let Err(wait) = state.limits.device_authorization.check(&peer.0) {
        return Err(OAuthError::rate_limited(wait));
    }
    if !is_form(headers) {
        return Err(OAuthError::invalid_request(
            "the body must be application/x-www-form-urlencoded",
        ));
    }
    if headers.contains_key(header::AUTHORIZATION) {
        return Err(OAuthError {
            www_authenticate: true,
            ..OAuthError::invalid_client(
                "client authentication is not supported: public clients only",
            )
        });
    }
    let params = Params::parse(body)
        .map_err(|r| OAuthError::invalid_request(format!("{} appears twice", r.0)))?;
    let client = authenticate_client(state, &params).await?;
    if !client.allows_grant(GRANT_DEVICE_CODE) {
        return Err(OAuthError::unauthorized_client(
            "the client did not register the device_code grant",
        ));
    }
    let Some(scope_str) = params.get("scope") else {
        return Err(OAuthError::invalid_scope("scope is required"));
    };
    let scope = scope::parse_login_scope(scope_str)
        .map_err(|e| OAuthError::invalid_scope(e.to_string()))?;

    let ttl = state.config.lifetimes.device_code;
    let expires = state.now() + ttl;
    let device_code = crypto::random_secret();
    let grant_key = crypto::secret_key(&device_code);
    let user_code = loop {
        let code = new_user_code();
        if state
            .store
            .insert(KIND_USER_CODE, &code, &grant_key, Some(expires))
            .await?
        {
            break code;
        }
    };
    let grant = DeviceGrant {
        client_id: client.client_id.clone(),
        scope: scope.to_scope_string(),
        device_id: scope.device_id.clone(),
        user_code: user_code.clone(),
        expires_at: state.unix() + ttl.as_secs(),
        status: GrantStatus::Pending,
    };
    if !state
        .store
        .insert(
            KIND_GRANT,
            &grant_key,
            &grant,
            Some(expires + EXPIRED_GRACE),
        )
        .await?
    {
        return Err(OAuthError::server_error());
    }
    tracing::info!(
        client_id = %client.client_id,
        device_id = %grant.device_id,
        "device authorization requested"
    );
    let interval = state.config.lifetimes.device_poll_interval.as_secs().max(1);
    let body = json!({
        "device_code": device_code,
        "user_code": display_user_code(&user_code),
        "verification_uri": state.url("link"),
        "verification_uri_complete": state.url(&format!("link?code={user_code}")),
        "expires_in": ttl.as_secs(),
        "interval": interval,
    });
    let mut resp = Json(body).into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(resp)
}

/// The device code grant of the token endpoint (RFC 8628 section 3.4 and 3.5).
pub(crate) async fn device_code_grant(
    state: &AppState,
    client: &Client,
    params: &Params,
) -> Result<(Tokens, String), OAuthError> {
    let Some(device_code) = params.get("device_code") else {
        return Err(OAuthError::invalid_request("device_code is required"));
    };
    let key = crypto::secret_key(device_code);
    let Some(read) = state.store.get::<DeviceGrant>(KIND_GRANT, &key).await? else {
        return Err(OAuthError::invalid_grant("the device code is not valid"));
    };
    let grant = read.value;
    if !crypto::ct_eq(grant.client_id.as_bytes(), client.client_id.as_bytes()) {
        return Err(OAuthError::invalid_grant(
            "the device code was issued to another client",
        ));
    }
    if state.unix() >= grant.expires_at {
        return Err(OAuthError::expired_token());
    }
    if too_fast(state, &key, grant.expires_at) {
        return Err(OAuthError::slow_down());
    }
    match grant.status {
        GrantStatus::Pending => Err(OAuthError::authorization_pending()),
        GrantStatus::Denied => {
            state.store.delete(KIND_GRANT, &key).await?;
            forget_poll(state, &key);
            Err(OAuthError::access_denied("The user denied access."))
        }
        GrantStatus::Approved { user_id } => {
            // taken: of two polls at once, one gets the tokens
            if state
                .store
                .take::<DeviceGrant>(KIND_GRANT, &key)
                .await?
                .is_none()
            {
                return Err(OAuthError::invalid_grant("the device code is not valid"));
            }
            forget_poll(state, &key);
            let tokens =
                start_session(state, client, &user_id, &grant.device_id, &grant.scope).await?;
            tracing::info!(
                client_id = %client.client_id,
                user_id = %user_id,
                device_id = %grant.device_id,
                "device code exchanged"
            );
            Ok((tokens, grant.scope))
        }
    }
}

/// Whether this poll comes before the interval has passed since the last one. If so the
/// interval grows by five seconds (RFC 8628 section 3.5, `slow_down`).
fn too_fast(state: &AppState, key: &str, expires_at: u64) -> bool {
    let now = state.now();
    let expires = std::time::UNIX_EPOCH + Duration::from_secs(expires_at);
    let mut polls = state.polls.lock().unwrap_or_else(|e| e.into_inner());
    let poll = polls.entry(key.to_owned()).or_insert(Poll {
        last: std::time::UNIX_EPOCH,
        interval: state.config.lifetimes.device_poll_interval,
        expires,
    });
    let elapsed = now.duration_since(poll.last).unwrap_or(Duration::ZERO);
    poll.last = now;
    if elapsed + POLL_LENIENCY < poll.interval {
        poll.interval += Duration::from_secs(5);
        true
    } else {
        false
    }
}

fn forget_poll(state: &AppState, key: &str) {
    state
        .polls
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(key);
}

/// The grant of a user code that is still waiting for the user.
async fn pending_grant(
    state: &AppState,
    user_code: &str,
) -> Result<Option<(String, crate::store::Read<DeviceGrant>)>, OAuthError> {
    let Some(key) = state.store.get::<String>(KIND_USER_CODE, user_code).await? else {
        return Ok(None);
    };
    let Some(read) = state
        .store
        .get::<DeviceGrant>(KIND_GRANT, &key.value)
        .await?
    else {
        return Ok(None);
    };
    if read.value.status != GrantStatus::Pending || state.unix() >= read.value.expires_at {
        return Ok(None);
    }
    Ok(Some((key.value, read)))
}

#[derive(Deserialize)]
pub(crate) struct LinkQuery {
    code: Option<String>,
}

fn code_entry_page(state: &AppState, typed: Option<&str>, error: Option<&str>) -> Page {
    let body = format!(
        "<p>Enter the code your other device shows.</p>\n{alert}\
         <form method=\"get\" action=\"{action}\">\n\
         <label for=\"code\">Code</label>\n\
         <input type=\"text\" id=\"code\" name=\"code\" class=\"code\" value=\"{typed}\" \
         autocomplete=\"one-time-code\" autocapitalize=\"characters\" spellcheck=\"false\" required autofocus>\n\
         <div class=\"actions\"><button type=\"submit\">Continue</button></div>\n</form>\n",
        alert = alert(error),
        action = esc(&state.path("link")),
        typed = esc(typed.unwrap_or("")),
    );
    Page::new("Sign in a device", body)
}

/// `GET /link`: the verification URI, with or without the user code.
pub(crate) async fn link_form(
    State(state): State<AppState>,
    peer: Peer,
    headers: HeaderMap,
    Query(q): Query<LinkQuery>,
) -> Response {
    if !state.config.device_authorization {
        return pages::error(
            &state,
            StatusCode::NOT_FOUND,
            "Not found",
            "There is nothing here.",
        );
    }
    let Some(typed) = q.code.filter(|c| !c.is_empty() && c.len() <= 64) else {
        return code_entry_page(&state, None, None).render(&state);
    };
    if state.limits.user_code.check(&peer.0).is_err() {
        return code_entry_page(
            &state,
            Some(&typed),
            Some("Too many codes tried. Wait a minute and try again."),
        )
        .status(StatusCode::TOO_MANY_REQUESTS)
        .render(&state);
    }
    let invalid = || {
        code_entry_page(
            &state,
            Some(&typed),
            Some("This code is not valid, or it has expired. Check the code on your device."),
        )
        .status(StatusCode::NOT_FOUND)
        .render(&state)
    };
    let Some(code) = normalize_user_code(&typed) else {
        return invalid();
    };
    let (_, read) = match pending_grant(&state, &code).await {
        Ok(Some(g)) => g,
        Ok(None) => return invalid(),
        Err(_) => return unavailable(&state),
    };
    let grant = read.value;
    let next = Next::Link(code.clone());
    let current = match session::current(&state, &headers).await {
        Ok(Some(c)) => c,
        Ok(None) => return see_other(&next.login_path(&state)),
        Err(_) => return unavailable(&state),
    };
    let client = match client::find(&state, &grant.client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return invalid(),
        Err(_) => return unavailable(&state),
    };
    let existing = match state.host.devices(&current.user.user_id).await {
        Ok(devices) => devices.into_iter().any(|d| d.device_id == grant.device_id),
        Err(e) => return host_failed(&state, e),
    };
    let csrf = Csrf::of(&state, &headers);
    let body = format!(
        "{whoami}<p>A device asks to sign in to your Matrix account.</p>\n\
         <div class=\"card\"><p>Check that the device shows this code:</p>\n\
         <p class=\"code\"><strong>{code}</strong></p></div>\n{card}\
         <h2>If you allow it, the device can</h2>\n\
         <ul><li>read and send your messages, and everything else your account can do on \
         {server}, for as long as it stays signed in,</li>\n\
         <li>as a new session with the device ID <strong class=\"uri\">{device}</strong>.</li></ul>\n\
         {replace}\
         <p><strong>Only allow it if the device is in front of you and you started signing it in \
         yourself.</strong> Nobody else needs this code: if someone sent you this link or the \
         code, deny.</p>\n\
         <div class=\"actions\">\n\
         <form method=\"post\" action=\"{action}\">{csrf}{codefield}{allow}\
         <button type=\"submit\">Allow</button></form>\n\
         <form method=\"post\" action=\"{action}\">{csrf}{codefield}{deny}\
         <button type=\"submit\" class=\"secondary\">Deny</button></form>\n</div>\n",
        whoami = pages::signed_in_as(
            &current.user.user_id,
            &state.path("logout"),
            &csrf.token(&state, "logout"),
            &next.encode()
        ),
        code = esc(&display_user_code(&code)),
        card = pages::client_card(&state, &client, None),
        server = esc(&state.config.server_name),
        device = esc(&grant.device_id),
        replace = if existing {
            "<p class=\"alert\">You already have a session with this device ID. Allowing this \
             signs that session out and gives its device to the new device.</p>\n"
        } else {
            ""
        },
        action = esc(&state.path("link")),
        csrf = hidden("csrf", &csrf.token(&state, "link")),
        codefield = hidden("code", &code),
        allow = hidden("action", "allow"),
        deny = hidden("action", "deny"),
    );
    Page::new("Sign in a device?", body)
        .cookie(csrf.set)
        .render(&state)
}

/// `POST /link`: the user's answer for a device.
pub(crate) async fn link_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !state.config.device_authorization {
        return pages::error(
            &state,
            StatusCode::NOT_FOUND,
            "Not found",
            "There is nothing here.",
        );
    }
    let Ok(form) = Params::parse(&body) else {
        return bad_form(&state);
    };
    if !check_form(&state, &headers, "link", form.get("csrf")) {
        return bad_form(&state);
    }
    let Some(code) = form.get("code").and_then(normalize_user_code) else {
        return bad_form(&state);
    };
    let current = match session::current(&state, &headers).await {
        Ok(Some(c)) => c,
        Ok(None) => return see_other(&Next::Link(code).login_path(&state)),
        Err(_) => return unavailable(&state),
    };
    let gone = || {
        pages::error(
            &state,
            StatusCode::NOT_FOUND,
            "This code has expired",
            "Start signing in again on your device.",
        )
    };
    let (key, read) = match pending_grant(&state, &code).await {
        Ok(Some(g)) => g,
        Ok(None) => return gone(),
        Err(_) => return unavailable(&state),
    };
    let allow = form.get("action") == Some("allow");
    let mut grant = read.value.clone();
    grant.status = if allow {
        GrantStatus::Approved {
            user_id: current.user.user_id.clone(),
        }
    } else {
        GrantStatus::Denied
    };
    let keep_until = std::time::UNIX_EPOCH + Duration::from_secs(grant.expires_at) + EXPIRED_GRACE;
    // compare-and-swap: of two answers, the first counts
    match state
        .store
        .replace(KIND_GRANT, &key, &read.raw, &grant, Some(keep_until))
        .await
    {
        Ok(true) => {}
        Ok(false) => return gone(),
        Err(_) => return unavailable(&state),
    }
    let _ = state.store.delete(KIND_USER_CODE, &code).await;
    if allow {
        tracing::info!(
            client_id = %grant.client_id,
            user_id = %current.user.user_id,
            device_id = %grant.device_id,
            "device allowed"
        );
        Page::new(
            "Your device is being signed in",
            "<p>Go back to your device: it will finish signing in by itself in a few \
             seconds. You can close this page.</p>\n"
                .to_owned(),
        )
        .render(&state)
    } else {
        tracing::info!(
            client_id = %grant.client_id,
            user_id = %current.user.user_id,
            "device denied"
        );
        Page::new(
            "The device was not signed in",
            "<p>You denied access. The device cannot use your account.</p>\n".to_owned(),
        )
        .render(&state)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn user_codes() {
        for _ in 0..100 {
            let c = new_user_code();
            assert_eq!(c.len(), 8);
            assert_eq!(normalize_user_code(&c).as_deref(), Some(c.as_str()));
            let shown = display_user_code(&c);
            assert_eq!(
                normalize_user_code(&shown.to_lowercase()).as_deref(),
                Some(c.as_str())
            );
        }
        assert_eq!(
            normalize_user_code("wdjb-mjht").as_deref(),
            Some("WDJBMJHT")
        );
        assert_eq!(
            normalize_user_code("WDJB MJHT").as_deref(),
            Some("WDJBMJHT")
        );
        assert_eq!(normalize_user_code("WDJB-MJH"), None);
        assert_eq!(
            normalize_user_code("ABCD-EFGH"),
            None,
            "vowels are not in the alphabet"
        );
    }
}
