//! The authorization endpoint (RFC 6749 section 4.1, with PKCE S256 from RFC 7636 always
//! required), the consent page, and the authorization codes.
//!
//! A request whose client or redirect URI is wrong ends on an error page of ours and is
//! never redirected (RFC 6749 section 4.1.2.1: no open redirects). Every other error is sent
//! to the client's redirect URI. Responses carry `iss` (RFC 9207).

use axum::{
    body::Bytes,
    extract::{RawQuery, State},
    response::Response,
};
use http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};

use crate::{
    client::{self, Client, GRANT_AUTHORIZATION_CODE},
    crypto,
    error::OAuthError,
    form::Params,
    http_util::{Csrf, Peer, check_form, see_other},
    login::{Next, bad_form, host_failed, is_ref, oauth_failed, unavailable},
    pages::{self, Page, esc, hidden},
    scope::{self, MatrixScope},
    session,
    state::AppState,
};

const KIND_REQUEST: &str = "authorization";
pub(crate) const KIND_CODE: &str = "code";
pub(crate) const KIND_CODE_USED: &str = "code_used";

/// The longest query string the authorization endpoint reads.
const MAX_QUERY: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ResponseMode {
    Query,
    Fragment,
}

/// An authorization request waiting for the user to sign in and consent.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct AuthRequest {
    pub client_id: String,
    /// As the client sent it (with the port it chose, for a loopback URI).
    pub redirect_uri: String,
    pub response_mode: ResponseMode,
    pub state: Option<String>,
    pub scope: Vec<String>,
    pub device_id: String,
    pub code_challenge: String,
    pub login_hint: Option<String>,
}

/// An authorization code, stored under its digest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct CodeGrant {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub scope: String,
    pub device_id: String,
    pub user_id: String,
}

/// What became of an exchanged code: the session it made, ended if the code comes again.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct CodeUsed {
    pub user_id: String,
    pub device_id: String,
}

/// A redirect to the client with the response parameters, `state` and `iss` added.
pub(crate) fn redirect_to_client(
    state: &AppState,
    redirect_uri: &str,
    mode: ResponseMode,
    client_state: Option<&str>,
    params: &[(&str, &str)],
) -> Response {
    let mut ser = form_urlencoded::Serializer::new(String::new());
    for (k, v) in params {
        ser.append_pair(k, v);
    }
    if let Some(s) = client_state {
        ser.append_pair("state", s);
    }
    ser.append_pair("iss", &state.issuer.url);
    let encoded = ser.finish();
    let mut location = redirect_uri.to_owned();
    match mode {
        ResponseMode::Query => {
            if !location.contains('?') {
                location.push('?');
            } else if !location.ends_with('?') && !location.ends_with('&') {
                location.push('&');
            }
        }
        // registered redirect URIs have no fragment
        ResponseMode::Fragment => location.push('#'),
    }
    location.push_str(&encoded);
    see_other(&location)
}

fn error_to_client(
    state: &AppState,
    redirect_uri: &str,
    mode: ResponseMode,
    client_state: Option<&str>,
    error: &str,
    description: &str,
) -> Response {
    redirect_to_client(
        state,
        redirect_uri,
        mode,
        client_state,
        &[("error", error), ("error_description", description)],
    )
}

fn bad_request_page(state: &AppState, message: &str) -> Response {
    pages::error(
        state,
        StatusCode::BAD_REQUEST,
        "This sign-in request is not valid",
        message,
    )
}

/// `GET authorization_endpoint`
pub(crate) async fn authorize(
    State(state): State<AppState>,
    peer: Peer,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    if state.limits.authorize.check(&peer.0).is_err() {
        return pages::error(
            &state,
            StatusCode::TOO_MANY_REQUESTS,
            "Too many sign-in attempts",
            "Wait a minute, then go back to the application and start again.",
        );
    }
    let query = query.unwrap_or_default();
    if query.len() > MAX_QUERY {
        return bad_request_page(&state, "The request is too long.");
    }
    let Ok(params) = Params::parse(query.as_bytes()) else {
        return bad_request_page(&state, "A parameter of the request appears twice.");
    };

    // First the client and its redirect URI: until both are right, nothing goes back to it.
    let Some(client_id) = params.get("client_id") else {
        return bad_request_page(&state, "The application did not say who it is (client_id).");
    };
    let client = match client::find(&state, client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return bad_request_page(
                &state,
                "The application is not registered here. Go back to the application and start again.",
            );
        }
        Err(_) => return unavailable(&state),
    };
    let Some(redirect_uri) = params.get("redirect_uri") else {
        return bad_request_page(
            &state,
            "The application did not say where to return (redirect_uri).",
        );
    };
    if !client.match_redirect_uri(redirect_uri) {
        tracing::info!(client_id = %client.client_id, "authorization request with an unregistered redirect URI");
        return bad_request_page(
            &state,
            "The application asked to return to an address it did not register.",
        );
    }

    let client_state = params.get("state");
    let mode = match params.get("response_mode") {
        None | Some("query") => ResponseMode::Query,
        Some("fragment") => ResponseMode::Fragment,
        Some(_) => {
            return error_to_client(
                &state,
                redirect_uri,
                ResponseMode::Query,
                client_state,
                "invalid_request",
                "response_mode must be query or fragment",
            );
        }
    };
    let fail = |error: &str, description: &str| {
        error_to_client(&state, redirect_uri, mode, client_state, error, description)
    };

    match params.get("response_type") {
        Some("code") => {}
        None => return fail("invalid_request", "response_type is required"),
        Some(_) => {
            return fail(
                "unsupported_response_type",
                "only response_type=code is supported",
            );
        }
    }
    if !client.allows_grant(GRANT_AUTHORIZATION_CODE) {
        return fail(
            "unauthorized_client",
            "the client did not register the authorization_code grant",
        );
    }
    let Some(challenge) = params.get("code_challenge") else {
        return fail(
            "invalid_request",
            "PKCE is required: code_challenge is missing",
        );
    };
    if params.get("code_challenge_method") != Some("S256") {
        return fail("invalid_request", "code_challenge_method must be S256");
    }
    // BASE64URL(SHA256(verifier)) without padding is 43 characters
    if challenge.len() != 43
        || !challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return fail("invalid_request", "code_challenge is not an S256 challenge");
    }
    let Some(scope_str) = params.get("scope") else {
        return fail("invalid_scope", "scope is required");
    };
    let scope = match scope::parse_login_scope(scope_str) {
        Ok(s) => s,
        Err(e) => return fail("invalid_scope", &e.to_string()),
    };

    let prompts: Vec<&str> = params
        .get("prompt")
        .map(|p| p.split(' ').filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();
    let create = prompts.contains(&"create");
    if create && !state.config.registration {
        return fail(
            "invalid_request",
            "this server does not offer registration (prompt=create)",
        );
    }

    let request = AuthRequest {
        client_id: client.client_id.clone(),
        redirect_uri: redirect_uri.to_owned(),
        response_mode: mode,
        state: client_state.map(str::to_owned),
        scope: scope.tokens.clone(),
        device_id: scope.device_id.clone(),
        code_challenge: challenge.to_owned(),
        login_hint: params.get("login_hint").map(str::to_owned),
    };

    let current = match session::current(&state, &headers).await {
        Ok(c) => c,
        Err(_) => return unavailable(&state),
    };
    if prompts.contains(&"none") {
        // nothing may be shown to the user, and consent is always asked
        let error = if current.is_some() {
            "consent_required"
        } else {
            "login_required"
        };
        return fail(error, "this server asks the user every time");
    }

    let id = crypto::random_id();
    let expires = state.now() + state.config.lifetimes.authorization_request;
    match state
        .store
        .insert(KIND_REQUEST, &id, &request, Some(expires))
        .await
    {
        Ok(true) => {}
        _ => return unavailable(&state),
    }
    let next = Next::Authorize(id);
    if create {
        return see_other(&state.path(&format!("register?next={}", next.encode())));
    }
    if current.is_none() || prompts.contains(&"login") {
        let mut path = next.login_path(&state);
        if let Some(user) = request.login_hint.as_deref().and_then(hint_username) {
            path.push_str("&username=");
            path.push_str(&form_urlencoded::byte_serialize(user.as_bytes()).collect::<String>());
        }
        return see_other(&path);
    }
    see_other(&next.path(&state))
}

/// The username of a `login_hint` of the form `mxid:@user:server` (MSC4198).
fn hint_username(hint: &str) -> Option<&str> {
    hint.strip_prefix("mxid:")
        .filter(|u| u.starts_with('@') && u.len() <= 255)
}

#[derive(Deserialize)]
pub(crate) struct ConsentQuery {
    req: Option<String>,
}

/// The consent page of an authorization request (`GET /consent?req=`).
pub(crate) async fn consent_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<ConsentQuery>,
) -> Response {
    let Some(id) = q.req.filter(|r| r.len() <= 64) else {
        return expired_page(&state);
    };
    let request = match state.store.get::<AuthRequest>(KIND_REQUEST, &id).await {
        Ok(Some(r)) => r.value,
        Ok(None) => return expired_page(&state),
        Err(_) => return unavailable(&state),
    };
    let next = Next::Authorize(id.clone());
    let current = match session::current(&state, &headers).await {
        Ok(Some(c)) => c,
        Ok(None) => return see_other(&next.login_path(&state)),
        Err(_) => return unavailable(&state),
    };
    let client = match client::find(&state, &request.client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return expired_page(&state),
        Err(_) => return unavailable(&state),
    };
    let existing = match state.host.devices(&current.user.user_id).await {
        Ok(devices) => devices
            .into_iter()
            .any(|d| d.device_id == request.device_id),
        Err(e) => return host_failed(&state, e),
    };
    let csrf = Csrf::of(&state, &headers);
    let body = format!(
        "{whoami}<p>An application asks to use your Matrix account.</p>\n{card}\
         <h2>If you allow it, the application can</h2>\n\
         <ul><li>read and send your messages, and everything else your account can do on \
         {server}, for as long as you stay signed in to it,</li>\n\
         <li>as a new session with the device ID <strong class=\"uri\">{device}</strong>.</li></ul>\n\
         {replace}\
         <p>Only allow it if you just started signing in to this application yourself.</p>\n\
         <div class=\"actions\">\n\
         <form method=\"post\" action=\"{action}\">{csrf}{req}{allow}\
         <button type=\"submit\">Allow</button></form>\n\
         <form method=\"post\" action=\"{action}\">{csrf}{req}{deny}\
         <button type=\"submit\" class=\"secondary\">Deny</button></form>\n</div>\n",
        whoami = pages::signed_in_as(
            &current.user.user_id,
            &state.path("logout"),
            &csrf.token(&state, "logout"),
            &next.encode()
        ),
        card = pages::client_card(&state, &client, Some(&request.redirect_uri)),
        server = esc(&state.config.server_name),
        device = esc(&request.device_id),
        replace = if existing {
            "<p class=\"alert\">You already have a session with this device ID. Allowing this \
             signs that session out and gives its device to this application.</p>\n"
        } else {
            ""
        },
        action = esc(&state.path("consent")),
        csrf = hidden("csrf", &csrf.token(&state, "consent")),
        req = hidden("req", &id),
        allow = hidden("action", "allow"),
        deny = hidden("action", "deny"),
    );
    let mut page = Page::new("Allow access to your account?", body).cookie(csrf.set);
    page.forms_redirect_out = true;
    page.render(&state)
}

fn expired_page(state: &AppState) -> Response {
    pages::error(
        state,
        StatusCode::NOT_FOUND,
        "This sign-in request has expired",
        "Go back to the application and start signing in again.",
    )
}

/// The answer of the consent page (`POST /consent`).
pub(crate) async fn consent_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(form) = Params::parse(&body) else {
        return bad_form(&state);
    };
    if !check_form(&state, &headers, "consent", form.get("csrf")) {
        return bad_form(&state);
    }
    let Some(id) = form.get("req").filter(|r| is_ref(r)) else {
        return expired_page(&state);
    };
    let current = match session::current(&state, &headers).await {
        Ok(Some(c)) => c,
        Ok(None) => return see_other(&Next::Authorize(id.to_owned()).login_path(&state)),
        Err(_) => return unavailable(&state),
    };
    // taken: one answer per request
    let request = match state.store.take::<AuthRequest>(KIND_REQUEST, id).await {
        Ok(Some(r)) => r,
        Ok(None) => return expired_page(&state),
        Err(_) => return unavailable(&state),
    };
    let client = match client::find(&state, &request.client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return expired_page(&state),
        Err(_) => return unavailable(&state),
    };
    match form.get("action") {
        Some("allow") => {}
        _ => {
            tracing::info!(client_id = %client.client_id, user_id = %current.user.user_id, "access denied by the user");
            return error_to_client(
                &state,
                &request.redirect_uri,
                request.response_mode,
                request.state.as_deref(),
                "access_denied",
                "The user denied access.",
            );
        }
    }
    match issue_code(&state, &client, &request, &current.user.user_id).await {
        Ok(code) => {
            tracing::info!(
                client_id = %client.client_id,
                user_id = %current.user.user_id,
                device_id = %request.device_id,
                "access allowed, code issued"
            );
            redirect_to_client(
                &state,
                &request.redirect_uri,
                request.response_mode,
                request.state.as_deref(),
                &[("code", &code)],
            )
        }
        Err(e) => oauth_failed(&state, e),
    }
}

async fn issue_code(
    state: &AppState,
    client: &Client,
    request: &AuthRequest,
    user_id: &str,
) -> Result<String, OAuthError> {
    let grant = CodeGrant {
        client_id: client.client_id.clone(),
        redirect_uri: request.redirect_uri.clone(),
        code_challenge: request.code_challenge.clone(),
        scope: MatrixScope {
            tokens: request.scope.clone(),
            device_id: request.device_id.clone(),
        }
        .to_scope_string(),
        device_id: request.device_id.clone(),
        user_id: user_id.to_owned(),
    };
    let expires = state.now() + state.config.lifetimes.authorization_code;
    loop {
        let code = crypto::random_secret();
        if state
            .store
            .insert(KIND_CODE, &crypto::secret_key(&code), &grant, Some(expires))
            .await?
        {
            return Ok(code);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_hints() {
        assert_eq!(
            hint_username("mxid:@alice:example.org"),
            Some("@alice:example.org")
        );
        assert_eq!(hint_username("alice"), None);
        assert_eq!(hint_username("mxid:alice"), None);
    }
}
