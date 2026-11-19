//! The token endpoint (RFC 6749 section 3.2): the authorization code grant with PKCE, the
//! refresh token grant with rotation, and the device code grant of RFC 8628.

use axum::{
    Json,
    body::Bytes,
    extract::State,
    response::{IntoResponse, Response},
};
use http::{HeaderMap, HeaderValue, header};
use serde_json::json;

use crate::{
    authorize::{CodeGrant, CodeUsed, KIND_CODE, KIND_CODE_USED},
    client::{self, Client, GRANT_AUTHORIZATION_CODE, GRANT_DEVICE_CODE, GRANT_REFRESH_TOKEN},
    crypto, device,
    error::OAuthError,
    form::{Params, is_form},
    host::{NewSession, TokenKind, TokenStatus, Tokens},
    http_util::Peer,
    scope::same_scope,
    state::AppState,
};

/// `POST token_endpoint`
pub(crate) async fn token_endpoint(
    State(state): State<AppState>,
    peer: Peer,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match token(&state, &peer, &headers, &body).await {
        Ok(resp) => resp,
        Err(e) => e.into_response(),
    }
}

async fn token(
    state: &AppState,
    peer: &Peer,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, OAuthError> {
    if !is_form(headers) {
        return Err(OAuthError::invalid_request(
            "the body must be application/x-www-form-urlencoded",
        ));
    }
    let params = Params::parse(body)
        .map_err(|r| OAuthError::invalid_request(format!("{} appears twice", r.0)))?;
    let grant_type = params.get("grant_type");
    if let Err(wait) = state.limits.token.check(&peer.0) {
        // a 4xx answer to a refresh makes the client sign out (the specification's "Token
        // refresh flow"): a refresh over the limit gets a 503 and tries again
        return Err(if grant_type == Some(GRANT_REFRESH_TOKEN) {
            OAuthError::temporarily_unavailable(Some(wait))
        } else {
            OAuthError::rate_limited(wait)
        });
    }
    if headers.contains_key(header::AUTHORIZATION) {
        // only public clients are registered: no client authenticates
        return Err(OAuthError {
            www_authenticate: true,
            ..OAuthError::invalid_client(
                "client authentication is not supported: public clients only",
            )
        });
    }
    let Some(grant_type) = grant_type else {
        return Err(OAuthError::invalid_request("grant_type is required"));
    };
    let known = [
        GRANT_AUTHORIZATION_CODE,
        GRANT_REFRESH_TOKEN,
        GRANT_DEVICE_CODE,
    ];
    if !known.contains(&grant_type)
        || (grant_type == GRANT_DEVICE_CODE && !state.config.device_authorization)
    {
        return Err(OAuthError::unsupported_grant_type(format!(
            "grant_type {grant_type} is not supported"
        )));
    }
    let client = authenticate_client(state, &params).await?;
    if !client.allows_grant(grant_type) {
        return Err(OAuthError::unauthorized_client(format!(
            "the client did not register the {grant_type} grant"
        )));
    }
    let (tokens, scope) = match grant_type {
        GRANT_AUTHORIZATION_CODE => authorization_code(state, &client, &params).await?,
        GRANT_REFRESH_TOKEN => refresh_token(state, &client, &params).await?,
        _ => device::device_code_grant(state, &client, &params).await?,
    };
    Ok(token_response(&tokens, &scope))
}

/// The client of a request to the token endpoint: a public client names itself with
/// `client_id` (RFC 6749 section 3.2.1).
pub(crate) async fn authenticate_client(
    state: &AppState,
    params: &Params,
) -> Result<Client, OAuthError> {
    let Some(client_id) = params.get("client_id") else {
        return Err(OAuthError::invalid_request("client_id is required"));
    };
    client::find(state, client_id)
        .await?
        .ok_or_else(|| OAuthError::invalid_client("unknown client"))
}

/// The successful answer (RFC 6749 section 5.1), never cached.
pub(crate) fn token_response(tokens: &Tokens, scope: &str) -> Response {
    let body = json!({
        "access_token": tokens.access_token,
        "token_type": "Bearer",
        "expires_in": tokens.expires_in.as_secs(),
        "refresh_token": tokens.refresh_token,
        "scope": scope,
    });
    let mut resp = Json(body).into_response();
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    resp
}

/// Whether `verifier` is a PKCE code verifier: 43 to 128 unreserved characters (RFC 7636
/// section 4.1).
fn is_code_verifier(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

async fn authorization_code(
    state: &AppState,
    client: &Client,
    params: &Params,
) -> Result<(Tokens, String), OAuthError> {
    let Some(code) = params.get("code") else {
        return Err(OAuthError::invalid_request("code is required"));
    };
    let key = crypto::secret_key(code);
    // Taken, so that it works once: a code that fails a check below is gone too, and its
    // verifier cannot be guessed at.
    let Some(grant) = state.store.take::<CodeGrant>(KIND_CODE, &key).await? else {
        // A code that was exchanged before: whoever has it now may not be the client, so the
        // session it made ends (RFC 6749 section 4.1.2).
        if let Some(used) = state.store.take::<CodeUsed>(KIND_CODE_USED, &key).await? {
            tracing::warn!(
                user_id = %used.user_id,
                device_id = %used.device_id,
                "an authorization code was used twice: ending the session it made"
            );
            state
                .host
                .end_session(&used.user_id, &used.device_id)
                .await?;
        }
        return Err(OAuthError::invalid_grant("the code is not valid"));
    };
    if !crypto::ct_eq(grant.client_id.as_bytes(), client.client_id.as_bytes()) {
        return Err(OAuthError::invalid_grant(
            "the code was issued to another client",
        ));
    }
    if params.get("redirect_uri") != Some(grant.redirect_uri.as_str()) {
        return Err(OAuthError::invalid_grant(
            "redirect_uri is not the one of the authorization request",
        ));
    }
    let Some(verifier) = params.get("code_verifier") else {
        return Err(OAuthError::invalid_grant("code_verifier is required"));
    };
    if !is_code_verifier(verifier)
        || !crypto::ct_eq(
            crypto::s256(verifier).as_bytes(),
            grant.code_challenge.as_bytes(),
        )
    {
        return Err(OAuthError::invalid_grant(
            "the code_verifier does not match",
        ));
    }
    let tokens = start_session(
        state,
        client,
        &grant.user_id,
        &grant.device_id,
        &grant.scope,
    )
    .await?;
    let used = CodeUsed {
        user_id: grant.user_id.clone(),
        device_id: grant.device_id.clone(),
    };
    let expires = state.now() + state.config.lifetimes.authorization_code;
    state
        .store
        .insert(KIND_CODE_USED, &key, &used, Some(expires))
        .await?;
    tracing::info!(
        client_id = %client.client_id,
        user_id = %grant.user_id,
        device_id = %grant.device_id,
        "authorization code exchanged"
    );
    Ok((tokens, grant.scope))
}

/// Creates the session of a grant, for a user who may still sign in.
pub(crate) async fn start_session(
    state: &AppState,
    client: &Client,
    user_id: &str,
    device_id: &str,
    scope: &str,
) -> Result<Tokens, OAuthError> {
    if state.host.user(user_id).await?.is_none() {
        return Err(OAuthError::invalid_grant("the user can no longer sign in"));
    }
    Ok(state
        .host
        .create_session(NewSession {
            user_id: user_id.to_owned(),
            device_id: device_id.to_owned(),
            client_id: client.client_id.clone(),
            client_name: client.metadata.client_name.clone(),
            scope: scope.to_owned(),
        })
        .await?)
}

async fn refresh_token(
    state: &AppState,
    client: &Client,
    params: &Params,
) -> Result<(Tokens, String), OAuthError> {
    let Some(refresh) = params.get("refresh_token") else {
        return Err(OAuthError::invalid_request("refresh_token is required"));
    };
    let session = match state.host.token_status(refresh).await? {
        TokenStatus::Active {
            kind: TokenKind::Refresh,
            session,
        } => session,
        TokenStatus::Replaced { session } => {
            // an old refresh token came back after its successor was used: one of the two
            // holders should not have it
            tracing::warn!(
                user_id = %session.user_id,
                device_id = %session.device_id,
                "a replaced refresh token was used: ending the session"
            );
            state
                .host
                .end_session(&session.user_id, &session.device_id)
                .await?;
            return Err(OAuthError::invalid_grant("the refresh token is not valid"));
        }
        _ => return Err(OAuthError::invalid_grant("the refresh token is not valid")),
    };
    let issued_to = session.client_id.as_deref().unwrap_or("");
    if !crypto::ct_eq(issued_to.as_bytes(), client.client_id.as_bytes()) {
        return Err(OAuthError::invalid_grant(
            "the refresh token was issued to another client",
        ));
    }
    let scope = session.scope.clone().unwrap_or_default();
    if let Some(asked) = params.get("scope")
        && !same_scope(asked, &scope)
    {
        return Err(OAuthError::invalid_scope(
            "a refresh keeps the scope of the session",
        ));
    }
    let Some(tokens) = state.host.refresh_session(refresh).await? else {
        return Err(OAuthError::invalid_grant("the refresh token is not valid"));
    };
    Ok((tokens, scope))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_verifiers() {
        assert!(is_code_verifier(&"a".repeat(43)));
        assert!(is_code_verifier(&"Az09-._~".repeat(16)));
        assert!(!is_code_verifier(&"a".repeat(42)));
        assert!(!is_code_verifier(&"a".repeat(129)));
        assert!(!is_code_verifier(&format!("{}+", "a".repeat(43))));
    }
}
