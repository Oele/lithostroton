//! The revocation endpoint (RFC 7009, as the specification's "Token revocation" uses it):
//! revoking an access token or a refresh token ends its session, both tokens with the device.

use axum::{
    body::Bytes,
    extract::State,
    response::{IntoResponse, Response},
};
use http::{HeaderMap, StatusCode, header};

use crate::{
    client,
    error::OAuthError,
    form::{Params, is_form},
    host::TokenStatus,
    http_util::Peer,
    state::AppState,
};

/// `POST revocation_endpoint`
pub(crate) async fn revocation_endpoint(
    State(state): State<AppState>,
    peer: Peer,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match revoke(&state, &peer, &headers, &body).await {
        Ok(()) => {
            let mut resp = StatusCode::OK.into_response();
            resp.headers_mut().insert(
                header::CACHE_CONTROL,
                http::HeaderValue::from_static("no-store"),
            );
            resp
        }
        Err(e) => e.into_response(),
    }
}

async fn revoke(
    state: &AppState,
    peer: &Peer,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), OAuthError> {
    if let Err(wait) = state.limits.revocation.check(&peer.0) {
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
    let Some(token) = params.get("token") else {
        return Err(OAuthError::invalid_request("token is required"));
    };
    // `token_type_hint` only helps a lookup; the host finds either kind.
    let session = match state.host.token_status(token).await? {
        TokenStatus::Active { session, .. } | TokenStatus::Replaced { session } => session,
        // RFC 7009 section 2.2: an invalid token is answered 200 as well
        TokenStatus::Unknown => return Ok(()),
    };
    // The specification: revoke even without a client_id, or with another client's, so that
    // secret scanners can revoke leaked tokens.
    let named = params.get("client_id");
    if named.is_some_and(|c| Some(c) != session.client_id.as_deref()) {
        let known = match named {
            Some(c) => client::find(state, c).await?.is_some(),
            None => false,
        };
        tracing::warn!(
            user_id = %session.user_id,
            device_id = %session.device_id,
            named_client_known = known,
            "a token was revoked by a client it was not issued to"
        );
    }
    state
        .host
        .end_session(&session.user_id, &session.device_id)
        .await?;
    tracing::info!(
        user_id = %session.user_id,
        device_id = %session.device_id,
        "session revoked"
    );
    Ok(())
}
