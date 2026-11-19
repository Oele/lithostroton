//! Authorization server metadata (RFC 8414), which the homeserver serves at
//! `/_matrix/client/v1/auth_metadata` (the specification's "Server metadata discovery").

use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use http::{HeaderValue, header};
use serde_json::{Value, json};

use crate::{
    client::{GRANT_AUTHORIZATION_CODE, GRANT_DEVICE_CODE, GRANT_REFRESH_TOKEN},
    scope::API_SCOPES,
    state::{AppState, Inner},
};

pub(crate) fn metadata(state: &Inner) -> Value {
    let mut grant_types = vec![GRANT_AUTHORIZATION_CODE, GRANT_REFRESH_TOKEN];
    if state.config.device_authorization {
        grant_types.push(GRANT_DEVICE_CODE);
    }
    let mut m = json!({
        "issuer": state.issuer.url,
        "authorization_endpoint": state.url("oauth2/authorize"),
        "token_endpoint": state.url("oauth2/token"),
        "revocation_endpoint": state.url("oauth2/revoke"),
        "registration_endpoint": state.url("oauth2/registration"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query", "fragment"],
        "grant_types_supported": grant_types,
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "revocation_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": API_SCOPES,
        "authorization_response_iss_parameter_supported": true,
    });
    if state.config.device_authorization {
        m["device_authorization_endpoint"] = json!(state.url("oauth2/device"));
    }
    if state.config.registration {
        m["prompt_values_supported"] = json!(["create"]);
    }
    m
}

/// `GET /.well-known/oauth-authorization-server` (and `openid-configuration`, where some
/// clients look).
pub(crate) async fn well_known(State(state): State<AppState>) -> Response {
    let mut resp = Json(metadata(&state)).into_response();
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=600"),
    );
    resp
}
