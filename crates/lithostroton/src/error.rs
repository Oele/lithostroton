//! OAuth 2.0 error responses (RFC 6749 section 5.2, RFC 7591 section 3.2.2, RFC 7009 section
//! 2.2.1, RFC 8628 section 3.5): JSON with `error` and `error_description`, not the Matrix
//! error format, as the specification says for these endpoints.

use std::time::Duration;

use axum::{
    Json,
    response::{IntoResponse, Response},
};
use http::{HeaderValue, StatusCode, header};
use serde_json::json;

use crate::{host::HostError, store::StoreError};

#[derive(Debug)]
pub(crate) struct OAuthError {
    pub status: StatusCode,
    pub error: &'static str,
    pub description: Option<String>,
    pub retry_after: Option<Duration>,
    /// Add `WWW-Authenticate: Basic`: the client tried HTTP Basic authentication.
    pub www_authenticate: bool,
}

impl OAuthError {
    fn new(status: StatusCode, error: &'static str, description: impl Into<String>) -> OAuthError {
        OAuthError {
            status,
            error,
            description: Some(description.into()),
            retry_after: None,
            www_authenticate: false,
        }
    }

    pub fn invalid_request(d: impl Into<String>) -> OAuthError {
        OAuthError::new(StatusCode::BAD_REQUEST, "invalid_request", d)
    }
    pub fn invalid_client(d: impl Into<String>) -> OAuthError {
        OAuthError::new(StatusCode::UNAUTHORIZED, "invalid_client", d)
    }
    pub fn invalid_grant(d: impl Into<String>) -> OAuthError {
        OAuthError::new(StatusCode::BAD_REQUEST, "invalid_grant", d)
    }
    pub fn unauthorized_client(d: impl Into<String>) -> OAuthError {
        OAuthError::new(StatusCode::BAD_REQUEST, "unauthorized_client", d)
    }
    pub fn unsupported_grant_type(d: impl Into<String>) -> OAuthError {
        OAuthError::new(StatusCode::BAD_REQUEST, "unsupported_grant_type", d)
    }
    pub fn invalid_scope(d: impl Into<String>) -> OAuthError {
        OAuthError::new(StatusCode::BAD_REQUEST, "invalid_scope", d)
    }
    pub fn invalid_client_metadata(d: impl Into<String>) -> OAuthError {
        OAuthError::new(StatusCode::BAD_REQUEST, "invalid_client_metadata", d)
    }
    pub fn invalid_redirect_uri(d: impl Into<String>) -> OAuthError {
        OAuthError::new(StatusCode::BAD_REQUEST, "invalid_redirect_uri", d)
    }
    pub fn authorization_pending() -> OAuthError {
        OAuthError::new(
            StatusCode::BAD_REQUEST,
            "authorization_pending",
            "The user has not answered yet.",
        )
    }
    pub fn slow_down() -> OAuthError {
        OAuthError::new(StatusCode::BAD_REQUEST, "slow_down", "Polling too often.")
    }
    pub fn access_denied(d: impl Into<String>) -> OAuthError {
        OAuthError::new(StatusCode::BAD_REQUEST, "access_denied", d)
    }
    pub fn expired_token() -> OAuthError {
        OAuthError::new(
            StatusCode::BAD_REQUEST,
            "expired_token",
            "The device code has expired.",
        )
    }
    pub fn server_error() -> OAuthError {
        OAuthError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "The server could not complete the request.",
        )
    }
    pub fn temporarily_unavailable(retry_after: Option<Duration>) -> OAuthError {
        OAuthError {
            retry_after,
            ..OAuthError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "Try again later.",
            )
        }
    }
    /// Over a rate limit: 429, with the time to wait.
    pub fn rate_limited(wait: Duration) -> OAuthError {
        OAuthError {
            retry_after: Some(wait),
            ..OAuthError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "Too many requests. Try again later.",
            )
        }
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let mut body = json!({ "error": self.error });
        if let Some(d) = &self.description {
            body["error_description"] = json!(d);
        }
        let mut resp = (self.status, Json(body)).into_response();
        let h = resp.headers_mut();
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
        if let Some(wait) = self.retry_after {
            h.insert(header::RETRY_AFTER, retry_after(wait));
        }
        if self.www_authenticate {
            h.insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic"));
        }
        resp
    }
}

/// `Retry-After` in whole seconds, at least one.
pub(crate) fn retry_after(wait: Duration) -> HeaderValue {
    HeaderValue::from(wait.as_secs_f64().ceil().max(1.0) as u64)
}

impl From<HostError> for OAuthError {
    fn from(e: HostError) -> OAuthError {
        match e {
            HostError::Refused(reason) => OAuthError::invalid_grant(reason),
            other => {
                tracing::error!(error = %other, "the homeserver failed a call");
                OAuthError::temporarily_unavailable(None)
            }
        }
    }
}

impl From<StoreError> for OAuthError {
    fn from(e: StoreError) -> OAuthError {
        tracing::error!(error = %e, "the store failed");
        OAuthError::temporarily_unavailable(None)
    }
}
