//! HTTP plumbing: the client's address, cookies, CSRF tokens, the security headers every
//! response gets, CORS for the endpoints web clients call.

use axum::{
    extract::{FromRequestParts, Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use http::{HeaderMap, HeaderValue, Method, StatusCode, header, request::Parts};

use crate::{crypto, ratelimit::address_key, state::AppState};

/// The rate-limit key of the client's address.
pub(crate) struct Peer(pub String);

impl FromRequestParts<AppState> for Peer {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Peer, Self::Rejection> {
        Ok(Peer(address_key(state.host.client_ip(parts))))
    }
}

pub(crate) const SESSION_COOKIE: &str = "__Secure-lithostroton-session";
pub(crate) const CSRF_COOKIE: &str = "__Secure-lithostroton-csrf";

/// The value of a cookie of the request.
pub(crate) fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.trim_matches('"').to_owned())
        .filter(|v| !v.is_empty())
}

/// A `Set-Cookie` value: `Secure`, `HttpOnly`, `SameSite=Lax`, for the issuer's path only.
/// `max_age` `None` makes a cookie for the browser session; `Some(0)` removes it.
pub(crate) fn set_cookie(
    state: &AppState,
    name: &str,
    value: &str,
    max_age: Option<u64>,
) -> HeaderValue {
    let mut c = format!(
        "{name}={value}; Path={}; Secure; HttpOnly; SameSite=Lax",
        state.issuer.path
    );
    if let Some(age) = max_age {
        c.push_str(&format!("; Max-Age={age}"));
    }
    // names and values are ours: base64url and fixed names
    HeaderValue::from_str(&c).unwrap_or_else(|_| HeaderValue::from_static(""))
}

/// The browser's CSRF cookie, and a new one to set if it has none.
pub(crate) struct Csrf {
    pub cookie: String,
    pub set: Option<HeaderValue>,
}

impl Csrf {
    pub fn of(state: &AppState, headers: &HeaderMap) -> Csrf {
        match cookie(headers, CSRF_COOKIE).filter(|c| c.len() == 43) {
            Some(cookie) => Csrf { cookie, set: None },
            None => {
                let cookie = crypto::random_secret();
                let set = Some(set_cookie(state, CSRF_COOKIE, &cookie, None));
                Csrf { cookie, set }
            }
        }
    }

    /// The token a form for `purpose` carries.
    pub fn token(&self, state: &AppState, purpose: &str) -> String {
        csrf_token(state, &self.cookie, purpose)
    }
}

fn csrf_token(state: &AppState, cookie: &str, purpose: &str) -> String {
    crypto::mac_b64(
        &state.key,
        &[b"csrf", cookie.as_bytes(), purpose.as_bytes()],
    )
}

/// Checks a form submission: it comes from a page of ours (`Origin`, `Sec-Fetch-Site` when
/// the browser sends them), and carries the CSRF token of the browser's cookie for this
/// `purpose`.
pub(crate) fn check_form(
    state: &AppState,
    headers: &HeaderMap,
    purpose: &str,
    token: Option<&str>,
) -> bool {
    if let Some(origin) = headers.get(header::ORIGIN)
        && origin.as_bytes() != state.issuer.origin.as_bytes()
    {
        return false;
    }
    if let Some(site) = headers.get("sec-fetch-site")
        && !matches!(site.as_bytes(), b"same-origin" | b"none")
    {
        return false;
    }
    let (Some(cookie), Some(token)) = (cookie(headers, CSRF_COOKIE), token) else {
        return false;
    };
    crypto::ct_eq(
        csrf_token(state, &cookie, purpose).as_bytes(),
        token.as_bytes(),
    )
}

/// The CSP of a page: nothing but our stylesheet, no scripts, no frames around it, forms only
/// to ourselves. The consent pages leave out `form-action`: the answer to their form is a
/// redirect to the client, which `form-action 'self'` would block.
pub(crate) fn page_csp(forms_redirect_out: bool) -> HeaderValue {
    if forms_redirect_out {
        HeaderValue::from_static(
            "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'",
        )
    } else {
        HeaderValue::from_static(
            "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        )
    }
}

/// The headers every response gets: no framing, no sniffing, no referrer, and not stored by
/// caches unless the handler said otherwise.
pub(crate) async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    if !h.contains_key(header::CONTENT_SECURITY_POLICY) {
        h.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
        );
    }
    if !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    resp
}

/// CORS for the endpoints web clients call from their own origin: any origin, no
/// credentials (none of these endpoints reads a cookie).
pub(crate) async fn cors(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if !state.config.cors {
        return next.run(req).await;
    }
    let preflight = req.method() == Method::OPTIONS;
    let mut resp = if preflight {
        StatusCode::NO_CONTENT.into_response()
    } else {
        next.run(req).await
    };
    let h = resp.headers_mut();
    h.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    if preflight {
        h.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, OPTIONS"),
        );
        h.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Authorization, Content-Type, Accept"),
        );
        h.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("86400"),
        );
    }
    resp
}

/// A `303 See Other` to `location`.
pub(crate) fn see_other(location: &str) -> Response {
    let mut resp = StatusCode::SEE_OTHER.into_response();
    if let Ok(v) = HeaderValue::from_str(location) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    resp
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn cookie_parsing() {
        let mut h = HeaderMap::new();
        h.append(
            header::COOKIE,
            "a=1; __Secure-lithostroton-csrf=xyz".parse().unwrap(),
        );
        h.append(header::COOKIE, "b=2".parse().unwrap());
        assert_eq!(cookie(&h, CSRF_COOKIE).as_deref(), Some("xyz"));
        assert_eq!(cookie(&h, "b").as_deref(), Some("2"));
        assert_eq!(cookie(&h, "c"), None);
    }
}
