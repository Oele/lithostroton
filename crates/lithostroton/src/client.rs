//! Clients: dynamic client registration (RFC 7591) with the Matrix rules for client metadata
//! and redirect URIs (the specification's "Client registration" section, RFC 8252 section 7
//! for native apps), and the matching of redirect URIs at authorization time.

use axum::{
    Json,
    body::Bytes,
    extract::State,
    response::{IntoResponse, Response},
};
use http::{HeaderValue, StatusCode, header};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{config::is_loopback, crypto, error::OAuthError, http_util::Peer, state::AppState};

pub(crate) const GRANT_AUTHORIZATION_CODE: &str = "authorization_code";
pub(crate) const GRANT_REFRESH_TOKEN: &str = "refresh_token";
pub(crate) const GRANT_DEVICE_CODE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Store kinds.
pub(crate) const KIND_CLIENT: &str = "client";
const KIND_CLIENT_DIGEST: &str = "client_digest";

/// The most redirect URIs a client may register.
const MAX_REDIRECT_URIS: usize = 20;
/// The longest URI accepted in client metadata.
const MAX_URI: usize = 2048;
/// The longest client name accepted, in characters.
const MAX_NAME: usize = 256;
/// The largest registration request body.
pub(crate) const MAX_REGISTRATION_BODY: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ApplicationType {
    Web,
    Native,
}

/// The metadata lithostroton registers for a client: what it understood and accepted of what
/// the client sent. Localized variants (`client_name#fr`) are not registered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ClientMetadata {
    pub application_type: ApplicationType,
    pub client_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tos_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,
    pub redirect_uris: Vec<String>,
    pub response_types: Vec<String>,
    pub grant_types: Vec<String>,
    pub token_endpoint_auth_method: String,
}

/// A registered client.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Client {
    pub client_id: String,
    pub client_id_issued_at: u64,
    pub metadata: ClientMetadata,
}

impl Client {
    pub fn allows_grant(&self, grant: &str) -> bool {
        self.metadata.grant_types.iter().any(|g| g == grant)
    }

    /// The registered redirect URI that `requested` matches, if any: the same string, or for
    /// a native client a loopback URI registered without a port and requested with one
    /// (RFC 8252 section 7.3: any port is accepted).
    pub fn match_redirect_uri(&self, requested: &str) -> bool {
        self.metadata.redirect_uris.iter().any(|registered| {
            registered == requested
                || (self.metadata.application_type == ApplicationType::Native
                    && loopback_with_port(registered, requested))
        })
    }
}

const LOOPBACK_PREFIXES: [&str; 3] = ["http://localhost", "http://127.0.0.1", "http://[::1]"];

/// Whether `requested` is `registered` (a loopback URI without a port) with a port added
/// after the host, and is otherwise the same string.
fn loopback_with_port(registered: &str, requested: &str) -> bool {
    for prefix in LOOPBACK_PREFIXES {
        let (Some(reg_rest), Some(req_rest)) = (
            registered.strip_prefix(prefix),
            requested.strip_prefix(prefix),
        ) else {
            continue;
        };
        if reg_rest.starts_with(':') {
            continue;
        }
        let Some(after_colon) = req_rest.strip_prefix(':') else {
            continue;
        };
        let digits = after_colon.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 || digits > 5 {
            continue;
        }
        let (port, rest) = after_colon.split_at(digits);
        if port.parse::<u16>().is_ok_and(|p| p != 0) && rest == reg_rest {
            return true;
        }
    }
    false
}

/// Why metadata is refused: `invalid_redirect_uri` or `invalid_client_metadata`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MetadataError {
    RedirectUri(String),
    Metadata(String),
}

impl From<MetadataError> for OAuthError {
    fn from(e: MetadataError) -> OAuthError {
        match e {
            MetadataError::RedirectUri(d) => OAuthError::invalid_redirect_uri(d),
            MetadataError::Metadata(d) => OAuthError::invalid_client_metadata(d),
        }
    }
}

fn meta_err(d: impl Into<String>) -> MetadataError {
    MetadataError::Metadata(d.into())
}

fn optional_string(obj: &Map<String, Value>, field: &str) -> Result<Option<String>, MetadataError> {
    match obj.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(meta_err(format!("{field} must be a string"))),
    }
}

fn string_array(
    obj: &Map<String, Value>,
    field: &str,
) -> Result<Option<Vec<String>>, MetadataError> {
    match obj.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| meta_err(format!("{field} must be an array of strings")))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        Some(_) => Err(meta_err(format!("{field} must be an array of strings"))),
    }
}

/// Whether `host` is `base` or a subdomain of it.
fn same_or_subdomain(host: &str, base: &str) -> bool {
    host == base
        || (host.len() > base.len()
            && host.ends_with(base)
            && host.as_bytes()[host.len() - base.len() - 1] == b'.')
}

/// An `https` URI with a host, no user or password and no fragment. With `lab` (the issuer
/// is on loopback) an `http` URI on loopback too, as a web client's development server has.
fn parse_https(uri: &str, field: &str, lab: bool) -> Result<url::Url, String> {
    if uri.len() > MAX_URI {
        return Err(format!("{field} is too long"));
    }
    if uri.contains('#') {
        return Err(format!("{field} must not have a fragment"));
    }
    let u = url::Url::parse(uri).map_err(|_| format!("{field} is not a valid URI"))?;
    match u.scheme() {
        "https" => {}
        "http" if lab && is_loopback(&u) => {}
        _ if lab => {
            return Err(format!(
                "{field} must use https (or http on a loopback host, as the issuer is)"
            ));
        }
        _ => return Err(format!("{field} must use https")),
    }
    if u.host_str().is_none_or(str::is_empty) {
        return Err(format!("{field} must have a host"));
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err(format!("{field} must not have a user or password"));
    }
    Ok(u)
}

/// An https URI of the client's that must be on the client URI's host or a subdomain of it.
fn check_related_uri(
    uri: &str,
    field: &str,
    client_host: &str,
    lab: bool,
) -> Result<(), MetadataError> {
    let u = parse_https(uri, field, lab).map_err(MetadataError::Metadata)?;
    if !u
        .host_str()
        .is_some_and(|h| same_or_subdomain(h, client_host))
    {
        return Err(meta_err(format!(
            "{field} must be on the host of client_uri or a subdomain of it"
        )));
    }
    Ok(())
}

/// The URI schemes that are never a native app's.
const FORBIDDEN_SCHEMES: [&str; 8] = [
    "javascript",
    "data",
    "file",
    "vbscript",
    "blob",
    "about",
    "ftp",
    "ws",
];

/// Checks one redirect URI by the specification's "Redirect URI validation". With `lab` (the
/// issuer is on loopback), a web client on loopback may use http.
pub(crate) fn check_redirect_uri(
    uri: &str,
    app: ApplicationType,
    client_host: &str,
    lab: bool,
) -> Result<(), String> {
    if uri.len() > MAX_URI {
        return Err("a redirect URI is too long".into());
    }
    if uri.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("a redirect URI must not have spaces or control characters".into());
    }
    if uri.contains('#') {
        return Err("a redirect URI must not have a fragment".into());
    }
    let u = url::Url::parse(uri).map_err(|_| format!("{uri} is not a valid URI"))?;
    let web_rules = |u: &url::Url| -> Result<(), String> {
        parse_https(uri, "a redirect URI", lab)?;
        if !u
            .host_str()
            .is_some_and(|h| same_or_subdomain(h, client_host))
        {
            return Err(format!(
                "{uri} must be on the host of client_uri ({client_host}) or a subdomain of it"
            ));
        }
        Ok(())
    };
    match (app, u.scheme()) {
        (_, "https") => web_rules(&u),
        (ApplicationType::Web, "http") if lab && is_loopback(&u) => web_rules(&u),
        (ApplicationType::Web, _) => Err(format!("{uri}: a web client's redirect URIs use https")),
        (ApplicationType::Native, "http") => {
            // a loopback interface, without a port (any port is accepted when it is used)
            let Some(rest) = LOOPBACK_PREFIXES.iter().find_map(|p| uri.strip_prefix(p)) else {
                return Err(format!(
                    "{uri}: an http redirect URI must be on localhost, 127.0.0.1 or [::1]"
                ));
            };
            if !(rest.is_empty() || rest.starts_with('/') || rest.starts_with('?')) {
                return Err(format!(
                    "{uri}: a loopback redirect URI must not have a port"
                ));
            }
            Ok(())
        }
        (ApplicationType::Native, scheme) => {
            // a private-use scheme: the client URI's host in reverse-DNS notation as its
            // prefix, and no authority
            let reversed: Vec<&str> = client_host.rsplit('.').collect();
            let reversed = reversed.join(".");
            if FORBIDDEN_SCHEMES.contains(&scheme)
                || client_host.parse::<std::net::IpAddr>().is_ok()
                || client_host.trim_start_matches('[').contains(':')
                || !client_host.contains('.')
            {
                return Err(format!("{uri}: this scheme cannot be a redirect URI"));
            }
            if !(scheme == reversed || scheme.starts_with(&format!("{reversed}."))) {
                return Err(format!(
                    "{uri}: a private-use scheme must start with {reversed}, the client URI's host in reverse-DNS notation"
                ));
            }
            // `uri` as sent, not as parsed: the scheme is followed by at most one slash
            let after = &uri[scheme.len() + 1..];
            if after.starts_with("//") {
                return Err(format!(
                    "{uri}: a private-use scheme URI must not have an authority"
                ));
            }
            Ok(())
        }
    }
}

/// Validates the metadata of a registration request (a JSON object) and returns what is
/// registered. `device_grant` says whether the device authorization grant is offered; `lab`
/// whether the issuer is on loopback, where a client on loopback may use http for its URIs.
pub(crate) fn validate_metadata(
    body: &Value,
    device_grant: bool,
    lab: bool,
) -> Result<ClientMetadata, MetadataError> {
    let obj = body
        .as_object()
        .ok_or_else(|| meta_err("the request body must be a JSON object"))?;

    let application_type = match optional_string(obj, "application_type")?.as_deref() {
        None | Some("web") => ApplicationType::Web,
        Some("native") => ApplicationType::Native,
        Some(_) => return Err(meta_err("application_type must be web or native")),
    };

    let client_uri =
        optional_string(obj, "client_uri")?.ok_or_else(|| meta_err("client_uri is required"))?;
    let parsed = parse_https(&client_uri, "client_uri", lab).map_err(MetadataError::Metadata)?;
    let client_host = parsed.host_str().unwrap_or_default().to_owned();

    let client_name = optional_string(obj, "client_name")?;
    if let Some(name) = &client_name {
        if name.chars().count() > MAX_NAME {
            return Err(meta_err("client_name is too long"));
        }
        if name.chars().any(char::is_control) {
            return Err(meta_err("client_name must not have control characters"));
        }
    }
    let related = |field: &str| -> Result<Option<String>, MetadataError> {
        let v = optional_string(obj, field)?;
        if let Some(uri) = &v {
            check_related_uri(uri, field, &client_host, lab)?;
        }
        Ok(v)
    };
    let logo_uri = related("logo_uri")?;
    let tos_uri = related("tos_uri")?;
    let policy_uri = related("policy_uri")?;

    match optional_string(obj, "token_endpoint_auth_method")?.as_deref() {
        None | Some("none") => {}
        Some(other) => {
            return Err(meta_err(format!(
                "token_endpoint_auth_method {other} is not supported: only none (public clients)"
            )));
        }
    }

    // grant types: the ones understood and offered, in a fixed order; RFC 7591's default is
    // authorization_code
    let asked = string_array(obj, "grant_types")?
        .unwrap_or_else(|| vec![GRANT_AUTHORIZATION_CODE.to_owned()]);
    let mut grant_types = Vec::new();
    for g in [
        GRANT_AUTHORIZATION_CODE,
        GRANT_REFRESH_TOKEN,
        GRANT_DEVICE_CODE,
    ] {
        if g == GRANT_DEVICE_CODE && !device_grant {
            continue;
        }
        if asked.iter().any(|a| a == g) {
            grant_types.push(g.to_owned());
        }
    }
    let code_grant = grant_types.iter().any(|g| g == GRANT_AUTHORIZATION_CODE);
    if !code_grant && !grant_types.iter().any(|g| g == GRANT_DEVICE_CODE) {
        return Err(meta_err(
            "grant_types must include authorization_code or urn:ietf:params:oauth:grant-type:device_code",
        ));
    }

    // response types: `code` is the only one; the others are ignored
    let asked = string_array(obj, "response_types")?.unwrap_or_else(|| vec!["code".to_owned()]);
    let response_types: Vec<String> = if asked.iter().any(|r| r == "code") {
        vec!["code".to_owned()]
    } else {
        Vec::new()
    };
    if code_grant && response_types.is_empty() {
        return Err(meta_err(
            "response_types must include code to use the authorization_code grant",
        ));
    }

    let mut redirect_uris: Vec<String> = Vec::new();
    for uri in string_array(obj, "redirect_uris")?.unwrap_or_default() {
        check_redirect_uri(&uri, application_type, &client_host, lab)
            .map_err(MetadataError::RedirectUri)?;
        if !redirect_uris.contains(&uri) {
            redirect_uris.push(uri);
        }
    }
    if redirect_uris.len() > MAX_REDIRECT_URIS {
        return Err(MetadataError::RedirectUri(format!(
            "at most {MAX_REDIRECT_URIS} redirect URIs"
        )));
    }
    if code_grant && redirect_uris.is_empty() {
        return Err(MetadataError::RedirectUri(
            "redirect_uris is required for the authorization_code grant".into(),
        ));
    }

    Ok(ClientMetadata {
        application_type,
        client_uri,
        client_name,
        logo_uri,
        tos_uri,
        policy_uri,
        redirect_uris,
        response_types,
        grant_types,
        token_endpoint_auth_method: "none".to_owned(),
    })
}

/// The registered client with this ID.
pub(crate) async fn find(state: &AppState, client_id: &str) -> Result<Option<Client>, OAuthError> {
    if client_id.len() > 128 {
        return Ok(None);
    }
    Ok(state
        .store
        .get::<Client>(KIND_CLIENT, client_id)
        .await?
        .map(|r| r.value))
}

/// Registers a client, or returns the client already registered with the same metadata (the
/// de-duplication the specification suggests: every client registers anew at each sign-in).
pub(crate) async fn register(
    state: &AppState,
    metadata: ClientMetadata,
) -> Result<Client, OAuthError> {
    let canonical = serde_json::to_vec(&metadata).map_err(|_| OAuthError::server_error())?;
    let digest = crypto::s256(&String::from_utf8_lossy(&canonical));
    if let Some(existing) = state
        .store
        .get::<String>(KIND_CLIENT_DIGEST, &digest)
        .await?
        && let Some(client) = find(state, &existing.value).await?
        && client.metadata == metadata
    {
        return Ok(client);
    }
    let client = Client {
        client_id: crypto::random_id(),
        client_id_issued_at: state.unix(),
        metadata,
    };
    if !state
        .store
        .insert(KIND_CLIENT, &client.client_id, &client, None)
        .await?
    {
        return Err(OAuthError::server_error());
    }
    if !state
        .store
        .insert(KIND_CLIENT_DIGEST, &digest, &client.client_id, None)
        .await?
    {
        // registered at the same moment by another request: use that one
        if let Some(existing) = state
            .store
            .get::<String>(KIND_CLIENT_DIGEST, &digest)
            .await?
            && let Some(other) = find(state, &existing.value).await?
            && other.metadata == client.metadata
        {
            state.store.delete(KIND_CLIENT, &client.client_id).await?;
            return Ok(other);
        }
    }
    Ok(client)
}

/// `POST registration_endpoint`: dynamic client registration (RFC 7591 section 3).
pub(crate) async fn registration_endpoint(
    State(state): State<AppState>,
    peer: Peer,
    body: Bytes,
) -> Response {
    if let Err(wait) = state.limits.registration.check(&peer.0) {
        return OAuthError::rate_limited(wait).into_response();
    }
    match registration(&state, &body).await {
        Ok(client) => {
            let mut body = serde_json::to_value(&client.metadata).unwrap_or_default();
            body["client_id"] = Value::String(client.client_id.clone());
            body["client_id_issued_at"] = Value::from(client.client_id_issued_at);
            let mut resp = (StatusCode::CREATED, Json(body)).into_response();
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Err(e) => e.into_response(),
    }
}

async fn registration(state: &AppState, body: &[u8]) -> Result<Client, OAuthError> {
    if body.len() > MAX_REGISTRATION_BODY {
        return Err(OAuthError::invalid_client_metadata(
            "the request is too large",
        ));
    }
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| OAuthError::invalid_client_metadata("the request body is not JSON"))?;
    let metadata = validate_metadata(
        &value,
        state.config.device_authorization,
        state.issuer.loopback,
    )?;
    let client = register(state, metadata).await?;
    tracing::info!(
        client_id = %client.client_id,
        client_uri = %client.metadata.client_uri,
        client_name = client.metadata.client_name.as_deref().unwrap_or(""),
        "client registered"
    );
    Ok(client)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use serde_json::json;

    use super::*;

    fn native(uri: &str) -> Result<(), String> {
        check_redirect_uri(uri, ApplicationType::Native, "example.com", false)
    }
    fn web(uri: &str) -> Result<(), String> {
        check_redirect_uri(uri, ApplicationType::Web, "example.com", false)
    }

    /// The examples of the specification's "Redirect URI validation".
    #[test]
    fn spec_examples_web() {
        for ok in [
            "https://example.com/callback",
            "https://app.example.com/callback",
            "https://example.com:5173/?query=value",
        ] {
            assert!(web(ok).is_ok(), "{ok}");
        }
        for bad in [
            "https://example.com/callback#fragment",
            "http://example.com/callback",
            "http://localhost/",
            "https://badexample.com/",
            "https://example.com.evil.org/",
            "https://user:pw@example.com/",
            "com.example.app:/callback",
        ] {
            assert!(web(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn spec_examples_native() {
        for ok in [
            "com.example.app:/callback",
            "com.example:/",
            "com.example:callback",
            "http://localhost/callback",
            "http://127.0.0.1/callback",
            "http://[::1]/callback",
            "https://app.example.com/claimed",
        ] {
            assert!(native(ok).is_ok(), "{ok}");
        }
        for bad in [
            "example:/callback",
            "com.example.app://callback",
            "https://localhost/callback",
            "http://localhost:1234/callback",
            "http://localhost:80/callback",
            "http://localhost.evil.org/callback",
            "com.examplex:/callback",
            "com.example.app:/callback#f",
            "javascript:alert(1)",
        ] {
            assert!(native(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn private_use_scheme_needs_a_dotted_domain() {
        assert!(
            check_redirect_uri("localhost:/cb", ApplicationType::Native, "localhost", false)
                .is_err()
        );
        assert!(
            check_redirect_uri("1.0.0.127:/cb", ApplicationType::Native, "127.0.0.1", false)
                .is_err()
        );
    }

    fn client(app: ApplicationType, uris: &[&str]) -> Client {
        Client {
            client_id: "c".into(),
            client_id_issued_at: 0,
            metadata: ClientMetadata {
                application_type: app,
                client_uri: "https://example.com/".into(),
                client_name: None,
                logo_uri: None,
                tos_uri: None,
                policy_uri: None,
                redirect_uris: uris.iter().map(|s| s.to_string()).collect(),
                response_types: vec!["code".into()],
                grant_types: vec![GRANT_AUTHORIZATION_CODE.into()],
                token_endpoint_auth_method: "none".into(),
            },
        }
    }

    #[test]
    fn exact_matching() {
        let c = client(ApplicationType::Web, &["https://example.com/cb"]);
        assert!(c.match_redirect_uri("https://example.com/cb"));
        for bad in [
            "https://example.com/cb/",
            "https://example.com/cb?x=1",
            "https://example.com/c",
            "https://EXAMPLE.com/cb",
            "https://example.com:443/cb",
            "https://example.com/cb#",
        ] {
            assert!(!c.match_redirect_uri(bad), "{bad}");
        }
    }

    #[test]
    fn loopback_any_port() {
        let c = client(
            ApplicationType::Native,
            &["http://127.0.0.1/cb", "http://[::1]/", "http://localhost"],
        );
        assert!(c.match_redirect_uri("http://127.0.0.1:49152/cb"));
        assert!(c.match_redirect_uri("http://127.0.0.1/cb"));
        assert!(c.match_redirect_uri("http://[::1]:8080/"));
        assert!(c.match_redirect_uri("http://localhost:1"));
        for bad in [
            "http://127.0.0.1:0/cb",
            "http://127.0.0.1:65536/cb",
            "http://127.0.0.1:80x/cb",
            "http://127.0.0.1:8080/cb2",
            "http://127.0.0.1:8080@evil.org/cb",
            "http://localhost:99/evil",
            "http://localhost.evil.org:99",
        ] {
            assert!(!c.match_redirect_uri(bad), "{bad}");
        }
        // a web client gets no port leeway
        let w = client(ApplicationType::Web, &["http://127.0.0.1/cb"]);
        assert!(!w.match_redirect_uri("http://127.0.0.1:8080/cb"));
    }

    #[test]
    fn metadata_defaults_and_filtering() {
        let m = validate_metadata(
            &json!({
                "client_name": "My App",
                "client_name#fr": "Mon application",
                "client_uri": "https://example.com/",
                "tos_uri": "https://example.com/tos.html",
                "redirect_uris": ["https://app.example.com/callback", "https://app.example.com/callback"],
                "token_endpoint_auth_method": "none",
                "response_types": ["code", "token"],
                "grant_types": ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"],
            }),
            true,
            false,
        )
        .unwrap();
        assert_eq!(m.application_type, ApplicationType::Web);
        assert_eq!(m.redirect_uris.len(), 1);
        assert_eq!(m.response_types, vec!["code"]);
        assert_eq!(m.grant_types, vec!["authorization_code", "refresh_token"]);
        let v = serde_json::to_value(&m).unwrap();
        assert!(v.get("client_name#fr").is_none());
    }

    #[test]
    fn metadata_refusals() {
        let base = json!({
            "client_uri": "https://example.com/",
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        });
        let with = |k: &str, v: Value| {
            let mut b = base.clone();
            b[k] = v;
            validate_metadata(&b, true, false)
        };
        assert!(validate_metadata(&base, true, false).is_ok());
        assert!(matches!(
            with("client_uri", Value::Null),
            Err(MetadataError::Metadata(_))
        ));
        assert!(with("client_uri", json!("http://example.com/")).is_err());
        assert!(with("client_uri", json!("https://u@example.com/")).is_err());
        assert!(with("logo_uri", json!("https://cdn.other.org/logo.png")).is_err());
        assert!(with("policy_uri", json!("http://example.com/p")).is_err());
        assert!(with("token_endpoint_auth_method", json!("client_secret_basic")).is_err());
        assert!(with("application_type", json!("desktop")).is_err());
        assert!(with("client_name", json!(7)).is_err());
        assert!(with("client_name", json!("a\u{0}b")).is_err());
        assert!(matches!(
            with("redirect_uris", json!(["https://evil.org/cb"])),
            Err(MetadataError::RedirectUri(_))
        ));
        assert!(matches!(
            with("redirect_uris", json!([])),
            Err(MetadataError::RedirectUri(_))
        ));
        assert!(with("response_types", json!(["token"])).is_err());
        assert!(with("grant_types", json!(["refresh_token"])).is_err());
        assert!(validate_metadata(&json!([]), true, false).is_err());
    }

    /// With the issuer on loopback (a lab), a web client served from a development server on
    /// loopback may use http; nowhere else, and not with the issuer elsewhere.
    #[test]
    fn loopback_lab_allows_http_on_loopback() {
        let dev = json!({
            "client_uri": "http://localhost:5173/",
            "logo_uri": "http://localhost:5173/logo.png",
            "policy_uri": "http://localhost:5173/policy",
            "redirect_uris": ["http://localhost:5173/callback"],
        });
        let m = validate_metadata(&dev, true, true).unwrap();
        assert_eq!(m.redirect_uris, vec!["http://localhost:5173/callback"]);
        assert_eq!(
            validate_metadata(&dev, true, false).unwrap_err(),
            MetadataError::Metadata("client_uri must use https".into())
        );

        for ok in ["http://127.0.0.1:8080/cb", "http://[::1]:8080/cb"] {
            let host = url::Url::parse(ok).unwrap().host_str().unwrap().to_owned();
            assert!(
                check_redirect_uri(ok, ApplicationType::Web, &host, true).is_ok(),
                "{ok}"
            );
            assert!(
                check_redirect_uri(ok, ApplicationType::Web, &host, false).is_err(),
                "{ok}"
            );
        }
        for bad in [
            // http off loopback, a host other than client_uri's, other schemes
            ("http://example.com/cb", "example.com"),
            ("http://127.0.0.1:5173/cb", "localhost"),
            ("http://localhost.example.com/cb", "localhost"),
            ("ftp://localhost/cb", "localhost"),
        ] {
            assert!(
                check_redirect_uri(bad.0, ApplicationType::Web, bad.1, true).is_err(),
                "{bad:?}"
            );
        }
        let off_loopback = json!({
            "client_uri": "http://example.com/",
            "redirect_uris": ["https://example.com/cb"],
        });
        assert!(validate_metadata(&off_loopback, true, true).is_err());
        // a native app's loopback redirect still has no port
        assert!(
            check_redirect_uri(
                "http://localhost:5173/cb",
                ApplicationType::Native,
                "example.com",
                true
            )
            .is_err()
        );
    }

    #[test]
    fn device_only_client() {
        let m = validate_metadata(
            &json!({
                "client_uri": "https://example.com/",
                "grant_types": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
            }),
            true,
            false,
        )
        .unwrap();
        assert_eq!(m.grant_types, vec![GRANT_REFRESH_TOKEN, GRANT_DEVICE_CODE]);
        assert!(m.redirect_uris.is_empty());
        // without the device grant on offer the client has nothing left to use
        assert!(
            validate_metadata(
                &json!({
                    "client_uri": "https://example.com/",
                    "grant_types": ["urn:ietf:params:oauth:grant-type:device_code"],
                }),
                false,
                false,
            )
            .is_err()
        );
    }
}
