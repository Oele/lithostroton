//! The test harness: lithostroton with a [`MemoryHost`] and a [`MemoryStore`] on a manual
//! clock, called in process, a browser with a cookie jar, and a Matrix client's side of the
//! flows.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::{collections::HashMap, sync::Arc, time::Duration};

use axum::{Router, body::Body};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{HeaderMap, Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use lithostroton::{
    Config, Embedded, MemoryStore,
    testing::{ManualClock, MemoryHost},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const ISSUER: &str = "https://hs.example.org/_lithostroton/";
pub const PREFIX: &str = "/_lithostroton";
pub const ORIGIN: &str = "https://hs.example.org";
pub const PASSWORD: &str = "correct horse battery staple";

pub struct Lab {
    pub app: Router,
    pub host: Arc<MemoryHost>,
    pub store: Arc<MemoryStore>,
    pub clock: ManualClock,
    pub embedded: Embedded,
    pub alice: String,
}

pub struct Resp {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

impl Resp {
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|_| panic!("not JSON: {}", self.body))
    }

    pub fn location(&self) -> String {
        self.headers
            .get(header::LOCATION)
            .unwrap_or_else(|| panic!("no Location, status {}: {}", self.status, self.body))
            .to_str()
            .unwrap()
            .to_owned()
    }

    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .map(|v| v.to_str().unwrap().to_owned())
    }

    /// The value of a hidden field of a form on the page (the first, or the one in the form
    /// that also holds `action=<within>`).
    pub fn hidden(&self, name: &str) -> String {
        hidden_in(&self.body, name).unwrap_or_else(|| panic!("no hidden {name} in {}", self.body))
    }
}

pub fn hidden_in(html: &str, name: &str) -> Option<String> {
    let needle = format!("name=\"{name}\" value=\"");
    let start = html.find(&needle)? + needle.len();
    let end = html[start..].find('"')? + start;
    Some(
        html[start..end]
            .replace("&amp;", "&")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&lt;", "<")
            .replace("&gt;", ">"),
    )
}

impl Lab {
    pub async fn new() -> Lab {
        Lab::with(|_| {}).await
    }

    pub async fn with(tweak: impl FnOnce(&mut Config)) -> Lab {
        let clock = ManualClock::new();
        let host = Arc::new(MemoryHost::new("example.org", clock.clock()));
        let alice = host.add_user("alice", PASSWORD);
        let store = Arc::new(MemoryStore::with_clock(clock.clock()));
        let mut config = Config::new(ISSUER.parse().unwrap(), "example.org");
        config.clock = clock.clock();
        tweak(&mut config);
        let embedded = Embedded::start(config, host.clone(), store.clone())
            .await
            .unwrap();
        let app = Router::new().nest(PREFIX, embedded.router());
        Lab {
            app,
            host,
            store,
            clock,
            embedded,
            alice,
        }
    }

    /// A path below the issuer, or an absolute URL of it, as a path.
    pub fn path(&self, p: &str) -> String {
        if let Some(rest) = p.strip_prefix(ORIGIN) {
            rest.to_owned()
        } else if p.starts_with('/') {
            p.to_owned()
        } else {
            format!("{PREFIX}/{p}")
        }
    }

    pub async fn request(&self, req: Request<Body>) -> Resp {
        use tower::ServiceExt;
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        Resp {
            status,
            headers,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }

    pub async fn get(&self, p: &str) -> Resp {
        self.request(Request::get(self.path(p)).body(Body::empty()).unwrap())
            .await
    }

    pub async fn post_form(&self, p: &str, fields: &[(&str, &str)]) -> Resp {
        self.post_form_with(p, fields, &[]).await
    }

    pub async fn post_form_with(
        &self,
        p: &str,
        fields: &[(&str, &str)],
        headers: &[(&str, &str)],
    ) -> Resp {
        let body = form(fields);
        let mut req = Request::post(self.path(p))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        self.request(req.body(Body::from(body)).unwrap()).await
    }

    pub async fn post_json(&self, p: &str, body: &Value) -> Resp {
        self.request(
            Request::post(self.path(p))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    pub async fn metadata(&self) -> Value {
        self.get(".well-known/oauth-authorization-server")
            .await
            .json()
    }

    /// Registers a client, returns its client ID.
    pub async fn register(&self, metadata: Value) -> String {
        let r = self.post_json("oauth2/registration", &metadata).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
        r.json()["client_id"].as_str().unwrap().to_owned()
    }

    pub async fn register_web(&self) -> String {
        self.register(web_client()).await
    }

    pub fn browser(&self) -> Browser<'_> {
        Browser {
            lab: self,
            cookies: HashMap::new(),
            ip: "192.0.2.10".into(),
        }
    }

    pub async fn token(&self, fields: &[(&str, &str)]) -> Resp {
        self.post_form("oauth2/token", fields).await
    }

    /// The whole authorization code flow for alice, as the client and the browser do it.
    pub async fn sign_in(&self, client_id: &str, device_id: &str) -> Value {
        let pkce = Pkce::new();
        let mut browser = self.browser();
        let code = browser
            .authorize_and_allow(&AuthParams::new(client_id, device_id, &pkce))
            .await;
        let r = self
            .token(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", WEB_REDIRECT),
                ("client_id", client_id),
                ("code_verifier", &pkce.verifier),
            ])
            .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        r.json()
    }
}

pub fn form(fields: &[(&str, &str)]) -> String {
    let mut s = form_urlencoded::Serializer::new(String::new());
    for (k, v) in fields {
        s.append_pair(k, v);
    }
    s.finish()
}

pub const WEB_REDIRECT: &str = "https://app.example.com/callback";

pub fn web_client() -> Value {
    json!({
        "client_name": "Test Client",
        "client_uri": "https://example.com/",
        "redirect_uris": [WEB_REDIRECT],
        "grant_types": ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "application_type": "web",
    })
}

pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

impl Pkce {
    pub fn new() -> Pkce {
        let verifier = format!("verifier-{}-{}", rand_hex(), rand_hex());
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        Pkce {
            verifier,
            challenge,
        }
    }
}

fn rand_hex() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(1);
    format!(
        "{:032x}",
        N.fetch_add(1, Ordering::Relaxed)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
    )
}

pub fn scope(device_id: &str) -> String {
    format!("urn:matrix:client:api:* urn:matrix:client:device:{device_id}")
}

/// The parameters of an authorization request, to change one at a time.
#[derive(Clone)]
pub struct AuthParams {
    pub params: Vec<(String, String)>,
}

impl AuthParams {
    pub fn new(client_id: &str, device_id: &str, pkce: &Pkce) -> AuthParams {
        AuthParams {
            params: vec![
                ("response_type".into(), "code".into()),
                ("client_id".into(), client_id.into()),
                ("redirect_uri".into(), WEB_REDIRECT.into()),
                ("scope".into(), scope(device_id)),
                ("state".into(), "st4te".into()),
                ("code_challenge".into(), pkce.challenge.clone()),
                ("code_challenge_method".into(), "S256".into()),
                ("response_mode".into(), "query".into()),
            ],
        }
    }

    pub fn set(mut self, k: &str, v: &str) -> AuthParams {
        self.params.retain(|(kk, _)| kk != k);
        self.params.push((k.into(), v.into()));
        self
    }

    pub fn without(mut self, k: &str) -> AuthParams {
        self.params.retain(|(kk, _)| kk != k);
        self
    }

    pub fn url(&self) -> String {
        let mut s = form_urlencoded::Serializer::new(String::new());
        for (k, v) in &self.params {
            s.append_pair(k, v);
        }
        format!("{PREFIX}/oauth2/authorize?{}", s.finish())
    }
}

/// The parameters of a redirect to the client: from the query or the fragment.
pub fn callback_params(location: &str) -> HashMap<String, String> {
    let part = location
        .split_once('#')
        .map(|(_, f)| f)
        .or_else(|| location.split_once('?').map(|(_, q)| q))
        .unwrap_or("");
    form_urlencoded::parse(part.as_bytes())
        .into_owned()
        .collect()
}

/// A browser: a cookie jar, an address, and same-origin form posts.
pub struct Browser<'a> {
    pub lab: &'a Lab,
    pub cookies: HashMap<String, String>,
    pub ip: String,
}

impl Browser<'_> {
    fn cookie_header(&self) -> String {
        self.cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn keep_cookies(&mut self, r: &Resp) {
        for v in r.headers.get_all(header::SET_COOKIE) {
            let v = v.to_str().unwrap();
            let (pair, attrs) = v.split_once(';').unwrap_or((v, ""));
            let (name, value) = pair.split_once('=').unwrap();
            if attrs.contains("Max-Age=0") || value.is_empty() {
                self.cookies.remove(name);
            } else {
                self.cookies.insert(name.to_owned(), value.to_owned());
            }
        }
    }

    pub async fn get(&mut self, p: &str) -> Resp {
        let req = Request::builder()
            .method(Method::GET)
            .uri(self.lab.path(p))
            .header(header::COOKIE, self.cookie_header())
            .header("x-test-client-ip", &self.ip)
            .body(Body::empty())
            .unwrap();
        let r = self.lab.request(req).await;
        self.keep_cookies(&r);
        r
    }

    pub async fn post(&mut self, p: &str, fields: &[(&str, &str)]) -> Resp {
        self.post_with(
            p,
            fields,
            &[("origin", ORIGIN), ("sec-fetch-site", "same-origin")],
        )
        .await
    }

    pub async fn post_with(
        &mut self,
        p: &str,
        fields: &[(&str, &str)],
        headers: &[(&str, &str)],
    ) -> Resp {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(self.lab.path(p))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, self.cookie_header())
            .header("x-test-client-ip", &self.ip);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let r = self
            .lab
            .request(req.body(Body::from(form(fields))).unwrap())
            .await;
        self.keep_cookies(&r);
        r
    }

    /// Signs in as alice on the sign-in page `login_path`, returns where it sends the browser.
    pub async fn login(&mut self, login_path: &str, username: &str, password: &str) -> Resp {
        let page = self.get(login_path).await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        let csrf = page.hidden("csrf");
        let next = page.hidden("next");
        self.post(
            "login",
            &[
                ("csrf", &csrf),
                ("next", &next),
                ("username", username),
                ("password", password),
            ],
        )
        .await
    }

    /// Opens the authorization URL and signs in if asked; returns the consent page.
    pub async fn authorize_to_consent(&mut self, params: &AuthParams) -> Resp {
        let r = self.get(&params.url()).await;
        assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
        let mut next = r.location();
        if next.contains("/login?") {
            let r = self.login(&next, "alice", PASSWORD).await;
            assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
            next = r.location();
        }
        assert!(next.contains("/consent?req="), "{next}");
        let page = self.get(&next).await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        page
    }

    /// Answers the consent page; returns the redirect to the client.
    pub async fn answer_consent(&mut self, page: &Resp, action: &str) -> Resp {
        let csrf = hidden_in(&page.body, "csrf").unwrap();
        let req = hidden_in(&page.body, "req").unwrap();
        // the first csrf field is the sign-out form's; the consent forms carry their own
        let consent_csrf = page
            .body
            .split("action=\"/_lithostroton/consent\"")
            .nth(1)
            .and_then(|f| hidden_in(f, "csrf"))
            .unwrap_or(csrf);
        self.post(
            "consent",
            &[("csrf", &consent_csrf), ("req", &req), ("action", action)],
        )
        .await
    }

    /// The whole browser side: authorize, sign in, allow. Returns the code.
    pub async fn authorize_and_allow(&mut self, params: &AuthParams) -> String {
        let page = self.authorize_to_consent(params).await;
        let r = self.answer_consent(&page, "allow").await;
        assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
        let p = callback_params(&r.location());
        assert_eq!(p.get("state").map(String::as_str), Some("st4te"));
        assert_eq!(p.get("iss").map(String::as_str), Some(ISSUER));
        p.get("code").expect("a code").clone()
    }
}

pub async fn exchange(
    lab: &Lab,
    code: &str,
    client_id: &str,
    redirect_uri: &str,
    verifier: &str,
) -> Resp {
    lab.token(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", verifier),
    ])
    .await
}

pub fn assert_oauth_error(r: &Resp, status: StatusCode, error: &str) {
    assert_eq!(r.status, status, "{}", r.body);
    assert_eq!(r.json()["error"], error, "{}", r.body);
    assert_eq!(r.header("cache-control").as_deref(), Some("no-store"));
}

pub const MINUTE: Duration = Duration::from_secs(60);
