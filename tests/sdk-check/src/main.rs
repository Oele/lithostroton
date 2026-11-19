//! Checks lithostroton with clients written by others:
//!
//! - matrix-rust-sdk's OAuth client: discovery, dynamic registration, the authorization code
//!   grant, a refresh, and logout (revocation);
//! - the `oauth2` crate: the device authorization grant of RFC 8628 with its polling, a
//!   refresh, and revocation.
//!
//! The browser's part (sign in, consent, entering the device's code) is done over HTTP by
//! this program, as a browser would.
//!
//! Without arguments it starts lithostroton in this process, with an in-memory homeserver, on
//! https://127.0.0.1:38401 with a certificate made for the run. With `--homeserver URL --user NAME --password PASSWORD` it runs against a
//! homeserver that embeds lithostroton.
//!
//! ```sh
//! cargo run -p lithostroton-sdk-check
//! cargo run -p lithostroton-sdk-check -- --homeserver https://matrix.example.org --user alice --password ...
//! ```

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use axum::{
    Json, Router,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use lithostroton::{Config, Embedded, MemoryStore, testing::MemoryHost};
use matrix_sdk::{
    Client,
    authentication::oauth::registration::{
        ApplicationType, ClientMetadata, Localized, OAuthGrantType,
    },
    utils::UrlOrQuery,
};
use oauth2::{
    AuthType, ClientId, DeviceAuthorizationUrl, RefreshToken, RevocationUrl, Scope,
    StandardDeviceAuthorizationResponse, StandardRevocableToken, TokenResponse, TokenUrl,
    basic::BasicClient,
};
use serde_json::{Value, json};
use url::Url;

const LAB_ADDR: &str = "127.0.0.1:38401";

/// The lab's certificate (DER), which the clients of this run trust.
static LAB_CERT: OnceLock<Vec<u8>> = OnceLock::new();

/// An HTTP client that does not follow redirects and trusts the lab's certificate.
fn http_client() -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
    if let Some(der) = LAB_CERT.get() {
        b = b.add_root_certificate(reqwest::Certificate::from_der(der)?);
    }
    Ok(b.build()?)
}
const LAB_USER: &str = "alice";
const LAB_PASSWORD: &str = "a password for the sdk check";

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,lithostroton=info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let arg = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1).cloned())
    };
    let (homeserver, user, password) = match arg("--homeserver") {
        Some(hs) => (
            hs,
            arg("--user").context("--user is needed with --homeserver")?,
            arg("--password").context("--password is needed with --homeserver")?,
        ),
        None => {
            start_lab().await?;
            (
                format!("https://{LAB_ADDR}"),
                LAB_USER.to_owned(),
                LAB_PASSWORD.to_owned(),
            )
        }
    };

    println!("homeserver {homeserver}");
    authorization_code_with_matrix_sdk(&homeserver, &user, &password)
        .await
        .context("matrix-sdk: authorization code grant")?;
    println!("ok  matrix-sdk: register, authorization code, whoami, refresh, logout");
    device_grant_with_oauth2(&homeserver, &user, &password)
        .await
        .context("oauth2: device authorization grant")?;
    println!("ok  oauth2: register, device grant, whoami, refresh, revoke");
    println!("all checks passed");
    Ok(())
}

// ---- the lab: lithostroton and the few homeserver endpoints the clients call ----

async fn start_lab() -> Result<()> {
    let host = Arc::new(MemoryHost::new(
        "lab.invalid",
        lithostroton::Clock::system(),
    ));
    host.add_user(LAB_USER, LAB_PASSWORD);
    let issuer: Url = format!("https://{LAB_ADDR}/_lithostroton/").parse()?;
    let oauth = Embedded::start(
        Config::new(issuer, "lab.invalid"),
        host.clone(),
        Arc::new(MemoryStore::new()),
    )
    .await?;
    let metadata = oauth.metadata();
    let app = Router::new()
        .nest("/_lithostroton", oauth.router())
        .route(
            "/_matrix/client/versions",
            get(|| async { Json(json!({ "versions": ["v1.15", "v1.18", "v1.19"] })) }),
        )
        .route(
            "/_matrix/client/v1/auth_metadata",
            get(move || {
                let m = metadata.clone();
                async move { Json(m) }
            }),
        )
        .route(
            "/_matrix/client/v3/account/whoami",
            get(move |headers: HeaderMap| whoami(host.clone(), headers)),
        )
        .fallback(|uri: axum::http::Uri| async move {
            eprintln!("lab: no route for {uri}");
            (
                StatusCode::NOT_FOUND,
                Json(json!({ "errcode": "M_UNRECOGNIZED", "error": "Unrecognized request" })),
            )
        });
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()])?;
    let _ = LAB_CERT.set(cert.cert.der().to_vec());
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
        cert.cert.pem().into_bytes(),
        cert.signing_key.serialize_pem().into_bytes(),
    )
    .await?;
    let addr: SocketAddr = LAB_ADDR.parse()?;
    // bind first, so that a taken port fails here
    let listener =
        std::net::TcpListener::bind(addr).with_context(|| format!("binding {LAB_ADDR}"))?;
    listener.set_nonblocking(true)?;
    tokio::spawn(async move {
        let _keep = oauth;
        axum_server::from_tcp_rustls(listener, tls)
            .expect("a bound listener")
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
    });
    Ok(())
}

async fn whoami(host: Arc<MemoryHost>, headers: HeaderMap) -> Response {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match token.and_then(|t| host.whoami(t)) {
        Some((user_id, device_id)) => {
            Json(json!({ "user_id": user_id, "device_id": device_id })).into_response()
        }
        None => (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "errcode": "M_UNKNOWN_TOKEN",
                "error": "Unknown access token",
                "soft_logout": false,
            })),
        )
            .into_response(),
    }
}

// ---- a browser ----

struct Browser {
    http: reqwest::Client,
    cookies: HashMap<String, String>,
}

struct Page {
    status: StatusCode,
    location: Option<String>,
    body: String,
}

impl Browser {
    fn new() -> Result<Browser> {
        Ok(Browser {
            http: http_client()?,
            cookies: HashMap::new(),
        })
    }

    fn cookie_header(&self) -> String {
        self.cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    async fn finish(&mut self, resp: reqwest::Response) -> Result<Page> {
        for v in resp.headers().get_all("set-cookie") {
            let v = v.to_str()?;
            let (pair, attrs) = v.split_once(';').unwrap_or((v, ""));
            let (name, value) = pair.split_once('=').context("a cookie without =")?;
            if attrs.contains("Max-Age=0") || value.is_empty() {
                self.cookies.remove(name);
            } else {
                self.cookies.insert(name.to_owned(), value.to_owned());
            }
        }
        let status = StatusCode::from_u16(resp.status().as_u16())?;
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        Ok(Page {
            status,
            location,
            body: resp.text().await?,
        })
    }

    async fn get(&mut self, url: &Url) -> Result<Page> {
        let resp = self
            .http
            .get(url.clone())
            .header("cookie", self.cookie_header())
            .send()
            .await?;
        self.finish(resp).await
    }

    async fn post(&mut self, url: &Url, fields: &[(&str, &str)]) -> Result<Page> {
        let body = {
            let mut ser = form_urlencoded::Serializer::new(String::new());
            for (k, v) in fields {
                ser.append_pair(k, v);
            }
            ser.finish()
        };
        let resp = self
            .http
            .post(url.clone())
            .header("cookie", self.cookie_header())
            .header("content-type", "application/x-www-form-urlencoded")
            .header("origin", url.origin().ascii_serialization())
            .body(body)
            .send()
            .await?;
        self.finish(resp).await
    }

    /// Follows a redirect of lithostroton's: a path, relative to `base`.
    fn follow(base: &Url, page: &Page) -> Result<Url> {
        let loc = page
            .location
            .as_deref()
            .ok_or_else(|| anyhow!("expected a redirect, got {}: {}", page.status, page.body))?;
        Ok(base.join(loc)?)
    }

    /// Signs in on a sign-in page; returns where it sends the browser.
    async fn sign_in(&mut self, login: &Url, user: &str, password: &str) -> Result<Url> {
        let page = self.get(login).await?;
        ensure!(
            page.status == StatusCode::OK,
            "sign-in page: {}",
            page.status
        );
        let csrf = hidden(&page.body, "csrf", None)?;
        let next = hidden(&page.body, "next", None)?;
        let action = login.join("login")?;
        let r = self
            .post(
                &action,
                &[
                    ("csrf", &csrf),
                    ("next", &next),
                    ("username", user),
                    ("password", password),
                ],
            )
            .await?;
        ensure!(
            r.status == StatusCode::SEE_OTHER,
            "signing in: {} {}",
            r.status,
            r.body
        );
        Browser::follow(login, &r)
    }

    /// Opens an authorization URL, signs in, allows; returns the redirect to the client.
    async fn authorize(&mut self, auth_url: &Url, user: &str, password: &str) -> Result<Url> {
        let r = self.get(auth_url).await?;
        let mut next = Browser::follow(auth_url, &r)?;
        if next.path().ends_with("/login") {
            next = self.sign_in(&next, user, password).await?;
        }
        let consent = self.get(&next).await?;
        ensure!(
            consent.status == StatusCode::OK,
            "consent page: {} {}",
            consent.status,
            consent.body
        );
        let action = next.join("consent")?;
        let form_marker = format!("action=\"{}\"", action.path());
        let csrf = hidden(&consent.body, "csrf", Some(&form_marker))?;
        let req = hidden(&consent.body, "req", Some(&form_marker))?;
        let r = self
            .post(
                &action,
                &[("csrf", &csrf), ("req", &req), ("action", "allow")],
            )
            .await?;
        let loc = r
            .location
            .ok_or_else(|| anyhow!("consent answered {}: {}", r.status, r.body))?;
        Ok(Url::parse(&loc)?)
    }

    /// Opens a device's verification URI, signs in, allows.
    async fn allow_device(&mut self, uri: &Url, user: &str, password: &str) -> Result<()> {
        let r = self.get(uri).await?;
        let page_url = if r.status == StatusCode::SEE_OTHER {
            let login = Browser::follow(uri, &r)?;
            self.sign_in(&login, user, password).await?
        } else {
            uri.clone()
        };
        let page = self.get(&page_url).await?;
        ensure!(
            page.status == StatusCode::OK,
            "device page: {} {}",
            page.status,
            page.body
        );
        let action = page_url.join("link")?;
        let marker = format!("action=\"{}\"", action.path());
        let csrf = hidden(&page.body, "csrf", Some(&marker))?;
        let code = hidden(&page.body, "code", Some(&marker))?;
        let r = self
            .post(
                &action,
                &[("csrf", &csrf), ("code", &code), ("action", "allow")],
            )
            .await?;
        ensure!(
            r.status == StatusCode::OK,
            "allowing the device: {} {}",
            r.status,
            r.body
        );
        Ok(())
    }
}

/// The value of a hidden field, the first after `after` if given.
fn hidden(html: &str, name: &str, after: Option<&str>) -> Result<String> {
    let html = match after {
        Some(marker) => html
            .split_once(marker)
            .map(|(_, rest)| rest)
            .ok_or_else(|| anyhow!("no {marker} on the page"))?,
        None => html,
    };
    let needle = format!("name=\"{name}\" value=\"");
    let start = html
        .find(&needle)
        .ok_or_else(|| anyhow!("no hidden field {name}"))?
        + needle.len();
    let end = html[start..].find('"').context("unterminated value")? + start;
    Ok(html[start..end].replace("&amp;", "&"))
}

// ---- matrix-sdk: authorization code grant ----

async fn authorization_code_with_matrix_sdk(
    homeserver: &str,
    user: &str,
    password: &str,
) -> Result<()> {
    let mut builder = Client::builder().homeserver_url(homeserver);
    if let Some(der) = LAB_CERT.get() {
        builder = builder.add_root_certificates(vec![reqwest::Certificate::from_der(der)?]);
    }
    let client = builder.build().await?;
    let oauth = client.oauth();
    let metadata = oauth.server_metadata().await?;
    println!("    issuer {}", metadata.issuer);

    let redirect: Url = "http://127.0.0.1/callback".parse()?;
    let mut client_metadata = ClientMetadata::new(
        ApplicationType::Native,
        vec![OAuthGrantType::AuthorizationCode {
            redirect_uris: vec![redirect.clone()],
        }],
        Localized::new("https://lithostroton.invalid/".parse()?, []),
    );
    client_metadata.client_name = Some(Localized::new("lithostroton sdk check".to_owned(), []));
    let registration = ruma::serde::Raw::new(&client_metadata)?;

    let data = oauth
        .login(redirect, None, Some(registration.into()), None)
        .build()
        .await?;
    // the browser
    let mut browser = Browser::new()?;
    let back = browser.authorize(&data.url, user, password).await?;
    ensure!(back.port().is_some() || back.host_str() == Some("127.0.0.1"));
    oauth.finish_login(UrlOrQuery::Url(back)).await?;

    let user_id = client
        .user_id()
        .context("no user ID after login")?
        .to_owned();
    let device_id = client
        .device_id()
        .context("no device ID after login")?
        .to_owned();
    println!("    signed in as {user_id}, device {device_id}");
    let me = client.whoami().await?;
    ensure!(me.user_id == user_id, "whoami says {}", me.user_id);

    let before = client.access_token().context("no access token")?;
    oauth.refresh_access_token().await?;
    let after = client
        .access_token()
        .context("no access token after refresh")?;
    ensure!(
        before != after,
        "the refresh did not change the access token"
    );
    client.whoami().await.context("whoami after the refresh")?;

    oauth.logout().await?;
    let status = http_client()?
        .get(format!("{homeserver}/_matrix/client/v3/account/whoami"))
        .bearer_auth(&after)
        .send()
        .await?
        .status();
    ensure!(
        status.as_u16() == 401,
        "the access token still works after logout: {status}"
    );
    Ok(())
}

// ---- the oauth2 crate: device authorization grant ----

async fn device_grant_with_oauth2(homeserver: &str, user: &str, password: &str) -> Result<()> {
    let http = http_client()?;
    let metadata: Value = serde_json::from_str(
        &http
            .get(format!("{homeserver}/_matrix/client/v1/auth_metadata"))
            .send()
            .await?
            .text()
            .await?,
    )?;
    let endpoint = |name: &str| -> Result<String> {
        metadata[name]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| anyhow!("no {name} in the metadata"))
    };

    // dynamic registration of a device-only client
    let registered: Value = serde_json::from_str(
        &http
            .post(endpoint("registration_endpoint")?)
            .header("content-type", "application/json")
            .body(
                json!({
                    "client_name": "lithostroton device check",
                    "client_uri": "https://lithostroton.invalid/",
                    "application_type": "native",
                    "grant_types": [
                        "urn:ietf:params:oauth:grant-type:device_code",
                        "refresh_token",
                    ],
                    "token_endpoint_auth_method": "none",
                })
                .to_string(),
            )
            .send()
            .await?
            .text()
            .await?,
    )?;
    let client_id = registered["client_id"]
        .as_str()
        .ok_or_else(|| anyhow!("registration failed: {registered}"))?;

    let oauth = BasicClient::new(ClientId::new(client_id.to_owned()))
        .set_auth_type(AuthType::RequestBody)
        .set_token_uri(TokenUrl::new(endpoint("token_endpoint")?)?)
        .set_device_authorization_url(DeviceAuthorizationUrl::new(endpoint(
            "device_authorization_endpoint",
        )?)?)
        .set_revocation_url(RevocationUrl::new(endpoint("revocation_endpoint")?)?);
    let client = oauth2_reqwest::ReqwestClient::from(http.clone());

    let device_id = "SDKCHECKDEV";
    let details: StandardDeviceAuthorizationResponse = oauth
        .exchange_device_code()
        .add_scope(Scope::new("urn:matrix:client:api:*".into()))
        .add_scope(Scope::new(format!("urn:matrix:client:device:{device_id}")))
        .request_async(&client)
        .await
        .map_err(|e| anyhow!("device authorization: {e:?}"))?;
    println!(
        "    user code {} at {}",
        details.user_code().secret(),
        details.verification_uri().as_str()
    );

    // the user, in a browser, meanwhile
    let complete = details
        .verification_uri_complete()
        .map(|u| u.secret().clone())
        .context("no verification_uri_complete")?;
    let (user, password) = (user.to_owned(), password.to_owned());
    let approval = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let mut browser = Browser::new()?;
        browser
            .allow_device(&Url::parse(&complete)?, &user, &password)
            .await
    });

    let token = oauth
        .exchange_device_access_token(&details)
        .request_async(&client, tokio::time::sleep, Some(Duration::from_secs(120)))
        .await
        .map_err(|e| anyhow!("device token: {e:?}"))?;
    approval.await??;

    let whoami = |access: String| {
        let http = http.clone();
        let url = format!("{homeserver}/_matrix/client/v3/account/whoami");
        async move {
            let r = http.get(url).bearer_auth(access).send().await?;
            let status = r.status().as_u16();
            let body: Value = serde_json::from_str(&r.text().await?).unwrap_or(Value::Null);
            anyhow::Ok((status, body))
        }
    };
    let (status, me) = whoami(token.access_token().secret().clone()).await?;
    ensure!(status == 200, "whoami: {status} {me}");
    ensure!(me["device_id"] == device_id, "whoami device: {me}");
    println!("    device signed in as {}", me["user_id"]);

    let refresh = token.refresh_token().context("no refresh token")?;
    let refreshed = oauth
        .exchange_refresh_token(&RefreshToken::new(refresh.secret().clone()))
        .request_async(&client)
        .await
        .map_err(|e| anyhow!("refresh: {e:?}"))?;
    let access = refreshed.access_token().secret().clone();
    let (status, _) = whoami(access.clone()).await?;
    ensure!(status == 200, "whoami after the refresh: {status}");

    oauth
        .revoke_token(StandardRevocableToken::AccessToken(
            refreshed.access_token().clone(),
        ))
        .map_err(|e| anyhow!("{e:?}"))?
        .request_async(&client)
        .await
        .map_err(|e| anyhow!("revoke: {e:?}"))?;
    let (status, _) = whoami(access).await?;
    if status != 401 {
        bail!("the access token still works after revocation: {status}");
    }
    Ok(())
}
