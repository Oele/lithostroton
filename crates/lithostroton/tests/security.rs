//! One or more tests for each security rule: RFC 9700 and the rules lithostroton was started
//! under.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::*;
use http::StatusCode;
use serde_json::json;

// ---- no open redirects ----

#[tokio::test]
async fn unknown_client_or_redirect_uri_never_redirects() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let pkce = Pkce::new();
    let base = AuthParams::new(&client_id, "D", &pkce);
    for params in [
        base.clone().set("client_id", "no-such-client"),
        base.clone().without("client_id"),
        base.clone()
            .set("redirect_uri", "https://evil.org/callback"),
        base.clone()
            .set("redirect_uri", "https://app.example.com/callback/x"),
        base.clone()
            .set("redirect_uri", "https://app.example.com/callback?x=1"),
        base.clone().without("redirect_uri"),
        // and with every other parameter wrong as well
        base.clone()
            .set("redirect_uri", "https://evil.org/callback")
            .set("response_type", "token"),
    ] {
        let r = lab.get(&params.url()).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", params.url());
        assert!(r.header("location").is_none(), "{}", params.url());
        assert!(r.body.contains("<h1>"));
    }
}

#[tokio::test]
async fn implicit_grant_is_refused() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let pkce = Pkce::new();
    for rt in ["token", "id_token", "code token"] {
        let r = lab
            .get(
                &AuthParams::new(&client_id, "D", &pkce)
                    .set("response_type", rt)
                    .url(),
            )
            .await;
        assert_eq!(
            callback_params(&r.location())["error"],
            "unsupported_response_type",
            "{rt}"
        );
    }
    // and a client cannot register for it
    let mut meta = web_client();
    meta["response_types"] = json!(["token"]);
    meta["grant_types"] = json!(["implicit"]);
    let r = lab.post_json("oauth2/registration", &meta).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

// ---- PKCE, always, with S256 ----

#[tokio::test]
async fn pkce_is_required_with_s256() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let pkce = Pkce::new();
    let base = AuthParams::new(&client_id, "D", &pkce);
    for params in [
        base.clone().without("code_challenge"),
        base.clone().without("code_challenge_method"),
        base.clone().set("code_challenge_method", "plain"),
        base.clone().set("code_challenge", "short"),
    ] {
        let r = lab.get(&params.url()).await;
        let p = callback_params(&r.location());
        assert_eq!(p["error"], "invalid_request", "{}", params.url());
        assert_eq!(p["state"], "st4te");
        assert_eq!(p["iss"], ISSUER);
    }
}

#[tokio::test]
async fn a_wrong_verifier_fails_and_burns_the_code() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let pkce = Pkce::new();
    let code = lab
        .browser()
        .authorize_and_allow(&AuthParams::new(&client_id, "D", &pkce))
        .await;
    let exchange = |verifier: Option<String>| {
        let lab = &lab;
        let code = code.clone();
        let client_id = client_id.clone();
        async move {
            let mut f = vec![
                ("grant_type", "authorization_code".to_owned()),
                ("code", code),
                ("redirect_uri", WEB_REDIRECT.to_owned()),
                ("client_id", client_id),
            ];
            if let Some(v) = verifier {
                f.push(("code_verifier", v));
            }
            let f: Vec<(&str, &str)> = f.iter().map(|(k, v)| (*k, v.as_str())).collect();
            lab.token(&f).await
        }
    };
    let r = exchange(Some(Pkce::new().verifier)).await;
    assert_oauth_error(&r, StatusCode::BAD_REQUEST, "invalid_grant");
    // the right verifier now: the code is gone
    let r = exchange(Some(pkce.verifier.clone())).await;
    assert_oauth_error(&r, StatusCode::BAD_REQUEST, "invalid_grant");
    assert!(lab.host.device_ids(&lab.alice).is_empty());

    // no verifier at all
    let pkce = Pkce::new();
    let code2 = lab
        .browser()
        .authorize_and_allow(&AuthParams::new(&client_id, "D", &pkce))
        .await;
    let r = lab
        .token(&[
            ("grant_type", "authorization_code"),
            ("code", &code2),
            ("redirect_uri", WEB_REDIRECT),
            ("client_id", &client_id),
        ])
        .await;
    assert_oauth_error(&r, StatusCode::BAD_REQUEST, "invalid_grant");
}

// ---- codes: single use, short-lived, bound to client, redirect URI and challenge ----

async fn fresh_code(lab: &Lab, client_id: &str) -> (String, Pkce) {
    let pkce = Pkce::new();
    let code = lab
        .browser()
        .authorize_and_allow(&AuthParams::new(client_id, "DEV1", &pkce))
        .await;
    (code, pkce)
}

#[tokio::test]
async fn codes_work_once_and_a_replay_ends_the_session() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let (code, pkce) = fresh_code(&lab, &client_id).await;
    let r = exchange(&lab, &code, &client_id, WEB_REDIRECT, &pkce.verifier).await;
    assert_eq!(r.status, StatusCode::OK);
    let access = r.json()["access_token"].as_str().unwrap().to_owned();
    let r = exchange(&lab, &code, &client_id, WEB_REDIRECT, &pkce.verifier).await;
    assert_oauth_error(&r, StatusCode::BAD_REQUEST, "invalid_grant");
    assert!(
        lab.host.whoami(&access).is_none(),
        "the session of the code ended"
    );
    assert!(lab.host.device_ids(&lab.alice).is_empty());
}

#[tokio::test]
async fn codes_expire() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let (code, pkce) = fresh_code(&lab, &client_id).await;
    lab.clock.advance(Duration::from_secs(121));
    let r = exchange(&lab, &code, &client_id, WEB_REDIRECT, &pkce.verifier).await;
    assert_oauth_error(&r, StatusCode::BAD_REQUEST, "invalid_grant");
}

#[tokio::test]
async fn codes_are_bound_to_client_and_redirect_uri() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let mut other = web_client();
    other["client_name"] = json!("Other");
    let other_id = lab.register(other).await;

    let (code, pkce) = fresh_code(&lab, &client_id).await;
    let r = exchange(&lab, &code, &other_id, WEB_REDIRECT, &pkce.verifier).await;
    assert_oauth_error(&r, StatusCode::BAD_REQUEST, "invalid_grant");

    let (code, pkce) = fresh_code(&lab, &client_id).await;
    let r = exchange(
        &lab,
        &code,
        &client_id,
        "https://app.example.com/other",
        &pkce.verifier,
    )
    .await;
    assert_oauth_error(&r, StatusCode::BAD_REQUEST, "invalid_grant");

    let (code, pkce) = fresh_code(&lab, &client_id).await;
    let r = lab
        .token(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", &client_id),
            ("code_verifier", &pkce.verifier),
        ])
        .await;
    assert_oauth_error(&r, StatusCode::BAD_REQUEST, "invalid_grant");
    assert!(lab.host.device_ids(&lab.alice).is_empty());
}

#[tokio::test]
async fn a_code_is_bound_to_the_browser_session_s_consent() {
    // the consent request can be answered once: a second allow gets nothing
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let mut b = lab.browser();
    let page = b
        .authorize_to_consent(&AuthParams::new(&client_id, "D", &Pkce::new()))
        .await;
    let r = b.answer_consent(&page, "allow").await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let r = b.answer_consent(&page, "allow").await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert!(r.header("location").is_none());
}

// ---- token endpoint strictness ----

#[tokio::test]
async fn token_endpoint_rejects_odd_requests() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    // a parameter twice
    let r = lab
        .request(
            http::Request::post(lab.path("oauth2/token"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(format!(
                    "grant_type=refresh_token&refresh_token=a&refresh_token=b&client_id={client_id}"
                )))
                .unwrap(),
        )
        .await;
    assert_oauth_error(&r, StatusCode::BAD_REQUEST, "invalid_request");
    // not a form
    let r = lab
        .post_json("oauth2/token", &json!({"grant_type": "refresh_token"}))
        .await;
    assert_oauth_error(&r, StatusCode::BAD_REQUEST, "invalid_request");
    // an unknown grant
    let r = lab
        .token(&[("grant_type", "password"), ("client_id", &client_id)])
        .await;
    assert_oauth_error(&r, StatusCode::BAD_REQUEST, "unsupported_grant_type");
    // client authentication is not something public clients do
    let r = lab
        .post_form_with(
            "oauth2/token",
            &[("grant_type", "refresh_token"), ("refresh_token", "x")],
            &[("authorization", "Basic Zm9vOmJhcg==")],
        )
        .await;
    assert_oauth_error(&r, StatusCode::UNAUTHORIZED, "invalid_client");
    assert_eq!(r.header("www-authenticate").as_deref(), Some("Basic"));
    // an unknown client
    let r = lab
        .token(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", "x"),
            ("client_id", "nope"),
        ])
        .await;
    assert_oauth_error(&r, StatusCode::UNAUTHORIZED, "invalid_client");
}

// ---- CSRF tokens on every form ----

#[tokio::test]
async fn forms_need_their_csrf_token() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let mut b = lab.browser();
    let r = b
        .get(&AuthParams::new(&client_id, "D", &Pkce::new()).url())
        .await;
    let login = b.get(&r.location()).await;
    let csrf = login.hidden("csrf");
    let next = login.hidden("next");
    let base = [
        ("next", next.as_str()),
        ("username", "alice"),
        ("password", PASSWORD),
    ];

    // no token, a made-up token, another browser's token
    for token in [
        None,
        Some("x".repeat(43)),
        Some(another_browsers_token(&mut b).await),
    ] {
        let mut f = base.to_vec();
        if let Some(t) = &token {
            f.push(("csrf", t));
        }
        let r = b.post("login", &f).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{token:?}");
        assert!(r.body.contains("expired"));
        assert!(!b.cookies.contains_key("__Secure-lithostroton-session"));
    }
    // the token, but posted from another origin or site
    let mut f = base.to_vec();
    f.push(("csrf", &csrf));
    for headers in [
        vec![("origin", "https://evil.org")],
        vec![("origin", "null")],
        vec![("sec-fetch-site", "cross-site")],
        vec![("sec-fetch-site", "same-site")],
    ] {
        let r = b.post_with("login", &f, &headers).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{headers:?}");
    }
    // the token without the cookie it was made for
    let mut stranger = lab.browser();
    let r = stranger.post("login", &f).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // finally right
    let r = b.post("login", &f).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
}

/// A valid CSRF token of the sign-in form, made for another browser's cookie.
async fn another_browsers_token(b: &mut Browser<'_>) -> String {
    let mut other = b.lab.browser();
    other.get("login").await.hidden("csrf")
}

#[tokio::test]
async fn consent_needs_its_csrf_token_and_gives_no_code_without() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let mut b = lab.browser();
    let page = b
        .authorize_to_consent(&AuthParams::new(&client_id, "D", &Pkce::new()))
        .await;
    let req = page.hidden("req");
    // the sign-out form's token is a valid token of this browser, for another form
    let logout_token = page.hidden("csrf");
    for fields in [
        vec![("req", req.as_str()), ("action", "allow")],
        vec![
            ("req", req.as_str()),
            ("action", "allow"),
            ("csrf", logout_token.as_str()),
        ],
    ] {
        let r = b.post("consent", &fields).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
        assert!(r.header("location").is_none());
    }
    // the request is still there to be answered properly
    let r = b.answer_consent(&page, "allow").await;
    assert!(callback_params(&r.location()).contains_key("code"));
}

#[tokio::test]
async fn device_answer_needs_its_csrf_token() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let r = lab
        .post_form(
            "oauth2/device",
            &[("client_id", &client_id), ("scope", &scope("D"))],
        )
        .await;
    let d = r.json();
    let code = d["user_code"].as_str().unwrap().replace('-', "");
    let mut b = lab.browser();
    let r = b
        .get(d["verification_uri_complete"].as_str().unwrap())
        .await;
    b.login(&r.location(), "alice", PASSWORD).await;
    let r = b
        .post("link", &[("code", &code), ("action", "allow")])
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = lab
        .token(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", d["device_code"].as_str().unwrap()),
            ("client_id", &client_id),
        ])
        .await;
    assert_oauth_error(&r, StatusCode::BAD_REQUEST, "authorization_pending");
}

// ---- framing, headers, cookies ----

#[tokio::test]
async fn every_response_forbids_framing_and_sniffing() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let mut b = lab.browser();
    let consent = b
        .authorize_to_consent(&AuthParams::new(&client_id, "D", &Pkce::new()))
        .await;
    let login = lab.get("login").await;
    let link = lab.get("link").await;
    let meta = lab.get(".well-known/oauth-authorization-server").await;
    let token = lab.token(&[("grant_type", "nope")]).await;
    let missing = lab.get("no/such/page").await;
    for r in [&consent, &login, &link, &meta, &token, &missing] {
        let csp = r.header("content-security-policy").unwrap();
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
        assert_eq!(r.header("x-frame-options").as_deref(), Some("DENY"));
        assert_eq!(
            r.header("x-content-type-options").as_deref(),
            Some("nosniff")
        );
        assert_eq!(r.header("referrer-policy").as_deref(), Some("no-referrer"));
    }
    for page in [&consent, &login, &link] {
        let csp = page.header("content-security-policy").unwrap();
        assert!(csp.contains("default-src 'none'"));
        assert!(!csp.contains("script-src"), "no scripts at all");
        assert!(!page.body.contains("<script"));
        assert_eq!(page.header("cache-control").as_deref(), Some("no-store"));
    }
    assert!(
        login
            .header("content-security-policy")
            .unwrap()
            .contains("form-action 'self'")
    );
}

#[tokio::test]
async fn cookies_are_secure_httponly_samesite_and_scoped() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let mut b = lab.browser();
    let r = b
        .get(&AuthParams::new(&client_id, "D", &Pkce::new()).url())
        .await;
    let page = b.get(&r.location()).await;
    let r = b
        .post(
            "login",
            &[
                ("csrf", &page.hidden("csrf")),
                ("next", &page.hidden("next")),
                ("username", "alice"),
                ("password", PASSWORD),
            ],
        )
        .await;
    let mut set: Vec<String> = page
        .headers
        .get_all("set-cookie")
        .iter()
        .chain(r.headers.get_all("set-cookie"))
        .map(|v| v.to_str().unwrap().to_owned())
        .collect();
    set.sort();
    assert_eq!(set.len(), 2, "{set:?}");
    for c in &set {
        assert!(c.starts_with("__Secure-lithostroton-"), "{c}");
        for attr in ["Secure", "HttpOnly", "SameSite=Lax", "Path=/_lithostroton/"] {
            assert!(c.split("; ").any(|a| a == attr), "{attr} in {c}");
        }
        assert!(!c.contains("Domain="));
    }
}

#[tokio::test]
async fn signing_in_gives_a_new_session_id() {
    let lab = Lab::new().await;
    let mut b = lab.browser();
    b.cookies.insert(
        "__Secure-lithostroton-session".into(),
        "planted-by-an-attacker-planted-by-an-attac".into(),
    );
    let r = b.login("login", "alice", PASSWORD).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_ne!(
        b.cookies["__Secure-lithostroton-session"],
        "planted-by-an-attacker-planted-by-an-attac"
    );
}

#[tokio::test]
async fn signing_out_ends_the_browser_session() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let mut b = lab.browser();
    let page = b
        .authorize_to_consent(&AuthParams::new(&client_id, "D", &Pkce::new()))
        .await;
    let old = b.cookies["__Secure-lithostroton-session"].clone();
    let r = b
        .post(
            "logout",
            &[
                ("csrf", &page.hidden("csrf")),
                ("next", &page.hidden("next")),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert!(r.location().contains("/login?next=authorize:"));
    assert!(!b.cookies.contains_key("__Secure-lithostroton-session"));
    // the old cookie, kept by someone, no longer signs in
    b.cookies
        .insert("__Secure-lithostroton-session".into(), old);
    let r = b.get(&format!("consent?req={}", page.hidden("req"))).await;
    assert!(r.location().contains("/login?"));
}

#[tokio::test]
async fn cors_on_client_endpoints_only() {
    let lab = Lab::new().await;
    let preflight = lab
        .request(
            http::Request::options(lab.path("oauth2/token"))
                .header("origin", "https://app.example.com")
                .header("access-control-request-method", "POST")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
    assert!(preflight.status.is_success(), "{}", preflight.status);
    assert_eq!(
        preflight.header("access-control-allow-origin").as_deref(),
        Some("*")
    );
    assert!(
        preflight
            .header("access-control-allow-credentials")
            .is_none()
    );
    let meta = lab.get(".well-known/oauth-authorization-server").await;
    assert_eq!(
        meta.header("access-control-allow-origin").as_deref(),
        Some("*")
    );
    let login = lab.get("login").await;
    assert!(login.header("access-control-allow-origin").is_none());

    let lab = Lab::with(|c| c.cors = false).await;
    let meta = lab.get(".well-known/oauth-authorization-server").await;
    assert!(meta.header("access-control-allow-origin").is_none());
}

// ---- rate limits ----

#[tokio::test]
async fn password_checks_are_rate_limited_per_address() {
    let lab = Lab::new().await;
    let mut b = lab.browser();
    // ten users from one address (under each user's own limit)
    for i in 0..10 {
        let r = b.login("login", &format!("user{i}"), "wrong").await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "attempt {i}");
    }
    let r = b.login("login", "alice", PASSWORD).await;
    assert_eq!(
        r.status,
        StatusCode::TOO_MANY_REQUESTS,
        "even the right password waits"
    );
    // another address is not held up
    let mut other = lab.browser();
    other.ip = "192.0.2.99".into();
    assert_eq!(
        other.login("login", "alice", PASSWORD).await.status,
        StatusCode::SEE_OTHER
    );
    // and after a while the address may try again
    lab.clock.advance(Duration::from_secs(6));
    let r = b.login("login", "alice", PASSWORD).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn password_checks_are_rate_limited_per_user() {
    let lab = Lab::new().await;
    for i in 0..5 {
        let mut b = lab.browser();
        b.ip = format!("198.51.100.{i}");
        let r = b.login("login", "@Alice:example.org", "wrong").await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
    }
    let mut b = lab.browser();
    b.ip = "203.0.113.1".into();
    let r = b.login("login", "alice", PASSWORD).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    lab.clock.advance(Duration::from_secs(12));
    let r = b.login("login", "alice", PASSWORD).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn token_requests_are_rate_limited_and_refreshes_get_503() {
    let lab = Lab::with(|c| {
        c.rate_limits.token_per_address = lithostroton::RateLimit::new(2, Duration::from_secs(60))
    })
    .await;
    let client_id = lab.register_web().await;
    let t = lab.sign_in(&client_id, "D").await; // one token request
    let rt = t["refresh_token"].as_str().unwrap();
    let refresh = [
        ("grant_type", "refresh_token"),
        ("refresh_token", rt),
        ("client_id", client_id.as_str()),
    ];
    assert_eq!(lab.token(&refresh).await.status, StatusCode::OK);
    let r = lab.token(&refresh).await;
    assert_oauth_error(
        &r,
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
    );
    assert!(r.header("retry-after").is_some());
    let r = lab
        .token(&[
            ("grant_type", "authorization_code"),
            ("client_id", &client_id),
        ])
        .await;
    assert_oauth_error(&r, StatusCode::TOO_MANY_REQUESTS, "rate_limited");
}

#[tokio::test]
async fn user_code_guessing_is_rate_limited() {
    let lab = Lab::new().await;
    let mut b = lab.browser();
    for _ in 0..10 {
        let r = b.get("link?code=BBBB-BBBB").await;
        assert_eq!(r.status, StatusCode::NOT_FOUND);
    }
    let r = b.get("link?code=BBBB-BBBB").await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn registrations_are_rate_limited() {
    let lab = Lab::new().await;
    for _ in 0..20 {
        assert_eq!(
            lab.post_json("oauth2/registration", &web_client())
                .await
                .status,
            StatusCode::CREATED
        );
    }
    let r = lab.post_json("oauth2/registration", &web_client()).await;
    assert_oauth_error(&r, StatusCode::TOO_MANY_REQUESTS, "rate_limited");
}

#[tokio::test]
async fn browser_session_expires() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let mut b = lab.browser();
    b.authorize_and_allow(&AuthParams::new(&client_id, "D", &Pkce::new()))
        .await;
    lab.clock.advance(Duration::from_secs(7 * 24 * 3600 + 1));
    let r = b
        .get(&AuthParams::new(&client_id, "D", &Pkce::new()).url())
        .await;
    assert!(r.location().contains("/login?"));
}

#[tokio::test]
async fn authorization_requests_expire() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let mut b = lab.browser();
    let page = b
        .authorize_to_consent(&AuthParams::new(&client_id, "D", &Pkce::new()))
        .await;
    lab.clock.advance(Duration::from_secs(31 * 60));
    let r = b.answer_consent(&page, "allow").await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert!(r.header("location").is_none());
}
