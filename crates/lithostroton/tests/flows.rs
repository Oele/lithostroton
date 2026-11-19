//! The flows of the specification's OAuth 2.0 API, end to end: metadata, registration, the
//! authorization code grant, refresh, revocation, the device authorization grant.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::*;
use http::StatusCode;
use lithostroton::Host;
use serde_json::json;

#[tokio::test]
async fn metadata_has_what_the_spec_requires() {
    let lab = Lab::new().await;
    let m = lab.metadata().await;
    assert_eq!(m["issuer"], ISSUER);
    for (field, path) in [
        ("authorization_endpoint", "oauth2/authorize"),
        ("token_endpoint", "oauth2/token"),
        ("revocation_endpoint", "oauth2/revoke"),
        ("registration_endpoint", "oauth2/registration"),
        ("device_authorization_endpoint", "oauth2/device"),
    ] {
        assert_eq!(m[field], format!("{ISSUER}{path}"), "{field}");
    }
    assert_eq!(m["response_types_supported"], json!(["code"]));
    assert_eq!(m["response_modes_supported"], json!(["query", "fragment"]));
    assert_eq!(m["code_challenge_methods_supported"], json!(["S256"]));
    let grants = m["grant_types_supported"].as_array().unwrap();
    for g in [
        "authorization_code",
        "refresh_token",
        "urn:ietf:params:oauth:grant-type:device_code",
    ] {
        assert!(grants.contains(&json!(g)), "{g}");
    }
    assert!(
        m.get("prompt_values_supported").is_none(),
        "registration is off"
    );
    assert_eq!(m, lab.embedded.metadata());
    assert_eq!(lab.get(".well-known/openid-configuration").await.json(), m);
}

#[tokio::test]
async fn registration_answers_201_and_deduplicates() {
    let lab = Lab::new().await;
    let r = lab.post_json("oauth2/registration", &web_client()).await;
    assert_eq!(r.status, StatusCode::CREATED);
    let body = r.json();
    let id = body["client_id"].as_str().unwrap().to_owned();
    assert_eq!(body["client_name"], "Test Client");
    assert_eq!(body["token_endpoint_auth_method"], "none");
    assert_eq!(body["redirect_uris"], json!([WEB_REDIRECT]));
    // the same metadata again: the same client
    assert_eq!(lab.register_web().await, id);
    // other metadata: another client
    let mut other = web_client();
    other["client_name"] = json!("Other");
    assert_ne!(lab.register(other).await, id);
}

#[tokio::test]
async fn registration_refusals_are_rfc7591_errors() {
    let lab = Lab::new().await;
    let mut bad = web_client();
    bad["redirect_uris"] = json!(["https://evil.org/cb"]);
    let r = lab.post_json("oauth2/registration", &bad).await;
    assert_oauth_error(&r, StatusCode::BAD_REQUEST, "invalid_redirect_uri");

    let mut bad = web_client();
    bad["client_uri"] = json!("http://example.com/");
    let r = lab.post_json("oauth2/registration", &bad).await;
    assert_oauth_error(&r, StatusCode::BAD_REQUEST, "invalid_client_metadata");

    let r = lab
        .request(
            http::Request::post(lab.path("oauth2/registration"))
                .body(axum::body::Body::from("not json"))
                .unwrap(),
        )
        .await;
    assert_oauth_error(&r, StatusCode::BAD_REQUEST, "invalid_client_metadata");
}

#[tokio::test]
async fn authorization_code_flow() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let t = lab.sign_in(&client_id, "DEVICEAAAA").await;
    assert_eq!(t["token_type"], "Bearer");
    assert_eq!(t["scope"], scope("DEVICEAAAA"));
    assert_eq!(t["expires_in"], 300);
    let access = t["access_token"].as_str().unwrap();
    assert!(t["refresh_token"].as_str().is_some());
    // the homeserver's own token check accepts the token: it issued it
    assert_eq!(
        lab.host.whoami(access),
        Some((lab.alice.clone(), "DEVICEAAAA".to_owned()))
    );
    assert_eq!(
        lab.host
            .device_display_name(&lab.alice, "DEVICEAAAA")
            .as_deref(),
        Some("Test Client")
    );
}

#[tokio::test]
async fn fragment_response_mode() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let pkce = Pkce::new();
    let mut b = lab.browser();
    let params = AuthParams::new(&client_id, "DEV1", &pkce).set("response_mode", "fragment");
    let page = b.authorize_to_consent(&params).await;
    let r = b.answer_consent(&page, "allow").await;
    let loc = r.location();
    assert!(loc.starts_with(&format!("{WEB_REDIRECT}#")), "{loc}");
    assert!(callback_params(&loc).contains_key("code"));
}

#[tokio::test]
async fn query_response_keeps_the_redirect_uris_query() {
    let lab = Lab::new().await;
    let mut meta = web_client();
    meta["redirect_uris"] = json!(["https://app.example.com/cb?tenant=x"]);
    let client_id = lab.register(meta).await;
    let pkce = Pkce::new();
    let mut b = lab.browser();
    let params = AuthParams::new(&client_id, "DEV1", &pkce)
        .set("redirect_uri", "https://app.example.com/cb?tenant=x");
    let page = b.authorize_to_consent(&params).await;
    let loc = b.answer_consent(&page, "allow").await.location();
    assert!(
        loc.starts_with("https://app.example.com/cb?tenant=x&code="),
        "{loc}"
    );
}

#[tokio::test]
async fn deny_sends_access_denied() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let pkce = Pkce::new();
    let mut b = lab.browser();
    let page = b
        .authorize_to_consent(&AuthParams::new(&client_id, "DEV1", &pkce))
        .await;
    let r = b.answer_consent(&page, "deny").await;
    let p = callback_params(&r.location());
    assert_eq!(p["error"], "access_denied");
    assert_eq!(p["state"], "st4te");
    assert!(!p.contains_key("code"));
    assert!(lab.host.device_ids(&lab.alice).is_empty());
}

#[tokio::test]
async fn a_signed_in_browser_goes_straight_to_consent() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let pkce = Pkce::new();
    let mut b = lab.browser();
    b.authorize_and_allow(&AuthParams::new(&client_id, "DEV1", &pkce))
        .await;
    let r = b
        .get(&AuthParams::new(&client_id, "DEV2", &pkce).url())
        .await;
    assert!(r.location().contains("/consent?req="), "{}", r.location());
    // prompt=login asks for the password again
    let r = b
        .get(
            &AuthParams::new(&client_id, "DEV3", &pkce)
                .set("prompt", "login")
                .url(),
        )
        .await;
    assert!(r.location().contains("/login?"), "{}", r.location());
}

#[tokio::test]
async fn consent_page_shows_the_client_as_unverified_and_the_device() {
    let lab = Lab::new().await;
    let mut meta = web_client();
    meta["client_name"] = json!("<script>alert(1)</script>");
    meta["tos_uri"] = json!("https://example.com/tos");
    let client_id = lab.register(meta).await;
    let pkce = Pkce::new();
    let mut b = lab.browser();
    let page = b
        .authorize_to_consent(&AuthParams::new(&client_id, "DEVICEXYZ", &pkce))
        .await;
    assert!(page.body.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(!page.body.contains("<script>"));
    assert!(page.body.contains("has not verified them"));
    assert!(page.body.contains("https://example.com/"));
    assert!(page.body.contains("app.example.com"));
    assert!(page.body.contains("DEVICEXYZ"));
    assert!(page.body.contains("https://example.com/tos"));
    assert!(page.body.contains("@alice:example.org"));
    assert!(!page.body.contains("already have a session"));

    // the same device ID again: the page says it replaces a session
    let code = b.answer_consent(&page, "allow").await;
    let code = callback_params(&code.location())["code"].clone();
    let r = lab
        .token(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", WEB_REDIRECT),
            ("client_id", &client_id),
            ("code_verifier", &pkce.verifier),
        ])
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let page = b
        .authorize_to_consent(&AuthParams::new(&client_id, "DEVICEXYZ", &Pkce::new()))
        .await;
    assert!(page.body.contains("already have a session"));
}

#[tokio::test]
async fn native_client_with_loopback_and_private_use_redirects() {
    let lab = Lab::new().await;
    let client_id = lab
        .register(json!({
            "client_name": "Native",
            "client_uri": "https://example.com/",
            "application_type": "native",
            "redirect_uris": ["http://127.0.0.1/callback", "com.example.app:/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": "none",
        }))
        .await;
    for redirect in [
        "http://127.0.0.1:43123/callback",
        "com.example.app:/callback",
    ] {
        let pkce = Pkce::new();
        let mut b = lab.browser();
        let params = AuthParams::new(&client_id, "NATIVE1", &pkce).set("redirect_uri", redirect);
        let page = b.authorize_to_consent(&params).await;
        let loc = b.answer_consent(&page, "allow").await.location();
        assert!(loc.starts_with(&format!("{redirect}?")), "{loc}");
        let code = callback_params(&loc)["code"].clone();
        let r = lab
            .token(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", redirect),
                ("client_id", &client_id),
                ("code_verifier", &pkce.verifier),
            ])
            .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    }
}

#[tokio::test]
async fn refresh_rotates_and_keeps_scope() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let t1 = lab.sign_in(&client_id, "DEV1").await;
    let r = lab
        .token(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", t1["refresh_token"].as_str().unwrap()),
            ("client_id", &client_id),
        ])
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let t2 = r.json();
    assert_ne!(t2["refresh_token"], t1["refresh_token"]);
    assert_ne!(t2["access_token"], t1["access_token"]);
    assert_eq!(t2["scope"], scope("DEV1"));
    assert!(
        lab.host
            .whoami(t2["access_token"].as_str().unwrap())
            .is_some()
    );
}

#[tokio::test]
async fn refresh_can_be_retried_until_the_new_tokens_are_used() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let t1 = lab.sign_in(&client_id, "DEV1").await;
    let refresh = |rt: String| {
        let lab = &lab;
        let client_id = client_id.clone();
        async move {
            lab.token(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &rt),
                ("client_id", &client_id),
            ])
            .await
        }
    };
    let rt1 = t1["refresh_token"].as_str().unwrap().to_owned();
    // the answer is lost: the client tries again with the same refresh token
    let lost = refresh(rt1.clone()).await;
    assert_eq!(lost.status, StatusCode::OK);
    let retry = refresh(rt1.clone()).await;
    assert_eq!(retry.status, StatusCode::OK, "{}", retry.body);
    let t2 = retry.json();
    // the tokens of the lost answer are dead
    assert!(
        lab.host
            .whoami(lost.json()["access_token"].as_str().unwrap())
            .is_none()
    );
    // the new access token is used: the old refresh token is replaced, and its reuse ends
    // the session
    assert!(
        lab.host
            .whoami(t2["access_token"].as_str().unwrap())
            .is_some()
    );
    let replay = refresh(rt1).await;
    assert_oauth_error(&replay, StatusCode::BAD_REQUEST, "invalid_grant");
    assert!(
        lab.host.device_ids(&lab.alice).is_empty(),
        "the session ended"
    );
    let r = refresh(t2["refresh_token"].as_str().unwrap().to_owned()).await;
    assert_oauth_error(&r, StatusCode::BAD_REQUEST, "invalid_grant");
}

#[tokio::test]
async fn refresh_is_bound_to_the_client_and_scope() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let mut other = web_client();
    other["client_name"] = json!("Other");
    let other_id = lab.register(other).await;
    let t1 = lab.sign_in(&client_id, "DEV1").await;
    let rt = t1["refresh_token"].as_str().unwrap();
    let r = lab
        .token(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt),
            ("client_id", &other_id),
        ])
        .await;
    assert_oauth_error(&r, StatusCode::BAD_REQUEST, "invalid_grant");
    let r = lab
        .token(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt),
            ("client_id", &client_id),
            ("scope", &scope("OTHERDEVICE")),
        ])
        .await;
    assert_oauth_error(&r, StatusCode::BAD_REQUEST, "invalid_scope");
    // the same scope in another order is fine
    let r = lab
        .token(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt),
            ("client_id", &client_id),
            (
                "scope",
                "urn:matrix:client:device:DEV1 urn:matrix:client:api:*",
            ),
        ])
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
}

#[tokio::test]
async fn revocation_ends_the_session() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    for (hint, field) in [
        ("access_token", "access_token"),
        ("refresh_token", "refresh_token"),
    ] {
        let t = lab.sign_in(&client_id, "DEV1").await;
        assert_eq!(lab.host.device_ids(&lab.alice), vec!["DEV1"]);
        let r = lab
            .post_form(
                "oauth2/revoke",
                &[
                    ("token", t[field].as_str().unwrap()),
                    ("token_type_hint", hint),
                    ("client_id", &client_id),
                ],
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        assert!(lab.host.device_ids(&lab.alice).is_empty());
        assert!(
            lab.host
                .whoami(t["access_token"].as_str().unwrap())
                .is_none()
        );
        let r = lab
            .token(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", t["refresh_token"].as_str().unwrap()),
                ("client_id", &client_id),
            ])
            .await;
        assert_oauth_error(&r, StatusCode::BAD_REQUEST, "invalid_grant");
    }
}

#[tokio::test]
async fn revocation_without_client_id_and_of_unknown_tokens() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let t = lab.sign_in(&client_id, "DEV1").await;
    // a secret scanner, without a client ID
    let r = lab
        .post_form(
            "oauth2/revoke",
            &[("token", t["access_token"].as_str().unwrap())],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(lab.host.device_ids(&lab.alice).is_empty());
    let r = lab
        .post_form("oauth2/revoke", &[("token", "nothing-like-it")])
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let r = lab
        .post_form("oauth2/revoke", &[("client_id", &client_id)])
        .await;
    assert_oauth_error(&r, StatusCode::BAD_REQUEST, "invalid_request");
}

#[tokio::test]
async fn deactivated_users_lose_their_browser_session_and_codes() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let pkce = Pkce::new();
    let mut b = lab.browser();
    let code = b
        .authorize_and_allow(&AuthParams::new(&client_id, "DEV1", &pkce))
        .await;
    lab.host.deactivate(&lab.alice);
    let r = lab
        .token(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", WEB_REDIRECT),
            ("client_id", &client_id),
            ("code_verifier", &pkce.verifier),
        ])
        .await;
    assert_oauth_error(&r, StatusCode::BAD_REQUEST, "invalid_grant");
    let r = b
        .get(&AuthParams::new(&client_id, "DEV2", &pkce).url())
        .await;
    assert!(
        r.location().contains("/login?"),
        "signed out: {}",
        r.location()
    );
}

#[tokio::test]
async fn registration_with_prompt_create() {
    let lab = Lab::with(|c| c.registration = true).await;
    assert_eq!(
        lab.metadata().await["prompt_values_supported"],
        json!(["create"])
    );
    let client_id = lab.register_web().await;
    let pkce = Pkce::new();
    let mut b = lab.browser();
    let r = b
        .get(
            &AuthParams::new(&client_id, "NEWDEV", &pkce)
                .set("prompt", "create")
                .url(),
        )
        .await;
    let loc = r.location();
    assert!(loc.contains("/register?next=authorize"), "{loc}");
    let page = b.get(&loc).await;
    let csrf = page.hidden("csrf");
    let next = page.hidden("next");
    let mut fields = vec![
        ("csrf", csrf.as_str()),
        ("next", next.as_str()),
        ("username", "bob"),
        ("password", "a long password"),
        ("password2", "another password"),
    ];
    let r = b.post("register", &fields).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.body.contains("not the same"));
    fields[4] = ("password2", "a long password");
    fields[2] = ("username", "alice");
    let r = b.post("register", &fields).await;
    assert!(r.body.contains("taken"), "{}", r.body);
    fields[2] = ("username", "bob");
    let r = b.post("register", &fields).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    assert!(r.location().contains("/consent?req="));
    let page = b.get(&r.location()).await;
    assert!(page.body.contains("@bob:example.org"));
    assert!(
        lab.host
            .check_password("bob", "a long password")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn prompt_create_without_registration_is_an_error_to_the_client() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let r = lab
        .get(
            &AuthParams::new(&client_id, "D", &Pkce::new())
                .set("prompt", "create")
                .url(),
        )
        .await;
    let p = callback_params(&r.location());
    assert_eq!(p["error"], "invalid_request");
}

#[tokio::test]
async fn prompt_none_is_answered_without_a_page() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let r = lab
        .get(
            &AuthParams::new(&client_id, "D", &Pkce::new())
                .set("prompt", "none")
                .url(),
        )
        .await;
    assert_eq!(callback_params(&r.location())["error"], "login_required");
}

#[tokio::test]
async fn login_hint_fills_in_the_username() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let mut b = lab.browser();
    let r = b
        .get(
            &AuthParams::new(&client_id, "D", &Pkce::new())
                .set("login_hint", "mxid:@alice:example.org")
                .url(),
        )
        .await;
    let page = b.get(&r.location()).await;
    assert!(
        page.body.contains("value=\"@alice:example.org\""),
        "{}",
        page.body
    );
}

// ---- the device authorization grant ----

async fn device_authorize(lab: &Lab, client_id: &str, device_id: &str) -> serde_json::Value {
    let r = lab
        .post_form(
            "oauth2/device",
            &[("client_id", client_id), ("scope", &scope(device_id))],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.header("cache-control").as_deref(), Some("no-store"));
    r.json()
}

async fn poll(lab: &Lab, client_id: &str, device_code: &str) -> Resp {
    lab.token(&[
        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ("device_code", device_code),
        ("client_id", client_id),
    ])
    .await
}

/// The browser side of the device grant: open the complete verification URI, sign in,
/// answer.
async fn answer_device(b: &mut Browser<'_>, verification_uri_complete: &str, action: &str) -> Resp {
    let r = b.get(verification_uri_complete).await;
    let page = if r.status == StatusCode::SEE_OTHER {
        let r = b.login(&r.location(), "alice", PASSWORD).await;
        b.get(&r.location()).await
    } else {
        r
    };
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    let form = page
        .body
        .split("action=\"/_lithostroton/link\"")
        .nth(1)
        .unwrap();
    let csrf = hidden_in(form, "csrf").unwrap();
    let code = hidden_in(form, "code").unwrap();
    b.post(
        "link",
        &[("csrf", &csrf), ("code", &code), ("action", action)],
    )
    .await
}

#[tokio::test]
async fn device_authorization_flow() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let d = device_authorize(&lab, &client_id, "QRDEVICE01").await;
    let user_code = d["user_code"].as_str().unwrap();
    assert_eq!(user_code.len(), 9, "XXXX-XXXX");
    assert_eq!(d["verification_uri"], format!("{ISSUER}link"));
    assert_eq!(
        d["verification_uri_complete"],
        format!("{ISSUER}link?code={}", user_code.replace('-', ""))
    );
    assert_eq!(d["expires_in"], 600);
    assert_eq!(d["interval"], 5);
    let device_code = d["device_code"].as_str().unwrap();

    let r = poll(&lab, &client_id, device_code).await;
    assert_oauth_error(&r, StatusCode::BAD_REQUEST, "authorization_pending");

    let mut b = lab.browser();
    let page_uri = d["verification_uri_complete"].as_str().unwrap();
    let r = b.get(page_uri).await;
    assert!(
        r.location().contains("/login?next=link:"),
        "{}",
        r.location()
    );
    let r = b.login(&r.location(), "alice", PASSWORD).await;
    let page = b.get(&r.location()).await;
    assert!(
        page.body.contains(user_code),
        "the page shows the code to compare"
    );
    assert!(page.body.contains("QRDEVICE01"));
    assert!(page.body.contains("Test Client"));
    let r = answer_device(&mut b, page_uri, "allow").await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("Go back to your device"));

    lab.clock.advance(std::time::Duration::from_secs(5));
    let r = poll(&lab, &client_id, device_code).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let t = r.json();
    assert_eq!(t["scope"], scope("QRDEVICE01"));
    assert_eq!(
        lab.host.whoami(t["access_token"].as_str().unwrap()),
        Some((lab.alice.clone(), "QRDEVICE01".to_owned()))
    );
    // the device code worked once
    lab.clock.advance(std::time::Duration::from_secs(5));
    let r = poll(&lab, &client_id, device_code).await;
    assert_oauth_error(&r, StatusCode::BAD_REQUEST, "invalid_grant");
    // the user code is spent
    let r = b.get(page_uri).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn device_code_entry_by_hand() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let d = device_authorize(&lab, &client_id, "TYPED").await;
    let mut b = lab.browser();
    let page = b.get("link").await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("name=\"code\""));
    // typed in lower case with a space
    let typed = d["user_code"]
        .as_str()
        .unwrap()
        .replace('-', " ")
        .to_lowercase();
    let r = b
        .get(&format!("link?code={}", typed.replace(' ', "+")))
        .await;
    assert!(
        r.location().contains("/login?next=link:"),
        "{}",
        r.location()
    );
}

#[tokio::test]
async fn device_grant_denied() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let d = device_authorize(&lab, &client_id, "DENYME").await;
    let mut b = lab.browser();
    let r = answer_device(
        &mut b,
        d["verification_uri_complete"].as_str().unwrap(),
        "deny",
    )
    .await;
    assert!(r.body.contains("denied"));
    let r = poll(&lab, &client_id, d["device_code"].as_str().unwrap()).await;
    assert_oauth_error(&r, StatusCode::BAD_REQUEST, "access_denied");
    assert!(lab.host.device_ids(&lab.alice).is_empty());
}

#[tokio::test]
async fn device_grant_slow_down_and_expiry() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let d = device_authorize(&lab, &client_id, "SLOW").await;
    let code = d["device_code"].as_str().unwrap();
    assert_oauth_error(
        &poll(&lab, &client_id, code).await,
        StatusCode::BAD_REQUEST,
        "authorization_pending",
    );
    // at once again: too fast, and the interval grows to 10 s
    assert_oauth_error(
        &poll(&lab, &client_id, code).await,
        StatusCode::BAD_REQUEST,
        "slow_down",
    );
    lab.clock.advance(std::time::Duration::from_secs(6));
    assert_oauth_error(
        &poll(&lab, &client_id, code).await,
        StatusCode::BAD_REQUEST,
        "slow_down",
    );
    lab.clock.advance(std::time::Duration::from_secs(15));
    assert_oauth_error(
        &poll(&lab, &client_id, code).await,
        StatusCode::BAD_REQUEST,
        "authorization_pending",
    );
    lab.clock.advance(10 * MINUTE);
    assert_oauth_error(
        &poll(&lab, &client_id, code).await,
        StatusCode::BAD_REQUEST,
        "expired_token",
    );
    // and the verification page no longer knows the user code
    let mut b = lab.browser();
    let r = b
        .get(d["verification_uri_complete"].as_str().unwrap())
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn device_grant_needs_the_registered_grant_type_and_client() {
    let lab = Lab::new().await;
    let mut meta = web_client();
    meta["grant_types"] = json!(["authorization_code", "refresh_token"]);
    let code_only = lab.register(meta).await;
    let r = lab
        .post_form(
            "oauth2/device",
            &[("client_id", &code_only), ("scope", &scope("D"))],
        )
        .await;
    assert_oauth_error(&r, StatusCode::BAD_REQUEST, "unauthorized_client");

    let client_id = lab.register_web().await;
    let d = device_authorize(&lab, &client_id, "D").await;
    let mut other = web_client();
    other["client_name"] = json!("Other");
    let other_id = lab.register(other).await;
    let r = poll(&lab, &other_id, d["device_code"].as_str().unwrap()).await;
    assert_oauth_error(&r, StatusCode::BAD_REQUEST, "invalid_grant");

    let r = lab
        .post_form(
            "oauth2/device",
            &[
                ("client_id", &client_id),
                ("scope", "urn:matrix:client:api:*"),
            ],
        )
        .await;
    assert_oauth_error(&r, StatusCode::BAD_REQUEST, "invalid_scope");
}

#[tokio::test]
async fn device_grant_can_be_turned_off() {
    let lab = Lab::with(|c| c.device_authorization = false).await;
    let m = lab.metadata().await;
    assert!(m.get("device_authorization_endpoint").is_none());
    assert!(
        !m["grant_types_supported"]
            .as_array()
            .unwrap()
            .contains(&json!("urn:ietf:params:oauth:grant-type:device_code"))
    );
    let client_id = lab.register_web().await;
    let r = lab
        .token(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", "x"),
            ("client_id", &client_id),
        ])
        .await;
    assert_oauth_error(&r, StatusCode::BAD_REQUEST, "unsupported_grant_type");
}

#[tokio::test]
async fn shutdown_answers_503() {
    let lab = Lab::new().await;
    let app = lab.app.clone();
    lab.embedded.shutdown().await;
    use tower::ServiceExt;
    let r = app
        .oneshot(
            http::Request::get(format!("{PREFIX}/.well-known/oauth-authorization-server"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
}
