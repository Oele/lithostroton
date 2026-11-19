//! The account pages: the account management URL of the specification (MSC4191).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::*;
use http::StatusCode;
use lithostroton::Host;
use serde_json::json;

async fn signed_in_browser(lab: &Lab) -> Browser<'_> {
    let mut b = lab.browser();
    let r = b.login("login?next=account", "alice", PASSWORD).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    assert!(r.location().ends_with("/account/"), "{}", r.location());
    b
}

/// The CSRF token of the form posting to `action` on the page.
fn form_csrf(page: &Resp, action: &str) -> String {
    let marker = format!("action=\"{PREFIX}/{action}\"");
    let form = page
        .body
        .split(&marker)
        .nth(1)
        .unwrap_or_else(|| panic!("no form {action}"));
    hidden_in(form, "csrf").unwrap()
}

#[tokio::test]
async fn metadata_advertises_the_account_url() {
    let lab = Lab::new().await;
    let m = lab.metadata().await;
    assert_eq!(m["account_management_uri"], format!("{ISSUER}account/"));
    assert_eq!(
        m["account_management_actions_supported"],
        json!([
            "org.matrix.profile",
            "org.matrix.devices_list",
            "org.matrix.device_view",
            "org.matrix.device_delete",
            "org.matrix.cross_signing_reset",
        ])
    );
    let lab = Lab::with(|c| c.account_management = false).await;
    let m = lab.metadata().await;
    assert!(m.get("account_management_uri").is_none());
    assert_eq!(lab.get("account/").await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn overview_needs_sign_in() {
    let lab = Lab::new().await;
    let r = lab.get("account/").await;
    assert!(
        r.location().ends_with("/login?next=account"),
        "{}",
        r.location()
    );
    let mut b = signed_in_browser(&lab).await;
    let page = b.get("account/").await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("@alice:example.org"));
    assert!(page.body.contains("Sessions"));
}

#[tokio::test]
async fn device_delete_deep_link_signs_in_and_comes_back() {
    let lab = Lab::new().await;
    let client_id = lab.register_web().await;
    let t = lab.sign_in(&client_id, "PHONE01").await;
    lab.sign_in(&client_id, "LAPTOP02").await;

    // as a client links it: the account URL with the action and the device
    let mut b = lab.browser();
    let r = b
        .get("account/?action=org.matrix.device_delete&device_id=PHONE01")
        .await;
    assert!(
        r.location()
            .ends_with("/account/sign-out?device_id=PHONE01"),
        "{}",
        r.location()
    );
    let r = b.get(&r.location()).await;
    assert!(
        r.location()
            .contains("/login?next=account:sign-out:PHONE01"),
        "{}",
        r.location()
    );
    let r = b.login(&r.location(), "alice", PASSWORD).await;
    assert!(
        r.location()
            .ends_with("/account/sign-out?device_id=PHONE01"),
        "{}",
        r.location()
    );
    let page = b.get(&r.location()).await;
    assert!(page.body.contains("PHONE01"));
    assert!(
        page.body.contains("Test Client"),
        "the client's name is shown"
    );
    let csrf = form_csrf(&page, "account/sign-out");

    // without the token: nothing happens
    let r = b
        .post("account/sign-out", &[("device_id", "PHONE01")])
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(lab.host.device_ids(&lab.alice), vec!["LAPTOP02", "PHONE01"]);

    let r = b
        .post(
            "account/sign-out",
            &[("csrf", &csrf), ("device_id", "PHONE01")],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    assert_eq!(lab.host.device_ids(&lab.alice), vec!["LAPTOP02"]);
    assert!(
        lab.host
            .whoami(t["access_token"].as_str().unwrap())
            .is_none()
    );

    let list = b.get("account/sessions").await;
    assert!(list.body.contains("LAPTOP02"));
    assert!(!list.body.contains("PHONE01"));
}

#[tokio::test]
async fn actions_lead_to_their_pages() {
    let lab = Lab::new().await;
    let mut b = signed_in_browser(&lab).await;
    for (query, page) in [
        ("action=org.matrix.profile", "/account/profile"),
        ("action=org.matrix.devices_list", "/account/sessions"),
        (
            "action=org.matrix.device_view&device_id=D1",
            "/account/session?device_id=D1",
        ),
        ("action=org.matrix.device_view", "/account/sessions"),
        (
            "action=org.matrix.device_delete&device_id=a/b",
            "/account/sessions",
        ),
        (
            "action=org.matrix.cross_signing_reset",
            "/account/cross-signing",
        ),
    ] {
        let r = b.get(&format!("account/?{query}")).await;
        assert!(r.location().ends_with(page), "{query}: {}", r.location());
    }
    let r = b.get("account/?action=org.example.unknown").await;
    assert_eq!(r.status, StatusCode::OK);
    let r = b.get("account/session?device_id=NOSUCH").await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn display_name() {
    let lab = Lab::new().await;
    let mut b = signed_in_browser(&lab).await;
    let page = b.get("account/profile").await;
    let csrf = form_csrf(&page, "account/profile");
    let r = b
        .post(
            "account/profile",
            &[("csrf", &csrf), ("displayname", "  Alice A.  ")],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("value=\"Alice A.\""));
    assert_eq!(
        lab.host.display_name(&lab.alice).as_deref(),
        Some("Alice A.")
    );
    let r = b
        .post(
            "account/profile",
            &[("csrf", &csrf), ("displayname", "a\u{7}b")],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = b
        .post("account/profile", &[("csrf", &csrf), ("displayname", "")])
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(lab.host.display_name(&lab.alice), None);
    let r = b
        .post("account/profile", &[("displayname", "No Token")])
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(lab.host.display_name(&lab.alice), None);
}

async fn change(b: &mut Browser<'_>, csrf: &str, current: &str, new: &str, new2: &str) -> Resp {
    b.post(
        "account/password",
        &[
            ("csrf", csrf),
            ("current", current),
            ("new", new),
            ("new2", new2),
        ],
    )
    .await
}

#[tokio::test]
async fn password_change() {
    let lab = Lab::new().await;
    let mut b = signed_in_browser(&lab).await;
    let page = b.get("account/password").await;
    let csrf = form_csrf(&page, "account/password");
    let r = change(&mut b, &csrf, "wrong", "new password 1", "new password 1").await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.body.contains("not right"));
    let r = change(&mut b, &csrf, PASSWORD, "new password 1", "new password 2").await;
    assert!(r.body.contains("not the same"));
    let r = change(&mut b, &csrf, PASSWORD, "short", "short").await;
    assert!(
        r.body.contains("at least 8"),
        "the host's refusal is shown: {}",
        r.body
    );
    let r = change(&mut b, &csrf, PASSWORD, "new password 1", "new password 1").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(
        lab.host
            .check_password("alice", "new password 1")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        lab.host
            .check_password("alice", PASSWORD)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn cross_signing_reset_needs_the_password() {
    let lab = Lab::new().await;
    let mut b = signed_in_browser(&lab).await;
    let page = b.get("account/cross-signing").await;
    assert!(
        page.body.contains("did not just ask"),
        "a warning against being talked into it"
    );
    let csrf = form_csrf(&page, "account/cross-signing");
    let r = b
        .post("account/cross-signing", &[("password", PASSWORD)])
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = b
        .post(
            "account/cross-signing",
            &[("csrf", &csrf), ("password", "wrong")],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(!lab.host.cross_signing_reset_allowed(&lab.alice));
    let r = b
        .post(
            "account/cross-signing",
            &[("csrf", &csrf), ("password", PASSWORD)],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(lab.host.cross_signing_reset_allowed(&lab.alice));
}

#[tokio::test]
async fn password_confirmation_is_rate_limited() {
    let lab = Lab::new().await;
    let mut b = signed_in_browser(&lab).await;
    let page = b.get("account/cross-signing").await;
    let csrf = form_csrf(&page, "account/cross-signing");
    // the sign-in used one of alice's five
    for _ in 0..4 {
        b.post(
            "account/cross-signing",
            &[("csrf", &csrf), ("password", "wrong")],
        )
        .await;
    }
    let r = b
        .post(
            "account/cross-signing",
            &[("csrf", &csrf), ("password", PASSWORD)],
        )
        .await;
    assert!(r.body.contains("Too many attempts"), "{}", r.body);
    assert!(!lab.host.cross_signing_reset_allowed(&lab.alice));
}

#[tokio::test]
async fn a_password_change_signs_other_browsers_out() {
    let lab = Lab::new().await;
    let mut other = signed_in_browser(&lab).await;
    other.ip = "198.51.100.7".into();
    lab.clock.advance(std::time::Duration::from_secs(5));
    let mut b = signed_in_browser(&lab).await;
    let page = b.get("account/password").await;
    let csrf = form_csrf(&page, "account/password");
    let r = change(&mut b, &csrf, PASSWORD, "new password 1", "new password 1").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(
        b.get("account/").await.status,
        StatusCode::OK,
        "this browser stays"
    );
    let r = other.get("account/").await;
    assert_eq!(
        r.status,
        StatusCode::SEE_OTHER,
        "the other browser is signed out"
    );
    assert!(r.location().contains("/login?"));
    // and signing in again there works, with the new password
    let r = other
        .login("login?next=account", "alice", "new password 1")
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(other.get("account/").await.status, StatusCode::OK);
}
