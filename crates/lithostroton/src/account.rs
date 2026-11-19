//! The account pages (the specification's "Account management" of the OAuth 2.0 API,
//! MSC4191): where clients send users to see their profile and sessions, sign a session out,
//! change their password and confirm a reset of their cross-signing keys.
//!
//! The account management URL is `<issuer>account/`; it takes the specification's `action`
//! and `device_id` parameters and goes to the page for them.

// `Err` is the response to send, as axum handlers return it.
#![allow(clippy::result_large_err)]

use axum::{
    body::Bytes,
    extract::{Query, State},
    response::Response,
};
use http::{HeaderMap, StatusCode};
use serde::Deserialize;

use crate::{
    client,
    form::Params,
    host::{Device, HostError},
    http_util::{Csrf, MONTHS, Peer, check_form, civil, see_other},
    login::{AccountPage, Next, bad_form, host_failed, is_device_ref, unavailable, username_key},
    pages::{self, Page, alert, esc, hidden},
    session::{self, Current},
    state::AppState,
};

/// The actions of the specification that the account pages take.
pub(crate) const ACTIONS: [&str; 5] = [
    "org.matrix.profile",
    "org.matrix.devices_list",
    "org.matrix.device_view",
    "org.matrix.device_delete",
    "org.matrix.cross_signing_reset",
];

/// The longest display name accepted, in characters.
const MAX_DISPLAY_NAME: usize = 256;

/// A date for people, in UTC: `19 Nov 2026, 10:31 UTC`.
fn date(t: std::time::SystemTime) -> String {
    let (y, mo, d, h, mi, _, _) = civil(t);
    format!("{d} {} {y}, {h:02}:{mi:02} UTC", MONTHS[mo - 1])
}

/// The signed-in browser, or the redirect to the sign-in page that comes back to `page`.
async fn signed_in(
    state: &AppState,
    headers: &HeaderMap,
    page: AccountPage,
) -> Result<Current, Response> {
    if !state.config.account_management {
        return Err(pages::error(
            state,
            StatusCode::NOT_FOUND,
            "Not found",
            "There is nothing here.",
        ));
    }
    match session::current(state, headers).await {
        Ok(Some(c)) => Ok(c),
        Ok(None) => Err(see_other(&Next::Account(page).login_path(state))),
        Err(_) => Err(unavailable(state)),
    }
}

fn account_path(state: &AppState, page: AccountPage) -> String {
    Next::Account(page).path(state)
}

/// The links between the account pages, and signing out of them.
fn nav(state: &AppState, csrf: &Csrf, current: &Current) -> String {
    let link = |page: AccountPage, label: &str| {
        format!(
            "<li><a href=\"{}\">{}</a></li>",
            esc(&account_path(state, page)),
            esc(label)
        )
    };
    format!(
        "{whoami}<nav aria-label=\"Account\"><ul>{}{}{}{}{}</ul></nav>\n",
        link(AccountPage::Overview, "Overview"),
        link(AccountPage::Profile, "Profile"),
        link(AccountPage::Sessions, "Sessions"),
        link(AccountPage::Password, "Password"),
        link(AccountPage::CrossSigning, "Reset cross-signing"),
        whoami = pages::signed_in_as(
            &current.user.user_id,
            &state.path("logout"),
            &csrf.token(state, "logout"),
            &Next::ACCOUNT.encode(),
        ),
    )
}

fn page(state: &AppState, csrf: &Csrf, current: &Current, title: &str, body: String) -> Page {
    Page::new(title, format!("{}{body}", nav(state, csrf, current))).cookie(csrf.set.clone())
}

#[derive(Deserialize)]
pub(crate) struct AccountQuery {
    action: Option<String>,
    device_id: Option<String>,
}

/// `GET /account/`: the account management URL. With an `action`, the page for it.
pub(crate) async fn overview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AccountQuery>,
) -> Response {
    let device = q.device_id.filter(|d| is_device_ref(d));
    let target = match (q.action.as_deref(), device) {
        (Some("org.matrix.profile"), _) => Some(AccountPage::Profile),
        (Some("org.matrix.devices_list"), _) => Some(AccountPage::Sessions),
        (Some("org.matrix.device_view"), Some(d)) => Some(AccountPage::Session(d)),
        (Some("org.matrix.device_delete"), Some(d)) => Some(AccountPage::SignOut(d)),
        (Some("org.matrix.device_view" | "org.matrix.device_delete"), None) => {
            Some(AccountPage::Sessions)
        }
        (Some("org.matrix.cross_signing_reset"), _) => Some(AccountPage::CrossSigning),
        _ => None,
    };
    if let Some(target) = target {
        // the page itself asks for sign-in, and comes back to itself
        return see_other(&account_path(&state, target));
    }
    let current = match signed_in(&state, &headers, AccountPage::Overview).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let csrf = Csrf::of(&state, &headers);
    let name = current
        .user
        .display_name
        .as_deref()
        .map(|n| format!(" ({})", esc(n)))
        .unwrap_or_default();
    let signed_in_at =
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(current.session.authenticated_at);
    let body = format!(
        "<div class=\"card\"><p>Your Matrix ID is <strong class=\"uri\">{user}</strong>{name}.</p>\n\
         <p class=\"note\">You signed in to these pages on {at}.</p></div>\n\
         <p>Here you can change your display name, see the sessions signed in to your account \
         and sign them out, change your password, and allow a reset of your cross-signing \
         keys.</p>\n",
        user = esc(&current.user.user_id),
        at = esc(&date(signed_in_at)),
    );
    page(&state, &csrf, &current, "Your account", body).render(&state)
}

// ---- profile ----

fn profile_page(
    state: &AppState,
    csrf: &Csrf,
    current: &Current,
    error: Option<&str>,
    saved: bool,
) -> Page {
    let action = esc(&account_path(state, AccountPage::Profile));
    let body = format!(
        "{alert}{saved}<form method=\"post\" action=\"{action}\">{csrf}\
         <label for=\"displayname\">Display name</label>\n\
         <input type=\"text\" id=\"displayname\" name=\"displayname\" value=\"{name}\" \
         maxlength=\"{MAX_DISPLAY_NAME}\" autocomplete=\"nickname\">\n\
         <p class=\"note\">Others see this name beside your messages. Leave it empty to show \
         your Matrix ID instead.</p>\n\
         <div class=\"actions\"><button type=\"submit\">Save</button></div></form>\n",
        alert = alert(error),
        saved = if saved {
            "<p role=\"status\">Saved.</p>\n"
        } else {
            ""
        },
        csrf = hidden("csrf", &csrf.token(state, "profile")),
        name = esc(current.user.display_name.as_deref().unwrap_or("")),
    );
    page(state, csrf, current, "Profile", body)
}

/// `GET /account/profile`
pub(crate) async fn profile_form(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let current = match signed_in(&state, &headers, AccountPage::Profile).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let csrf = Csrf::of(&state, &headers);
    profile_page(&state, &csrf, &current, None, false).render(&state)
}

/// `POST /account/profile`
pub(crate) async fn profile_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut current = match signed_in(&state, &headers, AccountPage::Profile).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Ok(form) = Params::parse(&body) else {
        return bad_form(&state);
    };
    if !check_form(&state, &headers, "profile", form.get("csrf")) {
        return bad_form(&state);
    }
    let csrf = Csrf::of(&state, &headers);
    let name = form
        .get("displayname")
        .map(str::trim)
        .filter(|n| !n.is_empty());
    if let Some(n) = name
        && (n.chars().count() > MAX_DISPLAY_NAME || n.chars().any(char::is_control))
    {
        return profile_page(
            &state,
            &csrf,
            &current,
            Some("That display name cannot be used."),
            false,
        )
        .status(StatusCode::BAD_REQUEST)
        .render(&state);
    }
    match state
        .host
        .set_display_name(&current.user.user_id, name)
        .await
    {
        Ok(()) => {}
        Err(HostError::Refused(reason)) => {
            return profile_page(&state, &csrf, &current, Some(&reason), false)
                .status(StatusCode::BAD_REQUEST)
                .render(&state);
        }
        Err(e) => return host_failed(&state, e),
    }
    tracing::info!(user_id = %current.user.user_id, "display name changed");
    current.user.display_name = name.map(str::to_owned);
    profile_page(&state, &csrf, &current, None, true).render(&state)
}

// ---- sessions ----

async fn client_name(state: &AppState, client_id: Option<&str>) -> Option<String> {
    let id = client_id?;
    client::find(state, id)
        .await
        .ok()
        .flatten()
        .and_then(|c| c.metadata.client_name)
}

fn session_name(d: &Device) -> String {
    d.display_name
        .clone()
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| "A session without a name".to_owned())
}

async fn session_details(state: &AppState, d: &Device) -> String {
    let mut rows = format!(
        "<dt>Device ID</dt><dd class=\"uri\">{}</dd>\n",
        esc(&d.device_id)
    );
    if let Some(name) = client_name(state, d.client_id.as_deref()).await {
        rows.push_str(&format!(
            "<dt>Signed in through</dt><dd>{} <span class=\"note\">(the name the application \
             gave itself)</span></dd>\n",
            esc(&name)
        ));
    }
    if let Some(t) = d.last_seen {
        rows.push_str(&format!("<dt>Last active</dt><dd>{}</dd>\n", esc(&date(t))));
    }
    if let Some(ip) = &d.last_seen_ip {
        rows.push_str(&format!(
            "<dt>Last address</dt><dd class=\"uri\">{}</dd>\n",
            esc(ip)
        ));
    }
    format!("<dl>\n{rows}</dl>\n")
}

/// `GET /account/sessions`
pub(crate) async fn sessions(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let current = match signed_in(&state, &headers, AccountPage::Sessions).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let devices = match state.host.devices(&current.user.user_id).await {
        Ok(d) => d,
        Err(e) => return host_failed(&state, e),
    };
    let csrf = Csrf::of(&state, &headers);
    let mut list = String::new();
    for d in &devices {
        list.push_str(&format!(
            "<li class=\"card\"><h2>{name}</h2>\n{details}\
             <p><a href=\"{signout}\">Sign out this session</a></p></li>\n",
            name = esc(&session_name(d)),
            details = session_details(&state, d).await,
            signout = esc(&account_path(
                &state,
                AccountPage::SignOut(d.device_id.clone())
            )),
        ));
    }
    let body = if devices.is_empty() {
        "<p>No sessions are signed in to your account.</p>\n".to_owned()
    } else {
        format!(
            "<p>These sessions are signed in to your account. Sign out any you do not \
             recognise.</p>\n<ul class=\"plain\">\n{list}</ul>\n"
        )
    };
    page(&state, &csrf, &current, "Sessions", body).render(&state)
}

#[derive(Deserialize)]
pub(crate) struct DeviceQuery {
    device_id: Option<String>,
}

async fn find_device(
    state: &AppState,
    user_id: &str,
    device_id: &str,
) -> Result<Option<Device>, HostError> {
    Ok(state
        .host
        .devices(user_id)
        .await?
        .into_iter()
        .find(|d| d.device_id == device_id))
}

fn no_such_session(state: &AppState, csrf: &Csrf, current: &Current) -> Response {
    page(
        state,
        csrf,
        current,
        "No such session",
        "<p>That session is not signed in to your account (any more).</p>\n".to_owned(),
    )
    .status(StatusCode::NOT_FOUND)
    .render(state)
}

/// `GET /account/session?device_id=`
pub(crate) async fn session_view(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<DeviceQuery>,
) -> Response {
    let Some(device_id) = q.device_id.filter(|d| is_device_ref(d)) else {
        return see_other(&account_path(&state, AccountPage::Sessions));
    };
    let current = match signed_in(&state, &headers, AccountPage::Session(device_id.clone())).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let csrf = Csrf::of(&state, &headers);
    let device = match find_device(&state, &current.user.user_id, &device_id).await {
        Ok(Some(d)) => d,
        Ok(None) => return no_such_session(&state, &csrf, &current),
        Err(e) => return host_failed(&state, e),
    };
    let body = format!(
        "<div class=\"card\"><h2>{name}</h2>\n{details}</div>\n\
         <p><a href=\"{signout}\">Sign out this session</a></p>\n",
        name = esc(&session_name(&device)),
        details = session_details(&state, &device).await,
        signout = esc(&account_path(
            &state,
            AccountPage::SignOut(device.device_id.clone())
        )),
    );
    page(&state, &csrf, &current, "Session", body).render(&state)
}

/// `GET /account/sign-out?device_id=`: the confirmation.
pub(crate) async fn sign_out_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<DeviceQuery>,
) -> Response {
    let Some(device_id) = q.device_id.filter(|d| is_device_ref(d)) else {
        return see_other(&account_path(&state, AccountPage::Sessions));
    };
    let current = match signed_in(&state, &headers, AccountPage::SignOut(device_id.clone())).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let csrf = Csrf::of(&state, &headers);
    let device = match find_device(&state, &current.user.user_id, &device_id).await {
        Ok(Some(d)) => d,
        Ok(None) => return no_such_session(&state, &csrf, &current),
        Err(e) => return host_failed(&state, e),
    };
    let body = format!(
        "<div class=\"card\"><h2>{name}</h2>\n{details}</div>\n\
         <p>Signing out ends this session: the device will need to sign in again, and it can \
         no longer read new encrypted messages until it does.</p>\n\
         <div class=\"actions\"><form method=\"post\" action=\"{action}\">{csrf}{device}\
         <button type=\"submit\" class=\"danger\">Sign out this session</button></form>\n\
         <a href=\"{back}\">Keep it</a></div>\n",
        name = esc(&session_name(&device)),
        details = session_details(&state, &device).await,
        action = esc(&state.path("account/sign-out")),
        csrf = hidden("csrf", &csrf.token(&state, "sign-out")),
        device = hidden("device_id", &device.device_id),
        back = esc(&account_path(&state, AccountPage::Sessions)),
    );
    page(&state, &csrf, &current, "Sign out a session?", body).render(&state)
}

/// `POST /account/sign-out`
pub(crate) async fn sign_out_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let current = match signed_in(&state, &headers, AccountPage::Sessions).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Ok(form) = Params::parse(&body) else {
        return bad_form(&state);
    };
    if !check_form(&state, &headers, "sign-out", form.get("csrf")) {
        return bad_form(&state);
    }
    let Some(device_id) = form.get("device_id") else {
        return bad_form(&state);
    };
    let csrf = Csrf::of(&state, &headers);
    match find_device(&state, &current.user.user_id, device_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return no_such_session(&state, &csrf, &current),
        Err(e) => return host_failed(&state, e),
    }
    if let Err(e) = state
        .host
        .end_session(&current.user.user_id, device_id)
        .await
    {
        return host_failed(&state, e);
    }
    tracing::info!(user_id = %current.user.user_id, device_id, "session signed out from the account page");
    see_other(&account_path(&state, AccountPage::Sessions))
}

// ---- password ----

fn password_page(
    state: &AppState,
    csrf: &Csrf,
    current: &Current,
    error: Option<&str>,
    sign_out: bool,
) -> Page {
    let body = format!(
        "{alert}<form method=\"post\" action=\"{action}\">{csrf}\
         <input type=\"text\" name=\"username\" value=\"{user}\" autocomplete=\"username\" hidden>\n\
         <label for=\"current\">Current password</label>\n\
         <input type=\"password\" id=\"current\" name=\"current\" autocomplete=\"current-password\" required>\n\
         <label for=\"new\">New password</label>\n\
         <input type=\"password\" id=\"new\" name=\"new\" autocomplete=\"new-password\" required>\n\
         <label for=\"new2\">New password again</label>\n\
         <input type=\"password\" id=\"new2\" name=\"new2\" autocomplete=\"new-password\" required>\n\
         <p class=\"check\"><input type=\"checkbox\" id=\"sign_out\" name=\"sign_out\" value=\"1\"{checked} \
         aria-describedby=\"sign_out-help\"> <label for=\"sign_out\">Also sign out all your \
         sessions</label></p>\n\
         <p class=\"note\" id=\"sign_out-help\">Every app and device signed in to your account \
         will have to sign in again, with the new password. Do this if someone else may know \
         your password. A device whose keys are not backed up can lose access to older \
         encrypted messages.</p>\n\
         <div class=\"actions\"><button type=\"submit\">Change password</button></div></form>\n",
        alert = alert(error),
        action = esc(&account_path(state, AccountPage::Password)),
        csrf = hidden("csrf", &csrf.token(state, "password")),
        user = esc(&current.user.user_id),
        checked = if sign_out { " checked" } else { "" },
    );
    page(state, csrf, current, "Change your password", body)
}

/// `GET /account/password`
pub(crate) async fn password_form(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let current = match signed_in(&state, &headers, AccountPage::Password).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let csrf = Csrf::of(&state, &headers);
    // ticked by default, as the legacy API's `logout_devices` defaults to true
    password_page(&state, &csrf, &current, None, true).render(&state)
}

/// Checks the password of the signed-in user, rate-limited like the sign-in form. `Err` is the
/// message for the user.
async fn confirm_password(
    state: &AppState,
    peer: &Peer,
    user_id: &str,
    password: Option<&str>,
) -> Result<(), Result<&'static str, HostError>> {
    let Some(password) = password else {
        return Err(Ok("Enter your password."));
    };
    if state.limits.password_address.check(&peer.0).is_err()
        || state
            .limits
            .password_user
            .check(&username_key(user_id))
            .is_err()
    {
        return Err(Ok("Too many attempts. Wait a minute and try again."));
    }
    match state.host.check_password(user_id, password).await {
        Ok(Some(u)) if u.user_id == user_id => Ok(()),
        Ok(_) => Err(Ok("That password is not right.")),
        Err(e) => Err(Err(e)),
    }
}

/// `POST /account/password`
pub(crate) async fn password_submit(
    State(state): State<AppState>,
    peer: Peer,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let current = match signed_in(&state, &headers, AccountPage::Password).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Ok(form) = Params::parse(&body) else {
        return bad_form(&state);
    };
    if !check_form(&state, &headers, "password", form.get("csrf")) {
        return bad_form(&state);
    }
    let csrf = Csrf::of(&state, &headers);
    let sign_out = form.get("sign_out").is_some();
    let refuse = |msg: &str| {
        password_page(&state, &csrf, &current, Some(msg), sign_out)
            .status(StatusCode::BAD_REQUEST)
            .render(&state)
    };
    let Some(new) = form.get("new") else {
        return refuse("Choose a new password.");
    };
    if form.get("new2") != Some(new) {
        return refuse("The new passwords are not the same.");
    }
    match confirm_password(&state, &peer, &current.user.user_id, form.get("current")).await {
        Ok(()) => {}
        Err(Ok(msg)) => return refuse(msg),
        Err(Err(e)) => return host_failed(&state, e),
    }
    match state.host.set_password(&current.user.user_id, new).await {
        Ok(()) => {}
        Err(HostError::Refused(reason)) => return refuse(&reason),
        Err(HostError::Unsupported) => {
            return refuse("This server does not let you change your password here.");
        }
        Err(e) => return host_failed(&state, e),
    }
    tracing::info!(user_id = %current.user.user_id, "password changed");
    // other browsers signed in to these pages are signed out; this one gets a new session
    let cookie = match session::restart_all(&state, &headers, &current.user.user_id).await {
        Ok(c) => c,
        Err(_) => return unavailable(&state),
    };
    let mut message = "<p>Your password is changed. Use the new one from now on. Other \
                       browsers signed in to these pages are signed out.</p>\n"
        .to_owned();
    if sign_out {
        message.push_str(&sign_out_everything(&state, &current.user.user_id).await);
    }
    page(&state, &csrf, &current, "Password changed", message)
        .cookie(Some(cookie))
        .render(&state)
}

/// Ends every session of the user (after a password change, if asked); says how it went.
async fn sign_out_everything(state: &AppState, user_id: &str) -> String {
    let sessions_link = format!(
        "<a href=\"{}\">Sessions</a>",
        esc(&account_path(state, AccountPage::Sessions))
    );
    let devices = match state.host.devices(user_id).await {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "listing devices after a password change failed");
            return format!(
                "<p class=\"alert\" role=\"alert\">Your sessions could not be signed out. Sign \
                 them out on the {sessions_link} page.</p>\n"
            );
        }
    };
    let mut failed = 0;
    for d in &devices {
        if let Err(e) = state.host.end_session(user_id, &d.device_id).await {
            tracing::error!(error = %e, device_id = %d.device_id, "signing out a session failed");
            failed += 1;
        }
    }
    tracing::info!(
        user_id,
        signed_out = devices.len() - failed,
        failed,
        "sessions signed out after a password change"
    );
    match (devices.len() - failed, failed) {
        (_, 0) if devices.is_empty() => "<p>No sessions were signed in.</p>\n".to_owned(),
        (1, 0) => "<p>Your one session is signed out.</p>\n".to_owned(),
        (n, 0) => format!("<p>All your {n} sessions are signed out.</p>\n"),
        (_, f) => format!(
            "<p class=\"alert\" role=\"alert\">{f} of your sessions could not be signed out. \
             Sign them out on the {sessions_link} page.</p>\n"
        ),
    }
}

// ---- cross-signing reset ----

fn cross_signing_page(
    state: &AppState,
    csrf: &Csrf,
    current: &Current,
    error: Option<&str>,
) -> Page {
    let body = format!(
        "{alert}<p>Your cross-signing keys are your identity for encrypted messages: other \
         people and your own devices trust you through them. Reset them only if you lost them, \
         for instance because you no longer have any signed-in device or your recovery key.</p>\n\
         <ul><li>People you talk to will see that your identity changed, and may have to \
         verify you again.</li>\n\
         <li>Your other sessions will have to be verified again.</li>\n\
         <li>Messages you cannot read now stay unreadable.</li></ul>\n\
         <p>If an application sent you here and you did not just ask to reset your identity, \
         stop here.</p>\n\
         <form method=\"post\" action=\"{action}\">{csrf}\
         <input type=\"text\" name=\"username\" value=\"{user}\" autocomplete=\"username\" hidden>\n\
         <label for=\"password\">Your password, to confirm</label>\n\
         <input type=\"password\" id=\"password\" name=\"password\" autocomplete=\"current-password\" required>\n\
         <div class=\"actions\"><button type=\"submit\" class=\"danger\">Allow the reset</button></div></form>\n",
        alert = alert(error),
        action = esc(&account_path(state, AccountPage::CrossSigning)),
        csrf = hidden("csrf", &csrf.token(state, "cross-signing")),
        user = esc(&current.user.user_id),
    );
    page(state, csrf, current, "Reset your cross-signing keys?", body)
}

/// `GET /account/cross-signing`
pub(crate) async fn cross_signing_form(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let current = match signed_in(&state, &headers, AccountPage::CrossSigning).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let csrf = Csrf::of(&state, &headers);
    cross_signing_page(&state, &csrf, &current, None).render(&state)
}

/// `POST /account/cross-signing`: the user confirms with their password, the homeserver lets
/// the client replace the keys.
pub(crate) async fn cross_signing_submit(
    State(state): State<AppState>,
    peer: Peer,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let current = match signed_in(&state, &headers, AccountPage::CrossSigning).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Ok(form) = Params::parse(&body) else {
        return bad_form(&state);
    };
    if !check_form(&state, &headers, "cross-signing", form.get("csrf")) {
        return bad_form(&state);
    }
    let csrf = Csrf::of(&state, &headers);
    match confirm_password(&state, &peer, &current.user.user_id, form.get("password")).await {
        Ok(()) => {}
        Err(Ok(msg)) => {
            return cross_signing_page(&state, &csrf, &current, Some(msg))
                .status(StatusCode::BAD_REQUEST)
                .render(&state);
        }
        Err(Err(e)) => return host_failed(&state, e),
    }
    if let Err(e) = state
        .host
        .allow_cross_signing_reset(&current.user.user_id)
        .await
    {
        return host_failed(&state, e);
    }
    tracing::info!(user_id = %current.user.user_id, "cross-signing reset allowed");
    page(
        &state,
        &csrf,
        &current,
        "Reset allowed",
        "<p>Go back to your application and finish the reset there. It is allowed for a few \
         minutes.</p>\n"
            .to_owned(),
    )
    .render(&state)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    #[test]
    fn dates() {
        assert_eq!(
            date(UNIX_EPOCH + Duration::from_secs(1_795_257_060)),
            "21 Nov 2026, 10:31 UTC"
        );
    }
}
