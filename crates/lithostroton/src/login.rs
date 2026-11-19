//! Signing in and out in the browser, and creating an account (`prompt=create`).
//!
//! Where the browser goes after signing in is never a URL from the request: it is a
//! [`Next`], a reference to a sign-in request, a device code or the account page, which
//! lithostroton turns into a path of its own. So the pages cannot be made to redirect
//! anywhere else.

use axum::{
    body::Bytes,
    extract::{Query, State},
    response::{IntoResponse, Response},
};
use http::{HeaderMap, StatusCode};
use serde::Deserialize;

use crate::{
    error::OAuthError,
    form::Params,
    host::{Availability, HostError, NewUser},
    http_util::{Csrf, Peer, check_form, see_other},
    pages::{self, Page, alert, esc, hidden},
    session,
    state::AppState,
};

/// Where to go after signing in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Next {
    /// The consent page of an authorization request.
    Authorize(String),
    /// The consent page of a device grant, by its user code.
    Link(String),
    /// The account page.
    Account,
}

fn is_ref(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl Next {
    pub fn parse(s: Option<&str>) -> Next {
        match s.and_then(|s| s.split_once(':')) {
            Some(("authorize", id)) if is_ref(id) => Next::Authorize(id.to_owned()),
            Some(("link", code)) if is_ref(code) => Next::Link(code.to_owned()),
            _ => Next::Account,
        }
    }

    pub fn encode(&self) -> String {
        match self {
            Next::Authorize(id) => format!("authorize:{id}"),
            Next::Link(code) => format!("link:{code}"),
            Next::Account => "account".to_owned(),
        }
    }

    /// The path to go to.
    pub fn path(&self, state: &AppState) -> String {
        match self {
            Next::Authorize(id) => state.path(&format!("consent?req={id}")),
            Next::Link(code) => state.path(&format!("link?code={code}")),
            Next::Account => state.path("account/"),
        }
    }

    /// The path of the sign-in page that comes back here.
    pub fn login_path(&self, state: &AppState) -> String {
        state.path(&format!("login?next={}", self.encode()))
    }
}

#[derive(Deserialize)]
pub(crate) struct NextQuery {
    next: Option<String>,
    username: Option<String>,
}

/// The key of a username for the per-user rate limit: the localpart, lowercased.
fn username_key(username: &str) -> String {
    let u = username.trim().trim_start_matches('@');
    let local = u.split(':').next().unwrap_or(u);
    local.to_lowercase()
}

fn login_page(
    state: &AppState,
    csrf: &Csrf,
    next: &Next,
    username: Option<&str>,
    error: Option<&str>,
) -> Page {
    let register = if state.config.registration {
        format!(
            "<p>No account yet? <a href=\"{}\">Create one</a>.</p>\n",
            esc(&state.path(&format!("register?next={}", next.encode())))
        )
    } else {
        String::new()
    };
    let body = format!(
        "{alert}<form method=\"post\" action=\"{action}\">\n{csrf}{next}\
         <label for=\"username\">Username</label>\n\
         <input type=\"text\" id=\"username\" name=\"username\" value=\"{username}\" \
         autocomplete=\"username\" autocapitalize=\"none\" spellcheck=\"false\" required autofocus>\n\
         <label for=\"password\">Password</label>\n\
         <input type=\"password\" id=\"password\" name=\"password\" autocomplete=\"current-password\" required>\n\
         <div class=\"actions\"><button type=\"submit\">Sign in</button></div>\n</form>\n\
         <p class=\"note\">Your username is the part of your Matrix ID between @ and :{server}.</p>\n{register}",
        alert = alert(error),
        action = esc(&state.path("login")),
        csrf = hidden("csrf", &csrf.token(state, "login")),
        next = hidden("next", &next.encode()),
        username = esc(username.unwrap_or("")),
        server = esc(&state.config.server_name),
    );
    Page::new(format!("Sign in to {}", state.config.server_name), body).cookie(csrf.set.clone())
}

/// `GET /login`
pub(crate) async fn login_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<NextQuery>,
) -> Response {
    let csrf = Csrf::of(&state, &headers);
    let next = Next::parse(q.next.as_deref());
    login_page(&state, &csrf, &next, q.username.as_deref(), None).render(&state)
}

/// `POST /login`
pub(crate) async fn login_submit(
    State(state): State<AppState>,
    peer: Peer,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(form) = Params::parse(&body) else {
        return bad_form(&state);
    };
    let next = Next::parse(form.get("next"));
    let csrf = Csrf::of(&state, &headers);
    if !check_form(&state, &headers, "login", form.get("csrf")) {
        return login_page(
            &state,
            &csrf,
            &next,
            form.get("username"),
            Some("The form had expired. Please try again."),
        )
        .status(StatusCode::BAD_REQUEST)
        .render(&state);
    }
    let (Some(username), Some(password)) = (form.get("username"), form.get("password")) else {
        return login_page(
            &state,
            &csrf,
            &next,
            form.get("username"),
            Some("Enter your username and password."),
        )
        .status(StatusCode::BAD_REQUEST)
        .render(&state);
    };
    if state.limits.password_address.check(&peer.0).is_err()
        || state
            .limits
            .password_user
            .check(&username_key(username))
            .is_err()
    {
        tracing::warn!("sign-in attempts over the rate limit");
        return login_page(
            &state,
            &csrf,
            &next,
            Some(username),
            Some("Too many attempts. Wait a minute and try again."),
        )
        .status(StatusCode::TOO_MANY_REQUESTS)
        .render(&state);
    }
    let user = match state.host.check_password(username, password).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            tracing::info!("sign-in with a wrong username or password");
            return login_page(
                &state,
                &csrf,
                &next,
                Some(username),
                Some("Wrong username or password."),
            )
            .status(StatusCode::BAD_REQUEST)
            .render(&state);
        }
        Err(e) => return host_failed(&state, e),
    };
    match session::start(&state, &user.user_id).await {
        Ok(cookie) => {
            tracing::info!(user_id = %user.user_id, "signed in");
            let mut resp = see_other(&next.path(&state));
            resp.headers_mut().append(http::header::SET_COOKIE, cookie);
            resp
        }
        Err(e) => oauth_failed(&state, e),
    }
}

/// `POST /logout`
pub(crate) async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(form) = Params::parse(&body) else {
        return bad_form(&state);
    };
    if !check_form(&state, &headers, "logout", form.get("csrf")) {
        return bad_form(&state);
    }
    let next = Next::parse(form.get("next"));
    match session::end(&state, &headers).await {
        Ok(cookie) => {
            let mut resp = see_other(&next.login_path(&state));
            resp.headers_mut().append(http::header::SET_COOKIE, cookie);
            resp
        }
        Err(e) => oauth_failed(&state, e),
    }
}

fn register_page(
    state: &AppState,
    csrf: &Csrf,
    next: &Next,
    username: Option<&str>,
    error: Option<&str>,
) -> Page {
    let body = format!(
        "{alert}<form method=\"post\" action=\"{action}\">\n{csrf}{next}\
         <label for=\"username\">Username</label>\n\
         <input type=\"text\" id=\"username\" name=\"username\" value=\"{username}\" \
         autocomplete=\"username\" autocapitalize=\"none\" spellcheck=\"false\" required autofocus \
         aria-describedby=\"username-help\">\n\
         <p class=\"note\" id=\"username-help\">Your Matrix ID will be @username:{server}.</p>\n\
         <label for=\"password\">Password</label>\n\
         <input type=\"password\" id=\"password\" name=\"password\" autocomplete=\"new-password\" required>\n\
         <label for=\"password2\">Password again</label>\n\
         <input type=\"password\" id=\"password2\" name=\"password2\" autocomplete=\"new-password\" required>\n\
         <div class=\"actions\"><button type=\"submit\">Create account</button></div>\n</form>\n\
         <p>Have an account? <a href=\"{login}\">Sign in</a>.</p>\n",
        alert = alert(error),
        action = esc(&state.path("register")),
        csrf = hidden("csrf", &csrf.token(state, "register")),
        next = hidden("next", &next.encode()),
        username = esc(username.unwrap_or("")),
        server = esc(&state.config.server_name),
        login = esc(&next.login_path(state)),
    );
    Page::new(
        format!("Create an account on {}", state.config.server_name),
        body,
    )
    .cookie(csrf.set.clone())
}

/// `GET /register`
pub(crate) async fn register_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<NextQuery>,
) -> Response {
    let next = Next::parse(q.next.as_deref());
    if !state.config.registration {
        return see_other(&next.login_path(&state));
    }
    let csrf = Csrf::of(&state, &headers);
    register_page(&state, &csrf, &next, None, None).render(&state)
}

/// `POST /register`
pub(crate) async fn register_submit(
    State(state): State<AppState>,
    peer: Peer,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !state.config.registration {
        return pages::error(
            &state,
            StatusCode::FORBIDDEN,
            "Registration is closed",
            "This server does not take new accounts here.",
        );
    }
    let Ok(form) = Params::parse(&body) else {
        return bad_form(&state);
    };
    let next = Next::parse(form.get("next"));
    let csrf = Csrf::of(&state, &headers);
    let username = form.get("username");
    let refuse = |msg: &str, status: StatusCode| {
        register_page(&state, &csrf, &next, username, Some(msg))
            .status(status)
            .render(&state)
    };
    if !check_form(&state, &headers, "register", form.get("csrf")) {
        return refuse(
            "The form had expired. Please try again.",
            StatusCode::BAD_REQUEST,
        );
    }
    let (Some(username), Some(password)) = (username, form.get("password")) else {
        return refuse("Choose a username and a password.", StatusCode::BAD_REQUEST);
    };
    if form.get("password2") != Some(password) {
        return refuse("The passwords are not the same.", StatusCode::BAD_REQUEST);
    }
    if state.limits.account_creation.check(&peer.0).is_err() {
        return refuse(
            "Too many accounts were created from your address. Try again later.",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let localpart = username.trim().trim_start_matches('@');
    let localpart = localpart.split(':').next().unwrap_or(localpart).to_owned();
    match state.host.localpart_available(&localpart).await {
        Ok(Availability::Available) => {}
        Ok(Availability::Taken) => {
            return refuse("That username is taken.", StatusCode::BAD_REQUEST);
        }
        Ok(Availability::Invalid(reason)) => {
            return refuse(&reason, StatusCode::BAD_REQUEST);
        }
        Err(e) => return host_failed(&state, e),
    }
    let user = match state
        .host
        .create_user(NewUser {
            localpart,
            password: password.to_owned(),
        })
        .await
    {
        Ok(user) => user,
        Err(HostError::Taken) => {
            return refuse("That username is taken.", StatusCode::BAD_REQUEST);
        }
        Err(HostError::Refused(reason)) => return refuse(&reason, StatusCode::BAD_REQUEST),
        Err(e) => return host_failed(&state, e),
    };
    tracing::info!(user_id = %user.user_id, "account created");
    match session::start(&state, &user.user_id).await {
        Ok(cookie) => {
            let mut resp = see_other(&next.path(&state));
            resp.headers_mut().append(http::header::SET_COOKIE, cookie);
            resp
        }
        Err(e) => oauth_failed(&state, e),
    }
}

pub(crate) fn bad_form(state: &AppState) -> Response {
    pages::error(
        state,
        StatusCode::BAD_REQUEST,
        "Something went wrong",
        "The form was not accepted. Go back, reload the page and try again.",
    )
}

pub(crate) fn host_failed(state: &AppState, e: HostError) -> Response {
    tracing::error!(error = %e, "the homeserver failed a call");
    pages::error(
        state,
        StatusCode::SERVICE_UNAVAILABLE,
        "Something went wrong",
        "The server could not complete this. Try again in a moment.",
    )
}

pub(crate) fn oauth_failed(state: &AppState, _e: OAuthError) -> Response {
    pages::error(
        state,
        StatusCode::SERVICE_UNAVAILABLE,
        "Something went wrong",
        "The server could not complete this. Try again in a moment.",
    )
}

/// The response to a page request when the store or the host failed while looking for the
/// browser's session.
pub(crate) fn unavailable(state: &AppState) -> Response {
    oauth_failed(state, OAuthError::server_error()).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_never_leaves() {
        assert_eq!(
            Next::parse(Some("authorize:abc_DEF-1")),
            Next::Authorize("abc_DEF-1".into())
        );
        assert_eq!(
            Next::parse(Some("link:BCDFGHJK")),
            Next::Link("BCDFGHJK".into())
        );
        for odd in [
            "https://evil.org/",
            "//evil.org",
            "authorize:../../x",
            "authorize:a?b",
            "authorize:",
            "link:a/b",
            "",
        ] {
            assert_eq!(Next::parse(Some(odd)), Next::Account, "{odd}");
        }
        assert_eq!(Next::parse(None), Next::Account);
    }

    #[test]
    fn username_keys() {
        assert_eq!(username_key("@Alice:example.org"), "alice");
        assert_eq!(username_key(" alice "), "alice");
    }
}
