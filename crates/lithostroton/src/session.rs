//! Browser sessions: a browser that signed in on lithostroton's pages. The cookie holds a
//! random ID; the store holds its digest.

use http::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};

use crate::{
    crypto,
    error::OAuthError,
    host::User,
    http_util::{SESSION_COOKIE, cookie, set_cookie},
    state::AppState,
};

const KIND: &str = "browser_session";
/// Per user: browser sessions that signed in before this time (Unix seconds) are ended.
const KIND_EPOCH: &str = "browser_epoch";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct BrowserSession {
    pub user_id: String,
    /// When the user last gave their password (Unix seconds).
    pub authenticated_at: u64,
}

/// The signed-in browser: its session and the user, who still may sign in.
pub(crate) struct Current {
    pub session: BrowserSession,
    pub user: User,
}

/// The browser's session, if it has a live one whose user may still sign in. A session of a
/// user who may no longer sign in is ended.
pub(crate) async fn current(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<Current>, OAuthError> {
    let Some(id) = cookie(headers, SESSION_COOKIE).filter(|c| c.len() == 43) else {
        return Ok(None);
    };
    let key = crypto::secret_key(&id);
    let Some(read) = state.store.get::<BrowserSession>(KIND, &key).await? else {
        return Ok(None);
    };
    let ended_before = state
        .store
        .get::<u64>(KIND_EPOCH, &read.value.user_id)
        .await?
        .map(|r| r.value)
        .unwrap_or(0);
    if read.value.authenticated_at < ended_before {
        state.store.delete(KIND, &key).await?;
        return Ok(None);
    }
    match state.host.user(&read.value.user_id).await? {
        Some(user) => Ok(Some(Current {
            session: read.value,
            user,
        })),
        None => {
            state.store.delete(KIND, &key).await?;
            Ok(None)
        }
    }
}

/// Starts a session for a user who just gave their password, and returns its cookie. A new
/// ID each time: a session ID set before sign-in is never promoted (no session fixation).
pub(crate) async fn start(state: &AppState, user_id: &str) -> Result<HeaderValue, OAuthError> {
    let ttl = state.config.lifetimes.browser_session;
    let session = BrowserSession {
        user_id: user_id.to_owned(),
        authenticated_at: state.unix(),
    };
    loop {
        let id = crypto::random_secret();
        if state
            .store
            .insert(
                KIND,
                &crypto::secret_key(&id),
                &session,
                Some(state.now() + ttl),
            )
            .await?
        {
            return Ok(set_cookie(state, SESSION_COOKIE, &id, Some(ttl.as_secs())));
        }
    }
}

/// Ends every browser session of the user (after a password change) and starts a new one
/// for this browser; returns its cookie.
pub(crate) async fn restart_all(
    state: &AppState,
    headers: &HeaderMap,
    user_id: &str,
) -> Result<HeaderValue, OAuthError> {
    let now = state.unix();
    let until = Some(state.now() + state.config.lifetimes.browser_session);
    loop {
        match state.store.get::<u64>(KIND_EPOCH, user_id).await? {
            Some(old) => {
                if state
                    .store
                    .replace(KIND_EPOCH, user_id, &old.raw, &now, until)
                    .await?
                {
                    break;
                }
            }
            None => {
                if state.store.insert(KIND_EPOCH, user_id, &now, until).await? {
                    break;
                }
            }
        }
    }
    if let Some(id) = cookie(headers, SESSION_COOKIE) {
        state.store.delete(KIND, &crypto::secret_key(&id)).await?;
    }
    start(state, user_id).await
}

/// Ends the browser's session, if any, and returns the cookie that removes it.
pub(crate) async fn end(state: &AppState, headers: &HeaderMap) -> Result<HeaderValue, OAuthError> {
    if let Some(id) = cookie(headers, SESSION_COOKIE) {
        state.store.delete(KIND, &crypto::secret_key(&id)).await?;
    }
    Ok(set_cookie(state, SESSION_COOKIE, "", Some(0)))
}
