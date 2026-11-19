//! What lithostroton asks of the homeserver it runs in.
//!
//! The homeserver owns users, devices and tokens. lithostroton checks passwords, creates
//! sessions, refreshes and ends them through the [`Host`] trait, and keeps no copies: the
//! access tokens are the homeserver's own, so its usual token check accepts them, without
//! an introspection round trip.
//!
//! The calls mirror the management API that Matrix Authentication Service calls on a
//! homeserver, with one difference: the host also issues the access and refresh tokens.

use std::{fmt, net::IpAddr, time::Duration, time::SystemTime};

use async_trait::async_trait;

/// A user of the homeserver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    /// The full Matrix user ID, `@localpart:server.name`.
    pub user_id: String,
    pub display_name: Option<String>,
}

/// What [`Host::create_session`] creates: a device for a user, with tokens for a client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewSession {
    pub user_id: String,
    /// The device ID the client chose (the `urn:matrix:client:device:<device_id>` scope
    /// token). It has been checked against the characters the specification allows.
    pub device_id: String,
    /// The OAuth client the session is granted to. The host keeps it with the session and
    /// gives it back in [`Session::client_id`].
    pub client_id: String,
    /// The client's name as it registered it (unverified), for the device's display name.
    pub client_name: Option<String>,
    /// The scope granted, space-separated. The host keeps it with the session and gives it
    /// back in [`Session::scope`].
    pub scope: String,
}

/// A session as the host knows it: a device of a user and the tokens issued for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub user_id: String,
    pub device_id: String,
    /// The client from [`NewSession::client_id`]; `None` for a session that did not come
    /// from lithostroton (a password login of the legacy API).
    pub client_id: Option<String>,
    /// The scope from [`NewSession::scope`]; `None` for a session that did not come from
    /// lithostroton.
    pub scope: Option<String>,
}

/// An access token and a refresh token.
#[derive(Clone, PartialEq, Eq)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
    /// How long the access token is valid. The specification wants it short-lived.
    pub expires_in: Duration,
}

impl fmt::Debug for Tokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tokens")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

/// Which kind of token [`Host::token_status`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenKind {
    Access,
    Refresh,
}

/// What [`Host::token_status`] knows of a token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenStatus {
    /// A token that works: an access token that has not expired, or a refresh token that
    /// [`Host::refresh_session`] would accept (including the previous refresh token while the
    /// tokens that replaced it have not been used yet).
    Active { kind: TokenKind, session: Session },
    /// A refresh token that was replaced, and whose replacement has since been used. Someone
    /// holds a token that should be gone: lithostroton ends the session
    /// ([`Host::end_session`]), as the specification recommends.
    ///
    /// A host that does not remember replaced tokens reports them as [`TokenStatus::Unknown`]
    /// instead, and the session survives a replay.
    Replaced { session: Session },
    /// Not a token of this homeserver, expired, or of a session that has ended.
    Unknown,
}

/// A device of a user, for the account pages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    pub device_id: String,
    pub display_name: Option<String>,
    pub last_seen: Option<SystemTime>,
    pub last_seen_ip: Option<String>,
    /// The OAuth client of the device's session, if it came from lithostroton.
    pub client_id: Option<String>,
}

/// What [`Host::localpart_available`] says of a localpart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Availability {
    Available,
    /// Someone has it.
    Taken,
    /// Not allowed, with a reason to show the user (characters, length, reserved).
    Invalid(String),
}

/// An account to create ([`Host::create_user`]).
#[derive(Clone, PartialEq, Eq)]
pub struct NewUser {
    pub localpart: String,
    pub password: String,
}

impl fmt::Debug for NewUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewUser")
            .field("localpart", &self.localpart)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Why the host did not do what was asked.
#[derive(Debug, thiserror::Error)]
pub enum HostError {
    /// The homeserver does not offer this (for instance account registration).
    #[error("not supported by this homeserver")]
    Unsupported,
    /// The localpart is taken (a registration that raced another).
    #[error("the user ID is taken")]
    Taken,
    /// Refused, with a reason that may be shown to the user (a password that is too weak, a
    /// deactivated account).
    #[error("refused: {0}")]
    Refused(String),
    /// Anything else (the database is unreachable). Clients get a 5xx and try again later.
    #[error("{0}")]
    Failed(String),
}

/// The homeserver lithostroton runs in. Every method may be called concurrently.
///
/// User IDs are full Matrix user IDs (`@alice:example.org`).
#[async_trait]
pub trait Host: Send + Sync + 'static {
    /// Checks a password. `username` is what the user typed: a localpart or a full user ID,
    /// which the host normalises as its password login does. `Some(user)` if the password
    /// is right and the user may sign in; `None` otherwise (wrong password, unknown user,
    /// deactivated or locked account), without saying which.
    ///
    /// For an unknown user, take about as long as for a known one (hash a dummy), so that
    /// timing does not tell which users exist. lithostroton rate-limits the calls.
    async fn check_password(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<User>, HostError>;

    /// The user, if they exist and may still sign in (not deactivated, not locked). Asked
    /// for a signed-in browser before each use of its session.
    async fn user(&self, user_id: &str) -> Result<Option<User>, HostError>;

    /// Creates the device `new.device_id` for `new.user_id` with an access token and a
    /// refresh token, keeps `client_id` and `scope` with them, and returns the tokens.
    ///
    /// If the user already has a device with that ID, its existing tokens end and the device
    /// is kept with the new tokens, as a password login with a known `device_id` does. The
    /// user saw the device ID on the consent page.
    ///
    /// The device's display name may come from `client_name`.
    async fn create_session(&self, new: NewSession) -> Result<Tokens, HostError>;

    /// What `token` is: an access token or refresh token of a session, and which session.
    /// Called before a refresh (to check the client) and for a revocation.
    async fn token_status(&self, token: &str) -> Result<TokenStatus, HostError>;

    /// Rotates a refresh token: issues a new access token and a new refresh token for the
    /// same session (same user, device, client and scope) and returns them; `None` if the
    /// token cannot be refreshed (any more).
    ///
    /// The specification asks that a client whose response got lost can try again with the
    /// refresh token it sent. So the refresh token keeps working until the tokens that
    /// replaced it are used (the new access token for a request, or the new refresh token
    /// for a refresh). Another refresh with it until then returns the same or new tokens,
    /// and those it handed out before stop working. Once the new tokens are used, the old
    /// refresh token is [`TokenStatus::Replaced`] and this returns `None` for it.
    ///
    /// Two refreshes of the same token at the same time must not both create a successor
    /// chain: take them one at a time.
    async fn refresh_session(&self, refresh_token: &str) -> Result<Option<Tokens>, HostError>;

    /// Ends a session: deletes the device with its access and refresh tokens (as a logout
    /// does). Ending a session that does not exist is not an error.
    async fn end_session(&self, user_id: &str, device_id: &str) -> Result<(), HostError>;

    /// The user's devices.
    async fn devices(&self, user_id: &str) -> Result<Vec<Device>, HostError>;

    /// Sets or removes the user's display name.
    async fn set_display_name(
        &self,
        user_id: &str,
        display_name: Option<&str>,
    ) -> Result<(), HostError>;

    /// Lets the user replace their cross-signing keys without User-Interactive
    /// Authentication for a while (the `m.oauth` UIA stage of
    /// `/keys/device_signing/upload`), as the user confirmed in the account pages.
    async fn allow_cross_signing_reset(&self, user_id: &str) -> Result<(), HostError>;

    /// Whether a localpart can be registered. Only asked when registration is enabled
    /// ([`crate::Config::registration`]).
    async fn localpart_available(&self, _localpart: &str) -> Result<Availability, HostError> {
        Err(HostError::Unsupported)
    }

    /// Creates an account. Only called when registration is enabled. [`HostError::Taken`] if
    /// the localpart was taken meanwhile; [`HostError::Refused`] for a password the
    /// homeserver does not accept, with the reason.
    async fn create_user(&self, _new: NewUser) -> Result<User, HostError> {
        Err(HostError::Unsupported)
    }

    /// Changes the user's password (the user gave the current one and lithostroton checked
    /// it with [`Host::check_password`]). The host may end the user's other sessions, as a
    /// password change through the legacy API can.
    async fn set_password(&self, _user_id: &str, _new_password: &str) -> Result<(), HostError> {
        Err(HostError::Unsupported)
    }

    /// Who an access token belongs to (`Some(user_id)`), for endpoints that take an optional
    /// access token (creating a rendezvous session). `Err(HostError::Refused)` for a token
    /// that is invalid or expired, so that the client is told to refresh it.
    async fn authenticate(&self, _access_token: &str) -> Result<Option<String>, HostError> {
        Err(HostError::Unsupported)
    }

    /// The address of the client that made a request, for rate limits. By default the peer
    /// address of the connection (axum's `ConnectInfo<SocketAddr>`). A host behind a reverse
    /// proxy returns the address it trusts from the proxy's headers instead.
    fn client_ip(&self, request: &http::request::Parts) -> Option<IpAddr> {
        request
            .extensions
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|c| c.0.ip())
    }
}
