//! For tests and labs: a [`MemoryHost`] that keeps users, devices and tokens in memory and
//! follows the [`Host`] contract, a [`ManualClock`], and [`check_host`], a suite of checks
//! that a host implementation can run against itself.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use async_trait::async_trait;

use crate::{
    clock::Clock,
    crypto,
    host::{
        Availability, Device, Host, HostError, NewSession, NewUser, Session, TokenKind,
        TokenStatus, Tokens, User,
    },
};

/// A clock that stands still until moved.
#[derive(Clone)]
pub struct ManualClock(Arc<Mutex<SystemTime>>);

impl ManualClock {
    /// A clock at a fixed time in 2026.
    pub fn new() -> ManualClock {
        ManualClock(Arc::new(Mutex::new(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000),
        )))
    }

    pub fn advance(&self, by: Duration) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) += by;
    }

    pub fn clock(&self) -> Clock {
        let t = self.0.clone();
        Clock::from_fn(move || *t.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

impl Default for ManualClock {
    fn default() -> ManualClock {
        ManualClock::new()
    }
}

struct UserRec {
    password: String,
    display_name: Option<String>,
    deactivated: bool,
}

struct DeviceRec {
    display_name: Option<String>,
    client_id: Option<String>,
    scope: Option<String>,
}

struct AccessRec {
    user_id: String,
    device_id: String,
    expires: SystemTime,
    /// The refresh token it was issued with.
    refresh: String,
}

struct RefreshRec {
    user_id: String,
    device_id: String,
    /// The refresh token this one replaced, which works until this one or its access token
    /// is used.
    prev: Option<String>,
    /// The token that replaced this one and has not been used yet.
    next: Option<String>,
    replaced: bool,
}

#[derive(Default)]
struct HostState {
    users: HashMap<String, UserRec>,
    devices: HashMap<(String, String), DeviceRec>,
    access: HashMap<String, AccessRec>,
    refresh: HashMap<String, RefreshRec>,
    cross_signing_resets: HashSet<String>,
}

impl HostState {
    fn session(&self, user_id: &str, device_id: &str) -> Session {
        let d = self
            .devices
            .get(&(user_id.to_owned(), device_id.to_owned()));
        Session {
            user_id: user_id.to_owned(),
            device_id: device_id.to_owned(),
            client_id: d.and_then(|d| d.client_id.clone()),
            scope: d.and_then(|d| d.scope.clone()),
        }
    }

    fn drop_tokens(&mut self, user_id: &str, device_id: &str) {
        self.access
            .retain(|_, a| !(a.user_id == user_id && a.device_id == device_id));
        self.refresh
            .retain(|_, r| !(r.user_id == user_id && r.device_id == device_id));
    }

    /// `refresh` (or an access token issued with it) is in use: the token it replaced is
    /// replaced for good, with its access tokens.
    fn used(&mut self, refresh: &str) {
        let Some(prev) = self.refresh.get_mut(refresh).and_then(|r| r.prev.take()) else {
            return;
        };
        if let Some(p) = self.refresh.get_mut(&prev) {
            p.replaced = true;
            p.next = None;
        }
        self.access.retain(|_, a| a.refresh != prev);
    }

    /// Forgets a refresh token and the access tokens issued with it.
    fn drop_refresh(&mut self, refresh: &str) {
        self.refresh.remove(refresh);
        self.access.retain(|_, a| a.refresh != refresh);
    }
}

/// A [`Host`] in memory, for tests and labs. Passwords are kept as given; tokens are random.
pub struct MemoryHost {
    server_name: String,
    clock: Clock,
    access_ttl: Duration,
    state: Mutex<HostState>,
}

impl MemoryHost {
    pub fn new(server_name: impl Into<String>, clock: Clock) -> MemoryHost {
        MemoryHost {
            server_name: server_name.into(),
            clock,
            access_ttl: Duration::from_secs(300),
            state: Mutex::new(HostState::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HostState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn user_id(&self, username: &str) -> String {
        let u = username.trim();
        if u.starts_with('@') {
            u.to_lowercase()
        } else {
            format!("@{}:{}", u.to_lowercase(), self.server_name)
        }
    }

    /// Adds a user, returns the user ID.
    pub fn add_user(&self, localpart: &str, password: &str) -> String {
        let id = self.user_id(localpart);
        self.lock().users.insert(
            id.clone(),
            UserRec {
                password: password.to_owned(),
                display_name: None,
                deactivated: false,
            },
        );
        id
    }

    /// Deactivates a user and ends their sessions.
    pub fn deactivate(&self, user_id: &str) {
        let mut s = self.lock();
        if let Some(u) = s.users.get_mut(user_id) {
            u.deactivated = true;
        }
        let devices: Vec<String> = s
            .devices
            .keys()
            .filter(|(u, _)| u == user_id)
            .map(|(_, d)| d.clone())
            .collect();
        for d in devices {
            s.devices.remove(&(user_id.to_owned(), d.clone()));
            s.drop_tokens(user_id, &d);
        }
    }

    /// The session an access token authenticates, as the homeserver's token check would find
    /// it. Using an access token counts as using the refresh token it came with.
    pub fn whoami(&self, access_token: &str) -> Option<(String, String)> {
        let now = self.clock.now();
        let mut s = self.lock();
        let a = s.access.get(access_token).filter(|a| a.expires > now)?;
        let (user, device, refresh) = (a.user_id.clone(), a.device_id.clone(), a.refresh.clone());
        s.used(&refresh);
        Some((user, device))
    }

    /// The device IDs of a user.
    pub fn device_ids(&self, user_id: &str) -> Vec<String> {
        let mut ids: Vec<String> = self
            .lock()
            .devices
            .keys()
            .filter(|(u, _)| u == user_id)
            .map(|(_, d)| d.clone())
            .collect();
        ids.sort();
        ids
    }

    /// The display name of a device.
    pub fn device_display_name(&self, user_id: &str, device_id: &str) -> Option<String> {
        self.lock()
            .devices
            .get(&(user_id.to_owned(), device_id.to_owned()))
            .and_then(|d| d.display_name.clone())
    }

    pub fn display_name(&self, user_id: &str) -> Option<String> {
        self.lock()
            .users
            .get(user_id)
            .and_then(|u| u.display_name.clone())
    }

    pub fn cross_signing_reset_allowed(&self, user_id: &str) -> bool {
        self.lock().cross_signing_resets.contains(user_id)
    }

    fn issue(
        &self,
        s: &mut HostState,
        user_id: &str,
        device_id: &str,
        prev: Option<String>,
    ) -> Tokens {
        let access = format!("lta_{}", crypto::random_secret());
        let refresh = format!("ltr_{}", crypto::random_secret());
        s.refresh.insert(
            refresh.clone(),
            RefreshRec {
                user_id: user_id.to_owned(),
                device_id: device_id.to_owned(),
                prev,
                next: None,
                replaced: false,
            },
        );
        s.access.insert(
            access.clone(),
            AccessRec {
                user_id: user_id.to_owned(),
                device_id: device_id.to_owned(),
                expires: self.clock.now() + self.access_ttl,
                refresh: refresh.clone(),
            },
        );
        Tokens {
            access_token: access,
            refresh_token: refresh,
            expires_in: self.access_ttl,
        }
    }
}

#[async_trait]
impl Host for MemoryHost {
    async fn check_password(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<User>, HostError> {
        let id = self.user_id(username);
        let s = self.lock();
        Ok(s.users.get(&id).and_then(|u| {
            (!u.deactivated && crypto::ct_eq(u.password.as_bytes(), password.as_bytes())).then(
                || User {
                    user_id: id.clone(),
                    display_name: u.display_name.clone(),
                },
            )
        }))
    }

    async fn user(&self, user_id: &str) -> Result<Option<User>, HostError> {
        Ok(self
            .lock()
            .users
            .get(user_id)
            .filter(|u| !u.deactivated)
            .map(|u| User {
                user_id: user_id.to_owned(),
                display_name: u.display_name.clone(),
            }))
    }

    async fn create_session(&self, new: NewSession) -> Result<Tokens, HostError> {
        let mut s = self.lock();
        if !s.users.get(&new.user_id).is_some_and(|u| !u.deactivated) {
            return Err(HostError::Refused("the account is deactivated".into()));
        }
        s.drop_tokens(&new.user_id, &new.device_id);
        let key = (new.user_id.clone(), new.device_id.clone());
        let display_name = s
            .devices
            .get(&key)
            .and_then(|d| d.display_name.clone())
            .or(new.client_name.clone());
        s.devices.insert(
            key,
            DeviceRec {
                display_name,
                client_id: Some(new.client_id),
                scope: Some(new.scope),
            },
        );
        Ok(self.issue(&mut s, &new.user_id, &new.device_id, None))
    }

    async fn token_status(&self, token: &str) -> Result<TokenStatus, HostError> {
        let now = self.clock.now();
        let s = self.lock();
        if let Some(a) = s.access.get(token).filter(|a| a.expires > now) {
            return Ok(TokenStatus::Active {
                kind: TokenKind::Access,
                session: s.session(&a.user_id, &a.device_id),
            });
        }
        if let Some(r) = s.refresh.get(token) {
            let session = s.session(&r.user_id, &r.device_id);
            return Ok(if r.replaced {
                TokenStatus::Replaced { session }
            } else {
                TokenStatus::Active {
                    kind: TokenKind::Refresh,
                    session,
                }
            });
        }
        Ok(TokenStatus::Unknown)
    }

    async fn refresh_session(&self, refresh_token: &str) -> Result<Option<Tokens>, HostError> {
        let mut s = self.lock();
        let Some(r) = s.refresh.get(refresh_token).filter(|r| !r.replaced) else {
            return Ok(None);
        };
        let (user, device, unused_next) = (r.user_id.clone(), r.device_id.clone(), r.next.clone());
        // a retry: what the lost answer handed out stops working
        if let Some(next) = unused_next {
            s.drop_refresh(&next);
        }
        // this token is in use: the one before it is replaced for good
        s.used(refresh_token);
        let tokens = self.issue(&mut s, &user, &device, Some(refresh_token.to_owned()));
        if let Some(r) = s.refresh.get_mut(refresh_token) {
            r.next = Some(tokens.refresh_token.clone());
        }
        Ok(Some(tokens))
    }

    async fn end_session(&self, user_id: &str, device_id: &str) -> Result<(), HostError> {
        let mut s = self.lock();
        s.devices
            .remove(&(user_id.to_owned(), device_id.to_owned()));
        s.drop_tokens(user_id, device_id);
        Ok(())
    }

    async fn devices(&self, user_id: &str) -> Result<Vec<Device>, HostError> {
        let mut devices: Vec<Device> = self
            .lock()
            .devices
            .iter()
            .filter(|((u, _), _)| u == user_id)
            .map(|((_, d), rec)| Device {
                device_id: d.clone(),
                display_name: rec.display_name.clone(),
                last_seen: None,
                last_seen_ip: None,
                client_id: rec.client_id.clone(),
            })
            .collect();
        devices.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        Ok(devices)
    }

    async fn set_display_name(
        &self,
        user_id: &str,
        display_name: Option<&str>,
    ) -> Result<(), HostError> {
        match self.lock().users.get_mut(user_id) {
            Some(u) => {
                u.display_name = display_name.map(str::to_owned);
                Ok(())
            }
            None => Err(HostError::Refused("no such user".into())),
        }
    }

    async fn allow_cross_signing_reset(&self, user_id: &str) -> Result<(), HostError> {
        self.lock().cross_signing_resets.insert(user_id.to_owned());
        Ok(())
    }

    async fn localpart_available(&self, localpart: &str) -> Result<Availability, HostError> {
        if localpart.is_empty()
            || !localpart
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._=-/".contains(&b))
        {
            return Ok(Availability::Invalid(
                "Use only a-z, 0-9 and . _ = - / in a username.".into(),
            ));
        }
        Ok(
            if self.lock().users.contains_key(&self.user_id(localpart)) {
                Availability::Taken
            } else {
                Availability::Available
            },
        )
    }

    async fn create_user(&self, new: NewUser) -> Result<User, HostError> {
        if new.password.len() < 8 {
            return Err(HostError::Refused(
                "Use a password of at least 8 characters.".into(),
            ));
        }
        let id = self.user_id(&new.localpart);
        let mut s = self.lock();
        if s.users.contains_key(&id) {
            return Err(HostError::Taken);
        }
        s.users.insert(
            id.clone(),
            UserRec {
                password: new.password,
                display_name: None,
                deactivated: false,
            },
        );
        Ok(User {
            user_id: id,
            display_name: None,
        })
    }

    async fn set_password(&self, user_id: &str, new_password: &str) -> Result<(), HostError> {
        if new_password.len() < 8 {
            return Err(HostError::Refused(
                "Use a password of at least 8 characters.".into(),
            ));
        }
        match self.lock().users.get_mut(user_id) {
            Some(u) => {
                u.password = new_password.to_owned();
                Ok(())
            }
            None => Err(HostError::Refused("no such user".into())),
        }
    }

    async fn authenticate(&self, access_token: &str) -> Result<Option<String>, HostError> {
        match self.whoami(access_token) {
            Some((user, _)) => Ok(Some(user)),
            None => Err(HostError::Refused("unknown or expired access token".into())),
        }
    }

    fn client_ip(&self, request: &http::request::Parts) -> Option<IpAddr> {
        // tests name the address in a header; otherwise the connection's
        request
            .headers
            .get("x-test-client-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .or_else(|| {
                request
                    .extensions
                    .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                    .map(|c| c.0.ip())
            })
    }
}

/// What [`check_host`] found wrong.
#[derive(Debug, thiserror::Error)]
#[error("host contract: {0}")]
pub struct ContractViolation(pub String);

fn expect(cond: bool, what: &str) -> Result<(), ContractViolation> {
    if cond {
        Ok(())
    } else {
        Err(ContractViolation(what.to_owned()))
    }
}

fn call<T>(r: Result<T, HostError>, what: &str) -> Result<T, ContractViolation> {
    r.map_err(|e| ContractViolation(format!("{what} failed: {e}")))
}

/// Checks a [`Host`] against the contract lithostroton relies on: password checks, session
/// creation, token status, refresh rotation with the retry window and replay detection, and
/// ending sessions. It needs an existing user who may sign in, with their password, and
/// [`Host::authenticate`] to stand for a request made with an access token. It creates and
/// ends sessions with device IDs starting `LITHOCHECK`.
pub async fn check_host(
    host: &dyn Host,
    username: &str,
    password: &str,
) -> Result<(), ContractViolation> {
    let user = call(
        host.check_password(username, password).await,
        "check_password",
    )?
    .ok_or_else(|| ContractViolation("check_password refused the right password".into()))?;
    expect(
        call(
            host.check_password(username, &format!("{password}x")).await,
            "check_password",
        )?
        .is_none(),
        "check_password accepted a wrong password",
    )?;
    expect(
        call(
            host.check_password("lithocheck-no-such-user", password)
                .await,
            "check_password",
        )?
        .is_none(),
        "check_password accepted an unknown user",
    )?;
    expect(
        call(host.user(&user.user_id).await, "user")?.is_some(),
        "user() does not find a user who signed in",
    )?;

    let device = format!(
        "LITHOCHECK{}",
        crypto::random_id()[..8]
            .to_ascii_uppercase()
            .replace(['-', '_'], "X")
    );
    let new = NewSession {
        user_id: user.user_id.clone(),
        device_id: device.clone(),
        client_id: "lithocheck-client".into(),
        client_name: Some("lithostroton host check".into()),
        scope: format!("urn:matrix:client:api:* urn:matrix:client:device:{device}"),
    };
    let t1 = call(host.create_session(new.clone()).await, "create_session")?;
    expect(
        t1.access_token != t1.refresh_token,
        "access and refresh tokens are the same",
    )?;
    let devices = call(host.devices(&user.user_id).await, "devices")?;
    expect(
        devices.iter().any(|d| d.device_id == device),
        "devices() does not list a created device",
    )?;

    let want = Session {
        user_id: user.user_id.clone(),
        device_id: device.clone(),
        client_id: Some(new.client_id.clone()),
        scope: Some(new.scope.clone()),
    };
    expect(
        call(host.token_status(&t1.access_token).await, "token_status")?
            == TokenStatus::Active {
                kind: TokenKind::Access,
                session: want.clone(),
            },
        "token_status of a new access token is not Active(Access) with the session's client and scope",
    )?;
    expect(
        call(host.token_status(&t1.refresh_token).await, "token_status")?
            == TokenStatus::Active {
                kind: TokenKind::Refresh,
                session: want.clone(),
            },
        "token_status of a new refresh token is not Active(Refresh) with the session's client and scope",
    )?;
    expect(
        call(
            host.token_status("lithocheck-not-a-token").await,
            "token_status",
        )? == TokenStatus::Unknown,
        "token_status of a made-up token is not Unknown",
    )?;
    expect(
        call(host.authenticate(&t1.access_token).await, "authenticate")?.as_deref()
            == Some(user.user_id.as_str()),
        "authenticate() does not accept a new access token",
    )?;

    // rotation, and a retry after a lost answer
    let t2 = call(
        host.refresh_session(&t1.refresh_token).await,
        "refresh_session",
    )?
    .ok_or_else(|| ContractViolation("refresh_session refused a fresh refresh token".into()))?;
    expect(
        t2.refresh_token != t1.refresh_token,
        "refresh_session did not rotate the refresh token",
    )?;
    let t3 = call(
        host.refresh_session(&t1.refresh_token).await,
        "refresh_session",
    )?
    .ok_or_else(|| {
        ContractViolation("refresh_session refused a retry before the new tokens were used".into())
    })?;
    if t3.refresh_token != t2.refresh_token {
        expect(
            call(
                host.refresh_session(&t2.refresh_token).await,
                "refresh_session",
            )?
            .is_none(),
            "after a retry, the refresh token of the lost answer still works",
        )?;
    }
    // the new tokens are used: the old refresh token is done
    expect(
        call(host.authenticate(&t3.access_token).await, "authenticate")?.is_some(),
        "authenticate() does not accept a refreshed access token",
    )?;
    expect(
        call(
            host.refresh_session(&t1.refresh_token).await,
            "refresh_session",
        )?
        .is_none(),
        "the old refresh token still works after the new access token was used",
    )?;
    expect(
        !matches!(
            call(host.token_status(&t1.refresh_token).await, "token_status")?,
            TokenStatus::Active { .. }
        ),
        "token_status of a replaced refresh token is Active",
    )?;
    expect(
        !matches!(
            call(host.token_status(&t1.access_token).await, "token_status")?,
            TokenStatus::Active { .. }
        ),
        "the access token of a replaced refresh token still works",
    )?;

    // a session made again for the same device replaces the old tokens
    let t4 = call(host.create_session(new.clone()).await, "create_session")?;
    expect(
        !matches!(
            call(host.token_status(&t3.access_token).await, "token_status")?,
            TokenStatus::Active { .. }
        ),
        "creating a session for an existing device did not end its old tokens",
    )?;

    // ending
    call(
        host.end_session(&user.user_id, &device).await,
        "end_session",
    )?;
    for t in [&t4.access_token, &t4.refresh_token] {
        expect(
            !matches!(
                call(host.token_status(t).await, "token_status")?,
                TokenStatus::Active { .. }
            ),
            "a token of an ended session is still Active",
        )?;
    }
    expect(
        call(
            host.refresh_session(&t4.refresh_token).await,
            "refresh_session",
        )?
        .is_none(),
        "the refresh token of an ended session still works",
    )?;
    let devices = call(host.devices(&user.user_id).await, "devices")?;
    expect(
        !devices.iter().any(|d| d.device_id == device),
        "end_session left the device",
    )?;
    call(
        host.end_session(&user.user_id, &device).await,
        "end_session of an ended session",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_host_keeps_the_contract() {
        let host = MemoryHost::new("example.org", Clock::system());
        host.add_user("alice", "correct horse");
        check_host(&host, "alice", "correct horse").await.unwrap();
    }

    #[tokio::test]
    async fn replay_after_use_is_reported() {
        let host = MemoryHost::new("example.org", Clock::system());
        let alice = host.add_user("alice", "pw");
        let t1 = host
            .create_session(NewSession {
                user_id: alice.clone(),
                device_id: "D".into(),
                client_id: "c".into(),
                client_name: None,
                scope: "s".into(),
            })
            .await
            .unwrap();
        let t2 = host
            .refresh_session(&t1.refresh_token)
            .await
            .unwrap()
            .unwrap();
        host.refresh_session(&t2.refresh_token)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            host.token_status(&t1.refresh_token).await.unwrap(),
            TokenStatus::Replaced { .. }
        ));
    }
}
