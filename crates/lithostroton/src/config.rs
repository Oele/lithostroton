//! What the host decides: where lithostroton is served, what it offers, how long things
//! live, how hard it limits.

use std::time::Duration;

use url::Url;

use crate::clock::Clock;

/// lithostroton's configuration, from the host. [`Config::new`] gives the defaults.
#[derive(Clone, Debug)]
pub struct Config {
    /// The issuer: the absolute URL the router is served under, with a trailing slash, for
    /// instance `https://matrix.example.org/_lithostroton/`. Every endpoint lithostroton
    /// advertises is below it. It must use `https`, except on a loopback host (`localhost`,
    /// `127.0.0.1`, `[::1]`) for tests and labs.
    pub issuer: Url,
    /// The homeserver's server name (`example.org`): shown on the pages, and how a user ID
    /// typed as a localpart is completed for display.
    pub server_name: String,
    /// The key the CSRF tokens of the forms are made with. `None`: a random key at each
    /// start, which makes forms that were open across a restart fail once.
    pub secret_key: Option<[u8; 32]>,
    /// Whether users can create an account (`prompt=create`). Off by default.
    pub registration: bool,
    /// Whether the device authorization grant (RFC 8628) is offered. On by default.
    pub device_authorization: bool,
    /// Whether the account pages are served and advertised (`account_management_uri`). On by
    /// default.
    pub account_management: bool,
    /// Whether lithostroton sends CORS headers on the endpoints that clients call from web
    /// pages (metadata, registration, token, revocation, device authorization). On by
    /// default. Turn it off if the host adds the same headers to everything it serves:
    /// a response with the header twice is refused by browsers.
    pub cors: bool,
    /// The rendezvous of sign-in with a QR code ([`crate::Embedded::client_router`]).
    pub rendezvous: RendezvousConfig,
    pub lifetimes: Lifetimes,
    pub rate_limits: RateLimits,
    /// Where lithostroton reads the time.
    pub clock: Clock,
}

impl Config {
    /// The defaults, for a router served at `issuer` for the homeserver `server_name`.
    pub fn new(issuer: Url, server_name: impl Into<String>) -> Config {
        Config {
            issuer,
            server_name: server_name.into(),
            secret_key: None,
            registration: false,
            device_authorization: true,
            account_management: true,
            cors: true,
            rendezvous: RendezvousConfig::default(),
            lifetimes: Lifetimes::default(),
            rate_limits: RateLimits::default(),
            clock: Clock::system(),
        }
    }
}

/// Who may create a rendezvous session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RendezvousCreate {
    /// Anyone, with or without an access token: a new device that is not signed in yet can
    /// put up a QR code. Rate limits and the cap on sessions bound the abuse.
    Anyone,
    /// Only a request with a working access token ([`crate::Host::authenticate`]).
    SignedIn,
}

/// The rendezvous of sign-in with a QR code (MSC4388, and the 2024 revision of MSC4108).
#[derive(Clone, Debug)]
pub struct RendezvousConfig {
    /// Whether the rendezvous endpoints answer. On by default.
    pub enabled: bool,
    /// Who may create a session. [`RendezvousCreate::Anyone`] by default.
    pub create: RendezvousCreate,
    /// How long a session lives. Five minutes, the most MSC4388 recommends.
    pub lifetime: Duration,
    /// How many sessions may exist at once. 10 000.
    pub max_sessions: usize,
}

impl Default for RendezvousConfig {
    fn default() -> RendezvousConfig {
        RendezvousConfig {
            enabled: true,
            create: RendezvousCreate::Anyone,
            lifetime: Duration::from_secs(300),
            max_sessions: 10_000,
        }
    }
}

/// How long things live.
#[derive(Clone, Debug)]
pub struct Lifetimes {
    /// An authorization code, from the redirect to the client until the client exchanges it.
    /// Clients exchange it at once; RFC 6749 allows at most ten minutes. Two minutes.
    pub authorization_code: Duration,
    /// An authorization request while the user signs in and consents. Thirty minutes.
    pub authorization_request: Duration,
    /// A device code and its user code (RFC 8628 `expires_in`). Ten minutes.
    pub device_code: Duration,
    /// The least time between two polls of a device code (RFC 8628 `interval`). Five
    /// seconds, the RFC's default.
    pub device_poll_interval: Duration,
    /// A signed-in browser. Seven days.
    pub browser_session: Duration,
}

impl Default for Lifetimes {
    fn default() -> Lifetimes {
        Lifetimes {
            authorization_code: Duration::from_secs(120),
            authorization_request: Duration::from_secs(30 * 60),
            device_code: Duration::from_secs(10 * 60),
            device_poll_interval: Duration::from_secs(5),
            browser_session: Duration::from_secs(7 * 24 * 3600),
        }
    }
}

/// A token bucket: `burst` requests at once, then one per `every`. An `every` of zero is no
/// limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimit {
    pub burst: u32,
    pub every: Duration,
}

impl RateLimit {
    pub const fn new(burst: u32, every: Duration) -> RateLimit {
        RateLimit { burst, every }
    }

    /// No limit.
    pub const fn unlimited() -> RateLimit {
        RateLimit::new(0, Duration::ZERO)
    }
}

/// The rate limits. Addresses are the host's [`crate::Host::client_ip`]; IPv6 addresses
/// count per /64.
#[derive(Clone, Debug)]
pub struct RateLimits {
    /// Password checks per client address (the sign-in form, the password change).
    pub password_per_address: RateLimit,
    /// Password checks per username, whatever the address: against guessing one account's
    /// password from many addresses.
    pub password_per_user: RateLimit,
    /// Requests to the token endpoint per client address. Over the limit a refresh is
    /// answered 503 rather than 429: the specification has clients treat a 4xx answer to a
    /// refresh as a sign-out.
    pub token_per_address: RateLimit,
    /// Client registrations per client address.
    pub registration_per_address: RateLimit,
    /// Device authorization requests per client address.
    pub device_authorization_per_address: RateLimit,
    /// User codes that match no waiting device, per client address: against guessing user
    /// codes. A right code costs nothing, but none is accepted while the limit is reached.
    pub user_code_per_address: RateLimit,
    /// Accounts created per client address.
    pub account_creation_per_address: RateLimit,
    /// Revocation requests per client address.
    pub revocation_per_address: RateLimit,
    /// Authorization requests per client address (each keeps a sign-in request in the store
    /// for a while).
    pub authorize_per_address: RateLimit,
    /// Rendezvous requests per client address (two devices poll about once a second each).
    pub rendezvous_per_address: RateLimit,
    /// Rendezvous sessions created per client address.
    pub rendezvous_create_per_address: RateLimit,
}

impl RateLimits {
    /// No limits at all: for test labs that sign in many times in a row. Never in production,
    /// where the password limits are what stand between an attacker and guessing passwords.
    pub fn unlimited() -> RateLimits {
        let u = RateLimit::unlimited();
        RateLimits {
            password_per_address: u,
            password_per_user: u,
            token_per_address: u,
            registration_per_address: u,
            device_authorization_per_address: u,
            user_code_per_address: u,
            account_creation_per_address: u,
            revocation_per_address: u,
            authorize_per_address: u,
            rendezvous_per_address: u,
            rendezvous_create_per_address: u,
        }
    }
}

impl Default for RateLimits {
    fn default() -> RateLimits {
        let s = Duration::from_secs;
        RateLimits {
            password_per_address: RateLimit::new(10, s(6)),
            password_per_user: RateLimit::new(5, s(12)),
            token_per_address: RateLimit::new(100, Duration::from_millis(500)),
            registration_per_address: RateLimit::new(20, s(6)),
            device_authorization_per_address: RateLimit::new(10, s(6)),
            user_code_per_address: RateLimit::new(10, s(6)),
            account_creation_per_address: RateLimit::new(3, s(600)),
            revocation_per_address: RateLimit::new(50, s(1)),
            authorize_per_address: RateLimit::new(30, s(2)),
            rendezvous_per_address: RateLimit::new(120, Duration::from_millis(200)),
            rendezvous_create_per_address: RateLimit::new(10, s(6)),
        }
    }
}

/// Why a configuration cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("the issuer must use https (http only on a loopback host): {0}")]
    IssuerScheme(String),
    #[error("the issuer must have a host, and no user, password, query or fragment: {0}")]
    IssuerForm(String),
    #[error("the server name is empty")]
    ServerName,
    #[error("{0} must be longer than zero")]
    Lifetime(&'static str),
    #[error("the authorization code lifetime must be at most ten minutes (RFC 6749 4.1.2)")]
    CodeLifetime,
}

/// The issuer as lithostroton uses it: with a trailing slash, its origin and its path.
#[derive(Clone, Debug)]
pub(crate) struct Issuer {
    /// `https://host[:port]/path/`
    pub url: String,
    /// `https://host[:port]`
    pub origin: String,
    /// `/path/`
    pub path: String,
}

impl Config {
    pub(crate) fn validate(&self) -> Result<Issuer, ConfigError> {
        let u = &self.issuer;
        let shown = u.as_str().to_owned();
        if u.cannot_be_a_base()
            || u.host_str().is_none()
            || !u.username().is_empty()
            || u.password().is_some()
            || u.query().is_some()
            || u.fragment().is_some()
        {
            return Err(ConfigError::IssuerForm(shown));
        }
        match u.scheme() {
            "https" => {}
            "http" if is_loopback(u) => {}
            _ => return Err(ConfigError::IssuerScheme(shown)),
        }
        if self.server_name.is_empty() {
            return Err(ConfigError::ServerName);
        }
        let l = &self.lifetimes;
        for (d, name) in [
            (l.authorization_code, "the authorization code lifetime"),
            (
                l.authorization_request,
                "the authorization request lifetime",
            ),
            (l.device_code, "the device code lifetime"),
            (l.device_poll_interval, "the device poll interval"),
            (l.browser_session, "the browser session lifetime"),
            (self.rendezvous.lifetime, "the rendezvous session lifetime"),
        ] {
            if d.is_zero() {
                return Err(ConfigError::Lifetime(name));
            }
        }
        if l.authorization_code > Duration::from_secs(600) {
            return Err(ConfigError::CodeLifetime);
        }
        let mut url = u.as_str().to_owned();
        if !url.ends_with('/') {
            url.push('/');
        }
        let mut path = u.path().to_owned();
        if !path.ends_with('/') {
            path.push('/');
        }
        Ok(Issuer {
            origin: u.origin().ascii_serialization(),
            url,
            path,
        })
    }
}

fn is_loopback(u: &Url) -> bool {
    match u.host() {
        Some(url::Host::Domain(d)) => d == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn cfg(issuer: &str) -> Config {
        Config::new(Url::parse(issuer).unwrap(), "example.org")
    }

    #[test]
    fn issuer_rules() {
        let i = cfg("https://example.org/_lithostroton").validate().unwrap();
        assert_eq!(i.url, "https://example.org/_lithostroton/");
        assert_eq!(i.path, "/_lithostroton/");
        assert_eq!(i.origin, "https://example.org");

        let i = cfg("http://127.0.0.1:38400/auth/").validate().unwrap();
        assert_eq!(i.origin, "http://127.0.0.1:38400");

        for bad in [
            "http://example.org/",
            "https://u:p@example.org/",
            "https://example.org/?q",
            "https://example.org/#f",
            "ftp://localhost/",
        ] {
            assert!(cfg(bad).validate().is_err(), "{bad}");
        }
    }

    #[test]
    fn code_lifetime_is_bounded() {
        let mut c = cfg("https://example.org/");
        c.lifetimes.authorization_code = Duration::from_secs(601);
        assert!(c.validate().is_err());
        c.lifetimes.authorization_code = Duration::ZERO;
        assert!(c.validate().is_err());
    }
}
