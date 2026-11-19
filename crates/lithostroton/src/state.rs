//! What every handler shares.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use crate::{
    config::{Config, Issuer},
    host::Host,
    ratelimit::Limiter,
    rendezvous::Sessions,
    store::{Store, Typed},
};

pub(crate) type AppState = Arc<Inner>;

pub(crate) struct Inner {
    pub config: Config,
    pub issuer: Issuer,
    pub host: Arc<dyn Host>,
    pub store: Typed,
    /// The key of the CSRF tokens.
    pub key: [u8; 32],
    pub limits: Limits,
    /// When each device code was last polled, and the interval it is held to (raised by
    /// `slow_down`), by the device code's store key.
    pub polls: Mutex<HashMap<String, Poll>>,
    /// The rendezvous sessions of sign-in with a QR code.
    pub rendezvous: Sessions,
}

pub(crate) struct Limits {
    pub password_address: Limiter,
    pub password_user: Limiter,
    pub token: Limiter,
    pub registration: Limiter,
    pub device_authorization: Limiter,
    pub user_code: Limiter,
    pub account_creation: Limiter,
    pub revocation: Limiter,
    pub rendezvous: Limiter,
    pub rendezvous_create: Limiter,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Poll {
    pub last: SystemTime,
    pub interval: Duration,
    pub expires: SystemTime,
}

impl Inner {
    pub fn new(
        config: Config,
        issuer: Issuer,
        host: Arc<dyn Host>,
        store: Arc<dyn Store>,
        key: [u8; 32],
    ) -> Inner {
        let r = &config.rate_limits;
        let c = || config.clock.clone();
        let limits = Limits {
            password_address: Limiter::new(r.password_per_address, c()),
            password_user: Limiter::new(r.password_per_user, c()),
            token: Limiter::new(r.token_per_address, c()),
            registration: Limiter::new(r.registration_per_address, c()),
            device_authorization: Limiter::new(r.device_authorization_per_address, c()),
            user_code: Limiter::new(r.user_code_per_address, c()),
            account_creation: Limiter::new(r.account_creation_per_address, c()),
            revocation: Limiter::new(r.revocation_per_address, c()),
            rendezvous: Limiter::new(r.rendezvous_per_address, c()),
            rendezvous_create: Limiter::new(r.rendezvous_create_per_address, c()),
        };
        Inner {
            config,
            issuer,
            host,
            store: Typed(store),
            key,
            limits,
            polls: Mutex::new(HashMap::new()),
            rendezvous: Sessions::default(),
        }
    }

    pub fn now(&self) -> SystemTime {
        self.config.clock.now()
    }

    pub fn unix(&self) -> u64 {
        self.config.clock.unix()
    }

    /// The absolute URL of a path below the issuer (`rel` without a leading slash).
    pub fn url(&self, rel: &str) -> String {
        format!("{}{rel}", self.issuer.url)
    }

    /// The absolute path of a path below the issuer, for links and redirects of our own.
    pub fn path(&self, rel: &str) -> String {
        format!("{}{rel}", self.issuer.path)
    }

    /// Forgets the poll records of device codes that have expired, and the rendezvous
    /// sessions that have.
    pub fn prune(&self) {
        let now = self.now();
        self.rendezvous.prune(now);
        self.polls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, p| p.expires > now);
    }
}
