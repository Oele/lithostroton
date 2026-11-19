//! The time lithostroton goes by: the system's, or one a test moves by hand.

use std::{
    fmt,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Where lithostroton reads the time: [`Clock::system`] unless a test supplies its own.
#[derive(Clone)]
pub struct Clock(Arc<dyn Fn() -> SystemTime + Send + Sync>);

impl Clock {
    /// The system clock.
    pub fn system() -> Clock {
        Clock(Arc::new(SystemTime::now))
    }

    /// A clock that reads the time from `now`.
    pub fn from_fn(now: impl Fn() -> SystemTime + Send + Sync + 'static) -> Clock {
        Clock(Arc::new(now))
    }

    pub fn now(&self) -> SystemTime {
        (self.0)()
    }

    /// Seconds since the Unix epoch.
    pub fn unix(&self) -> u64 {
        self.now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs()
    }
}

impl Default for Clock {
    fn default() -> Clock {
        Clock::system()
    }
}

impl fmt::Debug for Clock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Clock")
    }
}
