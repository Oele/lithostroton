//! Token buckets in memory, by key (a client address, a username).

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, SystemTime},
};

use crate::{clock::Clock, config::RateLimit};

/// How many keys a limiter keeps before it drops the buckets that have refilled.
const PRUNE_AT: usize = 10_000;

pub(crate) struct Limiter {
    limit: RateLimit,
    clock: Clock,
    buckets: Mutex<HashMap<String, Bucket>>,
}

struct Bucket {
    tokens: f64,
    at: SystemTime,
}

impl Limiter {
    pub fn new(limit: RateLimit, clock: Clock) -> Limiter {
        Limiter {
            limit,
            clock,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Takes one token for `key`: `Ok` if there was one, `Err(wait)` with the time until there
    /// is one.
    pub fn check(&self, key: &str) -> Result<(), Duration> {
        let burst = f64::from(self.limit.burst.max(1));
        let every = self.limit.every.as_secs_f64().max(1e-6);
        let now = self.clock.now();
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if buckets.len() >= PRUNE_AT {
            buckets.retain(|_, b| refill(b, now, every, burst) < burst);
        }
        let b = buckets.entry(key.to_owned()).or_insert(Bucket {
            tokens: burst,
            at: now,
        });
        let tokens = refill(b, now, every, burst);
        b.at = now;
        if tokens >= 1.0 {
            b.tokens = tokens - 1.0;
            Ok(())
        } else {
            b.tokens = tokens;
            Err(Duration::from_secs_f64((1.0 - tokens) * every))
        }
    }
}

fn refill(b: &Bucket, now: SystemTime, every: f64, burst: f64) -> f64 {
    let elapsed = now
        .duration_since(b.at)
        .unwrap_or(Duration::ZERO)
        .as_secs_f64();
    (b.tokens + elapsed / every).min(burst)
}

/// The key an address is limited under: the address itself, or its /64 for IPv6 (one
/// subscriber usually has a whole /64).
pub(crate) fn address_key(ip: Option<IpAddr>) -> String {
    match ip {
        Some(IpAddr::V4(v4)) => v4.to_string(),
        Some(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
        None => "unknown".to_owned(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn bucket_empties_and_refills() {
        let now = Arc::new(Mutex::new(SystemTime::UNIX_EPOCH));
        let n = now.clone();
        let clock = Clock::from_fn(move || *n.lock().unwrap());
        let l = Limiter::new(RateLimit::new(2, Duration::from_secs(10)), clock);
        assert!(l.check("a").is_ok());
        assert!(l.check("a").is_ok());
        let wait = l.check("a").unwrap_err();
        assert!(wait <= Duration::from_secs(10) && wait > Duration::from_secs(9));
        assert!(l.check("b").is_ok(), "keys are separate");
        *now.lock().unwrap() += Duration::from_secs(10);
        assert!(l.check("a").is_ok());
        assert!(l.check("a").is_err());
    }

    #[test]
    fn ipv6_counts_per_64() {
        let a: IpAddr = "2001:db8:1:2:3::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        assert_eq!(address_key(Some(a)), address_key(Some(b)));
        let m: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        assert_eq!(address_key(Some(m)), "192.0.2.1");
    }
}
