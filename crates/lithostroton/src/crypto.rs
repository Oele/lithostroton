//! Random values, digests, MACs and comparisons that do not leak through timing.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// `N` bytes from the operating system's random source.
pub(crate) fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    // Without a working random source nothing lithostroton hands out is safe: stop here
    // rather than hand out something guessable.
    #[allow(clippy::expect_used)]
    getrandom::fill(&mut bytes).expect("the operating system's random source failed");
    bytes
}

/// A secret of 256 random bits, base64url without padding (43 characters): authorization
/// codes, device codes, browser session IDs, CSRF cookies.
pub(crate) fn random_secret() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes::<32>())
}

/// An identifier that need not be secret but must not collide: 128 random bits.
pub(crate) fn random_id() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes::<16>())
}

/// A uniformly random index below `n` (`n` > 0), without modulo bias.
pub(crate) fn random_below(n: u32) -> u32 {
    debug_assert!(n > 0);
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let v = u32::from_le_bytes(random_bytes::<4>());
        if v < zone {
            return v % n;
        }
    }
}

/// The key a secret is stored under: SHA-256 of it, base64url. The store never holds the
/// secret itself, so reading the store does not give working codes or sessions.
pub(crate) fn secret_key(secret: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()))
}

/// SHA-256, base64url: the PKCE S256 transform (RFC 7636 section 4.2).
pub(crate) fn s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// HMAC-SHA256 of the parts, each prefixed with its length so that no two lists of parts
/// give the same input.
pub(crate) fn mac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    #[allow(clippy::expect_used)]
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes keys of any length");
    for part in parts {
        m.update(&(part.len() as u64).to_be_bytes());
        m.update(part);
    }
    m.finalize().into_bytes().into()
}

pub(crate) fn mac_b64(key: &[u8; 32], parts: &[&[u8]]) -> String {
    URL_SAFE_NO_PAD.encode(mac(key, parts))
}

/// Equality in time that depends on the lengths only, not on where the inputs differ.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s256_matches_rfc7636_appendix_b() {
        assert_eq!(
            s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn secrets_are_long_and_distinct() {
        let a = random_secret();
        let b = random_secret();
        assert_eq!(a.len(), 43);
        assert_ne!(a, b);
        assert_ne!(secret_key(&a), a);
    }

    #[test]
    fn mac_separates_parts() {
        let key = [7u8; 32];
        assert_ne!(mac(&key, &[b"ab", b"c"]), mac(&key, &[b"a", b"bc"]));
    }

    #[test]
    fn constant_time_eq() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
    }

    #[test]
    fn random_below_stays_in_range() {
        for _ in 0..1000 {
            assert!(random_below(20) < 20);
        }
    }
}
