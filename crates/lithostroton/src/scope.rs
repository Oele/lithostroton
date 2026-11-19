//! Scopes (RFC 6749 section 3.3) and the Matrix scope tokens of the specification's "Scope"
//! section: `urn:matrix:client:api:*` and `urn:matrix:client:device:<device_id>`, with the
//! unstable forms of MSC2967 that clients still send.

/// Full access to the client-server API, stable and unstable forms.
pub(crate) const API_SCOPES: [&str; 2] = [
    "urn:matrix:client:api:*",
    "urn:matrix:org.matrix.msc2967.client:api:*",
];

/// The prefix of the scope token that binds a device ID, stable and unstable forms.
pub(crate) const DEVICE_SCOPE_PREFIXES: [&str; 2] = [
    "urn:matrix:client:device:",
    "urn:matrix:org.matrix.msc2967.client:device:",
];

/// Accepted and left out of the granted scope: lithostroton is not an OpenID Provider and
/// issues no ID token. Some clients ask for it out of habit.
const OPENID: &str = "openid";

/// The longest device ID accepted.
const MAX_DEVICE_ID: usize = 255;

/// A scope a Matrix client may be granted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MatrixScope {
    /// The scope tokens granted, in the order asked, each once, as the client spelled them
    /// (stable or unstable).
    pub tokens: Vec<String>,
    /// The device ID of the device scope token.
    pub device_id: String,
}

impl MatrixScope {
    /// The granted scope as a scope string.
    pub fn to_scope_string(&self) -> String {
        self.tokens.join(" ")
    }
}

/// Why a scope is refused (`invalid_scope`), in words for `error_description`.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ScopeError {
    #[error("the scope is empty")]
    Empty,
    #[error("the scope has a character a scope may not have")]
    Syntax,
    #[error("the scope token {0:?} is not supported")]
    Unknown(String),
    #[error("the scope must include urn:matrix:client:api:*")]
    NoApi,
    #[error("the scope must include exactly one urn:matrix:client:device:<device_id>")]
    DeviceCount,
    #[error("the device ID must be 1 to 255 characters of A-Z, a-z, 0-9, '-', '.', '_' and '~'")]
    DeviceId,
}

/// Whether `token` is a scope token by RFC 6749's grammar: `%x21 / %x23-5B / %x5D-7E`.
fn is_scope_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|b| b == 0x21 || (0x23..=0x5B).contains(&b) || (0x5D..=0x7E).contains(&b))
}

/// Whether `id` is a device ID lithostroton accepts: unreserved characters (RFC 3986 section
/// 2.3), as the specification asks clients to use.
pub(crate) fn is_device_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_DEVICE_ID
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// Parses the scope a client asks for at login (authorization request, device
/// authorization request).
pub(crate) fn parse_login_scope(scope: &str) -> Result<MatrixScope, ScopeError> {
    let mut tokens: Vec<String> = Vec::new();
    let mut device_id: Option<String> = None;
    let mut api = false;
    let mut any = false;
    for token in scope.split(' ').filter(|t| !t.is_empty()) {
        any = true;
        if !is_scope_token(token) {
            return Err(ScopeError::Syntax);
        }
        if tokens.iter().any(|t| t == token) {
            continue;
        }
        if token == OPENID {
            continue;
        }
        if API_SCOPES.contains(&token) {
            api = true;
        } else if let Some(id) = DEVICE_SCOPE_PREFIXES
            .iter()
            .find_map(|p| token.strip_prefix(p))
        {
            if !is_device_id(id) {
                return Err(ScopeError::DeviceId);
            }
            if device_id.as_deref().is_some_and(|d| d != id) {
                return Err(ScopeError::DeviceCount);
            }
            device_id = Some(id.to_owned());
        } else {
            return Err(ScopeError::Unknown(token.to_owned()));
        }
        tokens.push(token.to_owned());
    }
    if !any {
        return Err(ScopeError::Empty);
    }
    if !api {
        return Err(ScopeError::NoApi);
    }
    // The same device ID in both forms is one device.
    let device_id = device_id.ok_or(ScopeError::DeviceCount)?;
    Ok(MatrixScope { tokens, device_id })
}

/// Whether two scope strings hold the same scope tokens, in any order.
pub(crate) fn same_scope(a: &str, b: &str) -> bool {
    let mut x: Vec<&str> = a.split(' ').filter(|t| !t.is_empty()).collect();
    let mut y: Vec<&str> = b.split(' ').filter(|t| !t.is_empty()).collect();
    x.sort_unstable();
    x.dedup();
    y.sort_unstable();
    y.dedup();
    x == y
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn stable_scope() {
        let s = parse_login_scope("urn:matrix:client:api:* urn:matrix:client:device:AAABBBCCCDDD")
            .unwrap();
        assert_eq!(s.device_id, "AAABBBCCCDDD");
        assert_eq!(
            s.to_scope_string(),
            "urn:matrix:client:api:* urn:matrix:client:device:AAABBBCCCDDD"
        );
    }

    #[test]
    fn unstable_scope_and_openid() {
        let s = parse_login_scope(
            "openid urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:abc-DEF_1.2~",
        )
        .unwrap();
        assert_eq!(s.device_id, "abc-DEF_1.2~");
        assert_eq!(s.tokens.len(), 2, "openid is not granted");
    }

    #[test]
    fn both_forms_of_one_device_are_one_device() {
        let s = parse_login_scope(
            "urn:matrix:client:api:* urn:matrix:client:device:X1 urn:matrix:org.matrix.msc2967.client:device:X1",
        )
        .unwrap();
        assert_eq!(s.device_id, "X1");
    }

    #[test]
    fn refusals() {
        use ScopeError::*;
        let cases = [
            ("", Empty),
            ("urn:matrix:client:device:A", NoApi),
            ("urn:matrix:client:api:*", DeviceCount),
            (
                "urn:matrix:client:api:* urn:matrix:client:device:A urn:matrix:client:device:B",
                DeviceCount,
            ),
            (
                "urn:matrix:client:api:* urn:matrix:client:device:",
                DeviceId,
            ),
            (
                "urn:matrix:client:api:* urn:matrix:client:device:a/b",
                DeviceId,
            ),
            (
                "urn:matrix:client:api:* urn:matrix:client:device:A urn:synapse:admin:*",
                Unknown("urn:synapse:admin:*".into()),
            ),
            ("urn:matrix:client:api:* \"x", Syntax),
        ];
        for (scope, want) in cases {
            assert_eq!(parse_login_scope(scope).unwrap_err(), want, "{scope}");
        }
        let long = format!(
            "urn:matrix:client:api:* urn:matrix:client:device:{}",
            "A".repeat(256)
        );
        assert_eq!(parse_login_scope(&long).unwrap_err(), DeviceId);
    }

    #[test]
    fn same_scope_ignores_order() {
        assert!(same_scope("a b", "b a"));
        assert!(!same_scope("a b", "a"));
    }
}
