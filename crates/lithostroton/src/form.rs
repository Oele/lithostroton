//! `application/x-www-form-urlencoded` parameters, as RFC 6749 wants them read: a parameter
//! sent twice is an error (section 3.1), and one sent without a value counts as absent.

use std::collections::HashMap;

use http::{HeaderMap, header};

/// The parameters of a request body or query string.
#[derive(Debug, Default)]
pub(crate) struct Params(HashMap<String, String>);

/// A parameter appeared twice: its name.
#[derive(Debug)]
pub(crate) struct Repeated(pub String);

impl Params {
    pub fn parse(input: &[u8]) -> Result<Params, Repeated> {
        let mut map = HashMap::new();
        for (k, v) in form_urlencoded::parse(input) {
            if map.insert(k.to_string(), v.into_owned()).is_some() {
                return Err(Repeated(k.into_owned()));
            }
        }
        Ok(Params(map))
    }

    /// The parameter's value, `None` if absent or empty.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .get(name)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    }
}

/// Whether the request says its body is a form (`application/x-www-form-urlencoded`, with any
/// parameters such as a charset).
pub(crate) fn is_form(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| {
            v.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn repeated_and_empty() {
        let p = Params::parse(b"a=1&b=&c=x%20y+z").unwrap();
        assert_eq!(p.get("a"), Some("1"));
        assert_eq!(p.get("b"), None);
        assert_eq!(p.get("c"), Some("x y z"));
        assert_eq!(Params::parse(b"a=1&a=1").unwrap_err().0, "a");
    }

    #[test]
    fn form_content_type() {
        let mut h = HeaderMap::new();
        assert!(!is_form(&h));
        h.insert(
            header::CONTENT_TYPE,
            "Application/X-WWW-Form-Urlencoded; charset=UTF-8"
                .parse()
                .unwrap(),
        );
        assert!(is_form(&h));
        h.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        assert!(!is_form(&h));
    }
}
