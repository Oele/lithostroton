//! The HTML pages: plain, accessible, without scripts. Everything that comes from outside
//! (client metadata, user input, user IDs) goes through [`esc`].

use axum::response::{IntoResponse, Response};
use http::{HeaderValue, StatusCode, header};

use crate::{client::Client, http_util::page_csp, state::AppState};

/// Escapes text for HTML element content and quoted attribute values.
pub(crate) fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// A page to send.
pub(crate) struct Page {
    pub status: StatusCode,
    pub title: String,
    pub body: String,
    /// The page's form answers with a redirect to a client (no `form-action 'self'`).
    pub forms_redirect_out: bool,
    pub cookies: Vec<HeaderValue>,
}

impl Page {
    pub fn new(title: impl Into<String>, body: String) -> Page {
        Page {
            status: StatusCode::OK,
            title: title.into(),
            body,
            forms_redirect_out: false,
            cookies: Vec::new(),
        }
    }

    pub fn status(mut self, status: StatusCode) -> Page {
        self.status = status;
        self
    }

    pub fn cookie(mut self, c: Option<HeaderValue>) -> Page {
        self.cookies.extend(c);
        self
    }

    pub fn render(self, state: &AppState) -> Response {
        let html = format!(
            "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
             <meta name=\"referrer\" content=\"no-referrer\">\n\
             <title>{title} · {server}</title>\n\
             <link rel=\"stylesheet\" href=\"{css}\">\n</head>\n<body>\n\
             <header><p class=\"server\">{server}</p></header>\n\
             <main>\n<h1>{title}</h1>\n{body}\n</main>\n</body>\n</html>\n",
            title = esc(&self.title),
            server = esc(&state.config.server_name),
            css = esc(&state.path("assets/style.css")),
            body = self.body,
        );
        let mut resp = (self.status, html).into_response();
        let h = resp.headers_mut();
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        h.insert(
            header::CONTENT_SECURITY_POLICY,
            page_csp(self.forms_redirect_out),
        );
        for c in self.cookies {
            h.append(header::SET_COOKIE, c);
        }
        resp
    }
}

/// A page that says something went wrong, with nowhere to go.
pub(crate) fn error(state: &AppState, status: StatusCode, title: &str, message: &str) -> Response {
    Page::new(title, format!("<p role=\"alert\">{}</p>", esc(message)))
        .status(status)
        .render(state)
}

/// A hidden form field.
pub(crate) fn hidden(name: &str, value: &str) -> String {
    format!(
        "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
        esc(name),
        esc(value)
    )
}

/// An alert paragraph, if there is something to say.
pub(crate) fn alert(message: Option<&str>) -> String {
    message
        .map(|m| format!("<p class=\"alert\" role=\"alert\">{}</p>\n", esc(m)))
        .unwrap_or_default()
}

/// What the user is told about a client: what it says of itself, marked as unverified.
pub(crate) fn client_card(state: &AppState, client: &Client, redirect_uri: Option<&str>) -> String {
    let m = &client.metadata;
    let name = m
        .client_name
        .as_deref()
        .filter(|n| !n.trim().is_empty())
        .unwrap_or("An application without a name");
    let mut rows = format!(
        "<dt>Website</dt><dd><span class=\"uri\">{}</span></dd>\n",
        esc(&m.client_uri)
    );
    if let Some(uri) = redirect_uri {
        rows.push_str(&format!(
            "<dt>Returns to</dt><dd><span class=\"uri\">{}</span></dd>\n",
            esc(&redirect_target(uri))
        ));
    }
    let mut links = Vec::new();
    if let Some(tos) = &m.tos_uri {
        links.push(format!(
            "<a href=\"{}\" rel=\"noopener noreferrer\" target=\"_blank\">Terms of service</a>",
            esc(tos)
        ));
    }
    if let Some(policy) = &m.policy_uri {
        links.push(format!(
            "<a href=\"{}\" rel=\"noopener noreferrer\" target=\"_blank\">Privacy policy</a>",
            esc(policy)
        ));
    }
    if !links.is_empty() {
        rows.push_str(&format!(
            "<dt>The application's documents</dt><dd>{}</dd>\n",
            links.join(" · ")
        ));
    }
    format!(
        "<section class=\"client\" aria-labelledby=\"client-name\">\n\
         <h2 id=\"client-name\">{name}</h2>\n<dl>\n{rows}</dl>\n\
         <p class=\"note\">The name and website are what the application says about itself. \
         {server} has not verified them.</p>\n</section>\n",
        name = esc(name),
        server = esc(&state.config.server_name),
    )
}

/// Where a redirect URI leads, for people: the host of an http(s) URI, the scheme of an app's.
fn redirect_target(uri: &str) -> String {
    match url::Url::parse(uri) {
        Ok(u) if u.scheme() == "https" || u.scheme() == "http" => {
            let host = u.host_str().unwrap_or_default();
            if matches!(host, "localhost" | "127.0.0.1" | "[::1]") {
                "an application on this device".to_owned()
            } else {
                host.to_owned()
            }
        }
        Ok(u) => format!("the app {}:", u.scheme()),
        Err(_) => uri.to_owned(),
    }
}

/// The signed-in user with a way to sign out.
pub(crate) fn signed_in_as(user_id: &str, logout_action: &str, csrf: &str, next: &str) -> String {
    format!(
        "<form class=\"whoami\" method=\"post\" action=\"{action}\">\n\
         <p>Signed in as <strong class=\"uri\">{user}</strong>. \
         {csrf}{next}<button type=\"submit\" class=\"link\">Not you? Sign out</button></p>\n</form>\n",
        action = esc(logout_action),
        user = esc(user_id),
        csrf = hidden("csrf", csrf),
        next = hidden("next", next),
    )
}

pub(crate) const STYLE: &str = r#":root {
  color-scheme: light dark;
  --bg: #fbfaf7; --fg: #1d1d1b; --muted: #5d5b55; --line: #d9d5cb;
  --accent: #1f5f8b; --accent-fg: #ffffff; --alert: #9b1c1c; --card: #ffffff;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #161614; --fg: #ecebe6; --muted: #aaa79e; --line: #3a3934;
    --accent: #7fb6dc; --accent-fg: #0d1a24; --alert: #ff9b9b; --card: #1f1f1c;
  }
}
* { box-sizing: border-box; }
html { font-size: 100%; }
body {
  margin: 0; background: var(--bg); color: var(--fg);
  font: 1rem/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
header { border-bottom: 1px solid var(--line); padding: 0.75rem 1rem; }
header .server { margin: 0; color: var(--muted); font-weight: 600; }
main { max-width: 34rem; margin: 0 auto; padding: 1.5rem 1rem 3rem; }
h1 { font-size: 1.6rem; line-height: 1.25; margin: 0.5rem 0 1rem; }
h2 { font-size: 1.2rem; margin: 0 0 0.5rem; }
a { color: var(--accent); }
.uri { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; word-break: break-all; }
.client, .card {
  background: var(--card); border: 1px solid var(--line); border-radius: 0.5rem;
  padding: 1rem; margin: 0 0 1.25rem;
}
dl { margin: 0; }
dt { color: var(--muted); font-size: 0.9rem; }
dd { margin: 0 0 0.5rem; }
.note { color: var(--muted); font-size: 0.9rem; margin: 0.5rem 0 0; }
.alert { color: var(--alert); font-weight: 600; }
label { display: block; font-weight: 600; margin: 1rem 0 0.25rem; }
input[type=text], input[type=password] {
  width: 100%; font: inherit; padding: 0.6rem 0.7rem;
  border: 1px solid var(--muted); border-radius: 0.35rem; background: var(--bg); color: var(--fg);
}
.code { font-family: ui-monospace, monospace; font-size: 1.5rem; letter-spacing: 0.15em; }
.actions { display: flex; flex-wrap: wrap; gap: 0.75rem; margin-top: 1.5rem; }
.actions form { margin: 0; }
button {
  font: inherit; font-weight: 600; padding: 0.6rem 1.2rem; border-radius: 0.35rem;
  border: 2px solid var(--accent); background: var(--accent); color: var(--accent-fg); cursor: pointer;
}
button.secondary { background: transparent; color: var(--accent); }
button.danger { background: transparent; color: var(--alert); border-color: var(--alert); }
button.link {
  background: none; border: none; padding: 0; color: var(--accent);
  text-decoration: underline; font-weight: 400;
}
:focus-visible { outline: 3px solid var(--accent); outline-offset: 2px; }
.whoami { margin: 0 0 1rem; color: var(--muted); }
.whoami p { margin: 0; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 0.5rem 0.25rem; border-bottom: 1px solid var(--line); vertical-align: top; }
nav ul { list-style: none; padding: 0; display: flex; flex-wrap: wrap; gap: 1rem; }
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping() {
        assert_eq!(
            esc("<a href=\"x\">'&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;"
        );
    }

    #[test]
    fn redirect_targets() {
        assert_eq!(
            redirect_target("https://app.example.com/cb"),
            "app.example.com"
        );
        assert_eq!(
            redirect_target("http://127.0.0.1:5000/cb"),
            "an application on this device"
        );
        assert_eq!(
            redirect_target("com.example.app:/cb"),
            "the app com.example.app:"
        );
    }
}
