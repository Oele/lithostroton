# lithostroton

An OAuth 2.0 authorization server for Matrix homeservers, in Rust, built to run inside the
homeserver's own process. It implements the
[OAuth 2.0 API](https://spec.matrix.org/latest/client-server-api/#oauth-20-api) of the Matrix
Client-Server specification (v1.15 and later): the sign-in, consent, token and device
authorization side of it.

λιθόστρωτον, "paved with stones": the Greek word for a mosaic floor.

## What it does

- Authorization server metadata (RFC 8414) for `GET /_matrix/client/v1/auth_metadata`.
- Dynamic client registration (RFC 7591) with the Matrix rules for client metadata and
  redirect URIs, including native apps' loopback and private-use-scheme redirects (RFC 8252).
  Registrations with the same metadata share one client ID. When the issuer itself is on a
  loopback host (a lab), clients on loopback may use http for their URIs too, as a web client's
  development server does.
- The authorization code grant with PKCE S256 (RFC 7636), always; exact redirect URI
  matching; single-use codes bound to client, redirect URI and challenge; `query` and
  `fragment` response modes; `iss` in the response (RFC 9207); `prompt=create`, `prompt=login`,
  `prompt=none`; `login_hint` (`mxid:`).
- Refresh tokens with rotation, a retry window for lost responses, and replay detection.
- Token revocation (RFC 7009): revoking either token ends the session.
- The device authorization grant (RFC 8628): user codes, polling interval, `slow_down`,
  expiry.
- Scopes `urn:matrix:client:api:*` and `urn:matrix:client:device:<device_id>`, and their
  unstable MSC2967 forms.
- Sign-in, registration and consent pages in plain, accessible HTML without scripts. The
  client's name and website are shown as unverified.
- The rendezvous of sign-in with a QR code: MSC4388 (`/_matrix/client/v1/rendezvous` and
  `io.element.msc4388`), and the 2024 revision of MSC4108 that released matrix-rust-sdk
  versions speak (`org.matrix.msc4108`).
- Account pages at the account management URL (MSC4191): profile (display name), sessions
  with sign-out, password change, and the confirmation of a cross-signing reset that the
  `m.oauth` stage of User-Interactive Authentication sends users to. The specification's
  `action` and `device_id` parameters lead to the right page.

## How it fits in a homeserver

The homeserver owns users, devices and tokens. It implements the `Host` trait: check a
password, create a device with an access token and a refresh token, report what a token is,
refresh, end a session, list devices, and a few more. lithostroton keeps no copies, and since
the homeserver issues the tokens, its own token check accepts them.

lithostroton's own state (registered clients, sign-ins in progress, browser sessions) goes in a
`Store`: a small key-value interface a homeserver keeps in one table of its database, or
`MemoryStore`.

```rust
let config = lithostroton::Config::new(
    "https://matrix.example.org/_lithostroton/".parse()?,
    "example.org",
);
let oauth = lithostroton::Embedded::start(config, host, store).await?;

let app = axum::Router::new()
    .nest("/_lithostroton", oauth.router())
    // and serve oauth.metadata() at /_matrix/client/v1/auth_metadata
    ;
```

`Embedded::client_router()` has the rendezvous endpoints at their `/_matrix/client/...` paths,
for the homeserver to merge into its own routes.

`lithostroton::testing` (feature `testing`) has an in-memory `Host` and `check_host`, a suite
of checks a homeserver can run against its own `Host` implementation.

## Tests

`cargo test` runs the unit and integration tests (an in-memory host, a browser with a cookie
jar, the clients' side of every flow, and the security rules below).

`cargo run -p lithostroton-sdk-check` checks lithostroton with clients written by others:
matrix-rust-sdk's OAuth client (registration, authorization code, refresh, logout) and the
`oauth2` crate's device authorization grant, against an in-process lab served over https. With
`--homeserver URL --user NAME --password PASSWORD` it runs against a homeserver that embeds
lithostroton.

## Security

Written to RFC 9700 (OAuth 2.0 Security Best Current Practice): no implicit grant, no open
redirects, PKCE S256 always, CSRF tokens on every form, `frame-ancestors 'none'`,
`Secure`/`HttpOnly`/`SameSite` cookies, constant-time comparisons, rate limits on password
checks and token requests, secrets stored as digests, nothing secret in logs. Each rule has a
test in `crates/lithostroton/tests/`.

## Origin

lithostroton is written from the Matrix specification, the MSCs behind it and the IETF RFCs. It
contains no code from other implementations of this API, and uses only permissively licensed
libraries.

## Licence

Apache License, Version 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
