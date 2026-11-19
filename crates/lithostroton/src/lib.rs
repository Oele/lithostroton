//! lithostroton: an OAuth 2.0 authorization server for Matrix homeservers, built to run
//! inside the homeserver's own process.
//!
//! It implements the OAuth 2.0 API of the Matrix Client-Server specification (v1.15 and
//! later): server metadata (RFC 8414), dynamic client registration (RFC 7591) with the Matrix
//! rules for redirect URIs (RFC 8252 for native apps), the authorization code grant with PKCE
//! S256 (RFC 7636), refresh tokens with rotation, token revocation (RFC 7009) and the device
//! authorization grant (RFC 8628), with sign-in and consent pages in plain HTML.
//!
//! # Embedding
//!
//! The homeserver implements [`Host`]: it checks passwords, creates devices and issues their
//! access and refresh tokens, refreshes and ends them. lithostroton keeps no copy of users,
//! devices or tokens; its own state (registered clients, sign-ins in progress, browser
//! sessions) is in a [`Store`], which the host keeps in its database or in memory
//! ([`MemoryStore`]).
//!
//! [`Embedded::start`] takes a [`Config`], the host and the store, and gives
//! [`Embedded::router`], which the homeserver nests under the issuer's path, and
//! [`Embedded::metadata`], which it serves at `/_matrix/client/v1/auth_metadata`.
//!
//! # Endpoints
//!
//! Below the issuer (`https://matrix.example.org/_lithostroton/` for instance):
//!
//! | path                                      | what                                   |
//! |-------------------------------------------|----------------------------------------|
//! | `.well-known/oauth-authorization-server`  | metadata (also `openid-configuration`) |
//! | `oauth2/registration`                     | client registration                    |
//! | `oauth2/authorize`                        | authorization endpoint                 |
//! | `oauth2/token`                            | token endpoint                         |
//! | `oauth2/revoke`                           | revocation endpoint                    |
//! | `oauth2/device`                           | device authorization endpoint          |
//! | `login`, `logout`, `register`             | sign-in pages                          |
//! | `consent`                                 | consent page of the authorization code |
//! | `link`                                    | verification URI of the device grant   |
//! | `rendezvous/{id}`                         | an MSC4108 (2024) rendezvous session   |
//!
//! [`Embedded::client_router`] has the rendezvous endpoints of sign-in with a QR code, at
//! their paths of the Client-Server API, for the homeserver to merge into its own routes:
//!
//! | path                                                      | what                       |
//! |-----------------------------------------------------------|----------------------------|
//! | `/_matrix/client/v1/rendezvous`, `…/{id}`, `…/{id}/{txn}` | MSC4388                    |
//! | `/_matrix/client/unstable/io.element.msc4388/rendezvous…` | MSC4388, unstable prefix   |
//! | `/_matrix/client/unstable/org.matrix.msc4108/rendezvous`  | MSC4108 (2024), creation   |
//!
//! # Security
//!
//! Following RFC 9700 (OAuth 2.0 Security Best Current Practice): no implicit grant, PKCE
//! S256 always, redirect URIs matched exactly (a native app's loopback URI with any port),
//! no redirect to an unverified URI, single-use authorization codes bound to client,
//! redirect URI and challenge, refresh token rotation with replay detection, CSRF tokens on
//! every form, `frame-ancestors 'none'`, `Secure`/`HttpOnly`/`SameSite` cookies,
//! constant-time comparisons of secrets, rate limits, secrets stored as digests, nothing
//! secret in logs.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod authorize;
mod client;
mod clock;
mod config;
mod crypto;
mod device;
mod embed;
mod error;
mod form;
mod host;
mod http_util;
mod login;
mod metadata;
mod pages;
mod ratelimit;
mod rendezvous;
mod revoke;
mod scope;
mod session;
mod state;
mod store;
mod token;

#[cfg(feature = "testing")]
pub mod testing;

pub use clock::Clock;
pub use config::{
    Config, ConfigError, Lifetimes, RateLimit, RateLimits, RendezvousConfig, RendezvousCreate,
};
pub use embed::{Embedded, StartError};
pub use host::{
    Availability, Device, Host, HostError, NewSession, NewUser, Session, TokenKind, TokenStatus,
    Tokens, User,
};
pub use store::{MemoryStore, Store, StoreError};
