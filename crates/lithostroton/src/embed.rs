//! lithostroton inside a homeserver's process: started with the homeserver's [`Host`] and a
//! [`Store`], serving its routes as an axum router that the homeserver mounts under the
//! issuer's path.

use std::{
    convert::Infallible,
    sync::{Arc, RwLock},
    time::Duration,
};

use axum::{
    Router,
    extract::{DefaultBodyLimit, Request, State},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use http::{HeaderValue, StatusCode, header};
use tower::ServiceExt;

use crate::{
    authorize, client,
    config::{Config, ConfigError},
    crypto, device,
    host::Host,
    http_util::{cors, security_headers, see_other},
    login, metadata, pages, revoke,
    state::{AppState, Inner},
    store::Store,
    token,
};

/// How often expired entries are purged from the store.
const SWEEP_EVERY: Duration = Duration::from_secs(300);

/// The largest request body any route reads.
const MAX_BODY: usize = 64 * 1024;

/// Why lithostroton did not start.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error(transparent)]
    Config(#[from] ConfigError),
}

/// lithostroton running in the caller's process.
///
/// ```no_run
/// # async fn f(host: std::sync::Arc<dyn lithostroton::Host>) -> Result<(), Box<dyn std::error::Error>> {
/// use std::sync::Arc;
/// use lithostroton::{Config, Embedded, MemoryStore};
///
/// let issuer = "https://matrix.example.org/_lithostroton/".parse()?;
/// let config = Config::new(issuer, "example.org");
/// let oauth = Embedded::start(config, host, Arc::new(MemoryStore::new())).await?;
///
/// // the routes, below the issuer's path
/// let app = axum::Router::new().nest("/_lithostroton", oauth.router());
/// // the metadata, for GET /_matrix/client/v1/auth_metadata
/// let metadata = oauth.metadata();
/// # Ok(()) }
/// ```
pub struct Embedded {
    state: AppState,
    routes: Arc<RwLock<Option<Router>>>,
    sweeper: tokio::task::JoinHandle<()>,
}

impl Embedded {
    /// Checks the configuration and starts. Runs on the caller's tokio runtime: a task purges
    /// expired entries from the store every few minutes.
    pub async fn start(
        config: Config,
        host: Arc<dyn Host>,
        store: Arc<dyn Store>,
    ) -> Result<Embedded, StartError> {
        let issuer = config.validate()?;
        let key = config.secret_key.unwrap_or_else(crypto::random_bytes::<32>);
        let state: AppState = Arc::new(Inner::new(config, issuer, host, store, key));
        let routes = routes(state.clone());
        let sweeper = tokio::spawn({
            let state = state.clone();
            async move {
                let mut tick = tokio::time::interval(SWEEP_EVERY);
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tick.tick().await;
                    if let Err(e) = state.store.0.purge_expired().await {
                        tracing::warn!(error = %e, "purging expired entries failed");
                    }
                    state.prune_polls();
                }
            }
        });
        tracing::info!(issuer = %state.issuer.url, "lithostroton started");
        Ok(Embedded {
            state,
            routes: Arc::new(RwLock::new(Some(routes))),
            sweeper,
        })
    }

    /// The routes, to be nested under the issuer's path (axum strips the prefix). Serve the
    /// application with `ConnectInfo<SocketAddr>`, or implement [`Host::client_ip`], so that
    /// rate limits see client addresses. After [`Embedded::shutdown`] they answer 503.
    pub fn router(&self) -> Router {
        let routes = self.routes.clone();
        Router::new().fallback_service(tower::service_fn(move |req: Request| {
            let served = routes.read().unwrap_or_else(|e| e.into_inner()).clone();
            async move {
                Ok::<_, Infallible>(match served {
                    Some(served) => served.oneshot(req).await?,
                    None => (StatusCode::SERVICE_UNAVAILABLE, "lithostroton has stopped")
                        .into_response(),
                })
            }
        }))
    }

    /// The authorization server metadata (RFC 8414) for the homeserver to serve at
    /// `/_matrix/client/v1/auth_metadata`.
    pub fn metadata(&self) -> serde_json::Value {
        metadata::metadata(&self.state)
    }

    /// The issuer, with its trailing slash.
    pub fn issuer(&self) -> &str {
        &self.state.issuer.url
    }

    /// Stops: the routes answer 503 and the purging task ends.
    pub async fn shutdown(self) {
        *self.routes.write().unwrap_or_else(|e| e.into_inner()) = None;
        self.sweeper.abort();
        let _ = self.sweeper.await;
        tracing::info!("lithostroton stopped");
    }
}

fn routes(state: AppState) -> Router {
    // what clients call, from web pages too
    let api = Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(metadata::well_known),
        )
        .route(
            "/.well-known/openid-configuration",
            get(metadata::well_known),
        )
        .route("/oauth2/registration", post(client::registration_endpoint))
        .route("/oauth2/token", post(token::token_endpoint))
        .route("/oauth2/revoke", post(revoke::revocation_endpoint))
        .route(
            "/oauth2/device",
            post(device::device_authorization_endpoint),
        )
        .layer(middleware::from_fn_with_state(state.clone(), cors));
    // what people see
    let pages = Router::new()
        .route("/", get(index))
        .route("/oauth2/authorize", get(authorize::authorize))
        .route("/login", get(login::login_form).post(login::login_submit))
        .route("/logout", post(login::logout))
        .route(
            "/register",
            get(login::register_form).post(login::register_submit),
        )
        .route(
            "/consent",
            get(authorize::consent_form).post(authorize::consent_submit),
        )
        .route("/link", get(device::link_form).post(device::link_submit))
        .route("/assets/style.css", get(style));
    api.merge(pages)
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

async fn index(State(state): State<AppState>) -> Response {
    see_other(&state.path("login"))
}

async fn style() -> Response {
    let mut resp = pages::STYLE.into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/css; charset=utf-8"),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    resp
}

async fn not_found(State(state): State<AppState>) -> Response {
    pages::error(
        &state,
        StatusCode::NOT_FOUND,
        "Not found",
        "There is nothing here.",
    )
}
