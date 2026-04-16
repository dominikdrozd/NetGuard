use crate::api;
use crate::state::AppState;
use crate::ws;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, patch, post, put};
use axum::Router;
use rust_embed::Embed;
use subtle::ConstantTimeEq;
use tower_http::cors::{AllowOrigin, CorsLayer};

#[derive(Embed)]
#[folder = "static/"]
struct StaticAssets;

/// Constant-time token comparison to prevent timing side-channel attacks.
fn token_matches(provided: &str, expected: &str) -> bool {
    if provided.len() != expected.len() {
        // Length mismatch reveals nothing useful since token length is fixed/known
        return false;
    }
    provided.as_bytes().ct_eq(expected.as_bytes()).into()
}

pub fn build_router(state: AppState) -> Router {
    let listen_port = state.listen_port;
    let listen_origin = format!("http://127.0.0.1:{listen_port}");
    let localhost_origin = format!("http://localhost:{listen_port}");

    // CORS: only allow same-origin
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list([
            listen_origin.parse::<HeaderValue>().unwrap(),
            localhost_origin.parse::<HeaderValue>().unwrap(),
        ]))
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::PATCH,
            axum::http::Method::DELETE,
        ])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]);

    // Token validation endpoint (no auth middleware -- this IS the auth check)
    // Body limit: 256 bytes max to prevent memory exhaustion on this unauth endpoint
    let auth_routes = Router::new()
        .route("/validate-token", post(validate_token))
        .layer(axum::extract::DefaultBodyLimit::max(256));

    // WS ticket endpoint (requires auth, returns a one-time ticket for WS upgrade)
    let ticket_route = Router::new()
        .route("/ws-ticket", post(ws::issue_ws_ticket))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // API routes (require auth)
    let api_routes = Router::new()
        .route("/connections", get(api::list_connections))
        .route("/connections/active", get(api::active_connections))
        .route("/connections/{id}", get(api::get_connection))
        .route("/rules", get(api::list_rules).post(api::create_rule))
        .route(
            "/rules/{id}",
            put(api::update_rule).delete(api::delete_rule),
        )
        .route("/rules/{id}/toggle", patch(api::toggle_rule))
        .route("/rules/reorder", post(api::reorder_rules))
        .route("/prompts", get(api::list_prompts))
        .route("/prompts/{id}/respond", post(api::respond_prompt))
        .route("/stats", get(api::get_stats))
        .route("/status", get(api::get_status))
        .route("/mitmproxy", get(api::get_mitmproxy_status))
        .route("/mitmproxy/enable", post(api::enable_mitmproxy))
        .route("/mitmproxy/disable", post(api::disable_mitmproxy))
        .route("/mitmproxy/ca-cert", get(api::download_mitm_ca))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    Router::new()
        .nest("/api", api_routes)
        .merge(ticket_route)
        .nest("/auth", auth_routes)
        // WebSocket (auth checked inside handler via one-time ticket)
        .route("/ws", get(ws::ws_handler))
        // Static files (SPA) - token is NOT injected
        .fallback(static_handler)
        .layer(cors)
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

/// Token validation endpoint with body size limit and rate limiting.
async fn validate_token(
    State(state): State<AppState>,
    body: String,
) -> Result<StatusCode, StatusCode> {
    // Body size limit: reject tokens > 256 bytes
    if body.len() > 256 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let token = body.trim();

    // Rate limiting: track failed attempts
    {
        let mut attempts = state.auth_attempts.lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        // Remove attempts older than 60 seconds
        attempts.retain(|t| now.duration_since(*t).as_secs() < 60);
        if attempts.len() >= 10 {
            tracing::warn!("Token validation rate limit exceeded");
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        if !token_matches(token, &state.api_token) {
            attempts.push(now);
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    Ok(StatusCode::OK)
}

/// Authentication middleware: requires Bearer token on API routes.
pub async fn auth_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    match auth_header {
        Some(value) if value.starts_with("Bearer ") => {
            let token = &value[7..];
            if token_matches(token, &state.api_token) {
                Ok(next.run(req).await)
            } else {
                Err(StatusCode::UNAUTHORIZED)
            }
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

/// Add security headers to all responses.
async fn security_headers(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    headers.insert(
        "Content-Security-Policy",
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws://127.0.0.1:* ws://localhost:*",
        ),
    );
    response
}

async fn static_handler(uri: axum::http::Uri) -> Response {
    let path = uri.path().trim_start_matches('/');

    if let Some(file) = StaticAssets::get(path) {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        return (
            [(header::CONTENT_TYPE, mime.as_ref())],
            file.data.to_vec(),
        )
            .into_response();
    }

    // SPA fallback: serve index.html WITHOUT injecting any secrets
    if let Some(file) = StaticAssets::get("index.html") {
        return Html(String::from_utf8_lossy(&file.data).to_string()).into_response();
    }

    (StatusCode::NOT_FOUND, "Not found").into_response()
}

pub async fn start_server(
    state: AppState,
    addr: &str,
    start_port: u16,
) -> Result<u16, std::io::Error> {
    let ip: std::net::IpAddr = addr.parse().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("bad bind addr {addr:?}: {e}"),
        )
    })?;

    let (listener, bound_port) =
        netguard_core::port_probe::try_bind_from(ip, start_port, 20).await?;

    if bound_port != start_port {
        tracing::warn!(
            "configured web port {start_port} on {addr} was busy; bound to {addr}:{bound_port} instead"
        );
    } else {
        tracing::info!("Web UI bound to http://{addr}:{bound_port}");
    }

    let mut state = state;
    state.listen_port = bound_port;

    let app = build_router(state);
    // with_connect_info lets handlers extract the caller's SocketAddr via
    // ConnectInfo<SocketAddr> — used for audit-logging security-sensitive
    // endpoints (e.g. the mitmproxy enable/disable toggle).
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(bound_port)
}
