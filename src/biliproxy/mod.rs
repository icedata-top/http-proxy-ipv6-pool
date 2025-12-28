//! Bilibili API reverse proxy with WBI signature support.
//!
//! This module implements a reverse proxy for Bilibili APIs that:
//! - Automatically signs requests with WBI signature
//! - Proxies cover images from i0.hdslb.com
//! - Supports external URL proxying
//! - Adds CORS headers
//! - Filters malicious scanner requests

pub mod core;
pub mod pool;
pub mod types;
pub mod utils;
pub mod wbi;

use self::{
    core::BiliproxyState,
    types::{ErrorResponse, HealthResponse, ResponseBody},
    utils::{empty, full, is_blocked_path, json_response, normalize_route, parse_query_string},
};
use chrono::Utc;
use http::{
    Method, Request, Response, StatusCode,
    header::{
        ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
        CONTENT_TYPE,
    },
};
use http_body_util::BodyExt;
use hyper::{body::Incoming, server::conn::http1 as server_http1, service::service_fn};
use hyper_util::rt::TokioIo;
use std::{
    convert::Infallible,
    net::{Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Instant,
};
use tokio::net::TcpListener;

/// Start the biliproxy server
pub async fn start_biliproxy(
    bind_addr: SocketAddr,
    sessdata: Option<String>,
    ipv6: Ipv6Addr,
    prefix_len: u8,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = Arc::new(BiliproxyState::new(sessdata, ipv6, prefix_len));
    let listener = TcpListener::bind(bind_addr).await?;

    println!("Biliproxy listening on {bind_addr}");
    println!("  Health check: http://{bind_addr}/health");
    println!("  WBI keys debug: http://{bind_addr}/debug/wbi-keys");
    println!("  Bilibili API: http://{bind_addr}/x/web-interface/nav");

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let state = state.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let state = state.clone();
                async move { handle_request(req, state).await }
            });

            if let Err(err) = server_http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                eprintln!("Biliproxy connection error: {err}");
            }
        });
    }
}

/// Handle incoming requests with metrics
async fn handle_request(
    req: Request<Incoming>,
    state: Arc<BiliproxyState>,
) -> Result<Response<ResponseBody>, Infallible> {
    let start = Instant::now();
    let method_str = req.method().to_string();
    let path = req.uri().path().to_string();
    let route = normalize_route(&path).to_string();

    let response = handle_request_inner(req, state).await;

    // Record metrics using the shared metrics module
    let status = response.status().as_u16();
    let duration_ms = start.elapsed().as_millis() as f64;

    let bytes = response
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());

    crate::metrics::record_request("biliproxy", &method_str, &route, status, duration_ms, bytes);

    Ok(response)
}

/// Internal request handler
async fn handle_request_inner(
    req: Request<Incoming>,
    state: Arc<BiliproxyState>,
) -> Response<ResponseBody> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(|s| s.to_string());

    // Handle CORS preflight
    if method == Method::OPTIONS {
        return Response::builder()
            .status(StatusCode::OK)
            .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .header(
                ACCESS_CONTROL_ALLOW_METHODS,
                "GET, POST, PUT, DELETE, OPTIONS",
            )
            .header(
                ACCESS_CONTROL_ALLOW_HEADERS,
                "Origin, X-Requested-With, Content-Type, Accept, Authorization",
            )
            .body(empty())
            .unwrap();
    }

    // Block scanner requests
    if is_blocked_path(&path) {
        println!("🚫 Blocked scanner request: {method} {path}");
        return json_response(
            StatusCode::NOT_FOUND,
            &ErrorResponse {
                error: "Not found".to_string(),
                message: None,
            },
        );
    }

    // Block root path
    if path == "/" {
        println!("🚫 Blocked root access");
        return json_response(
            StatusCode::NOT_FOUND,
            &ErrorResponse {
                error: "Not found".to_string(),
                message: None,
            },
        );
    }

    // Route requests
    match (method.clone(), path.as_str()) {
        (Method::GET, "/health") => {
            let response = HealthResponse {
                status: "ok",
                timestamp: Utc::now().to_rfc3339(),
            };
            json_response(StatusCode::OK, &response)
        }

        (Method::GET, "/debug/wbi-keys") => {
            let (client, user_agent, _) = state.ipv6_pool.get_random_client();
            match state
                .wbi_manager
                .get_keys_info(&client, &user_agent, state.sessdata.as_deref())
                .await
            {
                Ok(info) => json_response(StatusCode::OK, &info),
                Err(e) => json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &ErrorResponse {
                        error: e,
                        message: None,
                    },
                ),
            }
        }

        (Method::GET, "/robots.txt") => Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain")
            .body(full("User-agent: *\nDisallow: /\n"))
            .unwrap(),

        (Method::GET, p) if p.starts_with("/cover/") => {
            let filename = p.strip_prefix("/cover/").unwrap_or("");
            match state.proxy_cover(filename).await {
                Ok(response) => response,
                Err(e) => json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &ErrorResponse {
                        error: "Cover proxy request failed".to_string(),
                        message: Some(e),
                    },
                ),
            }
        }

        _ => {
            // Read body for non-GET requests
            let body_bytes = match req.into_body().collect().await {
                Ok(collected) => collected.to_bytes().to_vec(),
                Err(_) => Vec::new(),
            };

            let query_params = parse_query_string(query.as_deref());

            match state
                .proxy_request(&method, &path, query_params, body_bytes)
                .await
            {
                Ok(response) => response,
                Err(e) => json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &ErrorResponse {
                        error: "Proxy request failed".to_string(),
                        message: Some(e),
                    },
                ),
            }
        }
    }
}
