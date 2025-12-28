//! Prometheus metrics module for all services.
//!
//! This module provides a unified metrics collection system that can be used by:
//! - biliproxy: Bilibili API reverse proxy
//! - proxy: HTTP/HTTPS proxy with IPv6 pool
//! - controller: IPv6 address management API
//!
//! Metrics are exposed via an independent HTTP server on a configurable port.

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, header::CONTENT_TYPE};
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::{body::Incoming, server::conn::http1 as server_http1, service::service_fn};
use hyper_util::rt::TokioIo;
use lazy_static::lazy_static;
use prometheus::{
    Encoder, Gauge, HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder,
};
use std::{convert::Infallible, net::SocketAddr, time::Instant};
use tokio::net::TcpListener;

/// Metric prefix for all metrics
const METRIC_PREFIX: &str = "ipv6proxy";

/// Body type alias for responses
type ResponseBody = BoxBody<Bytes, Infallible>;

lazy_static! {
    /// Process start time for uptime calculation
    pub static ref START_TIME: Instant = Instant::now();

    /// Global Prometheus registry
    pub static ref REGISTRY: Registry = {
        let registry = Registry::new();

        // Register process collector for CPU, memory, FD metrics (Linux only)
        #[cfg(target_os = "linux")]
        {
            use prometheus::process_collector::ProcessCollector;
            let pc = ProcessCollector::for_self();
            registry.register(Box::new(pc)).expect("Failed to register process collector");
        }

        registry
    };

    /// HTTP request duration histogram
    /// Labels: service (biliproxy/proxy/controller), method, route, status
    pub static ref HTTP_REQUEST_DURATION_MS: HistogramVec = {
        let opts = HistogramOpts::new(
            format!("{METRIC_PREFIX}_http_request_duration_ms"),
            "Duration of HTTP requests in milliseconds"
        ).buckets(vec![10.0, 50.0, 100.0, 300.0, 500.0, 700.0, 1000.0, 3000.0, 5000.0, 7000.0, 10000.0]);
        let histogram = HistogramVec::new(opts, &["service", "method", "route", "status"]).unwrap();
        REGISTRY.register(Box::new(histogram.clone())).expect("Failed to register HTTP request duration");
        histogram
    };

    /// HTTP response bytes counter
    /// Labels: service, method, route, status
    pub static ref HTTP_RESPONSE_BYTES_TOTAL: IntCounterVec = {
        let opts = Opts::new(
            format!("{METRIC_PREFIX}_http_response_bytes_total"),
            "Total HTTP response bytes"
        );
        let counter = IntCounterVec::new(opts, &["service", "method", "route", "status"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).expect("Failed to register HTTP response bytes");
        counter
    };

    /// Proxy bandwidth counter (for CONNECT tunnels)
    /// Labels: direction (upload/download), proxy_type (random/stable)
    pub static ref PROXY_BANDWIDTH_BYTES_TOTAL: IntCounterVec = {
        let opts = Opts::new(
            format!("{METRIC_PREFIX}_proxy_bandwidth_bytes_total"),
            "Total proxy bandwidth in bytes"
        );
        let counter = IntCounterVec::new(opts, &["direction", "proxy_type"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).expect("Failed to register proxy bandwidth");
        counter
    };

    /// Proxy connection counter
    /// Labels: proxy_type (random/stable), status (success/failed)
    pub static ref PROXY_CONNECTIONS_TOTAL: IntCounterVec = {
        let opts = Opts::new(
            format!("{METRIC_PREFIX}_proxy_connections_total"),
            "Total proxy connections"
        );
        let counter = IntCounterVec::new(opts, &["proxy_type", "status"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).expect("Failed to register proxy connections");
        counter
    };

    /// Application uptime gauge
    pub static ref UPTIME_SECONDS: Gauge = {
        let opts = Opts::new(
            format!("{METRIC_PREFIX}_uptime_seconds"),
            "Uptime of the application in seconds"
        );
        let gauge = Gauge::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(gauge.clone())).expect("Failed to register uptime");
        gauge
    };
}

/// Record an HTTP request metric.
///
/// # Arguments
/// * `service` - Service name (biliproxy, proxy, controller)
/// * `method` - HTTP method
/// * `route` - Normalized route path
/// * `status` - HTTP status code
/// * `duration_ms` - Request duration in milliseconds
/// * `bytes` - Optional response body size in bytes
pub fn record_request(
    service: &str,
    method: &str,
    route: &str,
    status: u16,
    duration_ms: f64,
    bytes: Option<u64>,
) {
    let status_str = status.to_string();

    HTTP_REQUEST_DURATION_MS
        .with_label_values(&[service, method, route, &status_str])
        .observe(duration_ms);

    if let Some(b) = bytes {
        HTTP_RESPONSE_BYTES_TOTAL
            .with_label_values(&[service, method, route, &status_str])
            .inc_by(b);
    }
}

/// Record proxy bandwidth.
///
/// # Arguments
/// * `direction` - "upload" or "download"
/// * `proxy_type` - "random" or "stable"
/// * `bytes` - Number of bytes transferred
pub fn record_proxy_bandwidth(direction: &str, proxy_type: &str, bytes: u64) {
    PROXY_BANDWIDTH_BYTES_TOTAL
        .with_label_values(&[direction, proxy_type])
        .inc_by(bytes);
}

/// Record a proxy connection attempt.
///
/// # Arguments
/// * `proxy_type` - "random" or "stable"
/// * `success` - Whether the connection was successful
pub fn record_proxy_connection(proxy_type: &str, success: bool) {
    let status = if success { "success" } else { "failed" };
    PROXY_CONNECTIONS_TOTAL
        .with_label_values(&[proxy_type, status])
        .inc();
}

/// Render all metrics as Prometheus text format.
pub fn render_metrics() -> String {
    // Update uptime before rendering
    UPTIME_SECONDS.set(START_TIME.elapsed().as_secs_f64());

    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap_or_default()
}

/// Create an empty response body
fn empty() -> ResponseBody {
    Empty::<Bytes>::new().boxed()
}

/// Create a full response body from bytes
fn full<T: Into<Bytes>>(chunk: T) -> ResponseBody {
    Full::new(chunk.into()).boxed()
}

/// Handle metrics HTTP request
async fn handle_metrics_request(
    req: Request<Incoming>,
) -> Result<Response<ResponseBody>, Infallible> {
    let method = req.method();
    let path = req.uri().path();

    match (method, path) {
        (&Method::GET, "/metrics") => {
            let metrics = render_metrics();
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")
                .body(full(metrics))
                .unwrap())
        }
        (&Method::GET, "/health") => Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain")
            .body(full("OK"))
            .unwrap()),
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(empty())
            .unwrap()),
    }
}

/// Start the metrics HTTP server on the specified address.
///
/// This server exposes:
/// - GET /metrics - Prometheus metrics
/// - GET /health - Health check
pub async fn start_metrics_server(
    bind_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Force initialization of lazy statics
    lazy_static::initialize(&START_TIME);
    lazy_static::initialize(&REGISTRY);
    lazy_static::initialize(&HTTP_REQUEST_DURATION_MS);
    lazy_static::initialize(&HTTP_RESPONSE_BYTES_TOTAL);
    lazy_static::initialize(&PROXY_BANDWIDTH_BYTES_TOTAL);
    lazy_static::initialize(&PROXY_CONNECTIONS_TOTAL);
    lazy_static::initialize(&UPTIME_SECONDS);

    let listener = TcpListener::bind(bind_addr).await?;
    println!("Metrics server listening on http://{bind_addr}/metrics");

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        tokio::spawn(async move {
            let service = service_fn(handle_metrics_request);

            if let Err(err) = server_http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                eprintln!("Metrics server connection error: {err}");
            }
        });
    }
}
