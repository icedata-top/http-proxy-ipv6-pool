//! Bilibili API reverse proxy with WBI signature support.
//!
//! This module implements a reverse proxy for Bilibili APIs that:
//! - Automatically signs requests with WBI signature
//! - Proxies cover images from i0.hdslb.com
//! - Supports external URL proxying
//! - Adds CORS headers
//! - Filters malicious scanner requests

use bytes::Bytes;
use chrono::Utc;
use http::{
    Method, Request, Response, StatusCode,
    header::{
        ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
        CONTENT_TYPE, HeaderValue,
    },
};
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::{body::Incoming, server::conn::http1 as server_http1, service::service_fn};
use hyper_util::rt::TokioIo;
use lazy_static::lazy_static;
use md5::{Digest, Md5};
use parking_lot::RwLock;
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder,
};
use rand::Rng;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    convert::Infallible,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::net::TcpListener;

/// WBI mixin key encoding table
const MIXIN_KEY_ENC_TAB: [usize; 64] = [
    46, 47, 18, 2, 53, 8, 23, 32, 15, 50, 10, 31, 58, 3, 45, 35, 27, 43, 5, 49, 33, 9, 42, 19, 29,
    28, 14, 39, 12, 38, 41, 13, 37, 48, 7, 16, 24, 55, 40, 61, 26, 17, 0, 1, 60, 51, 30, 4, 22, 25,
    54, 21, 56, 59, 6, 63, 57, 62, 11, 36, 20, 34, 44, 52,
];

/// Default timeout for upstream requests (30 seconds)
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// WBI keys cache expiry (8 hours)
const WBI_KEYS_EXPIRY: Duration = Duration::from_secs(8 * 60 * 60);

/// Maximum retries for non-200 responses
const MAX_RETRIES: u32 = 5;

/// IPv6 pool size (number of pre-generated clients)
const IPV6_POOL_SIZE: usize = 128;

/// Body type alias for responses
type ResponseBody = BoxBody<Bytes, Infallible>;

lazy_static! {
    /// Patterns to block scanner requests
    static ref BLOCKED_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"^\.").unwrap(),
        Regex::new(r"\.(git|svn|hg)").unwrap(),
        Regex::new(r"\.(env|config|conf)$").unwrap(),
        Regex::new(r"\.(log|txt|bak)$").unwrap(),
        Regex::new(r"\.(sql|db|sqlite)$").unwrap(),
        Regex::new(r"\.(zip|tar|gz|rar)$").unwrap(),
        Regex::new(r"/(admin|wp-admin|wp-)").unwrap(),
        Regex::new(r"/(vendor|node_modules|\.)").unwrap(),
        Regex::new(r"/(backup|backups)").unwrap(),
        Regex::new(r"/(test|tests)").unwrap(),
        Regex::new(r"/\.well-known").unwrap(),
        Regex::new(r"\.(php|jsp|asp|py)$").unwrap(),
        Regex::new(r"/robots\.txt$").unwrap(),
        Regex::new(r"/sitemap").unwrap(),
        Regex::new(r"favicon\.ico$").unwrap(),
    ];

    /// Windows Desktop User-Agents for randomization
    static ref USER_AGENTS: Vec<&'static str> = vec![
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    ];

    /// Prometheus metrics registry
    static ref METRICS_REGISTRY: Registry = Registry::new();

    /// HTTP request duration histogram
    static ref HTTP_REQUEST_DURATION_MS: HistogramVec = {
        let opts = HistogramOpts::new(
            "biliproxy_http_request_duration_ms",
            "HTTP request duration in milliseconds"
        ).buckets(vec![10.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 2000.0, 5000.0, 10000.0]);
        let histogram = HistogramVec::new(opts, &["method", "route", "status"]).unwrap();
        METRICS_REGISTRY.register(Box::new(histogram.clone())).unwrap();
        histogram
    };

    /// HTTP response bytes counter
    static ref HTTP_RESPONSE_BYTES_TOTAL: IntCounterVec = {
        let opts = Opts::new(
            "biliproxy_http_response_bytes_total",
            "Total HTTP response bytes"
        );
        let counter = IntCounterVec::new(opts, &["method", "route", "status"]).unwrap();
        METRICS_REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };
}

/// WBI keys structure
#[derive(Clone, Debug)]
struct WbiKeys {
    img_key: String,
    sub_key: String,
    expires_at: Instant,
}

/// Generate a random IPv6 address within the given subnet.
fn generate_random_ipv6(ipv6_base: u128, prefix_len: u8) -> Ipv6Addr {
    if prefix_len == 0 {
        return Ipv6Addr::from(rand::thread_rng().gen::<u128>());
    }
    if prefix_len >= 128 {
        return Ipv6Addr::from(ipv6_base);
    }

    let rand_val: u128 = rand::thread_rng().gen();
    let shift_amount = 128 - prefix_len;
    let net_part = (ipv6_base >> shift_amount) << shift_amount;
    let host_part = (rand_val << prefix_len) >> prefix_len;
    Ipv6Addr::from(net_part | host_part)
}

/// IPv6 client pool for load distribution and 412 avoidance
/// Each client has a fixed User-Agent for more realistic behavior
struct Ipv6Pool {
    /// Each entry is (reqwest::Client, fixed User-Agent)
    clients: Vec<(reqwest::Client, &'static str)>,
}

impl Ipv6Pool {
    fn new(ipv6_base: u128, prefix_len: u8, timeout: Duration) -> Self {
        println!("Initializing IPv6 pool with {IPV6_POOL_SIZE} addresses...");
        let clients: Vec<_> = (0..IPV6_POOL_SIZE)
            .map(|i| {
                let ip = generate_random_ipv6(ipv6_base, prefix_len);
                let ua = random_user_agent();
                if i == 0 {
                    println!("  First pool IP: {ip}");
                }
                let client = reqwest::Client::builder()
                    .local_address(IpAddr::V6(ip))
                    .timeout(timeout)
                    .build()
                    .expect("Failed to create client");
                (client, ua)
            })
            .collect();
        println!("IPv6 pool initialized with {} clients", clients.len());
        Self { clients }
    }

    /// Get a random client with its fixed User-Agent
    fn get_random_client(&self) -> (&reqwest::Client, &'static str) {
        let idx = rand::thread_rng().gen_range(0..self.clients.len());
        (&self.clients[idx].0, self.clients[idx].1)
    }
}

/// Shared state for the biliproxy server
struct BiliproxyState {
    wbi_keys: RwLock<Option<WbiKeys>>,
    sessdata: Option<String>,
    ipv6_pool: Ipv6Pool,
}

/// Health check response
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    timestamp: String,
}

/// WBI keys debug response
#[derive(Serialize)]
struct WbiKeysResponse {
    #[serde(rename = "imgKey")]
    img_key: String,
    #[serde(rename = "subKey")]
    sub_key: String,
    #[serde(rename = "expiresAt")]
    expires_at: i64,
    #[serde(rename = "expiresIn")]
    expires_in: i64,
}

/// Error response
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

/// Bilibili nav API response for WBI keys
#[derive(Deserialize)]
struct NavResponse {
    data: Option<NavData>,
}

#[derive(Deserialize)]
struct NavData {
    wbi_img: Option<WbiImg>,
}

#[derive(Deserialize)]
struct WbiImg {
    img_url: String,
    sub_url: String,
}

/// Create an empty response body
fn empty() -> ResponseBody {
    Empty::<Bytes>::new().boxed()
}

/// Create a full response body from bytes
fn full<T: Into<Bytes>>(chunk: T) -> ResponseBody {
    Full::new(chunk.into()).boxed()
}

/// Get mixin key by scrambling img_key and sub_key
fn get_mixin_key(orig: &str) -> String {
    MIXIN_KEY_ENC_TAB
        .iter()
        .filter_map(|&n| orig.chars().nth(n))
        .take(32)
        .collect()
}

/// Generate a random User-Agent
fn random_user_agent() -> &'static str {
    let mut rng = rand::thread_rng();
    USER_AGENTS[rng.gen_range(0..USER_AGENTS.len())]
}

/// Generate random DedeUserID
fn random_dede_user_id() -> u64 {
    let mut rng = rand::thread_rng();
    let r: f64 = rng.gen();
    (r.powi(4) * 1_000_000_000_000.0) as u64
}

/// Generate random DedeUserID__ckMd5 (16 hex chars)
fn random_dede_ck_md5() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 8] = rng.gen();
    hex::encode(bytes)
}

/// Check if a path should be blocked (scanner protection)
fn is_blocked_path(path: &str) -> bool {
    let path_lower = path.to_lowercase();
    BLOCKED_PATTERNS.iter().any(|p| p.is_match(&path_lower))
}

impl BiliproxyState {
    fn new(sessdata: Option<String>, ipv6: Ipv6Addr, prefix_len: u8) -> Self {
        let ipv6_pool = Ipv6Pool::new(ipv6.into(), prefix_len, DEFAULT_TIMEOUT);

        Self {
            wbi_keys: RwLock::new(None),
            sessdata,
            ipv6_pool,
        }
    }

    /// Fetch WBI keys from Bilibili API
    async fn fetch_wbi_keys(&self) -> Result<WbiKeys, String> {
        let url = "https://api.bilibili.com/x/web-interface/nav";

        let (client, user_agent) = self.ipv6_pool.get_random_client();
        let mut request = client.get(url).header("User-Agent", user_agent);

        if let Some(ref sessdata) = self.sessdata {
            request = request.header("Cookie", format!("SESSDATA={sessdata}"));
        }

        let response = request
            .send()
            .await
            .map_err(|e| format!("Failed to fetch WBI keys: {e}"))?;

        let nav: NavResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse nav response: {e}"))?;

        let wbi_img = nav
            .data
            .and_then(|d| d.wbi_img)
            .ok_or_else(|| "No wbi_img in response".to_string())?;

        // Extract keys from URLs
        let img_key = extract_key_from_url(&wbi_img.img_url)?;
        let sub_key = extract_key_from_url(&wbi_img.sub_url)?;

        println!("WBI keys fetched: img_key={img_key}, sub_key={sub_key}");

        Ok(WbiKeys {
            img_key,
            sub_key,
            expires_at: Instant::now() + WBI_KEYS_EXPIRY,
        })
    }

    /// Get WBI keys (from cache or fetch new ones)
    async fn get_wbi_keys(&self) -> Result<(String, String), String> {
        // Check cache first
        {
            let cache = self.wbi_keys.read();
            if let Some(ref keys) = *cache {
                if Instant::now() < keys.expires_at {
                    return Ok((keys.img_key.clone(), keys.sub_key.clone()));
                }
            }
        }

        // Fetch new keys
        let new_keys = self.fetch_wbi_keys().await?;
        let result = (new_keys.img_key.clone(), new_keys.sub_key.clone());

        // Update cache
        {
            let mut cache = self.wbi_keys.write();
            *cache = Some(new_keys);
        }

        Ok(result)
    }

    /// Get WBI keys info for debug endpoint
    async fn get_wbi_keys_info(&self) -> Result<WbiKeysResponse, String> {
        let (img_key, sub_key) = self.get_wbi_keys().await?;
        let cache = self.wbi_keys.read();
        let keys = cache.as_ref().unwrap();

        let now = Instant::now();
        let expires_in = if keys.expires_at > now {
            (keys.expires_at - now).as_secs() as i64
        } else {
            0
        };

        Ok(WbiKeysResponse {
            img_key,
            sub_key,
            expires_at: Utc::now().timestamp() + expires_in,
            expires_in,
        })
    }

    /// Sign parameters with WBI signature
    async fn sign_with_wbi(
        &self,
        params: &HashMap<String, String>,
    ) -> Result<HashMap<String, String>, String> {
        let (img_key, sub_key) = self.get_wbi_keys().await?;
        let mixin_key = get_mixin_key(&format!("{img_key}{sub_key}"));

        // Add timestamp
        let wts = Utc::now().timestamp();
        let mut signed_params = params.clone();
        signed_params.insert("wts".to_string(), wts.to_string());

        // Sort and filter parameters
        let mut sorted_keys: Vec<_> = signed_params.keys().collect();
        sorted_keys.sort();

        let filtered_params: Vec<(String, String)> = sorted_keys
            .iter()
            .map(|k| {
                let v = signed_params.get(*k).unwrap();
                // Filter out special characters from values
                let filtered_v: String = v.chars().filter(|c| !"!'()*".contains(*c)).collect();
                ((*k).clone(), filtered_v)
            })
            .collect();

        // Build query string
        let query: String = filtered_params
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        // Calculate MD5 hash for w_rid
        let mut hasher = Md5::new();
        hasher.update(format!("{query}{mixin_key}"));
        let w_rid = hex::encode(hasher.finalize());

        signed_params.insert("w_rid".to_string(), w_rid);

        Ok(signed_params)
    }

    /// Proxy a cover image request
    async fn proxy_cover(&self, filename: &str) -> Result<Response<ResponseBody>, String> {
        let target_url = format!("https://i0.hdslb.com/bfs/archive/{filename}");
        let dede_user_id = random_dede_user_id();
        let dede_ck_md5 = random_dede_ck_md5();

        let (client, user_agent) = self.ipv6_pool.get_random_client();
        let response = client
            .get(&target_url)
            .header("User-Agent", user_agent)
            .header("Referer", "https://www.bilibili.com/")
            .header(
                "Cookie",
                format!("DedeUserID={dede_user_id}; DedeUserID__ckMd5={dede_ck_md5}"),
            )
            .send()
            .await
            .map_err(|e| format!("Cover proxy error: {e}"))?;

        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .bytes()
            .await
            .map_err(|e| format!("Failed to read cover body: {e}"))?;

        println!("Cover: {} - {}", status.as_u16(), filename);

        let mut builder =
            Response::builder().status(StatusCode::from_u16(status.as_u16()).unwrap());

        // Copy relevant headers
        for (key, value) in headers.iter() {
            let key_str = key.as_str().to_lowercase();
            if !["connection", "transfer-encoding", "content-encoding"].contains(&key_str.as_str())
            {
                if let Ok(hv) = HeaderValue::from_bytes(value.as_bytes()) {
                    builder = builder.header(key.clone(), hv);
                }
            }
        }

        // Add CORS headers
        builder = builder
            .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .header(ACCESS_CONTROL_ALLOW_METHODS, "GET, OPTIONS");

        builder
            .body(full(body))
            .map_err(|e| format!("Failed to build cover response: {e}"))
    }

    /// Proxy a generic request (with retry logic)
    async fn proxy_request(
        &self,
        method: &Method,
        path: &str,
        query_params: HashMap<String, String>,
        body: Vec<u8>,
    ) -> Result<Response<ResponseBody>, String> {
        let (target_url, should_sign) = self.determine_target(path);

        for attempt in 1..=MAX_RETRIES {
            let result = self
                .do_proxy_request(method, &target_url, &query_params, &body, should_sign)
                .await;

            match result {
                Ok(response) => {
                    let status = response.status();
                    if status == StatusCode::OK || status == StatusCode::NOT_FOUND {
                        return Ok(response);
                    }

                    if attempt < MAX_RETRIES {
                        println!(
                            "⚠️  Retry {}/{} - Status: {} - Regenerating signatures & cookies...",
                            attempt,
                            MAX_RETRIES - 1,
                            status.as_u16()
                        );
                        continue;
                    }

                    return Ok(response);
                }
                Err(e) => {
                    if attempt < MAX_RETRIES {
                        println!("⚠️  Retry {}/{} - Error: {}", attempt, MAX_RETRIES - 1, e);
                        continue;
                    }
                    return Err(e);
                }
            }
        }

        Err("Max retries exceeded".to_string())
    }

    /// Determine target URL and whether to sign
    fn determine_target(&self, path: &str) -> (String, bool) {
        let path_without_slash = path.trim_start_matches('/');

        // External URL proxy
        if path_without_slash.starts_with("http://") || path_without_slash.starts_with("https://") {
            return (path_without_slash.to_string(), false);
        }

        // api.vc.bilibili.com
        if path.starts_with("/apivc") {
            let api_path = path.strip_prefix("/apivc").unwrap_or("");
            return (format!("https://api.vc.bilibili.com{api_path}"), false);
        }

        // Default to api.bilibili.com with WBI signing
        (format!("https://api.bilibili.com{path}"), true)
    }

    /// Execute a single proxy request
    async fn do_proxy_request(
        &self,
        method: &Method,
        target_url: &str,
        query_params: &HashMap<String, String>,
        body: &[u8],
        should_sign: bool,
    ) -> Result<Response<ResponseBody>, String> {
        let dede_user_id = random_dede_user_id();
        let dede_ck_md5 = random_dede_ck_md5();

        // Determine referer based on bvid/avid/aid
        let referer = if let Some(bvid) = query_params.get("bvid") {
            format!("https://www.bilibili.com/video/{bvid}")
        } else if let Some(avid) = query_params.get("avid") {
            let avid_num = avid.trim_start_matches("av").trim_start_matches("AV");
            format!("https://www.bilibili.com/video/av{avid_num}")
        } else if let Some(aid) = query_params.get("aid") {
            format!("https://www.bilibili.com/video/av{aid}")
        } else {
            "https://www.bilibili.com/".to_string()
        };

        // Sign params if needed
        let final_params = if should_sign && *method == Method::GET {
            self.sign_with_wbi(query_params).await?
        } else {
            query_params.clone()
        };

        // Build URL with query params
        let url = if final_params.is_empty() {
            target_url.to_string()
        } else {
            let query_string: String = final_params
                .iter()
                .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
                .collect::<Vec<_>>()
                .join("&");
            format!("{target_url}?{query_string}")
        };

        // Build cookie
        let mut cookies = vec![
            format!("DedeUserID={}", dede_user_id),
            format!("DedeUserID__ckMd5={}", dede_ck_md5),
        ];
        if let Some(ref sessdata) = self.sessdata {
            cookies.push(format!("SESSDATA={sessdata}"));
        }

        let (client, user_agent) = self.ipv6_pool.get_random_client();
        let request_builder = match *method {
            Method::GET => client.get(&url),
            Method::POST => client.post(&url).body(body.to_vec()),
            Method::PUT => client.put(&url).body(body.to_vec()),
            Method::DELETE => client.delete(&url),
            _ => client.get(&url),
        };

        let response = request_builder
            .header("User-Agent", user_agent)
            .header("Referer", &referer)
            .header("Origin", &referer)
            .header("Cookie", cookies.join("; "))
            .send()
            .await
            .map_err(|e| format!("Proxy request failed: {e}"))?;

        let status = response.status();
        let headers = response.headers().clone();
        let response_body = response
            .bytes()
            .await
            .map_err(|e| format!("Failed to read response body: {e}"))?;

        println!("{} - {}", status.as_u16(), target_url);

        let mut builder =
            Response::builder().status(StatusCode::from_u16(status.as_u16()).unwrap());

        // Copy relevant headers
        for (key, value) in headers.iter() {
            let key_str = key.as_str().to_lowercase();
            if !["connection", "transfer-encoding", "content-encoding"].contains(&key_str.as_str())
            {
                if let Ok(hv) = HeaderValue::from_bytes(value.as_bytes()) {
                    builder = builder.header(key.clone(), hv);
                }
            }
        }

        // Add CORS headers
        builder = builder
            .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .header(
                ACCESS_CONTROL_ALLOW_METHODS,
                "GET, POST, PUT, DELETE, OPTIONS",
            )
            .header(
                ACCESS_CONTROL_ALLOW_HEADERS,
                "Origin, X-Requested-With, Content-Type, Accept, Authorization",
            );

        builder
            .body(full(response_body))
            .map_err(|e| format!("Failed to build response: {e}"))
    }
}

/// Extract key from Bilibili wbi URL
fn extract_key_from_url(url: &str) -> Result<String, String> {
    // URL format: https://i0.hdslb.com/bfs/wbi/xxx.png
    let last_slash = url.rfind('/').ok_or("Invalid URL format")?;
    let last_dot = url.rfind('.').ok_or("Invalid URL format")?;

    if last_dot <= last_slash {
        return Err("Invalid URL format".to_string());
    }

    Ok(url[last_slash + 1..last_dot].to_string())
}

/// Parse query string into HashMap
fn parse_query_string(query: Option<&str>) -> HashMap<String, String> {
    let mut params = HashMap::new();
    if let Some(q) = query {
        for pair in q.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                let decoded_key = urlencoding::decode(key).unwrap_or_else(|_| key.into());
                let decoded_value = urlencoding::decode(value).unwrap_or_else(|_| value.into());
                params.insert(decoded_key.into_owned(), decoded_value.into_owned());
            }
        }
    }
    params
}

/// Normalize route for metrics (avoid high cardinality)
fn normalize_route(path: &str) -> &str {
    if path.starts_with("/cover/") {
        "/cover"
    } else if path.starts_with("/apivc") {
        "/apivc"
    } else if path.starts_with("/https://") || path.starts_with("/http://") {
        "/external"
    } else if path.starts_with("/x/") {
        // Keep first two segments for Bilibili API routes
        path.split('/').take(3).collect::<Vec<_>>().join("/").leak()
    } else {
        path
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

    // Record metrics
    let status = response.status().as_u16().to_string();
    let duration_ms = start.elapsed().as_millis() as f64;

    HTTP_REQUEST_DURATION_MS
        .with_label_values(&[&method_str, &route, &status])
        .observe(duration_ms);

    if let Some(content_length) = response.headers().get("content-length") {
        if let Ok(len_str) = content_length.to_str() {
            if let Ok(len) = len_str.parse::<u64>() {
                HTTP_RESPONSE_BYTES_TOTAL
                    .with_label_values(&[&method_str, &route, &status])
                    .inc_by(len);
            }
        }
    }

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

        (Method::GET, "/debug/wbi-keys") => match state.get_wbi_keys_info().await {
            Ok(info) => json_response(StatusCode::OK, &info),
            Err(e) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &ErrorResponse {
                    error: e,
                    message: None,
                },
            ),
        },

        (Method::GET, "/metrics") => {
            let encoder = TextEncoder::new();
            let metric_families = METRICS_REGISTRY.gather();
            let mut buffer = Vec::new();
            encoder.encode(&metric_families, &mut buffer).unwrap();
            Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, encoder.format_type())
                .body(full(buffer))
                .unwrap()
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

/// Create a JSON response
fn json_response<T: Serialize>(status: StatusCode, body: &T) -> Response<ResponseBody> {
    let json = serde_json::to_string(body).unwrap_or_else(|_| "{}".to_string());
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .body(full(json))
        .unwrap()
}

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
