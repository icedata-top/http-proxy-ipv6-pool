use super::types::ResponseBody;
use bytes::Bytes;
use http::{
    Response, StatusCode,
    header::{ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE},
};
use http_body_util::{BodyExt, Empty, Full};
use lazy_static::lazy_static;
use rand::Rng;
use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;

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
}

/// Create an empty response body
pub fn empty() -> ResponseBody {
    Empty::<Bytes>::new().boxed()
}

/// Create a full response body from bytes
pub fn full<T: Into<Bytes>>(chunk: T) -> ResponseBody {
    Full::new(chunk.into()).boxed()
}

/// Generate a random User-Agent using ua_generator
pub fn random_user_agent() -> String {
    ua_generator::ua::spoof_ua().to_string()
}

/// Generate random DedeUserID
pub fn random_dede_user_id() -> u64 {
    let mut rng = rand::thread_rng();
    let r: f64 = rng.gen();
    (r.powi(4) * 1_000_000_000_000.0) as u64
}

/// Generate random DedeUserID__ckMd5 (16 hex chars)
pub fn random_dede_ck_md5() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 8] = rng.gen();
    hex::encode(bytes)
}

/// Check if a path should be blocked (scanner protection)
pub fn is_blocked_path(path: &str) -> bool {
    let path_lower = path.to_lowercase();
    BLOCKED_PATTERNS.iter().any(|p| p.is_match(&path_lower))
}

/// Parse query string into HashMap
pub fn parse_query_string(query: Option<&str>) -> HashMap<String, String> {
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
pub fn normalize_route(path: &str) -> &str {
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

/// Create a JSON response
pub fn json_response<T: Serialize>(status: StatusCode, body: &T) -> Response<ResponseBody> {
    let json = serde_json::to_string(body).unwrap_or_else(|_| "{}".to_string());
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .body(full(json))
        .unwrap()
}
