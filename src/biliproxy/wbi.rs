//! WBI (Web Bilibili Interface) signature support.
//!
//! This module handles all WBI-related logic:
//! - Key fetching, caching, and retrieval
//! - Parameter signing with MD5
//! - URL key extraction

use super::types::{NavResponse, WbiKeysResponse};
use chrono::Utc;
use md5::{Digest, Md5};
use parking_lot::RwLock;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

/// WBI keys cache expiry (8 hours)
pub const WBI_KEYS_EXPIRY: Duration = Duration::from_secs(8 * 60 * 60);

/// Bilibili nav API URL for fetching WBI keys
const NAV_API_URL: &str = "https://api.bilibili.com/x/web-interface/nav";

/// WBI mixin key encoding table
const MIXIN_KEY_ENC_TAB: [usize; 64] = [
    46, 47, 18, 2, 53, 8, 23, 32, 15, 50, 10, 31, 58, 3, 45, 35, 27, 43, 5, 49, 33, 9, 42, 19, 29,
    28, 14, 39, 12, 38, 41, 13, 37, 48, 7, 16, 24, 55, 40, 61, 26, 17, 0, 1, 60, 51, 30, 4, 22, 25,
    54, 21, 56, 59, 6, 63, 57, 62, 11, 36, 20, 34, 44, 52,
];

/// WBI keys structure
#[derive(Clone, Debug)]
pub struct WbiKeys {
    pub img_key: String,
    pub sub_key: String,
    pub expires_at: Instant,
}

/// WBI key manager with caching and all WBI operations
pub struct WbiManager {
    keys: RwLock<Option<WbiKeys>>,
}

impl WbiManager {
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(None),
        }
    }

    /// Get WBI keys (from cache or fetch new ones)
    pub async fn get_keys(
        &self,
        client: &reqwest::Client,
        user_agent: &str,
    ) -> Result<(String, String), String> {
        // Check cache first
        {
            let cache = self.keys.read();
            if let Some(ref keys) = *cache {
                if Instant::now() < keys.expires_at {
                    return Ok((keys.img_key.clone(), keys.sub_key.clone()));
                }
            }
        }

        // Fetch new keys
        let new_keys = fetch_wbi_keys(client, user_agent).await?;
        let result = (new_keys.img_key.clone(), new_keys.sub_key.clone());

        // Update cache
        {
            let mut cache = self.keys.write();
            *cache = Some(new_keys);
        }

        Ok(result)
    }

    /// Get WBI keys info for debug endpoint
    pub async fn get_keys_info(
        &self,
        client: &reqwest::Client,
        user_agent: &str,
    ) -> Result<WbiKeysResponse, String> {
        let (img_key, sub_key) = self.get_keys(client, user_agent).await?;

        let (expires_at, expires_in) = {
            let cache = self.keys.read();
            if let Some(ref keys) = *cache {
                let now = Instant::now();
                let expires_in = if keys.expires_at > now {
                    (keys.expires_at - now).as_secs() as i64
                } else {
                    0
                };
                (Utc::now().timestamp() + expires_in, expires_in)
            } else {
                (Utc::now().timestamp(), 0)
            }
        };

        Ok(WbiKeysResponse {
            img_key,
            sub_key,
            expires_at,
            expires_in,
        })
    }

    /// Sign parameters with WBI signature
    pub async fn sign(
        &self,
        params: &HashMap<String, String>,
        client: &reqwest::Client,
        user_agent: &str,
    ) -> Result<HashMap<String, String>, String> {
        let (img_key, sub_key) = self.get_keys(client, user_agent).await?;
        Ok(sign_params(params, &img_key, &sub_key))
    }
}

impl Default for WbiManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Fetch WBI keys from Bilibili API using provided client
pub async fn fetch_wbi_keys(client: &reqwest::Client, user_agent: &str) -> Result<WbiKeys, String> {
    let response = client
        .get(NAV_API_URL)
        .header("User-Agent", user_agent)
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

    let img_key = extract_key_from_url(&wbi_img.img_url)?;
    let sub_key = extract_key_from_url(&wbi_img.sub_url)?;

    println!("WBI keys fetched: img_key={img_key}, sub_key={sub_key}");

    Ok(WbiKeys {
        img_key,
        sub_key,
        expires_at: Instant::now() + WBI_KEYS_EXPIRY,
    })
}

/// Get mixin key by scrambling img_key and sub_key
fn get_mixin_key(orig: &str) -> String {
    MIXIN_KEY_ENC_TAB
        .iter()
        .filter_map(|&n| orig.chars().nth(n))
        .take(32)
        .collect()
}

/// Sign parameters with WBI signature
pub fn sign_params(
    params: &HashMap<String, String>,
    img_key: &str,
    sub_key: &str,
) -> HashMap<String, String> {
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
    signed_params
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
