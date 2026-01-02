use super::{
    pool::{DEFAULT_TIMEOUT, Ipv6Pool},
    types::ResponseBody,
    utils::{full, random_dede_ck_md5, random_dede_user_id},
    wbi::WbiManager,
};
use http::{
    Method, Response, StatusCode,
    header::{
        ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue,
    },
};
use std::{collections::HashMap, net::Ipv6Addr};

/// Maximum retries for non-200 responses
pub const MAX_RETRIES: u32 = 5;

/// Shared state for the biliproxy server
pub struct BiliproxyState {
    pub(crate) wbi_manager: WbiManager,
    pub(crate) ipv6_pool: Ipv6Pool,
}

impl BiliproxyState {
    pub fn new(ipv6: Ipv6Addr, prefix_len: u8) -> Self {
        let ipv6_pool = Ipv6Pool::new(ipv6.into(), prefix_len, DEFAULT_TIMEOUT);

        Self {
            wbi_manager: WbiManager::new(),
            ipv6_pool,
        }
    }

    /// Proxy a cover image request
    pub async fn proxy_cover(&self, filename: &str) -> Result<Response<ResponseBody>, String> {
        let target_url = format!("https://i0.hdslb.com/bfs/archive/{filename}");
        let dede_user_id = random_dede_user_id();
        let dede_ck_md5 = random_dede_ck_md5();

        let (client, user_agent, _) = self.ipv6_pool.get_random_client();
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

        for (key, value) in headers.iter() {
            let key_str = key.as_str().to_lowercase();
            if !["connection", "transfer-encoding", "content-encoding"].contains(&key_str.as_str())
            {
                if let Ok(hv) = HeaderValue::from_bytes(value.as_bytes()) {
                    builder = builder.header(key.clone(), hv);
                }
            }
        }

        builder = builder
            .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .header(ACCESS_CONTROL_ALLOW_METHODS, "GET, OPTIONS");

        self.ipv6_pool.maybe_rotate();
        builder
            .body(full(body))
            .map_err(|e| format!("Failed to build cover response: {e}"))
    }

    /// Proxy a generic request (with retry logic and bound-retry rotation)
    pub async fn proxy_request(
        &self,
        method: &Method,
        path: &str,
        query_params: HashMap<String, String>,
        body: Vec<u8>,
        incoming_cookie: Option<String>,
    ) -> Result<Response<ResponseBody>, String> {
        let (target_url, should_sign) = self.determine_target(path);
        let (_, _, idx) = self.ipv6_pool.get_random_client();

        for attempt in 1..=MAX_RETRIES {
            let result = self
                .do_proxy_request(
                    idx,
                    method,
                    &target_url,
                    &query_params,
                    &body,
                    should_sign,
                    incoming_cookie.as_deref(),
                )
                .await;

            match result {
                Ok(response) => {
                    let status = response.status();
                    if status == StatusCode::OK || status == StatusCode::NOT_FOUND {
                        self.ipv6_pool.maybe_rotate();
                        return Ok(response);
                    }

                    if attempt < MAX_RETRIES {
                        println!(
                            "⚠️  Retry {}/{} - Status: {} - Rotating slot {idx}...",
                            attempt,
                            MAX_RETRIES - 1,
                            status.as_u16()
                        );
                        self.ipv6_pool.force_rotate(idx);
                        continue;
                    }

                    self.ipv6_pool.maybe_rotate();
                    return Ok(response);
                }
                Err(e) => {
                    if attempt < MAX_RETRIES {
                        println!(
                            "⚠️  Retry {}/{} - Error: {e} - Rotating slot {idx}...",
                            attempt,
                            MAX_RETRIES - 1
                        );
                        self.ipv6_pool.force_rotate(idx);
                        continue;
                    }
                    return Err(e);
                }
            }
        }

        self.ipv6_pool.maybe_rotate();
        Err("Max retries exceeded".to_string())
    }

    fn determine_target(&self, path: &str) -> (String, bool) {
        let path_without_slash = path.trim_start_matches('/');

        if path_without_slash.starts_with("http://") || path_without_slash.starts_with("https://") {
            return (path_without_slash.to_string(), false);
        }

        if path.starts_with("/apivc") {
            let api_path = path.strip_prefix("/apivc").unwrap_or("");
            return (format!("https://api.vc.bilibili.com{api_path}"), false);
        }

        let should_sign = path.starts_with("/x/");
        (format!("https://api.bilibili.com{path}"), should_sign)
    }

    #[allow(clippy::too_many_arguments)]
    async fn do_proxy_request(
        &self,
        pool_index: usize,
        method: &Method,
        target_url: &str,
        query_params: &HashMap<String, String>,
        body: &[u8],
        should_sign: bool,
        incoming_cookie: Option<&str>,
    ) -> Result<Response<ResponseBody>, String> {
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
        let (client, user_agent) = self.ipv6_pool.get_client_by_index(pool_index);
        let final_params = if should_sign && *method == Method::GET {
            self.wbi_manager
                .sign(query_params, &client, &user_agent)
                .await?
        } else {
            query_params.clone()
        };

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

        // Use incoming cookie if provided, otherwise generate default
        let cookie_header = if let Some(cookie) = incoming_cookie {
            cookie.to_string()
        } else {
            let dede_user_id = random_dede_user_id();
            let dede_ck_md5 = random_dede_ck_md5();
            format!("DedeUserID={dede_user_id}; DedeUserID__ckMd5={dede_ck_md5}")
        };

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
            .header("Cookie", &cookie_header)
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

        for (key, value) in headers.iter() {
            let key_str = key.as_str().to_lowercase();
            if !["connection", "transfer-encoding", "content-encoding"].contains(&key_str.as_str())
            {
                if let Ok(hv) = HeaderValue::from_bytes(value.as_bytes()) {
                    builder = builder.header(key.clone(), hv);
                }
            }
        }

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
