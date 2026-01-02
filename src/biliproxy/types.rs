use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;

/// Body type alias for responses
pub type ResponseBody = BoxBody<Bytes, Infallible>;

/// Health check response
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub timestamp: String,
}

/// WBI keys debug response
#[derive(Serialize)]
pub struct WbiKeysResponse {
    #[serde(rename = "imgKey")]
    pub img_key: String,
    #[serde(rename = "subKey")]
    pub sub_key: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: i64,
    #[serde(rename = "expiresIn")]
    pub expires_in: i64,
}

/// Error response
#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Bilibili nav API response for WBI keys
#[derive(Deserialize)]
pub struct NavResponse {
    pub data: Option<NavData>,
}

#[derive(Deserialize)]
pub struct NavData {
    pub wbi_img: Option<WbiImg>,
}

#[derive(Deserialize)]
pub struct WbiImg {
    pub img_url: String,
    pub sub_url: String,
}
