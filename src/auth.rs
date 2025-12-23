//! Shared authentication utilities

use base64::Engine;
use http::{
    Request,
    header::{AUTHORIZATION, HeaderName, HeaderValue, PROXY_AUTHORIZATION},
};

/// Authenticate a request using HTTP Basic Auth with the Authorization header.
/// Returns true if credentials match, false otherwise.
pub fn authenticate_authorization<B>(
    req: &Request<B>,
    expected_username: &str,
    expected_password: &str,
) -> bool {
    authenticate_with_header(req, AUTHORIZATION, expected_username, expected_password)
}

/// Authenticate a request using HTTP Basic Auth with the Proxy-Authorization header.
/// Returns true if credentials match, false otherwise.
pub fn authenticate_proxy_authorization<B>(
    req: &Request<B>,
    expected_username: &str,
    expected_password: &str,
) -> bool {
    authenticate_with_header(
        req,
        PROXY_AUTHORIZATION,
        expected_username,
        expected_password,
    )
}

/// Authenticate a request using HTTP Basic Auth with a specified header.
fn authenticate_with_header<B>(
    req: &Request<B>,
    header_name: HeaderName,
    expected_username: &str,
    expected_password: &str,
) -> bool {
    if let Some(auth_header) = req.headers().get(header_name) {
        return validate_basic_auth(auth_header, expected_username, expected_password);
    }
    false
}

/// Validate a Basic auth header value against expected credentials.
pub fn validate_basic_auth(
    auth_header: &HeaderValue,
    expected_username: &str,
    expected_password: &str,
) -> bool {
    if let Ok(auth_str) = auth_header.to_str() {
        if auth_str.starts_with("Basic ") {
            let credentials = auth_str.trim_start_matches("Basic ");
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(credentials) {
                if let Ok(auth_string) = String::from_utf8(decoded) {
                    let parts: Vec<&str> = auth_string.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        return parts[0] == expected_username && parts[1] == expected_password;
                    }
                }
            }
        }
    }
    false
}
