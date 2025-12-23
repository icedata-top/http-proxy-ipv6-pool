use base64::Engine;
use hyper::{
    Body, Method, Request, Response, Server, StatusCode,
    header::{AUTHORIZATION, HeaderValue, WWW_AUTHENTICATE},
    service::{make_service_fn, service_fn},
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::{
    net::{Ipv6Addr, SocketAddr},
    sync::Arc,
};
use tokio::sync::RwLock;

/// Shared state for the stable IPv6 address
pub type StableIpv6State = Arc<RwLock<Ipv6Addr>>;

#[derive(Serialize)]
struct IpResponse {
    ip: String,
}

#[derive(Deserialize)]
struct SetIpRequest {
    ip: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

/// Generate a random IPv6 address within the given subnet
pub fn generate_random_ipv6(ipv6_base: u128, prefix_len: u8) -> Ipv6Addr {
    let rand: u128 = rand::thread_rng().gen();
    let net_part = (ipv6_base >> (128 - prefix_len)) << (128 - prefix_len);
    let host_part = (rand << prefix_len) >> prefix_len;
    let ipv6 = net_part | host_part;
    Ipv6Addr::from(ipv6)
}

/// Start the controller HTTP server
pub async fn start_controller(
    bind_addr: SocketAddr,
    state: StableIpv6State,
    ipv6_base: u128,
    prefix_len: u8,
    username: String,
    password: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let make_service = make_service_fn(move |_| {
        let state = state.clone();
        let username = username.clone();
        let password = password.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                handle_request(
                    req,
                    state.clone(),
                    ipv6_base,
                    prefix_len,
                    username.clone(),
                    password.clone(),
                )
            }))
        }
    });

    println!("Controller listening on {}", bind_addr);
    Server::bind(&bind_addr)
        .serve(make_service)
        .await
        .map_err(|e| e.into())
}

fn authenticate(req: &Request<Body>, username: &str, password: &str) -> bool {
    if let Some(auth_header) = req.headers().get(AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Basic ") {
                let credentials = auth_str.trim_start_matches("Basic ");
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(credentials) {
                    if let Ok(auth_string) = String::from_utf8(decoded) {
                        let parts: Vec<&str> = auth_string.splitn(2, ':').collect();
                        if parts.len() == 2 {
                            return parts[0] == username && parts[1] == password;
                        }
                    }
                }
            }
        }
    }
    false
}

async fn handle_request(
    req: Request<Body>,
    state: StableIpv6State,
    ipv6_base: u128,
    prefix_len: u8,
    username: String,
    password: String,
) -> Result<Response<Body>, hyper::Error> {
    // Check authentication
    if !authenticate(&req, &username, &password) {
        return Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(
                WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"Controller\""),
            )
            .body(Body::empty())
            .unwrap());
    }

    let path = req.uri().path();
    let method = req.method();

    match (method, path) {
        (&Method::GET, "/ip") => {
            let ip = state.read().await;
            let response = IpResponse { ip: ip.to_string() };
            Ok(json_response(StatusCode::OK, &response))
        }

        (&Method::POST, "/rotate") => {
            let new_ip = generate_random_ipv6(ipv6_base, prefix_len);
            {
                let mut ip = state.write().await;
                *ip = new_ip;
            }
            println!("Rotated stable IPv6 to: {}", new_ip);
            let response = IpResponse {
                ip: new_ip.to_string(),
            };
            Ok(json_response(StatusCode::OK, &response))
        }

        (&Method::POST, "/set") => {
            let body_bytes = hyper::body::to_bytes(req.into_body()).await?;
            match serde_json::from_slice::<SetIpRequest>(&body_bytes) {
                Ok(set_req) => {
                    match set_req.ip.parse::<Ipv6Addr>() {
                        Ok(new_ip) => {
                            // Validate the IP is within the subnet
                            let new_ip_u128: u128 = new_ip.into();
                            let net_part_new =
                                (new_ip_u128 >> (128 - prefix_len)) << (128 - prefix_len);
                            let net_part_base =
                                (ipv6_base >> (128 - prefix_len)) << (128 - prefix_len);

                            if net_part_new != net_part_base {
                                let response = ErrorResponse {
                                    error: "IP address is not within the configured subnet"
                                        .to_string(),
                                };
                                return Ok(json_response(StatusCode::BAD_REQUEST, &response));
                            }

                            {
                                let mut ip = state.write().await;
                                *ip = new_ip;
                            }
                            println!("Set stable IPv6 to: {}", new_ip);
                            let response = IpResponse {
                                ip: new_ip.to_string(),
                            };
                            Ok(json_response(StatusCode::OK, &response))
                        }
                        Err(_) => {
                            let response = ErrorResponse {
                                error: "Invalid IPv6 address format".to_string(),
                            };
                            Ok(json_response(StatusCode::BAD_REQUEST, &response))
                        }
                    }
                }
                Err(_) => {
                    let response = ErrorResponse {
                        error: "Invalid JSON body. Expected: {\"ip\": \"...\"}".to_string(),
                    };
                    Ok(json_response(StatusCode::BAD_REQUEST, &response))
                }
            }
        }

        _ => {
            let response = ErrorResponse {
                error: "Not found. Available endpoints: GET /ip, POST /rotate, POST /set"
                    .to_string(),
            };
            Ok(json_response(StatusCode::NOT_FOUND, &response))
        }
    }
}

fn json_response<T: Serialize>(status: StatusCode, body: &T) -> Response<Body> {
    let json = serde_json::to_string(body).unwrap_or_else(|_| "{}".to_string());
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Body::from(json))
        .unwrap()
}
