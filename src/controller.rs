use bytes::Bytes;
use http::{
    Method, Request, Response, StatusCode,
    header::{HeaderValue, WWW_AUTHENTICATE},
};
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::{body::Incoming, server::conn::http1 as server_http1, service::service_fn};
use hyper_util::rt::TokioIo;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::{
    convert::Infallible,
    net::{Ipv6Addr, SocketAddr},
};
use tokio::net::TcpListener;

use crate::{auth, proxy::StableIpv6State};

/// Body type alias for responses
type ResponseBody = BoxBody<Bytes, Infallible>;

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

/// Create an empty response body
fn empty() -> ResponseBody {
    Empty::<Bytes>::new().boxed()
}

/// Create a full response body from bytes
fn full<T: Into<Bytes>>(chunk: T) -> ResponseBody {
    Full::new(chunk.into()).boxed()
}

/// Generate a random IPv6 address within the given subnet.
/// Handles edge case where prefix_len is 0 (entire address is random).
pub fn generate_random_ipv6(ipv6_base: u128, prefix_len: u8) -> Ipv6Addr {
    if prefix_len == 0 {
        // All bits are host part - return completely random IPv6
        return Ipv6Addr::from(rand::thread_rng().gen::<u128>());
    }
    if prefix_len >= 128 {
        // All bits are network part - return base address
        return Ipv6Addr::from(ipv6_base);
    }

    let rand_val: u128 = rand::thread_rng().gen();
    let shift_amount = 128 - prefix_len;
    let net_part = (ipv6_base >> shift_amount) << shift_amount;
    let host_part = (rand_val << prefix_len) >> prefix_len;
    Ipv6Addr::from(net_part | host_part)
}

/// Validate that an IPv6 address is within the configured subnet.
/// Handles edge case where prefix_len is 0 (any address is valid).
fn validate_subnet(ip: Ipv6Addr, base: u128, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true; // Any IP is valid when prefix is /0
    }
    if prefix_len >= 128 {
        return u128::from(ip) == base;
    }

    let ip_u128: u128 = ip.into();
    let shift_amount = 128 - prefix_len;
    let net_part_ip = (ip_u128 >> shift_amount) << shift_amount;
    let net_part_base = (base >> shift_amount) << shift_amount;
    net_part_ip == net_part_base
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
    let listener = TcpListener::bind(bind_addr).await?;
    println!("Controller listening on {bind_addr}");

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let state = state.clone();
        let username = username.clone();
        let password = password.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let state = state.clone();
                let username = username.clone();
                let password = password.clone();
                async move {
                    handle_request(req, state, ipv6_base, prefix_len, username, password).await
                }
            });

            if let Err(err) = server_http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                eprintln!("Controller connection error: {err}");
            }
        });
    }
}

async fn handle_request(
    req: Request<Incoming>,
    state: StableIpv6State,
    ipv6_base: u128,
    prefix_len: u8,
    username: String,
    password: String,
) -> Result<Response<ResponseBody>, Infallible> {
    // Check authentication using shared auth module with hyper constant
    if !auth::authenticate_authorization(&req, &username, &password) {
        return Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(
                WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"Controller\""),
            )
            .body(empty())
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
            println!("Rotated stable IPv6 to: {new_ip}");
            let response = IpResponse {
                ip: new_ip.to_string(),
            };
            Ok(json_response(StatusCode::OK, &response))
        }

        (&Method::POST, "/set") => {
            // Collect body bytes
            let body_bytes = match req.into_body().collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => {
                    let response = ErrorResponse {
                        error: "Failed to read request body".to_string(),
                    };
                    return Ok(json_response(StatusCode::BAD_REQUEST, &response));
                }
            };

            match serde_json::from_slice::<SetIpRequest>(&body_bytes) {
                Ok(set_req) => match set_req.ip.parse::<Ipv6Addr>() {
                    Ok(new_ip) => {
                        // Validate the IP is within the subnet
                        if !validate_subnet(new_ip, ipv6_base, prefix_len) {
                            let response = ErrorResponse {
                                error: "IP address is not within the configured subnet".to_string(),
                            };
                            return Ok(json_response(StatusCode::BAD_REQUEST, &response));
                        }

                        {
                            let mut ip = state.write().await;
                            *ip = new_ip;
                        }
                        println!("Set stable IPv6 to: {new_ip}");
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
                },
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

fn json_response<T: Serialize>(status: StatusCode, body: &T) -> Response<ResponseBody> {
    let json = match serde_json::to_string(body) {
        Ok(json) => json,
        Err(e) => {
            eprintln!("Failed to serialize JSON response: {e}");
            "{}".to_string()
        }
    };
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(full(json))
        .unwrap()
}
