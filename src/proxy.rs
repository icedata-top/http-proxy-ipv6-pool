use bytes::Bytes;
use http::{
    Method, Request, Response, StatusCode,
    header::{HeaderValue, PROXY_AUTHENTICATE},
};
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::{
    body::Incoming, server::conn::http1 as server_http1, service::service_fn, upgrade::Upgraded,
};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
};
use rand::Rng;
use std::{
    convert::Infallible,
    io::{Error as IoError, ErrorKind},
    net::{IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::Arc,
};
use tokio::{
    net::{TcpListener, TcpSocket},
    sync::RwLock,
};

use crate::auth;

/// Shared state for the stable IPv6 address
pub type StableIpv6State = Arc<RwLock<Ipv6Addr>>;

/// Body type alias for responses
type ResponseBody = BoxBody<Bytes, hyper::Error>;

/// Create an empty response body
fn empty() -> ResponseBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

/// Create a full response body from bytes
fn full<T: Into<Bytes>>(chunk: T) -> ResponseBody {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

pub async fn start_proxy(
    listen_addr: SocketAddr,
    (ipv6, prefix_len): (Ipv6Addr, u8),
    username: String,
    password: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(listen_addr).await?;
    println!("Random proxy listening on {listen_addr}");

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let username = username.clone();
        let password = password.clone();

        tokio::spawn(async move {
            let proxy = Proxy {
                ipv6: ipv6.into(),
                prefix_len,
                username,
                password,
            };

            let service = service_fn(move |req| {
                let proxy = proxy.clone();
                async move { proxy.proxy(req).await }
            });

            if let Err(err) = server_http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(io, service)
                .with_upgrades()
                .await
            {
                eprintln!("Connection error: {err}");
            }
        });
    }
}

#[derive(Clone)]
pub(crate) struct Proxy {
    pub ipv6: u128,
    pub prefix_len: u8,
    pub username: String,
    pub password: String,
}

impl Proxy {
    pub(crate) async fn proxy(
        self,
        req: Request<Incoming>,
    ) -> Result<Response<ResponseBody>, Infallible> {
        if !auth::authenticate_proxy_authorization(&req, &self.username, &self.password) {
            return Ok(Response::builder()
                .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                .header(
                    PROXY_AUTHENTICATE,
                    HeaderValue::from_static("Basic realm=\"Proxy\""),
                )
                .body(empty())
                .unwrap());
        }

        if req.method() == Method::CONNECT {
            self.process_connect(req).await
        } else {
            self.process_request(req).await
        }
    }

    async fn process_connect(
        self,
        req: Request<Incoming>,
    ) -> Result<Response<ResponseBody>, Infallible> {
        let remote_addr = match req.uri().authority() {
            Some(auth) => auth.to_string(),
            None => {
                eprintln!("CONNECT request missing authority");
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(full("CONNECT missing authority"))
                    .unwrap());
            }
        };

        tokio::task::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    if let Err(e) = self.tunnel(upgraded, remote_addr).await {
                        eprintln!("Tunnel error: {e}");
                    }
                }
                Err(e) => {
                    eprintln!("Upgrade error: {e}");
                }
            }
        });

        Ok(Response::new(empty()))
    }

    async fn process_request(
        self,
        req: Request<Incoming>,
    ) -> Result<Response<ResponseBody>, Infallible> {
        let bind_addr = get_rand_ipv6(self.ipv6, self.prefix_len);
        let mut http_connector = HttpConnector::new();
        http_connector.set_local_address(Some(bind_addr));
        println!("{} via {bind_addr}", req.uri().host().unwrap_or_default());

        let client: Client<HttpConnector, Incoming> = Client::builder(TokioExecutor::new())
            .http1_title_case_headers(true)
            .http1_preserve_header_case(true)
            .build(http_connector);

        match client.request(req).await {
            Ok(res) => Ok(res.map(|b| b.boxed())),
            Err(e) => {
                eprintln!("Client error: {e}");
                Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(full(format!("Proxy error: {e}")))
                    .unwrap())
            }
        }
    }

    async fn tunnel(self, upgraded: Upgraded, addr_str: String) -> std::io::Result<()> {
        let addrs = match addr_str.to_socket_addrs() {
            Ok(addrs) => addrs,
            Err(e) => {
                eprintln!("Failed to resolve {addr_str}: {e}");
                return Err(e);
            }
        };

        for addr in addrs {
            let socket = TcpSocket::new_v6()?;
            let bind_addr = get_rand_ipv6_socket_addr(self.ipv6, self.prefix_len);
            if socket.bind(bind_addr).is_ok() {
                println!("{addr_str} via {bind_addr}");
                if let Ok(mut server) = socket.connect(addr).await {
                    let mut upgraded = TokioIo::new(upgraded);
                    tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;
                    return Ok(());
                }
            }
        }

        Err(IoError::new(
            ErrorKind::ConnectionRefused,
            format!("Failed to connect to {addr_str}"),
        ))
    }
}

fn get_rand_ipv6_socket_addr(ipv6: u128, prefix_len: u8) -> SocketAddr {
    let mut rng = rand::thread_rng();
    SocketAddr::new(get_rand_ipv6(ipv6, prefix_len), rng.gen::<u16>())
}

/// Generate a random IPv6 address within the subnet.
/// Handles edge cases for prefix_len 0 and 128.
fn get_rand_ipv6(ipv6: u128, prefix_len: u8) -> IpAddr {
    if prefix_len == 0 {
        return IpAddr::V6(Ipv6Addr::from(rand::thread_rng().gen::<u128>()));
    }
    if prefix_len >= 128 {
        return IpAddr::V6(Ipv6Addr::from(ipv6));
    }

    let rand_val: u128 = rand::thread_rng().gen();
    let shift_amount = 128 - prefix_len;
    let net_part = (ipv6 >> shift_amount) << shift_amount;
    let host_part = (rand_val << prefix_len) >> prefix_len;
    IpAddr::V6(Ipv6Addr::from(net_part | host_part))
}

/// Start a stable proxy server that uses a fixed IPv6 address from shared state
pub async fn start_stable_proxy(
    listen_addr: SocketAddr,
    state: StableIpv6State,
    username: String,
    password: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(listen_addr).await?;
    println!("Stable proxy listening on {listen_addr}");

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let state = state.clone();
        let username = username.clone();
        let password = password.clone();

        tokio::spawn(async move {
            let proxy = StableProxy {
                state,
                username,
                password,
            };

            let service = service_fn(move |req| {
                let proxy = proxy.clone();
                async move { proxy.proxy(req).await }
            });

            if let Err(err) = server_http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(io, service)
                .with_upgrades()
                .await
            {
                eprintln!("[stable] Connection error: {err}");
            }
        });
    }
}

#[derive(Clone)]
struct StableProxy {
    state: StableIpv6State,
    username: String,
    password: String,
}

impl StableProxy {
    async fn proxy(self, req: Request<Incoming>) -> Result<Response<ResponseBody>, Infallible> {
        if !auth::authenticate_proxy_authorization(&req, &self.username, &self.password) {
            return Ok(Response::builder()
                .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                .header(
                    PROXY_AUTHENTICATE,
                    HeaderValue::from_static("Basic realm=\"Proxy\""),
                )
                .body(empty())
                .unwrap());
        }

        if req.method() == Method::CONNECT {
            self.process_connect(req).await
        } else {
            self.process_request(req).await
        }
    }

    async fn process_connect(
        self,
        req: Request<Incoming>,
    ) -> Result<Response<ResponseBody>, Infallible> {
        let stable_ip = *self.state.read().await;
        let remote_addr = match req.uri().authority() {
            Some(auth) => auth.to_string(),
            None => {
                eprintln!("[stable] CONNECT request missing authority");
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(full("CONNECT missing authority"))
                    .unwrap());
            }
        };

        tokio::task::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    if let Err(e) = Self::tunnel_with_ip(upgraded, remote_addr, stable_ip).await {
                        eprintln!("[stable] Tunnel error: {e}");
                    }
                }
                Err(e) => {
                    eprintln!("[stable] Upgrade error: {e}");
                }
            }
        });

        Ok(Response::new(empty()))
    }

    async fn process_request(
        self,
        req: Request<Incoming>,
    ) -> Result<Response<ResponseBody>, Infallible> {
        let stable_ip = *self.state.read().await;
        let bind_addr = IpAddr::V6(stable_ip);
        let mut http_connector = HttpConnector::new();
        http_connector.set_local_address(Some(bind_addr));
        println!(
            "[stable] {} via {bind_addr}",
            req.uri().host().unwrap_or_default()
        );

        let client: Client<HttpConnector, Incoming> = Client::builder(TokioExecutor::new())
            .http1_title_case_headers(true)
            .http1_preserve_header_case(true)
            .build(http_connector);

        match client.request(req).await {
            Ok(res) => Ok(res.map(|b| b.boxed())),
            Err(e) => {
                eprintln!("[stable] Client error: {e}");
                Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(full(format!("Proxy error: {e}")))
                    .unwrap())
            }
        }
    }

    async fn tunnel_with_ip(
        upgraded: Upgraded,
        addr_str: String,
        stable_ip: Ipv6Addr,
    ) -> std::io::Result<()> {
        let addrs = match addr_str.to_socket_addrs() {
            Ok(addrs) => addrs,
            Err(e) => {
                eprintln!("[stable] Failed to resolve {addr_str}: {e}");
                return Err(e);
            }
        };

        for addr in addrs {
            let socket = TcpSocket::new_v6()?;
            let bind_addr = SocketAddr::new(IpAddr::V6(stable_ip), rand::random::<u16>());
            if socket.bind(bind_addr).is_ok() {
                println!("[stable] {addr_str} via {bind_addr}");
                if let Ok(mut server) = socket.connect(addr).await {
                    let mut upgraded = TokioIo::new(upgraded);
                    tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;
                    return Ok(());
                }
            }
        }

        Err(IoError::new(
            ErrorKind::ConnectionRefused,
            format!("[stable] Failed to connect to {addr_str}"),
        ))
    }
}
