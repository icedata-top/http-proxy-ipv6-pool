use hyper::{
    Body, Client, Method, Request, Response, Server, StatusCode,
    client::HttpConnector,
    header::{HeaderValue, PROXY_AUTHENTICATE},
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
};
use rand::Rng;
use std::{
    io::{Error as IoError, ErrorKind},
    net::{IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::Arc,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpSocket,
    sync::RwLock,
};

use crate::auth;

/// Shared state for the stable IPv6 address
pub type StableIpv6State = Arc<RwLock<Ipv6Addr>>;

pub async fn start_proxy(
    listen_addr: SocketAddr,
    (ipv6, prefix_len): (Ipv6Addr, u8),
    username: String,
    password: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let make_service = make_service_fn(move |_: &AddrStream| {
        let username = username.clone();
        let password = password.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                let proxy = Proxy {
                    ipv6: ipv6.into(),
                    prefix_len,
                    username: username.clone(),
                    password: password.clone(),
                };
                proxy.proxy(req)
            }))
        }
    });

    println!("Random proxy listening on {listen_addr}");
    Server::bind(&listen_addr)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve(make_service)
        .await
        .map_err(|err| err.into())
}

#[derive(Clone)]
pub(crate) struct Proxy {
    pub ipv6: u128,
    pub prefix_len: u8,
    pub username: String,
    pub password: String,
}

impl Proxy {
    pub(crate) async fn proxy(self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        // Use hyper constant via shared auth module
        if !auth::authenticate_proxy_authorization(&req, &self.username, &self.password) {
            return Ok(Response::builder()
                .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                .header(
                    PROXY_AUTHENTICATE,
                    HeaderValue::from_static("Basic realm=\"Proxy\""),
                )
                .body(Body::empty())
                .unwrap());
        }

        if req.method() == Method::CONNECT {
            self.process_connect(req).await
        } else {
            self.process_request(req).await
        }
    }

    async fn process_connect(self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        tokio::task::spawn(async move {
            let remote_addr = match req.uri().authority() {
                Some(auth) => auth.to_string(),
                None => {
                    eprintln!("CONNECT request missing authority");
                    return;
                }
            };
            match hyper::upgrade::on(req).await {
                Ok(mut upgraded) => {
                    if let Err(e) = self.tunnel(&mut upgraded, remote_addr).await {
                        eprintln!("Tunnel error: {e}");
                    }
                }
                Err(e) => {
                    eprintln!("Upgrade error: {e}");
                }
            }
        });
        Ok(Response::new(Body::empty()))
    }

    async fn process_request(self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        let bind_addr = get_rand_ipv6(self.ipv6, self.prefix_len);
        let mut http = HttpConnector::new();
        http.set_local_address(Some(bind_addr));
        println!("{} via {bind_addr}", req.uri().host().unwrap_or_default());

        let client = Client::builder()
            .http1_title_case_headers(true)
            .http1_preserve_header_case(true)
            .build(http);
        let res = client.request(req).await?;
        Ok(res)
    }

    async fn tunnel<A>(self, upgraded: &mut A, addr_str: String) -> std::io::Result<()>
    where
        A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    {
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
                    tokio::io::copy_bidirectional(upgraded, &mut server).await?;
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
    let make_service = make_service_fn(move |_: &AddrStream| {
        let state = state.clone();
        let username = username.clone();
        let password = password.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                let proxy = StableProxy {
                    state: state.clone(),
                    username: username.clone(),
                    password: password.clone(),
                };
                proxy.proxy(req)
            }))
        }
    });

    println!("Stable proxy listening on {listen_addr}");
    Server::bind(&listen_addr)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve(make_service)
        .await
        .map_err(|e| e.into())
}

#[derive(Clone)]
struct StableProxy {
    state: StableIpv6State,
    username: String,
    password: String,
}

impl StableProxy {
    async fn proxy(self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        // Use hyper constant via shared auth module
        if !auth::authenticate_proxy_authorization(&req, &self.username, &self.password) {
            return Ok(Response::builder()
                .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                .header(
                    PROXY_AUTHENTICATE,
                    HeaderValue::from_static("Basic realm=\"Proxy\""),
                )
                .body(Body::empty())
                .unwrap());
        }

        if req.method() == Method::CONNECT {
            self.process_connect(req).await
        } else {
            self.process_request(req).await
        }
    }

    async fn process_connect(self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        let stable_ip = *self.state.read().await;
        tokio::task::spawn(async move {
            let remote_addr = match req.uri().authority() {
                Some(auth) => auth.to_string(),
                None => {
                    eprintln!("[stable] CONNECT request missing authority");
                    return;
                }
            };
            match hyper::upgrade::on(req).await {
                Ok(mut upgraded) => {
                    if let Err(e) =
                        Self::tunnel_with_ip(&mut upgraded, remote_addr, stable_ip).await
                    {
                        eprintln!("[stable] Tunnel error: {e}");
                    }
                }
                Err(e) => {
                    eprintln!("[stable] Upgrade error: {e}");
                }
            }
        });
        Ok(Response::new(Body::empty()))
    }

    async fn process_request(self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        let stable_ip = *self.state.read().await;
        let bind_addr = IpAddr::V6(stable_ip);
        let mut http = HttpConnector::new();
        http.set_local_address(Some(bind_addr));
        println!(
            "[stable] {} via {bind_addr}",
            req.uri().host().unwrap_or_default()
        );

        let client = Client::builder()
            .http1_title_case_headers(true)
            .http1_preserve_header_case(true)
            .build(http);
        let res = client.request(req).await?;
        Ok(res)
    }

    async fn tunnel_with_ip<A>(
        upgraded: &mut A,
        addr_str: String,
        stable_ip: Ipv6Addr,
    ) -> std::io::Result<()>
    where
        A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    {
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
                    tokio::io::copy_bidirectional(upgraded, &mut server).await?;
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
