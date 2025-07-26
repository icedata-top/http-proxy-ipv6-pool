use base64::Engine;
use hyper::{
    Body, Client, Method, Request, Response, Server, StatusCode,
    client::HttpConnector,
    header::{HeaderValue, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION},
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
};
use rand::Rng;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpSocket,
};

pub async fn start_proxy(
    listen_addr: SocketAddr,
    (ipv6, prefix_len): (Ipv6Addr, u8),
    username: String,
    password: String,
    reverse_proxy: bool,
    target: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let make_service = make_service_fn(move |_: &AddrStream| {
        let username = username.clone();
        let password = password.clone();
        let target = target.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                let proxy = Proxy {
                    ipv6: ipv6.into(),
                    prefix_len,
                    username: username.clone(),
                    password: password.clone(),
                    reverse_proxy,
                    target: target.clone(),
                };
                proxy.proxy(req)
            }))
        }
    });

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
    pub reverse_proxy: bool,
    pub target: Option<String>,
}

impl Proxy {
    pub(crate) async fn proxy(self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        // In reverse proxy mode, we don't require authentication from clients
        // as we're acting as a reverse proxy to a backend server
        if !self.reverse_proxy && !self.authenticate(&req) {
            return Ok(Response::builder()
                .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                .header(
                    PROXY_AUTHENTICATE,
                    HeaderValue::from_static("Basic realm=\"Proxy\""),
                )
                .body(Body::empty())
                .unwrap());
        }

        if self.reverse_proxy {
            // In reverse proxy mode, forward all requests to the target server
            self.process_reverse_proxy_request(req).await
        } else {
            // Original forward proxy behavior
            match if req.method() == Method::CONNECT {
                self.process_connect(req).await
            } else {
                self.process_request(req).await
            } {
                Ok(resp) => Ok(resp),
                Err(e) => Err(e),
            }
        }
    }

    fn authenticate(&self, req: &Request<Body>) -> bool {
        if let Some(auth_header) = req.headers().get(PROXY_AUTHORIZATION) {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str.starts_with("Basic ") {
                    let credentials = auth_str.trim_start_matches("Basic ");
                    if let Ok(decoded) =
                        base64::engine::general_purpose::STANDARD.decode(credentials)
                    {
                        if let Ok(auth_string) = String::from_utf8(decoded) {
                            let parts: Vec<&str> = auth_string.splitn(2, ':').collect();
                            if parts.len() == 2 {
                                return parts[0] == self.username && parts[1] == self.password;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    async fn process_connect(self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        tokio::task::spawn(async move {
            let remote_addr = req.uri().authority().map(|auth| auth.to_string()).unwrap();
            let mut upgraded = hyper::upgrade::on(req).await.unwrap();
            self.tunnel(&mut upgraded, remote_addr).await
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

    async fn process_reverse_proxy_request(
        self,
        mut req: Request<Body>,
    ) -> Result<Response<Body>, hyper::Error> {
        let target_url = self.target.as_ref().unwrap();
        let bind_addr = get_rand_ipv6(self.ipv6, self.prefix_len);

        // Parse the target URL to extract scheme, host, and port
        let target_uri = match target_url.parse::<hyper::Uri>() {
            Ok(uri) => uri,
            Err(e) => {
                eprintln!("Invalid target URL: {e}");
                return Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::from("Invalid target URL configured"))
                    .unwrap());
            }
        };

        // Build new URI by combining target host with request path
        let new_uri = {
            let mut parts = req.uri().clone().into_parts();
            parts.scheme = target_uri.scheme().cloned();
            parts.authority = target_uri.authority().cloned();

            // If the original request doesn't have a path, use the target's path
            if parts.path_and_query.is_none()
                || parts.path_and_query.as_ref().unwrap().path() == "/"
            {
                if let Some(target_path) = target_uri.path_and_query() {
                    parts.path_and_query = Some(target_path.clone());
                }
            }

            match hyper::Uri::from_parts(parts) {
                Ok(uri) => uri,
                Err(e) => {
                    eprintln!("Failed to construct target URI: {e}");
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Body::from("Failed to construct target URI"))
                        .unwrap());
                }
            }
        };

        // Update the request URI
        *req.uri_mut() = new_uri;

        // Remove proxy-specific headers that shouldn't be forwarded
        req.headers_mut().remove(PROXY_AUTHORIZATION);
        req.headers_mut().remove("proxy-connection");

        let mut http = HttpConnector::new();
        http.set_local_address(Some(bind_addr));

        println!(
            "Reverse proxy: {} via {bind_addr} -> {target_url}",
            req.uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/")
        );

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
        if let Ok(addrs) = addr_str.to_socket_addrs() {
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
        } else {
            println!("error: {addr_str}");
        }

        Ok(())
    }
}

fn get_rand_ipv6_socket_addr(ipv6: u128, prefix_len: u8) -> SocketAddr {
    let mut rng = rand::thread_rng();
    SocketAddr::new(get_rand_ipv6(ipv6, prefix_len), rng.gen::<u16>())
}

fn get_rand_ipv6(mut ipv6: u128, prefix_len: u8) -> IpAddr {
    let rand: u128 = rand::thread_rng().gen();
    let net_part = (ipv6 >> (128 - prefix_len)) << (128 - prefix_len);
    let host_part = (rand << prefix_len) >> prefix_len;
    ipv6 = net_part | host_part;
    IpAddr::V6(ipv6.into())
}
