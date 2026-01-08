use clap::Parser;
use std::{
    net::{Ipv6Addr, SocketAddr},
    sync::Arc,
};
use tokio::sync::RwLock;

mod auth;
mod biliproxy;
mod controller;
mod metrics;
mod proxy;

shadow_rs::shadow!(build);

#[derive(Parser, Debug)]
#[command(name = "ipv6-proxy", version = build::CLAP_LONG_VERSION, about = build::CLAP_LONG_VERSION)]
struct Opt {
    /// Bind address for random proxy (e.g. 127.0.0.1:8080)
    #[arg(short = 'b', long = "bind", default_value = "127.0.0.1:8080")]
    bind: SocketAddr,

    /// Bind address for stable proxy (optional, e.g. 127.0.0.1:8081)
    #[arg(short = 's', long = "stable-bind")]
    stable_bind: Option<SocketAddr>,

    /// Bind address for controller API (optional, e.g. 127.0.0.1:8082)
    #[arg(short = 'c', long = "controller")]
    controller: Option<SocketAddr>,

    /// IPv6 subnet in CIDR notation (e.g. 2001:19f0:6001:48e4::/64)
    #[arg(short = 'i', long = "ipv6-subnet", value_parser = parse_ipv6_cidr)]
    ipv6_subnet: (Ipv6Addr, u8),

    /// Proxy authentication in format username:password
    #[arg(short = 'a', long = "auth", value_parser = parse_auth)]
    auth: (String, String),

    /// Bind address for biliproxy (optional, e.g. 127.0.0.1:3000)
    #[arg(long = "biliproxy")]
    biliproxy: Option<SocketAddr>,

    /// Bind address for metrics server (optional, e.g. 127.0.0.1:9090)
    #[arg(short = 'm', long = "metrics")]
    metrics: Option<SocketAddr>,
}

fn parse_ipv6_cidr(s: &str) -> Result<(Ipv6Addr, u8), String> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return Err("Invalid CIDR format. Expected format: 2001:db8::/64".into());
    }

    let addr = parts[0].parse::<Ipv6Addr>().map_err(|e| e.to_string())?;
    let prefix_len = parts[1].parse::<u8>().map_err(|e| e.to_string())?;

    if prefix_len > 128 {
        return Err("Prefix length must be between 0 and 128".into());
    }

    Ok((addr, prefix_len))
}

fn parse_auth(s: &str) -> Result<(String, String), String> {
    // Use splitn(2, ':') to allow colons in password
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err("Invalid auth format. Expected format: username:password".into());
    }

    let username = parts[0];
    let password = parts[1];

    // Validate that username and password are not empty
    if username.is_empty() {
        return Err("Username cannot be empty".into());
    }
    if password.is_empty() {
        return Err("Password cannot be empty".into());
    }

    Ok((username.to_string(), password.to_string()))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::parse();

    let (ipv6, prefix_len) = opt.ipv6_subnet;
    let ipv6_base: u128 = ipv6.into();
    let username = opt.auth.0;
    let password = opt.auth.1;

    // Only initialize stable state if stable proxy or controller is enabled
    let stable_state: Option<proxy::StableIpv6State> =
        if opt.stable_bind.is_some() || opt.controller.is_some() {
            let initial_ip = controller::generate_random_ipv6(ipv6_base, prefix_len);
            println!("Initial stable IPv6: {initial_ip}");
            Some(Arc::new(RwLock::new(initial_ip)))
        } else {
            None
        };

    // Start random proxy (always)
    let random_proxy = {
        let username = username.clone();
        let password = password.clone();
        async move {
            proxy::start_proxy(opt.bind, (ipv6, prefix_len), username, password)
                .await
                .map_err(|e| e.to_string())
        }
    };

    // Start stable proxy (optional)
    let stable_proxy = {
        let state = stable_state.clone();
        let username = username.clone();
        let password = password.clone();
        async move {
            if let (Some(stable_addr), Some(state)) = (opt.stable_bind, state) {
                proxy::start_stable_proxy(stable_addr, state, username, password)
                    .await
                    .map_err(|e| e.to_string())
            } else {
                Ok(())
            }
        }
    };

    // Start controller (optional)
    let controller_server = {
        let state = stable_state;
        let username = username.clone();
        let password = password.clone();
        async move {
            if let (Some(controller_addr), Some(state)) = (opt.controller, state) {
                controller::start_controller(
                    controller_addr,
                    state,
                    ipv6_base,
                    prefix_len,
                    username,
                    password,
                )
                .await
                .map_err(|e| e.to_string())
            } else {
                Ok(())
            }
        }
    };

    // Start biliproxy (optional)
    let biliproxy_server = {
        let biliproxy_addr = opt.biliproxy;
        async move {
            if let Some(addr) = biliproxy_addr {
                biliproxy::start_biliproxy(addr, ipv6, prefix_len)
                    .await
                    .map_err(|e| e.to_string())
            } else {
                Ok(())
            }
        }
    };

    // Start metrics server (optional)
    let metrics_server = {
        let metrics_addr = opt.metrics;
        async move {
            if let Some(addr) = metrics_addr {
                metrics::start_metrics_server(addr)
                    .await
                    .map_err(|e| e.to_string())
            } else {
                Ok(())
            }
        }
    };

    // Run all services concurrently - use try_join for better error handling
    // This will return immediately when any service fails
    tokio::try_join!(
        random_proxy,
        stable_proxy,
        controller_server,
        biliproxy_server,
        metrics_server
    )?;

    Ok(())
}
