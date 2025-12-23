use clap::Parser;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::RwLock;

mod controller;
mod proxy;

#[derive(Parser, Debug)]
#[command(name = "ipv6-proxy")]
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
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return Err("Invalid auth format. Expected format: username:password".into());
    }

    Ok((parts[0].to_string(), parts[1].to_string()))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::parse();

    let (ipv6, prefix_len) = opt.ipv6_subnet;
    let ipv6_base: u128 = ipv6.into();
    let username = opt.auth.0;
    let password = opt.auth.1;

    // Generate initial stable IPv6 address
    let initial_ip = controller::generate_random_ipv6(ipv6_base, prefix_len);
    let stable_state: proxy::StableIpv6State = Arc::new(RwLock::new(initial_ip));
    println!("Initial stable IPv6: {}", initial_ip);

    // Start random proxy (always)
    let random_proxy = {
        let username = username.clone();
        let password = password.clone();
        async move {
            println!("Random proxy listening on {}", opt.bind);
            proxy::start_proxy(opt.bind, (ipv6, prefix_len), username, password)
                .await
                .map_err(|e| format!("Random proxy error: {}", e))
        }
    };

    // Start stable proxy (optional)
    let stable_proxy = async {
        if let Some(stable_addr) = opt.stable_bind {
            let state = stable_state.clone();
            proxy::start_stable_proxy(stable_addr, state, username.clone(), password.clone())
                .await
                .map_err(|e| format!("Stable proxy error: {}", e))
        } else {
            Ok(())
        }
    };

    // Start controller (optional)
    let controller_server = async {
        if let Some(controller_addr) = opt.controller {
            let state = stable_state.clone();
            controller::start_controller(
                controller_addr,
                state,
                ipv6_base,
                prefix_len,
                username.clone(),
                password.clone(),
            )
            .await
            .map_err(|e| format!("Controller error: {}", e))
        } else {
            Ok(())
        }
    };

    // Run all services concurrently
    let (r1, r2, r3) = tokio::join!(random_proxy, stable_proxy, controller_server);
    r1?;
    r2?;
    r3?;

    Ok(())
}
