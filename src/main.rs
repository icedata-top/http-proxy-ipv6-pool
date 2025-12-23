use clap::Parser;
use std::net::{Ipv6Addr, SocketAddr};

mod proxy;

#[derive(Parser, Debug)]
#[command(name = "ipv6-proxy")]
struct Opt {
    /// Bind address (e.g. 127.0.0.1:6700)
    #[arg(short = 'b', long = "bind", default_value = "127.0.0.1:8080")]
    bind: SocketAddr,

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
    proxy::start_proxy(opt.bind, opt.ipv6_subnet, opt.auth.0, opt.auth.1).await
}
