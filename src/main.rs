use std::net::{Ipv6Addr, SocketAddr};
use structopt::StructOpt;

mod proxy;

#[derive(StructOpt, Debug)]
#[structopt(name = "ipv6-proxy")]
struct Opt {
    /// Bind address (e.g. 127.0.0.1:6700)
    #[structopt(short = "b", long = "bind", default_value = "127.0.0.1:8080")]
    bind: SocketAddr,

    /// IPv6 subnet in CIDR notation (e.g. 2001:19f0:6001:48e4::/64)
    #[structopt(short = "i", long = "ipv6-subnet", parse(try_from_str = parse_ipv6_cidr))]
    ipv6_subnet: (Ipv6Addr, u8),

    /// Proxy authentication in format username:password
    #[structopt(short = "a", long = "auth", parse(try_from_str = parse_auth))]
    auth: (String, String),

    /// Enable reverse proxy mode
    #[structopt(short = "r", long = "reverse-proxy")]
    reverse_proxy: bool,

    /// Target server for reverse proxy (e.g. https://ipv6.ip.sb)
    #[structopt(short = "t", long = "target")]
    target: Option<String>,
}

fn parse_ipv6_cidr(s: &str) -> Result<(Ipv6Addr, u8), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return Err("Invalid CIDR format. Expected format: 2001:db8::/64".into());
    }

    let addr = parts[0].parse::<Ipv6Addr>()?;
    let prefix_len = parts[1].parse::<u8>()?;

    if prefix_len > 128 {
        return Err("Prefix length must be between 0 and 128".into());
    }

    Ok((addr, prefix_len))
}

fn parse_auth(s: &str) -> Result<(String, String), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return Err("Invalid auth format. Expected format: username:password".into());
    }

    Ok((parts[0].to_string(), parts[1].to_string()))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::from_args();

    // Validate reverse proxy options
    if opt.reverse_proxy && opt.target.is_none() {
        return Err("Target server is required when using reverse proxy mode. Use --target to specify the server.".into());
    }

    proxy::start_proxy(
        opt.bind,
        opt.ipv6_subnet,
        opt.auth.0,
        opt.auth.1,
        opt.reverse_proxy,
        opt.target,
    )
    .await
}
