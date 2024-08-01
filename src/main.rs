use std::net::{Ipv6Addr, SocketAddr};
use structopt::StructOpt;

mod proxy;

#[derive(StructOpt, Debug)]
#[structopt(name = "ipv6-proxy")]
struct Opt {
    #[structopt(short, long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
    #[structopt(short, long)]
    ipv6: Ipv6Addr,
    #[structopt(short, long)]
    prefix_len: u8,
    #[structopt(short, long)]
    username: String,
    #[structopt(short, long)]
    password: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::from_args();
    proxy::start_proxy(opt.listen, (opt.ipv6, opt.prefix_len), opt.username, opt.password).await
}
