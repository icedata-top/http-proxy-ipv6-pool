use super::utils::random_user_agent;
use parking_lot::RwLock;
use rand::Rng;
use std::{
    net::{IpAddr, Ipv6Addr},
    time::Duration,
};

/// IPv6 pool size (number of pre-generated clients)
pub const IPV6_POOL_SIZE: usize = 16;

/// Default timeout for upstream requests (30 seconds)
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Generate a random IPv6 address within the given subnet.
pub fn generate_random_ipv6(ipv6_base: u128, prefix_len: u8) -> Ipv6Addr {
    if prefix_len == 0 {
        return Ipv6Addr::from(rand::thread_rng().gen::<u128>());
    }
    if prefix_len >= 128 {
        return Ipv6Addr::from(ipv6_base);
    }

    let rand_val: u128 = rand::thread_rng().gen();
    let shift_amount = 128 - prefix_len;
    let net_part = (ipv6_base >> shift_amount) << shift_amount;
    let host_part = (rand_val << prefix_len) >> prefix_len;
    Ipv6Addr::from(net_part | host_part)
}

/// IPv6 client pool for load distribution and 412 avoidance
/// Each client has a fixed User-Agent for more realistic behavior
pub struct Ipv6Pool {
    /// Each entry is (reqwest::Client, fixed User-Agent)
    clients: RwLock<Vec<(reqwest::Client, String)>>,
    /// Config for creating new clients during rotation
    ipv6_base: u128,
    prefix_len: u8,
    timeout: Duration,
}

impl Ipv6Pool {
    pub fn new(ipv6_base: u128, prefix_len: u8, timeout: Duration) -> Self {
        println!("Initializing IPv6 pool with {IPV6_POOL_SIZE} addresses...");
        let clients: Vec<_> = (0..IPV6_POOL_SIZE)
            .map(|i| {
                let ip = generate_random_ipv6(ipv6_base, prefix_len);
                let ua = random_user_agent();
                if i == 0 {
                    println!("  First pool IP: {ip}");
                }
                let client = reqwest::Client::builder()
                    .local_address(IpAddr::V6(ip))
                    .timeout(timeout)
                    .build()
                    .expect("Failed to create client");
                (client, ua)
            })
            .collect();
        println!("IPv6 pool initialized with {} clients", clients.len());
        Self {
            clients: RwLock::new(clients),
            ipv6_base,
            prefix_len,
            timeout,
        }
    }

    /// Get a random client with its fixed User-Agent and index (returns cloned values)
    pub fn get_random_client(&self) -> (reqwest::Client, String, usize) {
        let clients = self.clients.read();
        let idx = rand::thread_rng().gen_range(0..clients.len());
        (clients[idx].0.clone(), clients[idx].1.clone(), idx)
    }

    /// Get the client at a specific index (returns cloned values)
    pub fn get_client_by_index(&self, index: usize) -> (reqwest::Client, String) {
        let clients = self.clients.read();
        (clients[index].0.clone(), clients[index].1.clone())
    }

    /// Force rotate the client at the specified index (used when a request fails)
    /// Returns the new (client, user_agent) pair
    pub fn force_rotate(&self, index: usize) -> (reqwest::Client, String) {
        let ip = generate_random_ipv6(self.ipv6_base, self.prefix_len);
        let ua = random_user_agent();
        let client = reqwest::Client::builder()
            .local_address(IpAddr::V6(ip))
            .timeout(self.timeout)
            .build()
            .expect("Failed to create client");

        let mut clients = self.clients.write();
        clients[index] = (client.clone(), ua.clone());
        println!("🔄 Force rotated slot {index} to new IP: {ip}");
        (client, ua)
    }

    /// 1/128 chance to rotate a random client
    pub fn maybe_rotate(&self) {
        if rand::thread_rng().gen_range(0..128) == 0 {
            let ip = generate_random_ipv6(self.ipv6_base, self.prefix_len);
            let ua = random_user_agent();
            let client = reqwest::Client::builder()
                .local_address(IpAddr::V6(ip))
                .timeout(self.timeout)
                .build()
                .expect("Failed to create client");

            let mut clients = self.clients.write();
            let idx = rand::thread_rng().gen_range(0..clients.len());
            clients[idx] = (client, ua);
            println!("🔄 Rotated pool slot {idx} to new IP: {ip}");
        }
    }

    /// Create a one-time random client (not from the pool).
    /// Used for WBI-signed requests to avoid pool pollution.
    pub fn create_random_client(&self) -> (reqwest::Client, String) {
        let ip = generate_random_ipv6(self.ipv6_base, self.prefix_len);
        let ua = random_user_agent();
        let client = reqwest::Client::builder()
            .local_address(IpAddr::V6(ip))
            .timeout(self.timeout)
            .build()
            .expect("Failed to create client");
        println!("🎲 Created one-time random client: {ip}");
        (client, ua)
    }
}
