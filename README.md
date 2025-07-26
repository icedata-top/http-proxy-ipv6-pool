# Http Proxy IPv6 Pool

A HTTP proxy that makes every request from a random IPv6 address, with Proxy Authentication. Now supports both forward proxy and reverse proxy modes.

## Why?

- You want a ton of IPv6 addresses for proxy, and
- You want to expose this service to local containers so listening on `0.0.0.0` is required but are afraid of exposing the proxy directly on the Internet. And you not want to use the `host` network mode.

## Modes

### Forward Proxy Mode (Original)
- Acts as a traditional HTTP proxy
- Clients connect with proxy authentication
- Each client request uses a different IPv6 address
- Supports CONNECT method for HTTPS tunneling

### Reverse Proxy Mode (New)
- Acts as a reverse proxy to a specific target server
- No client authentication required
- All incoming requests are forwarded to the target server
- Each forwarded request uses a different IPv6 address
- Perfect for load balancing or anonymizing requests to a single service

## Tutorial - Routing Setup

Assuming you already have an entire IPv6 subnet routed to your server. Or, use HE.net's Tunnelbroker to get a /64 or /48.

A example of netplan for Tunnelbroker: `/etc/netplan/99-he-tunnel.yaml`

```yaml
network:
  version: 2
  tunnels:
    he-ipv6:
      mode: sit
      remote: 209.51.161.14 <--- HE's NY4 server 
      local: 192.3.187.235 <--- Your outbound IPv4 address
      addresses:
        - "2001:470:a::/48"
      routes:
        - to: default
          via: "2001:470:a::1" <--- Should match your /48 or /64

```

Get your IPv6 subnet prefix and interface name, for me is `2001:470:a::/48` and `eth0`.

```sh
$ ip a
......
2: eth0: <BROADCAST,MULTICAST,ALLMULTI,UP,LOWER_UP> mtu 1500 qdisc fq state UP group default qlen 1000
    ...
    inet6 fe80::216:3eff:fe7e:d3dd/64 scope link 
       valid_lft forever preferred_lft forever
```

Add route via default internet interface

```sh
ip route add 2001:470:a::/48 dev eth0
```

Open `ip_nonlocal_bind` for binding any IP address:

```sh
sysctl net.ipv6.ip_nonlocal_bind=1
```

To further optimize performance: `vim /etc/sysctl.conf`

```sh
fs.inotify.max_user_watches = 524288
net.ipv6.conf.all.proxy_ndp=1
net.ipv6.conf.default.forwarding=1
net.ipv6.conf.all.forwarding=1
net.ipv6.ip_nonlocal_bind=1
net.ipv4.ip_local_port_range=1024 64000
net.ipv6.route.max_size=409600
net.ipv4.tcp_max_syn_backlog=4096
net.ipv6.neigh.default.gc_thresh3=102400
kernel.threads-max=1200000
vm.max_map_count=6000000
kernel.pid_max=2000000
net.core.default_qdisc = cake
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
```

Then

```sh
sysctl -p
```

For IPv6 NDP, install `ndppd`:

```sh
apt install ndppd
```

then edit `/etc/ndppd.conf`:


```conf
route-ttl 30000

proxy eth0 {
    router no
    timeout 500
    ttl 30000

    rule 2001:470:a::/48 {
        static
    }
}
```
(edit the file to match your configuration)

Restart the service:
```sh
service ndppd restart
```


Now you can test by using `curl`:

```sh
$ curl --interface 2001:19f0:6001:48e4::1 ipv6.ip.sb
2001:19f0:6001:48e4::1

$ curl --interface 2001:19f0:6001:48e4::2 ipv6.ip.sb
2001:19f0:6001:48e4::2
```

Great!

## Usage

### Forward Proxy Mode (Original)

```sh
http-proxy-ipv6-pool --listen 0.0.0.0:51080 --ipv6 2001:a:a:: --prefix-len 48  --username admin --password 123456
```

To test it out:

```sh
$ while true; do curl -x http://admin:123456@127.0.0.1:51080 ipv6.ip.sb; done
2001:19f0:6001:48e4:971e:f12c:e2e7:d92a
2001:19f0:6001:48e4:6d1c:90fe:ee79:1123
2001:19f0:6001:48e4:f7b9:b506:99d7:1be9
2001:19f0:6001:48e4:a06a:393b:e82f:bffc
2001:19f0:6001:48e4:245f:8272:2dfb:72ce
2001:19f0:6001:48e4:df9e:422c:f804:94f7
2001:19f0:6001:48e4:dd48:6ba2:ff76:f1af
2001:19f0:6001:48e4:1306:4a84:570c:f829
2001:19f0:6001:48e4:6f3:4eb:c958:ddfa
2001:19f0:6001:48e4:aa26:3bf9:6598:9e82
2001:19f0:6001:48e4:be6b:6a62:f8f7:a14d
2001:19f0:6001:48e4:b598:409d:b946:17c
```

### Reverse Proxy Mode (New)

Use the reverse proxy mode to forward all incoming requests to a target server, with each request originating from a different IPv6 address:

```sh
http-proxy-ipv6-pool --bind 0.0.0.0:8080 --ipv6-subnet 2001:a:a::/48 --auth admin:123456 --reverse-proxy --target https://ipv6.ip.sb
```

To test the reverse proxy:

```sh
$ curl http://127.0.0.1:8080/
2001:19f0:6001:48e4:a1b2:c3d4:e5f6:7890

$ curl http://127.0.0.1:8080/
2001:19f0:6001:48e4:1a2b:3c4d:5e6f:7890
```

In reverse proxy mode:
- Each request to your proxy will be forwarded to the target server
- Each request uses a different random IPv6 address from your pool
- No proxy authentication is required from clients (the proxy acts transparently)
- All HTTP methods and paths are supported

### Register as service

Copy the binary to `/usr/local/bin/http-proxy-ipv6-pool`;

**For Forward Proxy Mode:**

In file `/etc/systemd/system/http-proxy-ipv6-pool.service` -

```
[Unit]
Description=HTTP Proxy IPv6 Pool Service
After=network.target

[Service]
Environment="PROXY_ARGS=--listen 0.0.0.0:51080 --ipv6 2001:a:a:: --prefix-len 48  --username admin --password 123456"
ExecStart=/usr/local/bin/http-proxy-ipv6-pool $PROXY_ARGS
Restart=on-failure
User=nobody
Group=nogroup

[Install]
WantedBy=multi-user.target
```

**For Reverse Proxy Mode:**

In file `/etc/systemd/system/http-proxy-ipv6-pool.service` -

```
[Unit]
Description=HTTP Proxy IPv6 Pool Service (Reverse Proxy)
After=network.target

[Service]
Environment="PROXY_ARGS=--bind 0.0.0.0:8080 --ipv6-subnet 2001:a:a::/48 --auth admin:123456 --reverse-proxy --target https://ipv6.ip.sb"
ExecStart=/usr/local/bin/http-proxy-ipv6-pool $PROXY_ARGS
Restart=on-failure
User=nobody
Group=nogroup

[Install]
WantedBy=multi-user.target
```

Then `systemctl daemon-reload; systemctl start http-proxy-ipv6-pool.service`.

## Author

**Http Proxy IPv6 Pool** © [zu1k](https://github.com/zu1k) and [Beining](https://github.com/cnbeining) and [Ovler](https://github.com/Ovler-Young), Released under the [MIT](./LICENSE) License.
