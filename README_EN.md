# SuperYellow Proxy

> **Multi TCP Stream Parallel Multiplexing + Adaptive Forward Error Correction — Next-Gen Proxy Protocol**

[中文版](README.md)

---

## Downloads

| Platform | File | Size |
|----------|------|------|
| Windows x64 | [superyellow-windows-amd64.exe](../../releases/download/v1.2.0/superyellow-windows-amd64.exe) | 13 MB |
| Android | [SuperYellow-Proxy-v1.0.apk](../../releases/download/v1.2.0/SuperYellow-Proxy-v1.0.apk) | 20 MB |
| iStoreOS/OpenWrt x64 | [SuperYellow_Client_v1.2.1_x86_64.run](../../releases/download/v1.2.0/SuperYellow_Client_v1.2.1_x86_64.run) | 6.5 MB |

---

## Features

1. **Multi TCP Stream Parallel Multiplexing** — 6 parallel TCP streams with independent FEC shards
2. **Adaptive Forward Error Correction** — Dynamic FEC parameters based on RTT and packet loss
3. **uTLS Fingerprint Camouflage** — Chrome TLS fingerprint (HelloChrome_Auto)
4. **Random Padding** — 64-byte aligned frames
5. **REALITY-Level SNI Disguise** — Returns real microsoft.com certificate in Camo mode
6. **VLESS Protocol Passthrough** — Compatible with PassWall, v2rayN, Clash
7. **SHA-256 Timestamp Authorization** — 15-second validity, anti-replay
8. **Mux.cool Multiplexing** — Source-level xray Mux (CMD=3) support
9. **Web Management Panel** — Server panel (port 8080), client panel (port 8899/9999)
10. **Multi-User Support** — Quotas, passwords, traffic limits, expiry dates

---

## Stability Architecture

- **Single-Stream Silent Healing** — Failed streams are closed individually; `monitorHealth` rebuilds them every 2 seconds
- **Zombie Session Cleanup** — Dead sessions are periodically garbage-collected
- **TCP Backpressure Control** — 3s write timeout, 64 concurrent write limit
- **nftables Loop Prevention** — Server IP bypasses PassWall via `psw_vps` set

---

## Quick Start

### Server (Ubuntu/Debian)

```bash
wget https://raw.githubusercontent.com/roger19981223-dotcom/superyellow-proxy/main/install.sh
chmod +x install.sh
sudo ./install.sh server
```

### Client — iStoreOS/OpenWrt Plugin

```bash
scp SuperYellow_Client_v1.2.1_x86_64.run root@ROUTER_IP:/tmp/
ssh root@ROUTER_IP
sh /tmp/SuperYellow_Client_v1.2.1_x86_64.run
vi /etc/config/superyellow_client.json
/etc/init.d/superyellow restart
```

Web panel: `http://ROUTER_IP:8899` | LuCI: Services -> SuperYellow Proxy

### Client — Windows

Run `superyellow-windows-amd64.exe`, open `http://localhost:9999`

### Client — Android

Install `SuperYellow-Proxy-v1.0.apk`, configure in app.

---

## Configuration

### Client (superyellow_client.json)

```json
{
  "enable": true,
  "active_node_id": "n_main",
  "nodes": [{
    "id": "n_main",
    "name": "My Server",
    "server": "YOUR_SERVER_IP:8443",
    "username": "YOUR_USERNAME",
    "password": "YOUR_PASSWORD",
    "sni": "YOUR_DOMAIN"
  }]
}
```

> **Important:** If the server has `domain` configured, the client's `sni` must match.

### Server (aether_config.json)

```json
{
  "panel_port": 8080,
  "listen_ports": "8443",
  "domain": "",
  "camo_mode": "proxy",
  "camo_target": "www.microsoft.com:443",
  "panel_user": "admin",
  "panel_pass": "your-strong-password",
  "users": [
    {"username": "Default", "password": "your-password"}
  ]
}
```

---

## PassWall Integration

Add Xray node: Protocol VLESS, Address 127.0.0.1, Port 11081, Transport TCP, Encryption none.

Server IP is auto-added to `psw_vps` nftables set for PassWall bypass.

---

## Protocol Parameters

| Parameter | Value |
|-----------|-------|
| Parallel streams | 6 |
| TLS version | TLS 1.3 only |
| ALPN | h2, http/1.1 |
| Frame magic | 0x41455448 ("AETH") |
| FEC library | github.com/klauspost/reedsolomon |
| TLS fingerprint | uTLS Chrome_Auto |
| Auth algorithm | SHA-256(SHA-256(user:pass) + timestamp_ms) |
| Token validity | 15 seconds |
| Target dial timeout | 30 seconds |
| Client ACK wait | 35 seconds |
| Write timeout | 3 seconds |
| Max concurrent writes | 64 |
| Read buffer cap | 32768 bytes |

---

## License

MIT License
