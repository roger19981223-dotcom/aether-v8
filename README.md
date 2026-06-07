# SuperYellow Proxy

> **多 TCP 流并行复用 + 自适应前向纠错 — 下一代代理协议**

SuperYellow 是一个高性能、抗封锁的代理协议，专为恶劣网络环境设计。通过多 TCP 流并行复用、自适应前向纠错、uTLS 指纹伪装、REALITY 级 SNI 伪装等技术，实现高速、低延迟、抗审查的代理体验。

English version: [README_EN.md](README_EN.md)

---

## 下载

| 平台 | 文件 | 大小 |
|------|------|------|
| Windows x64 | [superyellow-windows-amd64.exe](../../releases/download/v1.2.0/superyellow-windows-amd64.exe) | 13 MB |
| Android | [SuperYellow-Proxy-v1.0.apk](../../releases/download/v1.2.0/SuperYellow-Proxy-v1.0.apk) | 20 MB |
| iStoreOS/OpenWrt x64 | [SuperYellow_Client_v1.2.1_x86_64.run](../../releases/download/v1.2.0/SuperYellow_Client_v1.2.1_x86_64.run) | 6.5 MB |

下载对应平台的客户端，在 Web 面板中配置服务器信息即可使用。

---

## 协议特性

### 1. 多 TCP 流并行复用

SuperYellow 在服务器和客户端之间建立 **6 条并行 TCP 流**（NumStreams = 6），每条流独立携带 FEC 校验片，**单条流故障不影响整体传输**。

| 特性 | SuperYellow | 传统代理方式 |
|------|-------------|-------------|
| 包头开销 | 无，原生 TCP | 有 |
| 单流故障影响 | 无影响 | 整体重连 |
| 弱网下吞吐量 | 高 | 急剧下降 |

### 2. 自适应前向纠错

每 3 秒根据 RTT 和丢包率动态调整 FEC 参数：

| 网络状态 | 数据分片 | 校验片 | 冗余度 |
|---------|---------|--------|--------|
| 低延迟低丢包 (<2%) | 10 | 1 | 10% |
| 正常状态 | 4 | 1 | 25% |
| 高丢包 (>15%) | 4 | 2 | 50% |

FEC 解码失败时，系统自动跳过该帧，继续处理后续数据，不会阻塞。

### 3. uTLS 指纹伪装

使用 uTLS 模拟 Chrome TLS 指纹（HelloChrome_Auto），DPI 无法区分 SuperYellow 和普通 HTTPS 流量。

### 4. 随机 Padding（64 字节对齐）

每帧填充到 64 字节边界，消除流量包长特征。

### 5. REALITY 级 SNI 伪装

Camo 模式下，服务器返回真实 www.microsoft.com:443 证书，验证阶段完全合法。

### 6. VLESS 协议透传

直接透传 VLESS 协议，无需额外封装。兼容 PassWall、v2rayN、Clash 等标准 VLESS 客户端。

### 7. SHA-256 时间戳授权

token = SHA256(SHA256(username:password) + timestamp_ms)，15 秒内有效，防重放。

### 8. Mux.cool 多路复用支持

源码级支持 xray Mux（CMD=3），解析 mux.cool 帧协议，每个子流独立拨出目标。

### 9. Web 管理面板

- **服务端面板** (http://服务器IP:8080)：系统状态、用户管理、流量统计
- **客户端面板** (http://路由器IP:8899 或 http://localhost:9999)：配置、节点切换
- 🎲 随机生成客户端（用户名+密码）、📋 一键复制 VLESS 链接和 JSON 配置

### 10. 多用户支持

支持多用户配额/密码、流量限制、到期时间、实时流量统计。

---

## 稳定性架构

V8 经过大量实战测试和多轮稳定性修复，具备以下可靠性保障：

### 单流静默修复

当某条底层 TCP 流写入/读取失败时，**只关闭该流**，不触发全局重连。后台 `monitorHealth` 每 2 秒巡查，自动重建断开的流。FEC 冗余在流重建期间提供数据保护，用户无感知。

```
传统方案: 单流故障 → triggerReconnect() → 全部断开 → 网络风暴 → 重建
SuperYellow: 单流故障 → Close(该流) → monitorHealth 巡查 → 静默重建 → 无感
```

### 僵尸会话定时清理

服务器定期清理已关闭的僵尸会话，释放内存和资源。新连接可以立即创建新会话，避免"僵尸会话拒绝服务"问题。

### TCP 背压控制

- 写超时 3 秒，防止写入 goroutine 堆积
- 并发写入限制：`fs` 通道容量 64
- 读取缓冲区上限：32768 字节

### nftables 旁路循环防护

服务器 IP 通过 `psw_vps` nftables 集合绕过 PassWall 透明代理，防止无限回环。

---

## 架构图

```
客户端侧:
  PassWall/浏览器 → VLESS :11081 → SuperYellow 客户端插件
       → 6 条并行 TCP 流 (FEC 校验片)
       → uTLS (Chrome 指纹) + TLS 1.3
  ======= TCP (伪装为 HTTPS) ========
服务器侧:
  协议识别 (SNI 路由)
       → Camo 回退(伪装) / SuperYellow 处理
       → FEC 重组 + 帧分发
       → 目标服务器 (TCP)
```

---

## 快速部署

### 一键安装服务端 (Ubuntu/Debian)

```bash
wget https://raw.githubusercontent.com/roger19981223-dotcom/superyellow-proxy/main/install.sh
chmod +x install.sh
sudo ./install.sh server
```

### 安装客户端 — iStoreOS/OpenWrt 插件

```bash
# 下载 .run 包到路由器
scp SuperYellow_Client_v1.2.1_x86_64.run root@192.168.100.1:/tmp/

# SSH 登录路由器执行安装
ssh root@192.168.100.1
sh /tmp/SuperYellow_Client_v1.2.1_x86_64.run

# 编辑配置
vi /etc/config/superyellow_client.json
/etc/init.d/superyellow restart
```

安装后自动注册 PassWall 节点。Web 面板地址：`http://路由器IP:8899`

LuCI 集成页面：服务 → SuperYellow Proxy

### 安装客户端 — Windows

直接运行 `superyellow-windows-amd64.exe`，浏览器打开 `http://localhost:9999` 配置服务器。

### 安装客户端 — Android

安装 `SuperYellow-Proxy-v1.0.apk`，在 App 内配置服务器。

---

## 配置说明

### 客户端配置 (superyellow_client.json)

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

> **重要：** 如果服务器配置了 domain 字段，客户端的 sni 必须与之匹配，否则连接会被 Camo 模式拦截。

### 服务端配置 (aether_config.json)

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

> **注意：** domain 为空时使用自签证书；非空时自动申请 ACME 证书（需 80 端口空闲）。

---

## PassWall 集成

在 PassWall 中添加 Xray 节点：
- 协议：VLESS
- 地址：127.0.0.1
- 端口：11081
- 传输：TCP
- 加密：none

SuperYellow 自动将服务器 IP 加入 `psw_vps` nftables 集合，绕过 PassWall 透明代理。如果 PassWall 重启后旁路丢失，客户端插件会自动恢复。

---

## 技术细节

### FEC Reassembler 工作原理

SuperYellow 使用 Reed-Solomon 纠删码对帧进行分片编码。每组 N 个数据分片 + M 个校验片，接收端收到足够分片即可还原原始数据。

**容错机制：** 当某组 FEC 解码失败（分片不足或损坏），系统将该序列号标记为 nil 占位符写入 readyBuffer，drainReady 循环遇到 nil 时记录日志并跳过，继续处理后续已解码数据。确保单次 FEC 失败不会阻塞整个数据流。

```
readyBuffer: [seq=100: data] [seq=101: nil(skip)] [seq=102: data] [seq=103: data]
                                                    ↑ drainReady 继续前进
```

### 帧协议格式

每帧以魔数 `0x41455448` ("AETH") 开头，共 21 字节帧头：

```
[魔数:4B][类型:1B][长度:2B][ConnID:4B][长度:4B][时间戳:8B][Token:16B][数据:NB][Padding]
```

帧类型（客户端→服务器）：
- 0x01: CONNECT（建立连接）
- 0x02: DATA（双向，传输数据）
- 0x03: CLOSE（双向，关闭连接）
- 0x05: UDP（UDP 代理）

服务器→客户端：
- 0x01: CONNECT_ACK（连接建立成功）
- 0x02: CONNECT_NAK（连接建立失败）
- 0x03: CLOSE
- 0x04: DATA

### VLESS 协议处理

客户端读取 VLESS 请求头中的协议字节，正确映射 SOCKS5 ATYP：
- ATYP 0x01: IPv4（4 字节）
- ATYP 0x02/0x03: 域名（1 字节长度 + 域名）
- ATYP 0x04: IPv6（16 字节）

### ProtocolDemux 路由

服务器根据 `domain` 字段对入站 TLS 连接按以下规则路由：
1. SNI 匹配 domain → SuperYellow TLS 处理
2. SNI 不匹配 → Camo 回退（返回 nginx 欢迎页）

TLS 握手后检查 Magic 魔数：有 Magic → Aether 协议处理；无 Magic → 返回伪装页面。

---

## 协议参数

| 参数 | 值 |
|------|-----|
| 并行流数 | 6 |
| TLS 版本 | TLS 1.3 only |
| ALPN | h2, http/1.1 |
| 帧头魔数 | 0x41455448 ("AETH") |
| FEC 库 | github.com/klauspost/reedsolomon |
| TLS 指纹 | uTLS Chrome_Auto |
| 授权算法 | SHA-256(SHA-256(user:pass) + timestamp_ms) |
| Token 有效期 | 15 秒 |
| 目标拨出超时 | 30 秒 |
| 客户端 ACK 等待 | 35 秒 |
| 写超时 | 3 秒 |
| 最大并发写入数 | 64 |
| 读取缓冲区上限 | 32768 字节 |
| 帧分发发送超时 | 1 秒 |

---

## 许可证

MIT License
