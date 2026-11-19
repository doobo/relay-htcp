# relay-htcp

用 Go 实现的 **TCP over HTTP/2** 穿透工具：把任意 TCP 连接封装进标准 HTTPS/HTTP/2 流中，公网侧看起来是普通 Web 流量，同时提供 Token 认证、路由控制、连接池、心跳重连和内置 Web 管理面板。

当前版本：`0.1.0`

- 服务端部署在公网节点，暴露 HTTP(S) 端口。
- 客户端部署在内网节点，把本地端口映射到服务端可访问的内网服务。
- 客户端无需修改业务程序：把 SSH/MySQL/Redis 客户端指向本地监听端口即可。

```
┌─────────────┐   127.0.0.1:2222    ┌──────────────────┐   HTTPS / HTTP/2   ┌──────────────────┐   127.0.0.1:22   ┌─────────────┐
│ ssh client  │ ──────────────────▶ │ relay-htcp client │ ═════════════════▶ │ relay-htcp server │ ───────────────▶ │  ssh server │
└─────────────┘                     └──────────────────┘  控制流 + 数据流    └──────────────────┘                  └─────────────┘
```

## 特性

- **HTTP/2 多路复用**：一条底层连接上同时承载控制流和任意多条数据流，避免每个 TCP 连接重复 TLS 握手。
- **连接池**：客户端可建立多条独立隧道连接，新数据流轮询分配。
- **多服务端与故障转移**：客户端可配置多个服务端；每个本地监听可选择一个或多个服务端，策略支持轮询（`round_robin`）和故障转移（`failover`，始终优先第一个，服务端不可用或数据流打不开时才用下一个）。
- **CDN / Cloudflare 适配**：每个服务端可选 `transport: xhttp`，把双向流拆成“短上传 POST + 长下载 GET”，不依赖双向 HTTP/2 请求体，可穿过 Cloudflare 等七层代理；默认的 `http` 传输仍保留给直连或四层转发场景。
- **出口代理**：客户端可用 HTTP 或 SOCKS5 代理连接服务端（含 xhttp），默认关闭；适合本机需要经代理访问外网的场景。
- **认证与路由**：Bearer Token 认证；每个 Token 可绑定一个或多个路由（建议按最小权限分配）；路由名到内网地址的映射在服务端集中管理。
- **心跳与自愈**：PING/PONG 保活，连续丢失 `heartbeat_miss` 次后自动重连；指数退避。
- **TLS**：支持真实证书、自签证书、自定义 CA；ALPN 优先协商 `h2`。
- **明文 h2c**：无 TLS 时使用 HTTP/2 明文（h2c），适合内网和测试。
- **伪装（可选）**：浏览器风格请求头、仿 nginx 的 `Server` 头、未知路径返回静态诱饵页。
- **热更新**：通过管理面板或服务端 `SIGHUP` 修改配置，可热应用的字段无需重启即可生效；TLS 证书换文件即生效。
- **服务端出口代理**：支持全局 HTTP/SOCKS5 代理；内网路由可单独勾选“走代理”，未勾选的路由保持直连。
- **端口共用与伪装**：服务端管理面板可挂到隧道端口下的自定义路径，外部只看到一个 Web 服务。
- **加密登录与主题**：登录密码用 RSA-OAEP + AES-GCM（不支持 WebCrypto 时回退 TweetNaCl）加密；支持跟随系统/深色/浅色/纯黑主题。
- **表单化配置**：配置页按角色渲染结构化表单，密钥字段掩码显示、留空保持原值；仍可切换到 YAML 高级模式。
- **客户端 Token 独立页**：Token 列表从配置表单拆出，支持路由绑定、启用/禁用、一次性生成或重新生成；密钥只在生成时显示一次。每个 Token 支持日/周/月流量上限（MB，默认不限制）和限制开关，后台每 5 分钟（可配置）刷新一次；详情页可查看最近日流量。
- **IP 访问控制**：面板内维护黑白名单（IP/CIDR），默认空；白名单非空时只放行白名单，黑名单始终拒绝，回环地址不受限制；兼容 Cloudflare / cloudflared 的 `CF-Connecting-IP`、`X-Forwarded-For`。
- **密钥入库加密**：SQLite 中的配置与 Token 采用 AES-256-GCM 信封加密（随机数据密钥 + 独立主密钥），主密钥默认保存在数据库旁的 `0600` 密钥文件，也可用环境变量注入。
- **管理面板**：登录、实时状态、连接与流量统计、配置编辑、Token 管理、IP 访问控制、用户与角色管理，前端已内嵌进二进制。客户端面板支持一键重启：重新读取配置、重建隧道连接池并重新绑定本地监听，原本需要重启才生效的字段（`servers`、`tunnel.*`、`log.level` 等）也会立即应用。
- **单个二进制**：无额外运行时依赖；配置文件、TLS 证书和可选的 SQLite 数据库按需挂载。
- **无配置文件启动**：服务端和客户端都可以不写 `-config`。服务端使用内置默认值；客户端自动在 `./data/client.yaml` 生成引导配置并打开管理面板，配置完成后点击“重启”即可生效。

## 工作原理

1. 客户端启动后向服务端 `POST /tunnel` 发起控制流，携带 `Authorization: Bearer <token>`。
2. 控制流上只传输 PING/PONG 帧，用于保活和判断隧道是否存活。
3. 本地监听端口收到 TCP 连接后，客户端在**同一条 HTTP/2 连接**上发起 `POST /stream`，并通过 `X-Tunnel-Target` 指定路由。
4. 服务端校验 Token 与路由权限后，拨号到该路由对应的内网目标地址。
5. 双方把 HTTP 请求体/响应体当作字节流，用自定义帧协议双向转发 TCP 数据。

### 帧格式

所有隧道流量（控制流和数据流）都使用同一种二进制帧：

```
+--------+---------------------+--------------------+
| type   | length (BE32)       | payload            |
| 1 byte | 4 bytes             | length bytes       |
+--------+---------------------+--------------------+
```

| 类型 | 值 | 说明 |
|---|---|---|
| `DATA` | `0x0` | TCP 数据块，单帧最大 16383 字节 |
| `PING` | `0x1` | 心跳请求（客户端 → 服务端） |
| `PONG` | `0x2` | 心跳响应，payload 回显 PING |
| `CLOSE` | `0x3` | 优雅关闭，payload 可携带原因 |

在 HTTP/1.1 回退场景下，每条数据流会各自占用一条 TCP 连接（无法多路复用）；生产环境建议确保端到端 HTTP/2。

## 快速开始

### 1. 环境要求

- Go 1.27 或更高版本
- 可选：OpenSSL（生成测试证书）
- 可选：`ssh` 客户端（验证隧道）

### 2. 编译

```bash
cd relay-htcp

# 推荐：自动识别平台、注入版本号
make build

# 等价的手写命令
go build -trimpath -o relay-htcp ./cmd/relay-htcp
# Windows:
# go build -trimpath -o relay-htcp.exe ./cmd/relay-htcp
```

也可以直接运行：

```bash
go run ./cmd/relay-htcp version
```

完整的构建、打包与 GitHub 发布流程见下文「构建与发布」。

### 3. 准备证书

生产环境请使用真实域名 + 可信 CA 证书（如 Let's Encrypt）。本地测试可生成自签证书：

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout server.key -out server.crt \
  -subj "/CN=tunnel.example.com" \
  -addext "subjectAltName=DNS:tunnel.example.com,IP:203.0.113.10"
```

> 使用自签证书时，客户端需配置 `tls.ca_file` 指向 `server.crt`，或临时设置 `tls.insecure_skip_verify: true`。证书的 SAN 必须包含客户端实际连接使用的主机名或 IP。

如果只在局域网测试，可以完全省略 `tls` 段，使用明文 h2c。

### 4. 配置并启动服务端

`server.yaml`：

```yaml
listen: ":5630"

tls:
  cert: "server.crt"
  key: "server.key"

auth:
  tokens:
    - name: office-laptop
      token: "请替换为足够随机的长 Token"
      routes: [ssh, mysql]   # 可绑定多个路由；留空 = 全部（不推荐）
    - name: ops
      token: "另一个 Token"
      routes: [mysql]        # 不同服务用不同 Token，互相隔离

routes:
  - name: ssh
    target: "127.0.0.1:22"
  - name: mysql
    target: "127.0.0.1:3306"

tunnel:
  max_concurrent_streams: 128
  max_connections: 100
  dial_timeout: 10s
  idle_timeout: 90s

disguise:
  enabled: true

log:
  level: info
```

生成随机 Token：

```bash
openssl rand -hex 32
```

启动（`-config` 可选，`listen` 省略时默认 `:5630`）：

```bash
# 有配置文件
./relay-htcp server -config server.yaml

# 不带子命令默认就是 server；完全不用 -config 时使用内置默认值
#   监听 :5630，管理面板 /admin/，数据库 ./data/admin.db
#   默认允许所有 IP 访问管理面板（建议登录后在“IP 访问”页限制）
#   首次启动会在日志打印随机 admin 密码
./relay-htcp
# 等价于
./relay-htcp server

# 当前目录存在 server.yaml 时会自动加载
```

无配置启动会生成一个已禁用的占位 Token 和 `default → 127.0.0.1:22` 占位路由，启动后可在管理面板里修改。

临时改端口不必改配置：

```bash
./relay-htcp server -config server.yaml -port 8443
./relay-htcp server -config server.yaml -listen 127.0.0.1:8443
```

`-listen` / `-port` 优先于配置文件，也优先于面板保存到数据库里的 `listen`。

### 5. 配置并启动客户端

`client.yaml`：

```yaml
# 全局默认凭证；servers 里的条目可单独覆盖 token / CA
auth:
  token: "请替换为服务端配置的同一个 Token"

tls:
  ca_file: "server.crt"       # 使用自签证书时
  # insecure_skip_verify: true  # 仅测试环境

servers:
  - name: primary
    url: "https://tunnel.example.com:5630"
  - name: backup
    url: "https://backup.example.com:5630"
    token: "备份节点使用的另一个 Token"   # 可选

listeners:
  - local: "127.0.0.1:2222"
    target: "ssh"
    servers: [primary, backup]
    strategy: failover        # 优先 primary，不可用时才用 backup
  - local: "127.0.0.1:33060"
    target: "mysql"
    servers: [primary, backup]
    strategy: round_robin     # 在 primary / backup 之间轮询

tunnel:
  connections: 2              # 每个服务端各自建立 2 条连接
  heartbeat: 15s
  heartbeat_miss: 3
  reconnect_min: 1s
  reconnect_max: 30s
  stream_timeout: 30s

disguise:
  enabled: true

log:
  level: info
```

> 仍然兼容旧的单服务端写法：只写 `server: "https://..."` 时，启动时会自动迁移为 `servers` 列表。`listeners[].servers` 留空表示使用全部服务端；`strategy` 省略时默认 `round_robin`。

启动：

```bash
./relay-htcp client -config client.yaml
```

也可以完全不用 `-config`：

```bash
./relay-htcp client
```

- 当前目录存在 `data/client.yaml` 时直接加载；没有时兼容旧的 `./client.yaml`；
- 两者都不存在时，自动创建 `data/client.yaml` 和一个只开管理面板的引导配置（`servers` / `listeners` 为空）；
- 客户端管理面板默认在 `http://127.0.0.1:15630/admin/`，首次启动的随机密码打印在日志中；
- 在面板里填写服务端、Token 和本地监听，保存后点击“重启”即可生效。数据库默认放在 `data/client-admin.db`。

### 6. 验证

```bash
ssh -p 2222 user@127.0.0.1
```

或连接 MySQL：

```bash
mysql -h 127.0.0.1 -P 33060 -u root -p
```

客户端日志出现 `tunnel established`、服务端日志出现 `data stream closed` 即表示链路正常。

### 7. 明文 h2c（仅内网/测试）

服务端不配置 `tls`，客户端使用 `http://`：

```yaml
# server.yaml
listen: ":8080"
# 不写 tls 段

# client.yaml
servers:
  - name: lan
    url: "http://192.168.1.10:8080"
```

注意：h2c 不加密，Token 和数据都会以明文传输，只应在可信网络中使用。

### 8. Cloudflare / CDN（xhttp 传输）

经过 Cloudflare 橙云或其他七层 CDN 时，默认 `http` 传输的长时间双向 POST 会被缓冲或拒绝（日志里常见 `PROTOCOL_ERROR`、超时，或把 HTTP/1.1 响应当成 HTTP/2 帧）。此时把该服务端改成 `transport: xhttp`：

```yaml
servers:
  - name: cloudflare
    url: "https://ws.example.com"     # 走 CDN 的域名
    transport: xhttp
    token: "与服务端一致的 Token"

listeners:
  - local: "127.0.0.1:2222"
    target: "ssh"
    servers: [cloudflare]
    strategy: failover
```

relay-htcp 的 xhttp 前缀默认是 **`/relay`**，因此同一域名下的 Xray 可以继续占用 `/xhttp`，互不冲突。只要确保 Nginx 把 `/relay/` 转发到 relay-htcp 的监听端口：

```nginx
upstream relay_htcp {
    server 127.0.0.1:5630;
    keepalive 64;                       # 大量短上传 POST，需要复用连接
}

location ^~ /relay/ {
    proxy_pass http://relay_htcp;        # 不要带尾斜杠，否则 /relay 前缀会被吃掉
    proxy_http_version 1.1;
    proxy_set_header Connection "";      # 本项目不用 WebSocket
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;   # 覆盖，避免伪造 IP
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_read_timeout 300s;
    proxy_send_timeout 300s;
}
```

完整配置（TLS 终结、超时取舍、面板白名单、四层透传方案、常见坑）见[《反向代理注意事项》](#反向代理注意事项)。

如果还需要换前缀，服务端和客户端必须一起改：

```yaml
# 服务端 server.yaml
tunnel:
  xhttp_path: "/relay"

# 客户端 client.yaml
servers:
  - name: cloudflare
    url: "https://ws.example.com"
    transport: xhttp
    xhttp_path: "/relay"
```

xhttp 把每条 TCP 流拆成普通的 HTTP 请求：

- **下载**：`GET /relay/download?session=...`，长连接流式响应（服务端 → 客户端）
- **上传**：`POST /relay/upload?session=...`，携带一小批帧的短请求（客户端 → 服务端）
- **保活**：`POST /relay/ping`

这样 CDN 不需要支持双向 HTTP/2 请求体；上传总是完整结束的短 POST，下载是普通流式响应。它对应 Xray XHTTP 的 packet-up + stream-down 思路（不是依赖双向流的 stream-one）。代价是上传会按批发送，交互延迟比直连 `http` 传输略高。服务端无需额外开关，同一监听同时支持两种传输。

为了压低高延迟链路上的开销，xhttp 传输还做了两件事：

- **预开下载流（warm pool）**：每条本地连接原本要先发 `GET /download` 并等响应，才轮到数据流动，等于多付一个 RTT。客户端现在会在每条路由上预开 1 条下载流，下一条本地连接直接接管，省掉这次往返；未被使用的预开流 10 秒后自动关闭，期间服务端会提前 dial 一次内网目标，用完即释放。
- **上传流水线**：服务端在下载响应里声明 `X-Upload-Pipeline: 1`，客户端最多同时发 2 个 `POST /upload`，每个批次带 `X-Upload-Seq` 序号，服务端按序号重排后再写入目标，避免连续写入时每批都等一个 RTT。旧版服务端不声明该响应头，客户端会自动退回严格串行模式，不会打乱字节顺序。

按 280 ms 的单次 RTT 计算，这两项合计能把每条新连接的额外延迟从约 2 RTT 降到 0。

Cloudflare 侧建议：

- 保持橙云即可，不需要 WebSocket 或 gRPC；
- 给 `/relay/download*` 加一条 **Configuration Rule → Response body buffering = None**。默认的 Standard 会先缓冲/检查响应体开头，可能让下载流延迟到连接结束才到达；
- 不要缓存 `/relay/*`（服务端已返回 `Cache-Control: no-store`）；
- **Quick Tunnel 会缓冲 GET 响应直到连接结束**，不能用来验证 xhttp 的实时性；请用橙云域名或 named tunnel 测试。

Cloudflare 侧保持橙云即可，不需要 WebSocket；使用 cloudflared 时把源站指向隧道的监听端口。

### 9. 出口代理（HTTP / SOCKS5，可选）

如果客户端所在网络需要经过代理才能访问服务端，可启用出口代理：

```yaml
proxy:
  enabled: true
  type: socks5              # http | socks5
  address: "127.0.0.1:7890"
  username: ""              # 可选
  password: ""              # 可选
```

- 默认 `enabled: false`，即直连；启用后隧道控制流、数据流和 xhttp 请求都走该代理。
- `http` 代理通过 CONNECT 转发，适用于 `https://` 服务端；纯 h2c 的 `http://` 服务端请用 `socks5`。
- 代理配置属于启动参数，面板保存后需要重启客户端；面板的“代理”页签可编辑，密码以掩码显示。
- 该代理只影响客户端到服务端的连接，不影响本地监听端口和管理面板。

## 配置参考

配置采用 YAML，启动时校验；未知字段会被忽略，必填项缺失会直接报错退出。`log.level` 省略时默认 `info`，只接受 `debug` / `info` / `warn` / `error`。每个客户端 Token 可以绑定一个或多个路由，建议按最小权限分配。

> 例外：客户端在 `admin.enabled: true` 且没有任何 `servers` / `listeners` 时允许启动，用于无配置引导模式。服务端无配置文件启动时同样使用内置占位配置。

### 服务端 `server.yaml`

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `listen` | string | `:5630` | 监听地址，如 `:5630`、`127.0.0.1:5630`；可用启动参数 `-listen` / `-port` 临时覆盖 |
| `tls.cert` | string | 空 | 证书文件路径；与 `tls.key` 同时为空时使用明文 h2c |
| `tls.key` | string | 空 | 私钥文件路径 |
| `auth.tokens` | list | 必填 | 至少一个 Token，Token 值不能为空且不能重复 |
| `auth.tokens[].name` | string | 空 | 身份名称，用于日志和管理面板展示 |
| `auth.tokens[].token` | string | 必填 | Bearer Token 明文，建议至少 32 字节随机值 |
| `auth.tokens[].routes` | list | 空 | 该 Token 允许访问的路由名，可多选；留空表示允许所有路由（不推荐） |
| `auth.tokens[].enabled` | bool | `true` | 是否启用；禁用的 Token 保留在配置里但不再通过认证 |
| `auth.tokens[].limit_enabled` | bool | `false` | 启用日/周/月流量限制；后台任务定期刷新限制开关 |
| `auth.tokens[].daily_limit_mb` | int | `0` | 每日流量上限（MB），`0` 表示不限制 |
| `auth.tokens[].weekly_limit_mb` | int | `0` | 每周流量上限（MB），`0` 表示不限制 |
| `auth.tokens[].monthly_limit_mb` | int | `0` | 每月流量上限（MB），`0` 表示不限制 |
| `routes` | list | 必填 | 至少一个路由，名称不能重复 |
| `routes[].name` | string | 必填 | 逻辑路由名，客户端通过 `X-Tunnel-Target` 引用 |
| `routes[].target` | string | 必填 | TCP 目标，支持 `host:port` 或 `http(s)://host[:port]`（URL 仅取主机和端口，https 默认 443、http 默认 80） |
| `routes[].use_proxy` | bool | `false` | 该路由是否走服务端全局出口代理；未勾选的路由直连目标 |
| `proxy.enabled` | bool | `false` | 启用服务端出口代理，只影响 `routes[].use_proxy` 为 `true` 的路由 |
| `proxy.type` | string | `http` | `http`（CONNECT）或 `socks5` |
| `proxy.address` | string | 空 | 代理地址 `host:port`，启用时必填 |
| `proxy.username` | string | 空 | 代理用户名（可选） |
| `proxy.password` | string | 空 | 代理密码（可选） |
| `tunnel.max_concurrent_streams` | int | `128` | 每条 HTTP/2 连接允许的并发流上限，需重启生效 |
| `tunnel.max_connections` | int | `0` | 同时在线控制连接数上限，`0` 表示不限制 |
| `tunnel.dial_timeout` | duration | `10s` | 拨号内网目标的超时时间 |
| `tunnel.idle_timeout` | duration | `90s` | 控制流静默多久后断开 |
| `tunnel.xhttp_path` | string | `/relay` | xhttp 传输的端点前缀，默认 `/relay` |
| `tunnel.quota_refresh` | duration | `5m` | 重新统计 Token 流量并刷新限制开关的间隔 |
| `disguise.enabled` | bool | `true` | 是否启用诱饵页和伪装响应头 |
| `log.level` | string | `info` | `debug` / `info` / `warn` / `error` |
| `admin.*` | object | 见下文 | 管理面板配置 |

### 客户端 `client.yaml`

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `servers` | list | 必填* | 至少一个服务端；每个服务端独立建连、独立连接池。*`admin.enabled: true` 时可为空 |
| `servers[].name` | string | `server-N` | 服务端名称，供 `listeners[].servers` 引用；不能重复 |
| `servers[].url` | string | 必填 | 服务端地址，格式 `scheme://host[:port]`，不能带路径 |
| `servers[].transport` | string | `http` | `http` 直连（要求端到端 HTTP/2 全双工）；`xhttp` 适配 Cloudflare / CDN（短上传 POST + 长下载 GET） |
| `servers[].xhttp_path` | string | `/relay` | xhttp 端点前缀，必须与服务端 `tunnel.xhttp_path` 一致 |
| `servers[].token` | string | 空 | 覆盖 `auth.token`；留空使用全局 Token |
| `servers[].ca_file` | string | 空 | 覆盖 `tls.ca_file`；留空使用全局 CA |
| `servers[].insecure_skip_verify` | bool | `false` | 为 true 时跳过该服务端的证书校验（与全局值取或） |
| `server` | string | 空 | 旧版单服务端写法；与 `servers` 互斥，启动时自动迁移 |
| `tls.insecure_skip_verify` | bool | `false` | 全局跳过证书校验，仅测试环境使用 |
| `tls.ca_file` | string | 空 | 全局自定义 CA 证书（PEM） |
| `auth.token` | string | 空 | 全局默认 Token；每个服务端也可单独配置 |
| `proxy.enabled` | bool | `false` | 是否通过出口代理连接服务端；默认关闭，修改后需重启 |
| `proxy.type` | string | `http` | `http` 或 `socks5`；HTTP 代理仅用于 `https://` 服务端，SOCKS5 同时支持 h2c 和 TLS |
| `proxy.address` | string | 空 | 代理地址 `host:port`，也兼容 `http://user:pass@host:port` 写法 |
| `proxy.username` | string | 空 | 代理认证用户名（可选） |
| `proxy.password` | string | 空 | 代理认证密码（可选，面板中掩码显示） |
| `listeners` | list | 必填* | 至少一个本地监听，`local` 不能重复。*`admin.enabled: true` 时可为空 |
| `listeners[].local` | string | 必填 | 本地监听地址，如 `127.0.0.1:2222` |
| `listeners[].target` | string | 必填 | 服务端路由名 |
| `listeners[].servers` | list | 空 | 选择哪些服务端（按名称）；留空 = 全部 |
| `listeners[].strategy` | string | `round_robin` | `round_robin` 轮询 / `failover` 优先第一个，服务端不可用或数据流打不开时才用下一个 |
| `tunnel.connections` | int | `2` | 每个服务端的连接池大小，即该服务端的独立 HTTP/2 连接数；需重启生效 |
| `tunnel.heartbeat` | duration | `15s` | PING 发送间隔 |
| `tunnel.heartbeat_miss` | int | `3` | 连续丢失多少次 PONG 后判定隧道断开 |
| `tunnel.reconnect_min` | duration | `1s` | 重连初始退避 |
| `tunnel.reconnect_max` | duration | `30s` | 重连最大退避 |
| `tunnel.stream_timeout` | duration | `30s` | 本地连接等待可用隧道的最长时间 |
| `disguise.enabled` | bool | `true` | 是否发送浏览器风格请求头 |
| `disguise.user_agent` | string | 内置 Chrome UA | 自定义 User-Agent |
| `log.level` | string | `info` | `debug` / `info` / `warn` / `error` |
| `admin.*` | object | 见下文 | 管理面板配置 |

### 管理面板 `admin.*`（服务端与客户端通用）

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `enabled` | bool | `false` | 是否启用管理面板；关闭时不监听端口、不创建数据库 |
| `shared` | bool | `false` | 仅服务端：把面板挂到隧道端口，不再单独监听；公网节点推荐开启 |
| `path` | string | `/`（独立）/`/admin`（共用） | 面板 URL 前缀；共用模式下建议改成不易猜到的路径 |
| `allowed_cidrs` | list | 共用模式默认全部 IP | 静态 IP 白名单（默认 `0.0.0.0/0`、`::/0`）；运行期可在面板“IP 访问”页收紧 |
| `listen` | string | 服务端 `127.0.0.1:8080`；客户端 `127.0.0.1:15630` | 仅 `shared: false` 时使用，务必只绑定内网/回环地址 |
| `token` | string | 空 | 可选的静态管理 Token，供脚本直接访问 API，拥有 admin 权限 |
| `db_path` | string | `data/admin.db` | SQLite 数据库路径；目录不存在会自动创建 |
| `key_file` | string | `<db_path>.key` | 配置入库加密的主密钥文件；首次启动自动生成（0600） |
| `default_username` | string | `admin` | 首次运行创建的管理员用户名 |
| `default_password` | string | 空 | 首次运行的管理员密码；为空则随机生成并只在日志中打印一次 |
| `session_ttl` | duration | `24h` | 登录会话有效期 |

> 服务端管理面板默认监听 `127.0.0.1:8080`，客户端默认监听 `127.0.0.1:15630`，两端同机运行也不会端口冲突。`shared` 只对服务端有效；客户端没有入站隧道端口，始终使用独立监听。

### 配置优先级

1. 启动时先读取 `-config` 指定的 YAML 文件。
2. 如果管理面板曾保存过配置，数据库中的配置会覆盖文件配置（面板中显示来源为 `db`）。
3. 在面板中保存配置时，会同时写入数据库和 `-config` 指定的文件（文件权限 `0600`），并立即热应用可热更新的字段。
4. `admin` 段属于运行时配置，面板保存时不会覆盖它。

> 注意：一旦通过面板保存过配置，之后手工修改 YAML 文件不会生效，因为数据库配置优先。此时请在面板中编辑并保存，或使用 SQLite 工具删除 `settings` 表中 `key='config'` 的记录后再启动。

## 管理面板

服务端推荐把面板挂在隧道端口上（外部只看到一个 Web 服务）：

```yaml
admin:
  enabled: true
  shared: true
  path: "/ops-console"           # 自定义不易猜到的前缀
  allowed_cidrs: ["0.0.0.0/0", "::/0"]  # 默认全部放行；可在“IP 访问”页限制
  db_path: "data/admin.db"
  default_username: "admin"
  default_password: ""           # 留空 = 首次运行生成随机密码并打印到日志
  session_ttl: 24h
```

客户端或需要独立端口时使用：

```yaml
admin:
  enabled: true
  shared: false
  path: "/ops-console"
  listen: "127.0.0.1:15630"
  db_path: "data/admin.db"
```

第一次启动时，日志会打印：

```
admin panel: created default user with a generated initial password (shown only once) user=admin password=...
```

未配置 `db_path` 时默认使用 `./data/admin.db`，密钥文件为 `./data/admin.db.key`，目录不存在会自动创建。

请立即保存该密码并登录：

- 共用模式：`https://tunnel.example.com:5630/ops-console/`（即隧道端口 + `admin.path`）
- 独立模式：`http://127.0.0.1:15630/ops-console/`（服务端独立面板默认 `8080`）

如果服务端在远程机器上，建议通过 SSH 端口转发访问共用端口（源地址会呈现为回环，正好命中默认白名单）：

```bash
ssh -L 5630:127.0.0.1:5630 user@server
# 然后打开 http://127.0.0.1:5630/ops-console/
```

独立模式下直接打开管理监听端口根路径也会跳转到登录页（`/` → `admin.path/`）。共用模式同样支持：**命中 `allowed_cidrs` 白名单的来源**访问 `/` 会跳到 `admin.path/`，其他来源仍然看到诱饵页，因此不会向公网暴露管理入口。

### 登录安全与主题

- **加密登录**：浏览器先请求一次 `POST /api/auth/challenge` 获取 RSA 公钥、X25519 公钥和一次性 nonce，再用 WebCrypto（AES-GCM + RSA-OAEP）加密 `{username,password,nonce}`；不支持 `crypto.subtle` 的明文 HTTP 环境自动回退到 TweetNaCl box。密码不会以明文进入请求体，nonce 单次有效、防重放。
- 这层加密只是让被动观察者看不到密码，**不能替代 TLS**；公网共用端口仍应启用 TLS。
- **主题**：支持 跟随系统 / 深色 / 浅色 / 纯黑，登录页和顶栏都能切换，选择保存在浏览器 `localStorage`。
- 登录后默认进入结构化配置表单，密钥字段始终掩码；`admin` 还可切换 YAML 高级模式。

面板页签：

- **状态**：运行时长、活跃隧道/连接、上下行字节数、诱饵页访问次数、实时连接列表；底部显示当日流量（服务端按客户端 Token、客户端按服务端路由），默认展示前 20 条并可按 Token/服务端筛选。
- **配置**：默认使用结构化表单编辑，字段分组随服务端/客户端角色自动变化；`admin` 可切换到 YAML 高级模式。保存结果会列出哪些字段已热应用、哪些需要重启。
- **客户端 Token**（仅服务端）：独立管理页，可新增/编辑/删除 Token、多选绑定路由、启用/禁用、一次性生成或重新生成密钥；支持日/周/月流量上限与限制开关，“详细”可查看周期统计和最近日流量。
- **IP 访问**（仅管理员）：维护管理面板的黑白名单，支持 IP 与 CIDR，保存后立即生效。
- **用户**：创建/修改/删除用户，分配 `admin` 或 `viewer` 角色，启用/禁用账号。

顶栏右侧把用户名和“退出登录”合并成了一个下拉菜单。

### 客户端 Token 页

Token 已从配置表单中拆出，避免在长表单里误操作。页面上可以：

- 新建 Token：留空自动生成随机值，保存成功后**只显示一次**并支持复制；
- 编辑：修改名称、路由（可多选）、启用状态；Token 留空表示保持不变；
- 重新生成：勾选后生成新值并显示一次，旧值立即失效；
- 删除：最后一个 Token 不允许删除（配置要求至少保留一个）。

密钥不会出现在列表响应里，只显示“已设置 …abcd”形式的尾部提示。

### IP 访问控制

`IP 访问` 页把规则保存在 SQLite（与其他设置一样加密），默认两个列表都为空：

- 白名单非空：只允许白名单中的 IP/CIDR；
- 黑名单：命中的地址始终拒绝，即使同时出现在白名单；
- `127.0.0.1` / `::1` 永不过滤，避免把本机锁在门外；
- 两个列表都为空：允许所有来源。

客户端 IP 解析顺序：当直连来源是回环或链路本地地址（本机 cloudflared、nginx 等）时，依次读取 `CF-Connecting-IP`、`X-Forwarded-For` 第一项、`X-Real-IP`；其他来源（包括普通内网地址）只信任 TCP 对端地址，防止伪造头部绕过白名单。

### 表单化配置

配置页默认按角色渲染结构化表单：服务端包含监听/TLS、隧道参数、内网路由（Token 已移到独立页）；客户端的配置页拆成“服务端 / 本地监听 / 代理 / 隧道参数”四个子页签，服务端列表和本地监听分别编辑。服务端页可维护多个服务端及各自的 Token/CA，本地监听页为每个监听选择服务端并设置轮询或故障转移策略：**“选择服务端”是下拉多选**，选项来自服务端列表（含同一次编辑里刚改的名字），不勾选即表示使用全部服务端。表单由后端 schema 驱动（`Provider.ConfigFormSchema`），后续新增可调参数只需在 schema 中加一行，前端和 API 无需改动。

密钥字段掩码规则：

- `GET /api/config/form` 中所有 secret 字段恒为空字符串，明文凭证不会发送到浏览器；
- 保存时留空表示“保持原值”；表格行用隐藏的 `_id` 对应原行，增删行、改名都不会误删已有 Token；
- 需要更换时直接填入新值即可，保存后仍按前述方式加密入库。

如果更习惯直接编辑整段配置，可点“YAML”切回原有模式；`admin` 才能使用该模式，`viewer` 的 YAML 按钮会隐藏，后端也会拒绝读取，避免 Token 明文泄露。

### 角色与安全机制

- `admin`：可读写配置和用户。
- `viewer`：只读，可查看状态和掩码后的配置表单，但不能读取 YAML、修改配置或用户。
- 密码使用 bcrypt（cost 10）存储；会话 Token 只在数据库中保存 SHA-256 哈希。
- 登录失败默认按 IP 限流：每分钟最多 10 次失败；成功登录会清空计数。
- 系统会阻止删除/禁用/降级最后一个启用的管理员，也禁止删除当前登录账号。
- 修改密码、禁用用户会吊销该用户的所有会话。

> 安全提醒：`viewer` 可以读取完整配置，其中包含隧道 Token。请只给可信人员分配账号。

### 密钥入库加密

通过面板保存的配置整段写入 SQLite 的 `settings` 表。写入前会先做两层加密：

1. 首次运行生成 32 字节随机**数据密钥（DEK）**，用 AES-256-GCM 加密配置值；每个值使用独立 nonce，并把 settings 键名作为 AAD，密文无法被挪到其它行。
2. DEK 由 32 字节**主密钥（KEK）**包裹后保存在 `settings` 表的 `__data_key__` 行；KEK 不进入数据库。

KEK 来源（按优先级）：

- 环境变量 `RELAY_HTCP_MASTER_KEY`：64 位 hex 或 base64 编码的 32 字节密钥，适合生产环境由 secrets manager / systemd `EnvironmentFile` 注入。
- 密钥文件：默认 `<db_path>.key`，首次启动自动生成，权限 `0600`，可通过 `admin.key_file` 改路径。

因此只拿到数据库文件的人看不到 `auth.tokens[].token`、客户端 `auth.token` 等凭证。需要注意：

- **数据库和密钥文件必须一起备份、分开保管。** 丢失密钥文件后已有配置无法解密，启动会直接报错而不会覆盖数据库；此时恢复原密钥文件或原 `RELAY_HTCP_MASTER_KEY` 即可。
- 旧版本留下的明文 settings 记录会在启动迁移时自动加密。
- 这层加密只保护 SQLite 静态数据：面板对已登录用户返回的配置、回写的 `-config` YAML 文件（权限 `0600`）仍是明文。`viewer` 角色可以看到完整配置，请只授予可信人员。

### 热更新范围

| 端 | 立即生效 | 需要重启 |
|---|---|---|
| 服务端 | `auth.tokens`、`routes`、`proxy.*`、`tunnel.dial_timeout`、`tunnel.idle_timeout`、`tunnel.max_connections`、`tunnel.xhttp_path`、`tunnel.quota_refresh`、`disguise.enabled` | `listen`、`tunnel.max_concurrent_streams`、`log.level`、启用/关闭 TLS |
| 服务端 TLS | 证书/私钥内容与路径（保存配置或 SIGHUP 后，下一次握手生效） | 启用/关闭 TLS（明文 h2c ↔ TLS） |
| 客户端 | `listeners`（新增/删除/改目标/改服务端选择） | `servers`、`auth.token`、`tls`、`proxy`、`tunnel.*`、`log.level` |

客户端删除或改目标监听器时，已建立的连接会继续跑到结束，不会被强行中断。

需要重启的字段保存后不会立即生效，可在客户端面板右上角点击“重启”：进程会原地重载配置、重建连接池并重新绑定监听，期间连接短暂中断，面板会话和已保存的配置保留。脚本也可以直接调用 `POST /api/restart`。

#### 服务端 SIGHUP 重载

服务端支持类似 `nginx -s reload` 的重载：修改 `-config` 指定的 YAML 后发送 `SIGHUP`，进程会重新读取文件并热应用，**不重启进程、不重绑监听、不断开已有隧道流**。

```bash
kill -HUP <pid>
# 或：systemctl reload relay-htcp    （ExecReload=/bin/kill -HUP $MAINPID）
```

行为细节：

- 只应用可热更新的字段（上表第一列），需要重启的字段会在日志里以 `restart_required` 明确列出，不会被静默忽略。
- 文件不存在、YAML 语法错误或校验失败时**保留当前运行配置**并记录 error，进程继续服务。
- 重载成功后同步写入管理数据库（启动时数据库优先于文件），磁盘上的 YAML 保持原样，不会被重排或丢掉注释。
- TLS 证书会在保存配置或 SIGHUP 时强制重新读取；即使不发信号，替换证书文件后也会在下一次握手前（最多 1 分钟后，按文件 mtime 检查）自动生效。替换成半写坏的证书时保留旧证书继续服务，只记录 warning。
- 没有配置文件（内置默认配置启动）时 SIGHUP 只打印一条 warning，不做任何变更。
- 客户端侧没有 SIGHUP 语义，仍是面板“重启”。

### 管理 API

启用 `admin.path` 后，所有接口都位于该前缀之下（例如 `/ops-console/api/status`）；下表的路径省略前缀。

所有 `/api/*` 接口（除登录和挑战外）都需要：

```
Authorization: Bearer <session-token 或 admin.token>
```

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/api/auth/challenge` | 获取登录公钥与一次性 nonce，公开接口，`Cache-Control: no-store` |
| `POST` | `/api/auth/login` | 登录，公开接口；接受 `encrypted` / `box` / 明文三种 body |
| `GET` | `/api/auth/me` | 当前身份 |
| `POST` | `/api/auth/logout` | 注销当前会话 |
| `GET` | `/api/status` | 实时状态 |
| `POST` | `/api/restart` | 重启客户端（重新读取配置、重建连接池、重新绑定监听）；仅客户端支持，需要 admin 权限 |
| `GET` | `/api/config` | 当前配置 YAML 与来源（`file`/`db`）；仅 admin，viewer 不可读（YAML 含 Token 明文） |
| `PUT` | `/api/config` | 保存配置，body 为 `{"yaml":"..."}` |
| `GET` | `/api/config/form` | 结构化表单 schema 与当前值（secret 字段已掩码） |
| `PUT` | `/api/config/form` | 保存表单，body 为 `{"values":{...}}`；secret 留空保持原值 |
| `GET` | `/api/tokens` | 客户端 Token 列表（仅服务端；密钥只返回尾部提示） |
| `GET` | `/api/tokens/{index}/traffic` | 单个 Token 的周期统计与最近日流量（`days` 默认 14） |
| `POST` | `/api/tokens` | 新建 Token，空 token 自动生成并在响应中返回一次 |
| `PUT` | `/api/tokens/{index}` | 修改名称/路由/启用状态/流量限制；`generate:true` 重新生成 |
| `DELETE` | `/api/tokens/{index}` | 删除 Token；至少保留一个 |
| `GET` | `/api/traffic/daily` | 当日日流量；服务端按 Token（`token`）筛选，客户端按服务端（`server`）筛选，默认最多 20 条 |
| `GET` | `/api/ip-access` | 黑白名单与当前识别到的客户端 IP |
| `PUT` | `/api/ip-access` | 保存黑白名单，立即生效 |
| `GET` | `/api/users` | 用户列表 |
| `POST` | `/api/users` | 创建用户 |
| `PUT` | `/api/users/{id}` | 修改密码/角色/启用状态 |
| `DELETE` | `/api/users/{id}` | 删除用户 |

示例（独立模式、根路径）：

```bash
# 登录（明文 body 保留给脚本；浏览器使用加密 body）
curl -s -X POST http://127.0.0.1:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"你的密码"}'

# 查询状态
curl -s http://127.0.0.1:8080/api/status \
  -H 'Authorization: Bearer rhtcp_...'

# 使用静态管理 Token
curl -s http://127.0.0.1:8080/api/status \
  -H 'Authorization: Bearer <admin.token>'
```

## 协议端点

| 方法 | 路径 | 认证 | 说明 |
|---|---|---|---|
| `POST` | `/tunnel` | Bearer Token | 控制流，保持长连接并交换 PING/PONG |
| `POST` | `/stream` | Bearer Token | 数据流，必须携带 `X-Tunnel-Target: <route>` |
| `POST` | `/relay/ping` | Bearer Token | xhttp 传输的保活请求 |
| `GET` | `/relay/download?session=<id>` | Bearer Token | xhttp 下载流，响应体持续输出帧 |
| `POST` | `/relay/upload?session=<id>` | Bearer Token | xhttp 上传批，body 为若干帧 |
| `GET` | `/health` | 无 | 健康检查，返回 `{"status":"ok","connections":N,"decoy_views":M}` |
| 其他 | 任意 | 无 | 启用伪装时返回诱饵页，否则返回 404 |

数据流请求头示例：

```
POST /stream HTTP/1.1
Host: tunnel.example.com
Authorization: Bearer <token>
X-Tunnel-Target: ssh
Content-Type: application/octet-stream
```

## 安全建议

1. **生产环境必须使用 TLS**，并优先使用真实 CA 签发的证书；不要长期启用 `insecure_skip_verify`。
2. **Token 要足够强**：至少 32 字节随机值（`openssl rand -hex 32`），每个服务使用独立 Token，并按最小权限配置 `routes`，不要复用。
3. **管理面板默认允许所有 IP 访问**。共用模式（`admin.shared: true`）会把登录入口放到隧道端口；上线前请把 `admin.path` 改成不易猜到的前缀，并在“IP 访问”页配置白名单/黑名单收紧访问，同时通过 TLS 暴露端口。远程管理优先走 SSH 端口转发或 VPN。
4. **不要在管理面板保存后手工改文件**，以免误以为配置已生效；以面板显示的来源为准。
5. **保护数据库、密钥文件和配置文件**：数据库中的配置与 Token 已加密，但 `<db_path>.key`（或 `RELAY_HTCP_MASTER_KEY`）是解密钥匙，应与数据库分开保管；配置文件写入权限为 `0600`，且内容仍是明文，数据库与配置文件都应限制访问。
6. **`/health` 是公开端点**，会暴露连接数；如不用于监控，建议在边界代理/防火墙处屏蔽。
7. **伪装不是加密**。TLS 才是传输保护手段；伪装只影响流量外观，无法对抗主动探测或流量分析。
8. 仅在你拥有或获得明确授权的网络和主机上使用本工具，并遵守当地法律法规。
9. **IP 访问控制页的规则会立即生效**。白名单配错可能把远程管理端锁在外面，回环地址（本机）始终保留；远程环境请先确认可通过 SSH 端口转发从本机恢复。转发头只在直连来源为回环/私有地址时才会被信任。

## 测试

```bash
go vet ./...
go test ./...
```

测试覆盖：

- 协议帧编解码、最大帧、非法类型、截断输入
- 服务端认证、路由权限、健康检查、诱饵页
- 端口默认 `:5630`、启动参数覆盖、Token 多路由校验、日志级别校验
- 无配置文件启动：服务端内置默认配置、自动创建 `data/admin.db`；客户端自动创建 `data/client.yaml`、`data/client-admin.db` 引导并可通过面板完成配置
- 客户端连接池、监听器热增删、配置热应用
- 端到端明文 h2c、TLS、断线重连
- xhttp 传输：h2c、TLS，以及经过 HTTP/1.1 流式反代（模拟 CDN）的端到端回显
- 客户端出口代理：HTTP CONNECT 与 SOCKS5 的端到端回显，默认关闭
- 管理后台登录、限流、会话、用户 CRUD、配置保存、角色权限
- 加密登录：WebCrypto 与 NaCl 两种载荷、nonce 单次使用、过期拒绝、前缀挂载与 IP 白名单
- 表单化配置：schema 路径校验、secret 掩码、留空保持原值、类型转换
- 客户端 Token 页：列表掩码、创建/更新/删除、路由校验、一次性生成
- IP 访问控制：白/黑名单、回环豁免、Cloudflare 转发头、规则持久化
- 配置入库加密：落库密文、信封数据密钥、错误主密钥拒绝、篡改检测、旧明文自动迁移

单独运行某个包：

```bash
go test ./internal/tunnel -run E2E -v
go test ./internal/admin -v
```

> Windows 上如果 `go test` 报测试二进制 `Access is denied`，通常是安全软件拦截了临时目录中的可执行文件。可先 `go test -c -o ui.test.exe ./internal/admin/ui/` 再手动运行，或把 Go 构建缓存目录加入白名单。

## 构建与发布

日常开发用 Makefile，等价命令也写在括号里；没有 `make` 时可直接用括号里的 `go` 命令。

| 目标 | 作用 |
|---|---|
| `make build` | 编译当前平台二进制到 `./relay-htcp`（Windows 为 `relay-htcp.exe`） |
| `make vet` / `make test` | `go vet ./...` / `go test ./...` |
| `make fmt-check` | 检查 `gofmt`，CI 使用 |
| `make all` | `vet` + `test`，提交前跑一遍 |
| `make licenses` | 收集依赖许可证到 `dist/THIRD_PARTY_LICENSES`，并复制 `LICENSE` |
| `make release` | 交叉编译各平台发布包到 `dist/`，并生成 `SHA256SUMS` |
| `make help` | 列出全部目标 |

版本号在编译期注入（`main.go` 里是 `var version`，可用 `-ldflags` 覆盖）：

```bash
make build VERSION=v0.2.0 && ./relay-htcp version   # relay-htcp v0.2.0
```

本地打全平台发布包（默认 `linux/amd64 linux/arm64 linux/386 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64`，可用 `PLATFORMS="..."` 覆盖）：

```bash
make release VERSION=v0.2.0
ls dist
# relay-htcp-v0.2.0-linux-amd64.tar.gz ... SHA256SUMS LICENSE THIRD_PARTY_LICENSES
```

每个发布包内含二进制、`LICENSE` 和 `THIRD_PARTY_LICENSES`；`dist/SHA256SUMS` 可用于下载后校验。

### GitHub Actions 发布

工作流在 `.github/workflows/release.yml`，两种触发方式：

```bash
# 1. 推标签：自动跑检查、打包、建 Release
git tag v0.2.0 && git push origin v0.2.0
```

2. 手动触发：Actions 页选择 **Release → Run workflow**，填写版本号（`v0.2.0` 或 `0.2.0` 均可），可勾选草稿 / 预发布。

流程固定为：确定并校验版本号 → `fmt-check` / `vet` / `test` → `make release` → 校验 `SHA256SUMS` → 生成下载说明 → 打标签（手动触发时）并 `gh release create`。标签已存在或 Release 已存在都会直接失败，避免覆盖已发布的产物。

## 目录结构

```
cmd/relay-htcp/        命令行入口（server / client / version）
internal/config/       YAML 配置解析、校验与默认值
internal/protocol/     自定义二进制帧协议
internal/tunnel/       隧道服务端、客户端连接池、数据流转发
internal/disguise/     浏览器头、诱饵页伪装
internal/admin/        管理后台 API、SQLite 存储（配置入库加密）、加密登录、认证与限流
internal/admin/ui/     内嵌的单页管理前端（主题、加密登录、表单配置、用户管理）
config/                服务端/客户端示例配置
data/                  运行时默认目录（client.yaml、admin.db / client-admin.db、主密钥、WAL；自动创建）
Makefile               构建、检查、打包入口
scripts/               发布辅助脚本（依赖许可证收集）
.github/workflows/     CI 发布流程
Task.md                最初的设计与实施方案
```

## 故障排查

| 现象 | 可能原因 | 处理 |
|---|---|---|
| 启动报 `auth.tokens: at least one token required` | 配置缺少 Token | 按示例添加 `auth.tokens` |
| 客户端 `server rejected tunnel: 401` | Token 不一致或未带 Bearer 前缀 | 核对两端 Token |
| `route not permitted`（403） | 当前 Token 的 `routes` 不包含该路由 | 在客户端 Token 页为该 Token 勾选该路由，或调整 Token |
| `unknown route`（404） | `listeners[].target` 与服务端 `routes[].name` 不一致 | 统一路由名 |
| `target unavailable`（502） | 服务端无法连接内网目标 | 检查目标地址、端口和服务状态 |
| `no live tunnel available` | 客户端未建立控制流 | 检查网络、TLS、Token 和服务端日志 |
| `x509: certificate signed by unknown authority` | 自签证书未被信任 | 配置 `tls.ca_file`，或测试时临时 `insecure_skip_verify: true` |
| `HTTP/2 required for tunnel streams` | 链路没有协商到 HTTP/2，或 HTTP/1.1 不支持全双工 | 使用 HTTPS 并确保端到端 h2；经过七层代理时改用 `transport: xhttp`（见[反向代理注意事项](#反向代理注意事项)） |
| 隧道频繁重连 | 网络抖动或心跳超时 | 适当增大 `heartbeat`/`heartbeat_miss`，检查 NAT 空闲超时 |
| 面板密码遗忘 | 首次密码只打印一次，且不会覆盖已有账号 | 备份后删除数据库重新初始化，或用 SQLite 工具更新 `admin_users.password_hash`；注意删除数据库会丢失面板中保存的配置和用户 |
| 启动报 `unwrap data key (wrong master key or corrupted database?)` | 密钥文件被替换或丢失，或 `RELAY_HTCP_MASTER_KEY` 与建库时不一致 | 恢复原来的密钥文件/环境变量；不要删除数据库 |

### 反向代理注意事项

代理怎么配取决于客户端 `servers[].transport`，两者必须匹配：

| 客户端 `transport` | 链路要求 | 可用的代理 |
|---|---|---|
| `http`（默认） | 端到端 HTTP/2 **全双工**：`POST /tunnel`、`POST /stream` 需要边读请求体边写响应体 | 只有 **TCP 四层透传**（或直连） |
| `xhttp` | 普通 HTTP/1.1 请求/响应：短 `POST /relay/upload` + 长 `GET /relay/download` | 四层、Nginx 七层、Cloudflare 等 CDN 均可 |

Nginx 不能把 HTTP/2 转给上游（`grpc_pass` 只适用于 gRPC），HTTP/1.1 上游也不保证全双工，所以**走七层代理时必须用 `xhttp`**；想保留默认的 `http` 传输，就只能用 `stream` 四层转发。

#### 方案 A：Nginx 七层 + xhttp（公网推荐）

```nginx
upstream relay_htcp {
    server 127.0.0.1:5630;
    keepalive 64;                 # xhttp 上传是大量短 POST，复用连接很关键
}

server {
    listen 443 ssl;
    http2 on;                     # nginx >= 1.25.1；老版本写 listen 443 ssl http2;
    server_name relay.example.com;

    ssl_certificate     /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;

    client_max_body_size 8m;      # 服务端单次上传上限 4 MiB，不必设成 512m

    location ^~ / {               # 不带尾斜杠，原样透传 /relay /health /admin
        proxy_pass http://relay_htcp;
        proxy_http_version 1.1;

        # 本项目不使用 WebSocket：清空 Connection 才能启用上游 keep-alive
        proxy_set_header Connection "";
        proxy_set_header Upgrade "";

        # 单跳代理：覆盖而不是追加，否则客户端自带的 XFF 可以伪造面板白名单
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;

        # 下载 GET 是长流式响应：必须关缓冲
        # （服务端也返回了 X-Accel-Buffering: no，这里显式关闭可覆盖不认该头的中转）
        proxy_buffering off;
        proxy_cache off;
        proxy_max_temp_file_size 0;

        # 上传随到随转，不等整个 body
        proxy_request_buffering off;

        # 客户端每 tunnel.heartbeat（默认 15s）发 PING，服务端在下载流回 PONG；
        # 读超时保持 > 3×heartbeat 即可，不必开到一小时
        proxy_connect_timeout 10s;
        proxy_send_timeout    300s;
        proxy_read_timeout    300s;
        send_timeout          300s;

        proxy_socket_keepalive on;
    }
}
```

客户端对应配置：

```yaml
servers:
  - name: nginx
    url: "https://relay.example.com"
    token: "与服务端一致的 Token"
    transport: xhttp
    xhttp_path: "/relay"      # 必须与服务端 tunnel.xhttp_path 一致

listeners:
  - local: "127.0.0.1:2222"
    target: "ssh"
    servers: [nginx]
    strategy: failover
```

关键点：

| 配置 | 原因 |
|---|---|
| `upstream` + `keepalive 64` + `proxy_set_header Connection ""` | 每个 xhttp 上传都是独立短 POST；`Connection: Upgrade`（WebSocket 写法）会让上游 keep-alive 失效 |
| `proxy_buffering off` / `proxy_cache off` | `/relay/download` 是长流式响应，缓冲会让数据攒在 nginx 里、延迟飙升甚至超时 |
| `proxy_request_buffering off` | 上传边到边转，避免先落盘再转发 |
| `proxy_read_timeout 300s` | 空闲时靠 PING/PONG 保活；超时时间要大于 `3 × tunnel.heartbeat` |
| `client_max_body_size 8m` | 服务端 `maxXHTTPUploadBody` 限制单次上传 4 MiB，太大的值只会让代理白收数据 |
| `X-Forwarded-For $remote_addr`（覆盖） | 面板取 XFF 的第一段；用 `$proxy_add_x_forwarded_for` 追加会保留客户端伪造值，可绕过 `admin.allowed_cidrs` |
| `location ^~ /` 且 `proxy_pass` 不带尾斜杠 | `proxy_pass http://x/;` 会吃掉路径前缀，导致 `/relay/*` 404 |

其他：

- 只想对外暴露隧道时，把 location 收窄成 `location ^~ /relay/ { ... }`，`/admin`、`/health` 就不经过公网；若保留 `^~ /`，建议在 nginx 里对面板路径加 `allow/deny` 或依赖面板自身的 IP 白名单。
- 不要改写 `Authorization`、`X-Tunnel-Target`、`X-Tunnel-Protocol` 等头部，也不要对 `/relay/*` 开启 gzip 或内容改写——帧是二进制流，必须原样透传。
- 面板的 IP 白名单只在直连对端是回环/链路本地时信任 `CF-Connecting-IP`、`X-Forwarded-For`、`X-Real-IP`，所以本机 nginx 反代可以正常识别真实客户端；再往上一层是 Cloudflare 时优先用 `CF-Connecting-IP`。
- 前面还有 CDN（Cloudflare 等）时，CDN 会掐空闲连接，保持默认 15s 心跳即可，但不要把 `proxy_read_timeout` 设到 60s 以下。

验证：

```bash
nginx -t && nginx -s reload
curl -s https://relay.example.com/health     # {"status":"ok","connections":N,...}
```

客户端日志应出现 `tunnel established server=nginx ...`，服务端 `/health` 的 `connections` 会随 `tunnel.connections` 增长。

#### 方案 B：四层透传（保留 `http` 传输）

```nginx
stream {
    upstream relay_htcp { server 127.0.0.1:5630; }
    server {
        listen 8443;
        proxy_pass relay_htcp;
        proxy_timeout 1h;             # 隧道是长连接
        proxy_socket_keepalive on;
    }
}
```

此时 TLS 由 relay-htcp 自己终结（服务端配置 `tls.cert`/`tls.key`），客户端写 `url: "https://relay.example.com:8443"`、`transport: http`；自签证书用 `tls.ca_file` 或临时 `insecure_skip_verify: true`。这种形态下证书热加载和 `SIGHUP` 重载仍然有效（TLS 不经过代理终结）。

#### 不支持的组合

- `http` 传输 + Nginx `proxy_pass` 七层：请求体会被缓冲或整包转发，隧道会卡死或超时，日志常见 `HTTP/2 required for tunnel streams` 或 5 分钟后断开。
- 让七层代理压缩、改写或缓存 `/relay/*` 的响应：帧是二进制流，任何改写都会破坏协议。


## 已知限制与后续方向

- 仅支持 TCP，不支持 UDP。
- 需要在客户端显式配置本地监听端口，不提供 TUN/透明代理模式。
- 不自动申请 TLS 证书（ACME）；证书内容可热加载，但更换路径或启用/关闭 TLS 需重启。
- 管理面板独立监听时不提供 TLS；共用模式复用隧道端口的 TLS（h2c 时仍为明文），请配合 IP 白名单使用。
- 暂无内置的密码重置命令、Prometheus 指标、带宽/配额限制。
- 当前功能验证以单元测试和端到端测试为主，尚未包含大规模长稳压测。

## 许可证

本项目采用 [Apache License 2.0](LICENSE) 授权，版权归 `relay-htcp contributors` 所有。

- 允许商用、修改、分发和私有化部署，需保留版权声明与 `LICENSE` 文件；
- 分发修改后的版本时，须标注你做了哪些改动；
- 附带明确的专利授权，同时禁止使用项目名称/商标暗示官方背书；
- 软件按“现状”提供，不附带任何担保。

> 免责提醒：本工具用于合法授权的网络访问。请遵守当地法律法规及你所在组织的安全策略，仅在你拥有或获得明确授权的主机上使用。
