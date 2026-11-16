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
- **认证与路由**：Bearer Token 认证；每个 Token 可限制可访问的路由；路由名到内网地址的映射在服务端集中管理。
- **心跳与自愈**：PING/PONG 保活，连续丢失 `heartbeat_miss` 次后自动重连；指数退避。
- **TLS**：支持真实证书、自签证书、自定义 CA；ALPN 优先协商 `h2`。
- **明文 h2c**：无 TLS 时使用 HTTP/2 明文（h2c），适合内网和测试。
- **伪装（可选）**：浏览器风格请求头、仿 nginx 的 `Server` 头、未知路径返回静态诱饵页。
- **热更新**：通过管理面板修改配置，部分字段无需重启即可生效。
- **端口共用与伪装**：服务端管理面板可挂到隧道端口下的自定义路径，外部只看到一个 Web 服务。
- **加密登录与主题**：登录密码用 RSA-OAEP + AES-GCM（不支持 WebCrypto 时回退 TweetNaCl）加密；支持跟随系统/深色/浅色/纯黑主题。
- **表单化配置**：配置页按角色渲染结构化表单，密钥字段掩码显示、留空保持原值；仍可切换到 YAML 高级模式。
- **密钥入库加密**：SQLite 中的配置与 Token 采用 AES-256-GCM 信封加密（随机数据密钥 + 独立主密钥），主密钥默认保存在数据库旁的 `0600` 密钥文件，也可用环境变量注入。
- **管理面板**：登录、实时状态、连接与流量统计、配置编辑、用户与角色管理，前端已内嵌进二进制。
- **单个二进制**：无额外运行时依赖；配置文件、TLS 证书和可选的 SQLite 数据库按需挂载。

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

go build -trimpath -o relay-htcp ./cmd/relay-htcp
# Windows:
# go build -trimpath -o relay-htcp.exe ./cmd/relay-htcp
```

也可以直接运行：

```bash
go run ./cmd/relay-htcp version
```

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
listen: ":8443"

tls:
  cert: "server.crt"
  key: "server.key"

auth:
  tokens:
    - name: office-laptop
      token: "请替换为足够随机的长 Token"
      routes: [ssh]          # 留空表示允许所有路由
    - name: ops
      token: "另一个 Token"
      # routes 省略 = 所有路由

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

启动：

```bash
./relay-htcp server -config server.yaml
```

### 5. 配置并启动客户端

`client.yaml`：

```yaml
server: "https://tunnel.example.com:8443"

tls:
  ca_file: "server.crt"       # 使用自签证书时
  # insecure_skip_verify: true  # 仅测试环境

auth:
  token: "请替换为服务端配置的同一个 Token"

listeners:
  - local: "127.0.0.1:2222"
    target: "ssh"
  - local: "127.0.0.1:33060"
    target: "mysql"

tunnel:
  connections: 2
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

启动：

```bash
./relay-htcp client -config client.yaml
```

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
server: "http://192.168.1.10:8080"
```

注意：h2c 不加密，Token 和数据都会以明文传输，只应在可信网络中使用。

## 配置参考

配置采用 YAML，启动时校验；未知字段会被忽略，必填项缺失会直接报错退出。

### 服务端 `server.yaml`

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `listen` | string | 必填 | 监听地址，如 `:8443`、`127.0.0.1:8443` |
| `tls.cert` | string | 空 | 证书文件路径；与 `tls.key` 同时为空时使用明文 h2c |
| `tls.key` | string | 空 | 私钥文件路径 |
| `auth.tokens` | list | 必填 | 至少一个 Token，Token 值不能为空且不能重复 |
| `auth.tokens[].name` | string | 空 | 身份名称，用于日志和管理面板展示 |
| `auth.tokens[].token` | string | 必填 | Bearer Token 明文，建议至少 32 字节随机值 |
| `auth.tokens[].routes` | list | 空 | 允许访问的路由名；为空表示允许所有路由 |
| `routes` | list | 必填 | 至少一个路由，名称不能重复 |
| `routes[].name` | string | 必填 | 逻辑路由名，客户端通过 `X-Tunnel-Target` 引用 |
| `routes[].target` | string | 必填 | 内网目标地址，如 `127.0.0.1:22` |
| `tunnel.max_concurrent_streams` | int | `128` | 每条 HTTP/2 连接允许的并发流上限，需重启生效 |
| `tunnel.max_connections` | int | `0` | 同时在线控制连接数上限，`0` 表示不限制 |
| `tunnel.dial_timeout` | duration | `10s` | 拨号内网目标的超时时间 |
| `tunnel.idle_timeout` | duration | `90s` | 控制流静默多久后断开 |
| `disguise.enabled` | bool | `true` | 是否启用诱饵页和伪装响应头 |
| `log.level` | string | `info` | `debug` / `info` / `warn` / `error` |
| `admin.*` | object | 见下文 | 管理面板配置 |

### 客户端 `client.yaml`

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `server` | string | 必填 | 服务端地址，格式 `scheme://host[:port]`，不能带路径；`https://` 走 TLS，`http://` 走 h2c |
| `tls.insecure_skip_verify` | bool | `false` | 跳过证书校验，仅测试环境使用 |
| `tls.ca_file` | string | 空 | 自定义 CA 证书（PEM），用于自签或私有 CA |
| `auth.token` | string | 必填 | 与服务端 Token 一致 |
| `listeners` | list | 必填 | 至少一个本地监听，`local` 不能重复 |
| `listeners[].local` | string | 必填 | 本地监听地址，如 `127.0.0.1:2222` |
| `listeners[].target` | string | 必填 | 服务端路由名 |
| `tunnel.connections` | int | `2` | 连接池大小，即独立 HTTP/2 连接数，需重启生效 |
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
| `allowed_cidrs` | list | 共用模式默认回环 | 允许访问面板的 CIDR；独立模式为空表示不限制 |
| `listen` | string | `127.0.0.1:8080` | 仅 `shared: false` 时使用，务必只绑定内网/回环地址 |
| `token` | string | 空 | 可选的静态管理 Token，供脚本直接访问 API，拥有 admin 权限 |
| `db_path` | string | `relay-htcp-admin.db` | SQLite 数据库路径 |
| `key_file` | string | `<db_path>.key` | 配置入库加密的主密钥文件；首次启动自动生成（0600） |
| `default_username` | string | `admin` | 首次运行创建的管理员用户名 |
| `default_password` | string | 空 | 首次运行的管理员密码；为空则随机生成并只在日志中打印一次 |
| `session_ttl` | duration | `24h` | 登录会话有效期 |

> 服务端和客户端默认都使用 `127.0.0.1:8080`。若在同一台机器上同时运行两端，请为其中一个改端口（示例配置中客户端使用 `8081`）。`shared` 只对服务端有效；客户端没有入站隧道端口，始终使用独立监听。

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
  allowed_cidrs: ["127.0.0.0/8", "::1/128"]
  db_path: "relay-htcp-admin.db"
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
  listen: "127.0.0.1:8080"
  db_path: "relay-htcp-admin.db"
```

第一次启动时，日志会打印：

```
admin panel: created default user with a generated initial password (shown only once) user=admin password=...
```

请立即保存该密码并登录：

- 共用模式：`https://tunnel.example.com:8443/ops-console/`（即隧道端口 + `admin.path`）
- 独立模式：`http://127.0.0.1:8080/ops-console/`

如果服务端在远程机器上，建议通过 SSH 端口转发访问共用端口（源地址会呈现为回环，正好命中默认白名单）：

```bash
ssh -L 8443:127.0.0.1:8443 user@server
# 然后打开 http://127.0.0.1:8443/ops-console/
```

### 登录安全与主题

- **加密登录**：浏览器先请求一次 `POST /api/auth/challenge` 获取 RSA 公钥、X25519 公钥和一次性 nonce，再用 WebCrypto（AES-GCM + RSA-OAEP）加密 `{username,password,nonce}`；不支持 `crypto.subtle` 的明文 HTTP 环境自动回退到 TweetNaCl box。密码不会以明文进入请求体，nonce 单次有效、防重放。
- 这层加密只是让被动观察者看不到密码，**不能替代 TLS**；公网共用端口仍应启用 TLS。
- **主题**：支持 跟随系统 / 深色 / 浅色 / 纯黑，登录页和顶栏都能切换，选择保存在浏览器 `localStorage`。
- 登录后默认进入结构化配置表单，密钥字段始终掩码；支持切换 YAML 高级模式。

面板包含三个页签：

- **状态**：运行时长、活跃隧道/连接、上下行字节数、诱饵页访问次数、实时连接列表。
- **配置**：默认使用结构化表单编辑，字段分组随服务端/客户端角色自动变化；可切换到 YAML 高级模式。保存结果会列出哪些字段已热应用、哪些需要重启。
- **用户**：创建/修改/删除用户，分配 `admin` 或 `viewer` 角色，启用/禁用账号。

### 表单化配置

配置页默认按角色渲染结构化表单：服务端包含监听/TLS、隧道参数、内网路由、客户端 Token；客户端包含服务端连接、本地监听、隧道参数。表单由后端 schema 驱动（`Provider.ConfigFormSchema`），后续新增可调参数只需在 schema 中加一行，前端和 API 无需改动。

密钥字段掩码规则：

- `GET /api/config/form` 中所有 secret 字段恒为空字符串，明文凭证不会发送到浏览器；
- 保存时留空表示“保持原值”；表格行用隐藏的 `_id` 对应原行，增删行、改名都不会误删已有 Token；
- 需要更换时直接填入新值即可，保存后仍按前述方式加密入库。

如果更习惯直接编辑整段配置，可点“YAML”切回原有模式；该模式下已登录用户仍能看到明文，`viewer` 权限需谨慎授予。

### 角色与安全机制

- `admin`：可读写配置和用户。
- `viewer`：只读，可查看状态和完整配置，但不能修改配置或用户。
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
| 服务端 | `auth.tokens`、`routes`、`tunnel.dial_timeout`、`tunnel.idle_timeout`、`tunnel.max_connections`、`disguise.enabled` | `listen`、`tls`、`tunnel.max_concurrent_streams`、`log.level` |
| 客户端 | `listeners`（新增/删除/改目标）、`disguise` | `server`、`auth.token`、`tls`、`tunnel.*`、`log.level` |

客户端删除或改目标监听器时，已建立的连接会继续跑到结束，不会被强行中断。

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
| `GET` | `/api/config` | 当前配置 YAML 与来源（`file`/`db`） |
| `PUT` | `/api/config` | 保存配置，body 为 `{"yaml":"..."}` |
| `GET` | `/api/config/form` | 结构化表单 schema 与当前值（secret 字段已掩码） |
| `PUT` | `/api/config/form` | 保存表单，body 为 `{"values":{...}}`；secret 留空保持原值 |
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
2. **Token 要足够强**：至少 32 字节随机值（`openssl rand -hex 32`），不同客户端使用不同 Token，并按需限制 `routes`。
3. **管理面板默认只允许回环访问**。共用模式（`admin.shared: true`）会把登录入口放到隧道端口，请务必：把 `admin.path` 改成不易猜到的前缀、保留 `allowed_cidrs` 白名单（默认仅回环）、并通过 TLS 暴露端口；远程管理优先走 SSH 端口转发或 VPN。
4. **不要在管理面板保存后手工改文件**，以免误以为配置已生效；以面板显示的来源为准。
5. **保护数据库、密钥文件和配置文件**：数据库中的配置与 Token 已加密，但 `<db_path>.key`（或 `RELAY_HTCP_MASTER_KEY`）是解密钥匙，应与数据库分开保管；配置文件写入权限为 `0600`，且内容仍是明文，数据库与配置文件都应限制访问。
6. **`/health` 是公开端点**，会暴露连接数；如不用于监控，建议在边界代理/防火墙处屏蔽。
7. **伪装不是加密**。TLS 才是传输保护手段；伪装只影响流量外观，无法对抗主动探测或流量分析。
8. 仅在你拥有或获得明确授权的网络和主机上使用本工具，并遵守当地法律法规。

## 测试

```bash
go vet ./...
go test ./...
```

测试覆盖：

- 协议帧编解码、最大帧、非法类型、截断输入
- 服务端认证、路由权限、健康检查、诱饵页
- 客户端连接池、监听器热增删、配置热应用
- 端到端明文 h2c、TLS、断线重连
- 管理后台登录、限流、会话、用户 CRUD、配置保存、角色权限
- 加密登录：WebCrypto 与 NaCl 两种载荷、nonce 单次使用、过期拒绝、前缀挂载与 IP 白名单
- 表单化配置：schema 路径校验、secret 掩码、留空保持原值、类型转换
- 配置入库加密：落库密文、信封数据密钥、错误主密钥拒绝、篡改检测、旧明文自动迁移

单独运行某个包：

```bash
go test ./internal/tunnel -run E2E -v
go test ./internal/admin -v
```

> Windows 上如果 `go test` 报测试二进制 `Access is denied`，通常是安全软件拦截了临时目录中的可执行文件。可先 `go test -c -o ui.test.exe ./internal/admin/ui/` 再手动运行，或把 Go 构建缓存目录加入白名单。

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
Task.md                最初的设计与实施方案
```

## 故障排查

| 现象 | 可能原因 | 处理 |
|---|---|---|
| 启动报 `auth.tokens: at least one token required` | 配置缺少 Token | 按示例添加 `auth.tokens` |
| 客户端 `server rejected tunnel: 401` | Token 不一致或未带 Bearer 前缀 | 核对两端 Token |
| `route not permitted`（403） | 当前 Token 的 `routes` 不包含该路由 | 在服务端为该 Token 添加路由或清空 `routes` |
| `unknown route`（404） | `listeners[].target` 与服务端 `routes[].name` 不一致 | 统一路由名 |
| `target unavailable`（502） | 服务端无法连接内网目标 | 检查目标地址、端口和服务状态 |
| `no live tunnel available` | 客户端未建立控制流 | 检查网络、TLS、Token 和服务端日志 |
| `x509: certificate signed by unknown authority` | 自签证书未被信任 | 配置 `tls.ca_file`，或测试时临时 `insecure_skip_verify: true` |
| `HTTP/2 required for tunnel streams` | 链路没有协商到 HTTP/2，或 HTTP/1.1 不支持全双工 | 使用 HTTPS 并确保端到端 h2；代理需支持流式双向转发 |
| 隧道频繁重连 | 网络抖动或心跳超时 | 适当增大 `heartbeat`/`heartbeat_miss`，检查 NAT 空闲超时 |
| 面板密码遗忘 | 首次密码只打印一次，且不会覆盖已有账号 | 备份后删除数据库重新初始化，或用 SQLite 工具更新 `admin_users.password_hash`；注意删除数据库会丢失面板中保存的配置和用户 |
| 启动报 `unwrap data key (wrong master key or corrupted database?)` | 密钥文件被替换或丢失，或 `RELAY_HTCP_MASTER_KEY` 与建库时不一致 | 恢复原来的密钥文件/环境变量；不要删除数据库 |

### 反向代理注意事项

- 推荐使用 **TCP 四层转发**，让 TLS 和 HTTP/2 端到端保持原样。
- 如果使用 Nginx 等七层代理，必须关闭请求/响应缓冲，保证双向流式转发；如果代理只能以 HTTP/1.1 与上游通信，还需确认其支持全双工流式转发，否则长连接数据流可能被缓冲或卡住。
- 不要让代理改写 `Authorization`、`X-Tunnel-Target`、`X-Tunnel-Protocol` 等头部。

## 已知限制与后续方向

- 仅支持 TCP，不支持 UDP。
- 需要在客户端显式配置本地监听端口，不提供 TUN/透明代理模式。
- 不自动申请或热加载 TLS 证书；证书变更需重启。
- 管理面板独立监听时不提供 TLS；共用模式复用隧道端口的 TLS（h2c 时仍为明文），请配合 IP 白名单使用。
- 暂无内置的密码重置命令、Prometheus 指标、带宽/配额限制。
- 当前功能验证以单元测试和端到端测试为主，尚未包含大规模长稳压测。

## 许可证

本仓库目前未包含 `LICENSE` 文件。使用、分发或商用前请先与项目所有者确认授权方式。
