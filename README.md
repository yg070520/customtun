# CustomTun

一个轻量级 SSH 隧道服务，配合 Caddy 实现自定义域名的 HTTP 反向代理。通过一条 SSH 命令，将本地服务暴露到公网。

## 核心特性

- **自定义子域名** — 交互式输入自定义子域名，或自动生成随机域名
- **Caddy 集成** — 自动通过 Caddy Admin API 注册/注销反向代理路由，支持自动 HTTPS
- **SSH 端口转发** — 基于 SSH `-R` 参数实现安全的远程端口转发
- **零客户端配置** — 客户端只需标准 SSH 命令，无需安装额外工具
- **连接保护** — IP 速率限制、并发限制、自动封禁等滥用防护机制

## 快速使用

```bash
ssh -p 8888 -t -R 8080:localhost:8080 yourdomain.com
```

连接后进入交互界面：

```
Welcome to yourdomain.com!
You can choose a custom subdomain or get a random one.
Rules: 3-32 chars, lowercase letters, numbers, and hyphens only.

Enter subdomain (or press Enter for random): myapp

Connection successful!
Assigned domain: myapp.yourdomain.com
Forwarding:     myapp.yourdomain.com -> localhost:8080
Press Ctrl+C to disconnect.
```

访问 `https://myapp.yourdomain.com` 即可访问本地 `localhost:8080` 的服务。

## 工作原理

```text
客户端                          服务器
┌──────────┐    SSH -R     ┌──────────────┐     Caddy API      ┌───────────┐
│ App:8080 │◄──────────────│ CustomTun    │────────────────────►│  Caddy    │
└──────────┘  端口转发      │ (SSH :8888)  │  注册/注销路由      │ (HTTPS)   │
                           └──────────────┘                    └─────┬─────┘
                                  ▲                                  │
                                  │         ┌────────────────┐       │
                                  └─────────│ Tunnel Listener│◄──────┘
                                            │ 127.0.0.1:rand │  反向代理
                                            └────────────────┘
```

1. 客户端通过 `ssh -R` 建立 SSH 端口转发
2. 服务端交互提示输入子域名（或自动生成）
3. 服务端调用 Caddy Admin API 注册路由 `subdomain.domain → 127.0.0.1:<随机端口>`
4. 外部请求到达 Caddy → 转发到本地 listener → 通过 SSH 转发到客户端
5. 客户端断开时自动删除 Caddy 路由

## 前置条件

- 已安装并运行 [Caddy](https://caddyserver.com/)，Admin API 监听 `localhost:2019`
- 域名 DNS 已配置通配符解析：`*.yourdomain.com → YOUR_SERVER_IP`
- Go 1.24+（编译时需要）

## 部署

### 1. DNS 配置

```text
A    yourdomain.com      → YOUR_SERVER_IP
A    *.yourdomain.com    → YOUR_SERVER_IP
```

### 2. Caddy 配置

确保 Caddy 运行并有基础 HTTP 服务配置（Admin API 默认监听 `localhost:2019`）。

### 3. 编译运行

```bash
git clone https://github.com/yg070520/customtun.git
cd customtun
go build -o customtun cmd/tunnl/main.go
./customtun
```

## 配置

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `SSH_ADDR` | `:8888` | SSH 监听地址 |
| `HOST_KEY_PATH` | `host_key` | SSH Host Key 路径（首次运行自动生成） |
| `DOMAIN` | `jatus.top` | 服务域名 |
| `CADDY_ADMIN_URL` | `http://localhost:2019` | Caddy Admin API 地址 |

## 项目结构

```text
customtun/
├── cmd/tunnl/              # 程序入口
│   └── main.go
├── internal/
│   ├── config/             # 配置常量
│   │   └── config.go
│   ├── server/             # 服务端实现
│   │   ├── server.go       # Server 结构体，子域名管理
│   │   ├── ssh.go          # SSH 连接处理，交互式子域名选择
│   │   ├── caddy.go        # Caddy Admin API 路由管理
│   │   └── abuse.go        # 滥用追踪与 IP 封禁
│   └── subdomain/          # 子域名生成与校验
│       └── subdomain.go
├── Dockerfile
├── docker-compose.yml
└── Makefile
```

## 保护机制

| 限制项 | 值 | 说明 |
|--------|-----|------|
| 每 IP 并发连接 | 3 | 单 IP 最多同时 3 个隧道 |
| 总连接数 | 1000 | 服务器最大隧道数 |
| 每分钟新连接 | 10 | 单 IP 每分钟最多新建 10 个连接 |
| SSH 握手超时 | 30s | 握手未完成则断开 |
| IP 封禁时长 | 1 小时 | 触发封禁后的屏蔽时间 |
| 触发封禁阈值 | 10 次违规 | 累计违规次数达到后自动封禁 |

## 客户端建议

### 保持连接稳定

```bash
ssh -p 8888 -t -R 8080:localhost:8080 \
  -o "ServerAliveInterval=10" \
  -o "ServerAliveCountMax=3" \
  yourdomain.com
```

### 使用 autossh 自动重连

```bash
autossh -M 0 -p 8888 -t -R 8080:localhost:8080 \
  -o "ServerAliveInterval=10" \
  -o "ServerAliveCountMax=3" \
  yourdomain.com
```

## License

MIT
