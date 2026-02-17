# Dynamic Proxy 代码运行逻辑总览

本文基于 `main.go` 的实际执行路径，按“启动 → 更新代理池 → 对外服务请求”顺序说明。

## 1. 启动阶段（`main`）

程序入口会先读取 `config.yaml`，做默认值填充与配置校验（例如认证必须用户名密码同时存在）。随后创建两个代理池：
- `strictPool`（严格模式）
- `relaxedPool`（宽松模式）

然后先同步执行一次代理更新，确保尽量在服务监听前有可用代理；之后再启动 4 个服务协程：
1. SOCKS5 Strict
2. SOCKS5 Relaxed
3. HTTP Strict
4. HTTP Relaxed

主协程通过 `WaitGroup` 阻塞，保持进程常驻。

## 2. 配置加载与默认值策略

`loadConfig` 的行为：
- 读取并解析 YAML。
- 校验 `proxy_list_urls` 至少 1 个。
- 为并发数、更新间隔、健康检查超时、端口等字段设置默认值。
- 校验认证配置一致性（用户名和密码要么都空，要么都非空）。

认证开关通过 `isProxyAuthEnabled()` 统一判断。

## 3. 代理池数据结构与轮换策略

`ProxyPool` 内部维护：
- `proxies []string`：当前可用代理列表
- `index`：当前选中的代理下标
- `nextSwitch`：下次切换时间
- `hasSelected`：是否已经完成首选

核心行为：
- `Update`：替换代理列表并重置轮换状态。
- `GetNext`：
  - 更新后首次请求固定使用第 1 个代理；
  - 同一个代理保持使用 30 分钟（`proxySwitchInterval`）；
  - 到期后按环形顺序切换。

这不是“每请求轮询”，而是“按时间片轮换”。

## 4. 代理抓取与解析流程

`fetchProxyList` 从两类来源抓取：
- `proxy_list_urls`：普通格式（逐行解析，移除 `http://` / `https://` / `socks4://` / `socks5://` 前缀）
- `special_proxy_list_urls`：复杂格式（`parseSpecialProxyURL` 用正则从任意文本中抽取 `ip:port`）

两个来源最终都归一化为 `ip:port`，并通过 `map` 去重。若最终为空，视为抓取失败。

## 5. 健康检查模型（Strict + Relaxed）

`healthCheckProxies` 对每个候选代理执行并发检测（受 `health_check_concurrency` 控制）：

1. 先做 strict 检查：
   - 经 SOCKS5 连接到 `www.google.com:443`
   - 执行 TLS 握手并校验证书（`InsecureSkipVerify=false`）
   - 握手耗时需低于阈值 `tls_handshake_threshold_seconds`
2. strict 成功则直接同时记入 strict/relaxed。
3. strict 失败再做 relaxed：
   - 同样握手流程，但不校验证书（`InsecureSkipVerify=true`）

此外每个代理检测都有总超时（`total_timeout_seconds`），并打印进度条日志。

## 6. 代理池更新与定时任务

`updateProxyPool` 包含完整链路：抓取 → 健康检查 → 更新 strict/relaxed 两个池。

并发保护：
- 使用 `atomic.CompareAndSwapInt32` 防止重复更新重入。
- 若某模式本次无健康代理，则保留旧池不覆盖，避免“更新后归零”。

`startProxyUpdater`：
- 可先执行一次同步更新（启动阶段传 `true`）。
- 再按 `update_interval_minutes` 周期触发异步更新。

## 7. SOCKS5 服务请求路径

SOCKS5 服务通过 `go-socks5` 启动。

对每个连接请求：
1. `CustomDialer.Dial` 从对应池获取当前代理。
2. 构造到上游代理的 SOCKS5 dialer。
3. 通过上游代理拨号目标地址。
4. 返回 `LoggedConn` 包装连接，记录读写字节与关闭日志。

如果配置了认证，SOCKS5 会启用用户名密码认证。

## 8. HTTP/HTTPS 服务请求路径

HTTP 服务统一入口 `handleHTTPProxy`：
1. 记录请求日志。
2. 校验 `Proxy-Authorization`（仅 Basic，且仅在开启认证时强制）。
3. 从池中拿代理并创建 SOCKS5 dialer。
4. 分流：
   - `CONNECT`：走 `handleHTTPSProxy`（隧道模式）
   - 普通 HTTP 方法：构造新请求后通过 `http.Client` 转发

细节：
- 转发普通 HTTP 时会删除 `Proxy-Authorization` 头，避免向目标站泄漏代理凭据。
- HTTPS `CONNECT` 通过 Hijack 底层连接，返回 `200 Connection Established` 后做双向 `io.Copy`。

## 9. 认证机制

- 开关：`auth.username` 与 `auth.password` 同时非空。
- HTTP：检查 `Proxy-Authorization: Basic ...`。
- SOCKS5：配置 `UserPassAuthenticator`。

若只配置用户名或只配置密码，程序在启动时直接报错退出。

## 10. 运行特性与注意点

- 双池并行：strict 提供更高安全性，relaxed 提供更高兼容性。
- 轮换粒度是“30 分钟”，非每请求切换。
- 健康检查依赖对 `www.google.com:443` 的可达性，在某些网络环境可能导致可用代理被误判。
- 抓取阶段 `InsecureSkipVerify=true`，方便从证书异常源拉取列表，但降低了源站证书校验安全性。
