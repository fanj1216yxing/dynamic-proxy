

## 中文

高性能的 SOCKS5/HTTP 动态代理服务器，自动从代理列表获取、测活并轮询使用代理。

### 功能特性

- 🚀 **多源支持**: 同时从多个URL获取代理
- 🔄 **自动轮换**: 轮询算法自动切换代理
- 💪 **高并发**: 可配置的并发健康检查（默认200）
- ⚡ **快速测活**: TLS握手验证和性能过滤
- 🔧 **灵活配置**: 基于YAML的配置文件
- 🌐 **双协议**: SOCKS5和HTTP代理服务器
- 🔒 **HTTPS支持**: 完整的CONNECT隧道支持
- 📊 **实时进度**: 健康检查时的实时进度条
- 🎯 **智能过滤**: 自动移除慢速和不可靠的代理
- 🔁 **自动更新**: 定期刷新代理池（可配置间隔）
- 🔐 **双模式**: 严格模式（启用SSL验证）和宽松模式（禁用SSL验证）
- 🧩 **混合协议识别**: HTTP Mixed 入口可识别 socks5/socks5h/http/https/vmess/vless/hy2（后3者按 HTTPS CONNECT 兼容模式接入）

### 快速开始


```bash
# 克隆仓库
git clone https://github.com/fanj1216yxing/dynamic-proxy.git
cd dynamic-proxy

# 下载依赖
go mod download

# 编译
go build -o dynamic-proxy

# 运行
./dynamic-proxy
```

#### Docker 部署

**使用 Docker:**

```bash
# 构建镜像
docker build -t dynamic-proxy .

# 运行容器
docker run -d \
  --name dynamic-proxy \
  -p 17233:17233 \
  -p 17283:17283 \
  -p 17284:17284 \
  -p 17285:17285 \
  -p 17286:17286 \
  -p 17287:17287 \
  -p 17288:17288 \
  -p 17289:17289 \
  -p 17290:17290 \
  -v $(pwd)/config.yaml:/app/config.yaml:ro \
  --restart unless-stopped \
  dynamic-proxy
```

**使用 Docker Compose:**

```bash
# 启动服务
docker-compose up -d

# 查看日志
docker-compose logs -f

# 停止服务
docker-compose down
```

**Docker 配置说明:**

Docker 镜像使用多阶段构建，体积最小化：
- 基础镜像: Alpine Linux
- 包含 CA 证书支持 HTTPS
- 暴露端口:
  - 17233 展示当前代理池内所有的代理
  - 17283 (SOCKS5 严格模式 - 启用SSL验证)
  - 17284 (SOCKS5 宽松模式 - 禁用SSL验证)
  - 17285 (HTTP 严格模式 - 启用SSL验证)
  - 17286 (HTTP 宽松模式 - 禁用SSL验证)
  - 17287 (轮换控制端口 - 随机切换到一个新的健康代理)
  - 17288 (HTTP 混合入口 - 仅自动使用 HTTP/HTTPS/SOCKS5 上游代理)
  - 17289 (HTTP CF 混合入口 - 自动使用可通过 CF 挑战的 HTTP/HTTPS/SOCKS5 上游代理)
  - 17290 (HTTP 主流协议混合入口 - 自动使用 VMESS/VLESS/HY2 上游代理)
- 配置文件可通过卷挂载，方便更新

### 配置说明

编辑 `config.yaml` 自定义设置：

```yaml
# 代理列表URL（支持多个源）
proxy_list_urls:
  - "https://raw.githubusercontent.com/r00tee/Proxy-List/main/Socks5.txt"
  - "https://raw.githubusercontent.com/ClearProxy/checked-proxy-list/main/socks5/raw/all.txt"
  # 也支持 Clash 订阅（YAML），会自动识别并提取 socks5/socks5h/http/https/vmess/vless/hy2 节点
  # 添加更多源
  # - "https://example.com/proxy-list.txt"

# 健康检查并发数（同时测试数量）
health_check_concurrency: 2000

# 更新间隔（分钟）
update_interval_minutes: 5
proxy_switch_interval_min: 30          # 自动轮换间隔（分钟），填 now 表示每次请求都轮换

# 单阶段健康检查超时设置（当两阶段关闭时生效）
health_check:
  total_timeout_seconds: 8              # 总超时时间
  tls_handshake_threshold_seconds: 4    # TLS握手阈值

# 两阶段健康检查（工业级大规模代理池推荐）
health_check_two_stage:
  enabled: true
  stage_one:                            # 第一阶段：快速淘汰
    total_timeout_seconds: 4
    tls_handshake_threshold_seconds: 2
  stage_two:                            # 第二阶段：精细检测
    total_timeout_seconds: 8
    tls_handshake_threshold_seconds: 4

# 主流协议内核配置
detector:
  core: ""                 # 可选: mihomo | meta | singbox；为空时主流协议拨号不启用

# 服务器端口
ports:
  socks5_strict: ":17283"    # SOCKS5 严格模式（启用SSL验证）
  socks5_relaxed: ":17284"   # SOCKS5 宽松模式（禁用SSL验证）
  http_strict: ":17285"      # HTTP 严格模式（启用SSL验证）
  http_relaxed: ":17286"     # HTTP 宽松模式（禁用SSL验证）
  rotate_control: ":17287"  # 访问该端口随机切换到一个新的健康代理
  http_mixed: ":17288"      # HTTP混合入口（仅自动选择 HTTP/HTTPS/SOCKS5 上游）
  http_cf_mixed: ":17289"   # HTTP混合入口（仅使用可通过CF挑战的 HTTP/HTTPS/SOCKS5 上游）
  http_mainstream_mixed: ":17290" # HTTP混合入口（仅自动选择 VMESS/VLESS/HY2 上游）

# 可选代理认证（username/password 必须同时配置）
auth:
  username: ""
  password: ""
```

#### 配置选项

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `proxy_list_urls` | 代理源URL列表 | 2个源 |
| `health_check_concurrency` | 并发健康检查数 | 2000 |
| `update_interval_minutes` | 代理池刷新间隔 | 5分钟 |
| `proxy_switch_interval_min` | 自动轮换间隔（单位: 分钟）；支持 `now`（每次请求轮换） | 30分钟 |
| `total_timeout_seconds` | 健康检查总超时 | 8秒 |
| `tls_handshake_threshold_seconds` | 最大TLS握手时间 | 4秒 |
| `health_check_two_stage.enabled` | 是否启用两阶段健康检查 | true |
| `health_check_two_stage.stage_one.*` | 第一阶段快速筛选超时参数 | 4秒 / 2秒 |
| `health_check_two_stage.stage_two.*` | 第二阶段精细检测超时参数 | 8秒 / 4秒 |
| `detector.core` | 主流协议内核后端（mihomo/meta/singbox） | 空（未启用） |
| `ports.socks5_strict` | SOCKS5服务器端口（启用SSL验证） | :17283 |
| `ports.socks5_relaxed` | SOCKS5服务器端口（禁用SSL验证） | :17284 |
| `ports.http_strict` | HTTP代理服务器端口（启用SSL验证） | :17285 |
| `ports.http_relaxed` | HTTP代理服务器端口（禁用SSL验证） | :17286 |
| `ports.rotate_control` | 手动轮换控制端口（随机切换到一个新的健康代理） | :17287 |
| `ports.http_mixed` | HTTP混合入口（仅自动选择 HTTP/HTTPS/SOCKS5 上游） | :17288 |
| `ports.http_cf_mixed` | HTTP混合入口（仅使用可通过CF挑战的 HTTP/HTTPS/SOCKS5 上游） | :17289 |
| `ports.http_mainstream_mixed` | HTTP主流协议混合入口（仅自动选择 VMESS/VLESS/HY2 上游） | :17290 |
| `auth.username` | 代理认证用户名（可选） | 空 |
| `auth.password` | 代理认证密码（可选） | 空 |

### 使用方法

#### 命令行

```bash
# 使用curl测试（SOCKS5 严格模式 - 启用SSL验证）
curl --socks5 127.0.0.1:17283 https://api.ipify.org

# 使用curl测试（SOCKS5 宽松模式 - 禁用SSL验证）
curl --socks5 127.0.0.1:17284 https://api.ipify.org

# 使用curl测试（HTTP 严格模式 - 启用SSL验证）
curl -x http://127.0.0.1:17285 https://api.ipify.org

# 使用curl测试（HTTP 宽松模式 - 禁用SSL验证）
curl -x http://127.0.0.1:17286 https://api.ipify.org

# 开启认证后的测试（HTTP）
curl -x http://username:password@127.0.0.1:17285 https://api.ipify.org

# 开启认证后的测试（SOCKS5）
curl --proxy socks5://username:password@127.0.0.1:17283 https://api.ipify.org

# Force rotate to a random healthy proxy (both strict/relaxed pools)
curl http://127.0.0.1:17287

# HTTP混合入口（仅自动使用 HTTP/HTTPS/SOCKS5 上游代理）
curl -x http://127.0.0.1:17288 https://api.ipify.org

# HTTP CF混合入口（自动使用可通过CF挑战的 HTTP/HTTPS/SOCKS5 上游代理）
curl -x http://127.0.0.1:17289 https://api.ipify.org

# HTTP主流协议混合入口（仅自动使用 VMESS/VLESS/HY2 上游代理）
curl -x http://127.0.0.1:17290 https://api.ipify.org

# 查看当前可自动通过 CF 挑战的代理列表（需在 config 中启用 cf_challenge_check）
curl http://127.0.0.1:17287/cf-proxies
```

#### 浏览器配置

**SOCKS5代理（严格模式 - 推荐）：**
- 主机: `127.0.0.1`
- 端口: `17283`

**SOCKS5代理（宽松模式 - 兼容性）：**
- 主机: `127.0.0.1`
- 端口: `17284`

**HTTP代理（严格模式 - 推荐）：**
- 主机: `127.0.0.1`
- 端口: `17285`

**HTTP代理（宽松模式 - 兼容性）：**
- 主机: `127.0.0.1`
- 端口: `17286`

**HTTP混合入口（仅自动选择 HTTP/HTTPS/SOCKS5 上游）：**
- 主机: `127.0.0.1`
- 端口: `17288`

**HTTP CF混合入口（仅 CF-pass HTTP/HTTPS/SOCKS5 上游）：**
- 主机: `127.0.0.1`
- 端口: `17289`

**HTTP主流协议混合入口（仅自动选择 VMESS/VLESS/HY2 上游）：**
- 主机: `127.0.0.1`
- 端口: `17290`

#### 编程示例

**Python:**

```python
import requests

# HTTP代理（严格模式 - 推荐）
proxies = {
    'http': 'http://127.0.0.1:17285',
    'https': 'http://127.0.0.1:17285'
}
response = requests.get('https://api.ipify.org', proxies=proxies)
print(response.text)

# HTTP代理（宽松模式 - 兼容性）
proxies = {
    'http': 'http://127.0.0.1:17286',
    'https': 'http://127.0.0.1:17286'
}
response = requests.get('https://api.ipify.org', proxies=proxies)
print(response.text)

# SOCKS5代理（严格模式 - 推荐）
proxies = {
    'http': 'socks5://127.0.0.1:17283',
    'https': 'socks5://127.0.0.1:17283'
}
response = requests.get('https://api.ipify.org', proxies=proxies)
print(response.text)

# SOCKS5代理（宽松模式 - 兼容性）
proxies = {
    'http': 'socks5://127.0.0.1:17284',
    'https': 'socks5://127.0.0.1:17284'
}
response = requests.get('https://api.ipify.org', proxies=proxies)
print(response.text)
```

**Node.js:**

```javascript
const axios = require('axios');
const { SocksProxyAgent } = require('socks-proxy-agent');

// SOCKS5代理（严格模式 - 推荐）
const strictAgent = new SocksProxyAgent('socks5://127.0.0.1:17283');
axios.get('https://api.ipify.org', { httpAgent: strictAgent, httpsAgent: strictAgent })
  .then(response => console.log(response.data));

// SOCKS5代理（宽松模式 - 兼容性）
const relaxedAgent = new SocksProxyAgent('socks5://127.0.0.1:17284');
axios.get('https://api.ipify.org', { httpAgent: relaxedAgent, httpsAgent: relaxedAgent })
  .then(response => console.log(response.data));

// HTTP代理（严格模式 - 推荐）
axios.get('https://api.ipify.org', {
  proxy: {
    host: '127.0.0.1',
    port: 17285
  }
}).then(response => console.log(response.data));

// HTTP代理（宽松模式 - 兼容性）
axios.get('https://api.ipify.org', {
  proxy: {
    host: '127.0.0.1',
    port: 17286
  }
}).then(response => console.log(response.data));
```

### 工作原理

1. **代理获取**: 启动时从配置的URL获取代理列表
2. **健康检查**: 并发健康检查，包含TLS握手验证
   - **严格模式**: 启用SSL证书验证进行测试
   - **宽松模式**: 禁用SSL证书验证进行测试
   - **优化策略**: 如果代理通过严格模式测试，自动添加到两个池
3. **双代理池**: 维护两个独立的代理池（严格和宽松）
4. **自动更新**: 按配置间隔刷新两个代理池
5. **轮询分配**: 使用轮询算法分配请求到代理
6. **双协议**: 同时提供SOCKS5和HTTP代理协议，每种协议都有两种模式（共4个服务器）

### 架构图

```
┌─────────────────┐
│   代理源列表    │
│  (支持多个URL)  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  获取并合并     │
│   (自动去重)    │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────┐
│          健康检查                   │
│         (200并发)                   │
│  ┌──────────────┐  ┌──────────────┐│
│  │  严格模式    │  │  宽松模式    ││
│  │ (SSL验证)    │  │(无SSL验证)   ││
│  │ - TCP连接    │  │- TCP连接     ││
│  │ - TLS+证书   │  │- 仅TLS       ││
│  │ - 速度测试   │  │- 速度测试    ││
│  └──────────────┘  └──────────────┘│
└────────┬────────────────┬───────────┘
         │                │
         ▼                ▼
┌─────────────────┐ ┌─────────────────┐
│   严格代理池    │ │   宽松代理池    │
│  (SSL已验证)    │ │  (更高兼容性)   │
└────────┬────────┘ └────────┬────────┘
         │                   │
    ┌────┴────┐         ┌────┴────┐
    ▼         ▼         ▼         ▼
┌────────┐┌────────┐┌────────┐┌────────┐
│SOCKS5  ││  HTTP  ││SOCKS5  ││  HTTP  │
│严格    ││ 严格   ││宽松    ││ 宽松   │
│:17283  ││ :17285 ││:17284  ││ :17286 │
└────────┘└────────┘└────────┘└────────┘
```

### 性能特性

- **并发健康检查**: 可配置的工作池（默认200）
- **无锁轮换**: 原子操作实现代理选择
- **最小锁竞争**: 读写锁保护代理池更新
- **连接复用**: HTTP传输连接池
- **快速过滤**: 拒绝TLS握手>5秒的代理

### 故障排除

**问题："No available proxies"**

- 检查网络连接
- 验证代理源URL可访问
- 等待健康检查完成
- 检查防火墙设置

**问题：连接失败**

- 代理可能暂时不可用
- 目标网站可能屏蔽代理IP
- 尝试多次请求使用不同代理
- 如果网络受限，调整 `health_check_concurrency`

**问题：性能慢**

- 降低 `tls_handshake_threshold_seconds` 过滤慢速代理
- 增加 `health_check_concurrency` 加快更新
- 添加更可靠的代理源

### 贡献

欢迎贡献！请随时提交Pull Request。

### 许可证

MIT License
