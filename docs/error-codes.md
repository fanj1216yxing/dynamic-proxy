# Dynamic Proxy 错误码规范

统一格式：`DP-<PROTOCOL>-<NNN>`。

- `PROTOCOL`：`SS` / `SSR` / `TRJ` / `GEN`（未知或通用协议）。
- `NNN`：三位数字，按错误域分段。

## 1) 参数校验类（`00x`）

- `DP-SS-001` / `DP-SSR-001` / `DP-TRJ-001`：地址非法、URL 解析失败、请求构造失败。
- `DP-SS-002` / `DP-SSR-002` / `DP-TRJ-002`：认证缺失或认证失败。
- `DP-SS-003` / `DP-SSR-003` / `DP-TRJ-003`：协议不支持。

## 2) 外部内核类（`10x`）

- `DP-SS-101` / `DP-SSR-101` / `DP-TRJ-101`：外部内核未配置或不可用。
- `DP-SS-102` / `DP-SSR-102` / `DP-TRJ-102`：内核启动/握手流程失败。
- `DP-SS-103` / `DP-SSR-103` / `DP-TRJ-103`：连接被拒绝或目标不可达。

## 3) 网络与握手类（`20x`）

- `DP-SS-201` / `DP-SSR-201` / `DP-TRJ-201`：超时。
- `DP-SS-202` / `DP-SSR-202` / `DP-TRJ-202`：证书验证失败。
- `DP-SS-203` / `DP-SSR-203` / `DP-TRJ-203`：SNI/主机名不匹配。
- `DP-SS-204` / `DP-SSR-204` / `DP-TRJ-204`：连接 EOF。
- `DP-SS-205` / `DP-SSR-205` / `DP-TRJ-205`：协议错误（非预期 TLS/HTTP 记录等）。
- `DP-SS-206` / `DP-SSR-206` / `DP-TRJ-206`：TLS 握手超时。

## 4) 兜底

- `DP-GEN-999`：未知错误。

> 说明：业务层继续保留 `category` 作为二级标签，`error_code` 作为统一主键用于日志和聚合统计。
