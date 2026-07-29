# User Accounts Collector 配置说明

## 配置文件

User Accounts 采集器的配置位于 `config.json` 文件中的 `userAccounts` 部分。

## 配置项说明

```json
{
  "userAccounts": {
    "enable": 1,
    "interval": 3600,
    "collect_users": true,
    "collect_shadow": true,
    "collect_sudo": true
  }
}
```

### enable - 采集模式

控制采集器的运行模式：

| 值 | 模式 | 说明 |
|---|---|---|
| 0 | 禁用 | 不采集用户账户信息 |
| 1 | 全量采集 | 每次采集都输出所有用户信息，指标值=0 |
| 2 | 增量采集 | 根据 interval 判断，输出变化的用户信息 |

**推荐配置**：
- 开发/测试环境：`1`（全量采集，便于调试）
- 生产环境：`2`（增量采集，减少网络传输）

### interval - 全量采集间隔

当 `enable=2`（增量采集）时，控制全量采集的时间间隔（单位：秒）。

| 场景 | 推荐值 | 说明 |
|---|---|---|
| 频繁变更 | 1800 | 30 分钟全量采集一次 |
| 常规环境 | 3600 | 1 小时全量采集一次 |
| 稳定环境 | 86400 | 24 小时全量采集一次 |

**注意**：此配置仅在 `enable=2` 时生效。

### collect_users - 采集用户基本信息

是否采集用户基本信息（username, uid, gid, gecos, home, shell）。

| 值 | 说明 |
|---|---|
| true | 采集用户基本信息 |
| false | 不采集用户基本信息 |

**推荐配置**：`true`

### collect_shadow - 采集密码最后修改时间

是否采集用户密码最后修改时间（需要读取 `/etc/shadow` 文件）。

| 值 | 说明 | 权限要求 |
|---|---|---|
| true | 采集密码最后修改时间 | 需要 shadow 文件读取权限 |
| false | 不采集密码最后修改时间 | 无特殊权限要求 |

**推荐配置**：`true`（需配合 ACL 权限设置）

**权限设置**：
```bash
# 使用脚本设置
sudo ./scripts/setup_acl.sh prometheus

# 或手动设置
sudo setfacl -m u:prometheus:r /etc/shadow
```

### collect_sudo - 采集 sudo 权限

是否采集用户 sudo 权限信息（需要读取 `/etc/sudoers` 文件）。

| 值 | 说明 | 权限要求 |
|---|---|---|
| true | 采集 sudo 权限信息 | 需要 sudoers 文件读取权限 |
| false | 不采集 sudo 权限信息 | 无特殊权限要求 |

**推荐配置**：`true`（需配合 ACL 权限设置）

**权限设置**：
```bash
# 使用脚本设置
sudo ./scripts/setup_acl.sh prometheus

# 或手动设置
sudo setfacl -m u:prometheus:r /etc/sudoers
sudo setfacl -m u:prometheus:rx /etc/sudoers.d
```

## 配置示例

### 示例 1：全量采集模式（开发/测试）

```json
{
  "userAccounts": {
    "enable": 1,
    "interval": 3600,
    "collect_users": true,
    "collect_shadow": true,
    "collect_sudo": true
  }
}
```

**说明**：
- 每次采集都输出所有用户信息
- 指标值始终为 0（全量采集）
- 适合开发和测试环境

### 示例 2：增量采集模式（生产环境）

```json
{
  "userAccounts": {
    "enable": 2,
    "interval": 3600,
    "collect_users": true,
    "collect_shadow": true,
    "collect_sudo": true
  }
}
```

**说明**：
- 只输出变化的用户信息
- 每小时全量采集一次
- 适合生产环境，减少网络传输

### 示例 3：仅采集基本信息（无特殊权限）

```json
{
  "userAccounts": {
    "enable": 2,
    "interval": 86400,
    "collect_users": true,
    "collect_shadow": false,
    "collect_sudo": false
  }
}
```

**说明**：
- 只采集用户基本信息（不需要特殊权限）
- 不采集密码时间和 sudo 权限
- 适合普通用户运行，无需配置 ACL

### 示例 4：禁用采集

```json
{
  "userAccounts": {
    "enable": 0,
    "interval": 3600,
    "collect_users": false,
    "collect_shadow": false,
    "collect_sudo": false
  }
}
```

**说明**：
- 完全禁用 user_accounts 采集器
- 重启 node_exporter 后生效

## 增量采集工作原理

当 `enable=2` 时，采集器采用增量模式：

1. **首次运行**：全量采集，所有用户指标值=0
2. **间隔内运行**：
   - **新增用户**：指标值=1
   - **更新用户**（uid、shell 等变化）：指标值=2
   - **删除用户**：指标值=3
3. **达到间隔时间**：再次全量采集，所有用户指标值=0

### 指标值说明

| 值 | 类型 | 说明 |
|---|---|---|
| 0 | 全量 | 全量采集时的所有用户 |
| 1 | 新增 | 新创建的用户 |
| 2 | 更新 | 用户信息发生变化 |
| 3 | 删除 | 被删除的用户（仅记录一次） |

## 配置生效

修改 `config.json` 后，需要重启 node_exporter 才能生效：

```bash
# systemd 服务
sudo systemctl restart node_exporter

# 或直接运行
sudo pkill node_exporter
./node_exporter &
```

## 验证配置

### 1. 检查配置是否加载

查看启动日志：
```bash
journalctl -u node_exporter -f
```

### 2. 检查指标输出

访问 Prometheus 指标端点：
```bash
curl http://localhost:9100/metrics | grep user_accounts
```

预期输出示例：
```
# HELP node_user_accounts_info User account information.
# TYPE node_user_accounts_info gauge
node_user_accounts_info{username="root",uid="0",gid="0",gecos="root",home="/root",shell="/bin/bash"} 0
node_user_accounts_info{username="prometheus",uid="1000",gid="1000",gecos="Prometheus",home="/home/prometheus",shell="/bin/bash"} 0
```

### 3. 检查权限是否足够

如果配置了 `collect_shadow` 或 `collect_sudo` 但权限不足，日志中会出现警告：
```
level=warn msg="Failed to read shadow file" err="permission denied"
```

## 故障排除

### 问题 1：配置未生效

**检查步骤**：
1. 确认配置文件路径正确（应在启动目录）
2. 确认 JSON 格式正确
3. 确认已重启 node_exporter

### 问题 2：增量采集未检测到变化

**检查步骤**：
1. 确认 `enable=2`
2. 确认 `interval` 设置合理
3. 检查 `lastFullCollectTime` 是否正确更新

### 问题 3：权限不足

**解决方案**：
1. 配置 ACL 权限（见 [user_accounts_acl.md](user_accounts_acl.md)）
2. 或将 `collect_shadow` 和 `collect_sudo` 设置为 `false`

## 性能影响

| 配置 | CPU 影响 | 内存影响 | 采集时间 |
|---|---|---|---|
| 仅用户基本信息 | 低 | 低 | <10ms |
| + shadow 信息 | 低 | 低 | <20ms |
| + sudo 信息 | 中 | 低 | <50ms |
| 全量采集 | 低 | 中 | <100ms |

**建议**：
- 用户数量 < 100：所有功能均可开启
- 用户数量 100-1000：建议开启增量采集
- 用户数量 > 1000：建议禁用 sudo 采集或增加 interval

## 相关文件

- [user_accounts_linux.go](../collector/user_accounts_linux.go) - 采集器实现
- [setup_acl.sh](../scripts/setup_acl.sh) - ACL 设置脚本
- [user_accounts_acl.md](user_accounts_acl.md) - ACL 权限设置指南
