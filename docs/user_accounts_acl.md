# User Accounts Collector ACL 权限设置指南

## 概述

`user_accounts` 采集器需要读取以下文件来获取用户账户信息：

- `/etc/passwd` - 用户基本信息（所有用户可读）
- `/etc/shadow` - 密码最后修改时间（需要 root 或特殊权限）
- `/etc/sudoers` 和 `/etc/sudoers.d/*` - sudo 权限信息（需要 root 或特殊权限）

为了安全起见，建议使用 **ACL（访问控制列表）** 授予普通用户读取权限，而不是以 root 身份运行 node_exporter。

## 方法一：使用 setup_acl.sh 脚本（推荐）

项目提供了自动化脚本来设置 ACL 权限：

```bash
# 语法
sudo ./scripts/setup_acl.sh <username>

# 示例：为 prometheus 用户设置权限
sudo ./scripts/setup_acl.sh prometheus
```

脚本会自动：
1. 检查用户是否存在
2. 检查 setfacl 是否可用
3. 设置 `/etc/shadow` 的读取权限
4. 设置 `/etc/sudoers` 的读取权限
5. 设置 `/etc/sudoers.d` 目录的读取和执行权限
6. 显示当前的 ACL 设置

## 方法二：手动设置 ACL 权限

### 1. 安装 ACL 工具

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install acl
```

**CentOS/RHEL:**
```bash
sudo yum install acl
```

**RHEL/CentOS 8+:**
```bash
sudo dnf install acl
```

### 2. 设置文件权限

假设运行 node_exporter 的用户是 `prometheus`：

```bash
# 授予 /etc/shadow 读取权限
sudo setfacl -m u:prometheus:r /etc/shadow

# 授予 /etc/sudoers 读取权限
sudo setfacl -m u:prometheus:r /etc/sudoers

# 授予 /etc/sudoers.d 目录读取和执行权限
sudo setfacl -m u:prometheus:rx /etc/sudoers.d
```

### 3. 验证权限设置

```bash
# 查看 shadow 文件的 ACL
getfacl /etc/shadow

# 查看 sudoers 文件的 ACL
getfacl /etc/sudoers

# 查看 sudoers.d 目录的 ACL
getfacl /etc/sudoers.d
```

预期输出示例：
```
# file: etc/shadow
# owner: root
# group: shadow
user::r--
user:prometheus:r--
group::r--
mask::r--
other::---
```

### 4. 测试权限

切换到普通用户并测试读取权限：

```bash
# 切换到 prometheus 用户
sudo su - prometheus

# 测试读取 shadow 文件
cat /etc/shadow | head -1

# 测试读取 sudoers 文件
cat /etc/sudoers | head -5

# 返回 root
exit
```

## 方法三：使用 systemd 服务配置（备选）

如果系统不支持 ACL，可以使用 systemd 的 `ReadWritePaths` 或创建自定义服务单元：

```ini
# /etc/systemd/system/node_exporter.service
[Unit]
Description=Node Exporter
After=network.target

[Service]
User=prometheus
Group=prometheus
ExecStart=/usr/local/bin/node_exporter

# 授予特定文件读取权限
ReadWritePaths=/etc/shadow

[Install]
WantedBy=multi-user.target
```

然后重新加载 systemd：
```bash
sudo systemctl daemon-reload
sudo systemctl enable node_exporter
sudo systemctl start node_exporter
```

**注意**：这种方法可能因系统配置而异，ACL 方法更可靠。

## 移除 ACL 权限

如果需要移除之前设置的 ACL 权限：

```bash
# 移除 shadow 文件的 ACL
sudo setfacl -x u:prometheus /etc/shadow

# 移除 sudoers 文件的 ACL
sudo setfacl -x u:prometheus /etc/sudoers

# 移除 sudoers.d 目录的 ACL
sudo setfacl -x u:prometheus /etc/sudoers.d
```

或者使用脚本移除：
```bash
# 创建移除脚本
cat > /tmp/remove_acl.sh << 'EOF'
#!/bin/bash
USERNAME=$1
sudo setfacl -x u:$USERNAME /etc/shadow
sudo setfacl -x u:$USERNAME /etc/sudoers
sudo setfacl -x u:$USERNAME /etc/sudoers.d
echo "ACL permissions removed for user: $USERNAME"
EOF

chmod +x /tmp/remove_acl.sh
sudo /tmp/remove_acl.sh prometheus
```

## 故障排除

### 问题 1: setfacl 命令不存在

**解决方案**: 安装 acl 包（见上文"安装 ACL 工具"部分）

### 问题 2: 无法设置 shadow 文件 ACL

错误信息：`setfacl: Failed to modify: Operation not supported`

**原因**: 文件系统不支持 ACL

**解决方案**:
1. 检查文件系统是否支持 ACL:
   ```bash
   mount | grep /etc
   ```
2. 如果未启用 ACL，重新挂载：
   ```bash
   sudo mount -o remount,acl /etc
   ```
   或编辑 `/etc/fstab` 添加 `acl` 选项

### 问题 3: 普通用户仍然无法读取 shadow 文件

**检查步骤**:
```bash
# 1. 确认 ACL 已设置
getfacl /etc/shadow

# 2. 确认用户名正确
id prometheus

# 3. 检查 SELinux 是否阻止（CentOS/RHEL）
getenforce
# 如果是 Enforcing，尝试临时设置为 Permissive
sudo setenforce 0
# 测试后恢复
sudo setenforce 1
```

### 问题 4: node_exporter 日志显示"Failed to read shadow file"

**检查步骤**:
```bash
# 1. 确认 node_exporter 运行的用户
ps aux | grep node_exporter

# 2. 以该用户身份测试读取
sudo -u <username> cat /etc/shadow | head -1

# 3. 检查日志
journalctl -u node_exporter -f
```

## 安全注意事项

1. **最小权限原则**: 只授予必要的读取权限，不要授予写入权限
2. **定期审计**: 定期检查 ACL 设置，确保没有多余的权限
3. **监控**: 监控 `/etc/shadow` 和 `/etc/sudoers` 文件的访问日志
4. **备份**: 在修改 ACL 之前备份原始权限：
   ```bash
   getfacl /etc/shadow > /tmp/shadow.acl.bak
   getfacl /etc/sudoers > /tmp/sudoers.acl.bak
   ```

## 相关文件

- [user_accounts_linux.go](../collector/user_accounts_linux.go) - 采集器实现
- [setup_acl.sh](../scripts/setup_acl.sh) - ACL 设置脚本
- [config.json](../config.json) - 配置文件示例

## 参考文档

- [setfacl 手册](https://linux.die.net/man/1/setfacl)
- [getfacl 手册](https://linux.die.net/man/1/getfacl)
- [Prometheus Node Exporter 文档](https://github.com/prometheus/node_exporter)
