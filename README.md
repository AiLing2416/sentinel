# Sentinel

<p align="center">
  <img src="data/icons/hicolor/scalable/apps/io.github.ailing2416.sentinel.svg" width="128" height="128" alt="Sentinel Logo">
</p>

Sentinel 是一个专为 GNOME 桌面环境设计的 SSH 连接管理器。它旨在提供一个现代、安全且与系统深度集成的终端管理方案。

## 核心功能

- **SSH 会话管理**：支持多标签页连接，集成 VTE 终端模拟器。
- **凭据集成**：可选集成 Bitwarden CLI 存储和检索 SSH 密钥及密码。
- **双因子认证 (2FA)**：支持自动从 Bitwarden 获取 TOTP 验证码。
- **高级连接能力**：支持多级跳板机嵌套 (ProxyJump) 和 SSH 代理转发 (Agent Forwarding)。
- **端口转发**：支持本地 (Local)、远程 (Remote) 和动态 (Dynamic/SOCKS) 端口转发规则。
- **SFTP 支持**：通过 FUSE 挂载提供内置的文件浏览与管理功能。
- **安全优先**：敏感数据在内存中加密处理，不存储明文密码至本地数据库。

## 安装

您可以从 GitHub Releases 下载最新的 Flatpak 安装包。

### 命令行安装

```bash
# 下载 bundle 后执行
flatpak install --user sentinel.flatpak
```

### 运行应用

```bash
flatpak run io.github.ailing2416.sentinel
```

## 开发架构

基于 Python 3、PyGObject 和 GTK4 构建，遵循 GNOME 应用设计规范 (Adwaita)。项目采用 Meson 编译系统并支持 Flatpak 打包。
