# Sentinel 安全审计报告

**最后更新日期**: 2026-03-12

本报告总结了 Sentinel 项目中发现的潜在安全漏洞、代码缺陷以及与 GNOME 开发指南不一致的地方。核心原则是遵循安全规范并最大限度减小攻击面。

---

## 1. 风险概览

| 风险等级 | 问题描述 | 影响范围 | 状态 |
| :--- | :--- | :--- | :--- |
| 🔴 **严重** | 外部二进制文件 (rclone) 未经验证下载 | 命令执行 / 供应链攻击 | ✅ 已修复 |
| 🔴 **严重** | `SecureBytes` 内存保护机制存在缺陷 | 凭据内存残留 | ✅ 已修复 |
| 🟠 **高危** | Bitwarden 主密码通过命令行参数传递 | 本地用户凭据窃取 | ✅ 已修复 |
| 🟠 **高危** | 违反“凭据不落地”原则（libsecret 缓存） | 凭据持久化风险 | ✅ 已修复 |
| 🟡 **中危** | 强制启用的底层调试日志 | 信息泄露 | ✅ 已修复 |
| 🟡 **中危** | DEBUG 信息的标准输出 (Stdout) 泄露 | 元数据泄露 | ✅ 已修复 |

---

## 2. 详细漏洞描述

### 2.1 未经验证的外部二进制文件下载
- **位置**: `src/services/rclone_service.py` (`ensure_rclone` 函数)
- **描述**: 原本应用在检测到 `rclone` 缺失时，会从远程服务器下载并直接赋予执行权限。
- **状态**: **已修复**。现已改为本地预打包模式，`rclone` 二进制文件放置在项目的 `bin/` 目录下。移除了运行时下载逻辑，彻底消除了未经验证下载带来的风险。
- **改进**: 
    - 移除了运行时下载代码。
    - 使用相对于项目根目录的路径加载 `rclone`。
    - 计划在未来提供 Flatpak 版本时，通过 Flatpak 的构建清单或扩展机制提供经过验证的二进制文件。

### 2.2 `SecureBytes` 的副本泄露
- **位置**: `src/utils/secure.py`
- **描述**: 旨在保护内存的 `SecureBytes` 类提供了 `get_str()` 和 `get()` 方法。
- **状态**: **已修复**。
- **改进**: 
    - 重命名了 `get()` 和 `get_str()` 为 `unsafe_get_bytes()` 和 `unsafe_get_str()` 以提示风险。
    - 引入了 `get_view()` 返回 `memoryview`，该视图在 `SecureBytes.clear()` 时会同步置零。
    - 在 SSHService 和 RcloneService 中优先选择 `get_view()` 并在使用后立即调用 `clear()`。
    - UI 对话框（如 `prompt_vault_unlock`）现在直接返回 `SecureBytes` 对象。

### 2.3 Bitwarden 主密码传递不安全
- **位置**: `src/vault/bitwarden.py` (`unlock` 方法)
- **描述**: 调用 `bw unlock` 时直接将密码作为位置参数传递。
- **状态**: **已修复**。
- **改进**: 重写了 `BitwardenBackend.unlock`，主密码现在通过 `asyncio.subprocess.PIPE` (stdin) 传递，并配合 `--raw` 参数直接获取令牌。

### 2.4 凭据持久化策略冲突
- **位置**: `src/vault/bitwarden.py`
- **描述**: 应用默认将 Bitwarden 会话令牌和检索到的明文密码缓存到 GNOME Keyring (libsecret)。
- **状态**: **已修复**。
- **改进**: 
    - 移除了所有在 `libsecret` 中存储 Bitwarden 会话令牌和凭据缓存的代码。
    - 引入了基于内存的 `_item_cache`，并使用 `SecureBytes` 和 `SSHKeyMaterial` 封装缓存条目。
    - 确保在登出、锁定或检测到 Token 失效时，立即清空内存缓存。

### 2.5 敏感路径与元数据泄露 (Logging/Stdout)
- **位置**: `src/services/ssh_service.py`, `src/vault/bitwarden.py`
- **描述**: 永久启用了 `asyncssh` 的底层调试，且包含大量 `print()` 调试信息。
- **状态**: **已修复**。
- **改进**: 
    - 移除了 `ssh_service.py` 中强制开启的 `DEBUG` 日志级别和 `asyncssh` 调试设置。
    - 将 `asyncssh` 的全局日志级别默认设为 `WARNING`。
    - 将 `bitwarden.py` 中所有的 `print()` 调试信息替换为 `logger.debug()`。

---

## 3. GNOME 开发指南遵循情况

- **[符合]** UI 使用纯 Python 和 libadwaita 构建，遵循 HIG 原则。
- **[符合]** 数据库设计遵循了“不存储密码”的隔离原则。
- **[不符合]** 应尽量避免自行下载二进制文件，改为让用户安装或包含在沙盒环境中。
- **[不符合]** 进程通信应更加谨慎地处理敏感参数（stdin vs args）。

---

## 4. 后续维护建议

1. **持续监控**: 定期审计第三方库（如 `asyncssh`, `asyncio`）的安全通告。
2. **内存泄露检测**: 使用 `valgrind` 或 Python 内存分析工具定期检查在高压力并发连接下是否有敏感数据残留。
3. **Flatpak 打包**: 尽快迁移到 Flatpak 打包以利用沙盒机制限制 `rclone` 和其他外部二进制文件的权限。
