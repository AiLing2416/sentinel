# Sentinel — GNOME SSH 连接管理器

> **项目代号**: Sentinel  
> **定位**: 安全、美观、刚好够用的 GNOME SSH 连接管理与终端工具  
> **创建日期**: 2026-03-08  

---

## 1. 项目愿景

Sentinel 是一款原生 GNOME 风格的 SSH 连接管理工具，旨在：

- 提供**精致的 libadwaita UI**，与 GNOME 桌面无缝融合
- 通过**密码管理器集成**（Bitwarden 等）在多设备间安全同步凭据
- 以**最小必要功能集**降低攻击面，同时覆盖日常 SSH 工作流
- 通过**自动化安全测试**持续保障代码质量与安全性

---

## 2. 技术栈

| 层级 | 技术选型 | 说明 |
|------|---------|------|
| 语言 | Python 3.12+ | 生态成熟，便于安全审计 |
| GUI 框架 | GTK 4 + libadwaita | 原生 GNOME HIG 体验 |
| UI 构建 | 纯 Python (libadwaita) | 灵活的编程式 UI 构建，动态性强，且无需引入额外编译依赖 |
| SSH 库 | asyncssh | 异步高性能 SSH 实现 |
| 终端模拟 | VTE 4 (gi bindings) | GNOME 原生终端组件 |
| 密钥/凭据 | libsecret + Bitwarden CLI | 本地密钥环 + 远程保险库 |
| 数据存储 | SQLite (通过 aiosqlite) | 连接配置本地持久化 |
| 配置同步 | Bitwarden Vault / 导入导出 | 跨设备共享连接配置 |
| 构建系统 | Meson + Ninja | GNOME 标准构建系统 |
| 包格式 | Flatpak | 沙盒隔离，安全发布 |
| 测试框架 | pytest + pytest-asyncio | 单元/集成/安全测试 |
| CI/CD | GitHub Actions | 自动构建、测试、发布 |
| 代码质量 | Ruff, mypy, bandit | Lint、类型检查、安全扫描 |

---

## 3. 功能规格

### 3.1 核心功能（MVP）

#### 3.1.1 连接管理
- 新增 / 编辑 / 删除 / 复制 SSH 连接配置
- 连接字段：名称、主机、端口、用户名、认证方式、跳板机、备注
- 连接分组（文件夹 / 标签）
- 快速搜索与筛选
- 拖拽排序

#### 3.1.2 认证方式
- 密码认证
- SSH 密钥认证（支持 Ed25519 / RSA / ECDSA）
- 密钥 + 密码短语
- SSH Agent 转发
- 从密码管理器自动加载凭据

#### 3.1.3 终端会话
- 基于 VTE 的内嵌终端
- 多标签页会话
- 会话自动重连
- 终端字体 / 颜色方案自定义（跟随系统 / 自定义）
- 本地 Shell 标签页

#### 3.1.4 密码管理器集成
- **Bitwarden**（首选）：通过 `bw` CLI 交互
  - 搜索保险库条目（按主机名 / 名称匹配）
  - 读取用户名、密码、SSH 密钥、TOTP
  - 会话令牌安全管理（内存中，不写入磁盘）
  - 应用内锁定 / 解锁保险库
- **GNOME Keyring / libsecret**：本地凭据后备存储
- **可扩展后端接口**：为未来添加 1Password / KeePassXC 等预留

#### 3.1.5 同步机制
- 连接配置可导出为加密 JSON 文件
- 通过 Bitwarden Secure Notes 同步连接配置（不含敏感凭据）
  - 凭据始终通过密码管理器实时获取
  - 仅同步连接元数据（主机、端口、用户名、分组等）
- 导入 / 导出 OpenSSH `~/.ssh/config` 格式

### 3.2 辅助功能

#### 3.2.1 SSH 密钥管理
- 生成新 SSH 密钥对（Ed25519 / RSA）
- 查看本地密钥列表
- 一键复制公钥
- 部署公钥到远程主机（`ssh-copy-id` 等效）

#### 3.2.2 SFTP 文件传输
- 简化文件浏览器（远程目录列表）
- 上传 / 下载文件
- 拖拽文件传输

#### 3.2.3 端口转发
- 本地端口转发（Local Forward）
- 远程端口转发（Remote Forward）
- 动态端口转发（SOCKS 代理）
- 转发规则保存在连接配置中

### 3.3 明确不做

以下功能**不在项目范围内**，以控制复杂度和攻击面：

- ❌ 内置 VPN / 隧道管理（使用系统 NetworkManager）
- ❌ 远程桌面 / VNC / RDP
- ❌ 完整的文件管理器（使用 Nautilus + SFTP）
- ❌ 脚本自动化 / 批量命令执行
- ❌ 自建同步服务器（依赖已有密码管理器基础设施）
- ❌ 服务器监控 / Dashboard

---

## 4. 架构设计

### 4.1 目录结构

```
ssh/
├── meson.build                    # 构建系统入口
├── meson_options.txt              # 构建选项
├── PROJECT_SPEC.md                # 本文档
├── README.md
├── LICENSE                        # GPL-3.0-or-later
├── .github/
│   └── workflows/
│       ├── ci.yml                 # CI 流水线
│       └── release.yml            # 发布流水线
├── data/
│   ├── icons/                     # 应用图标
│   ├── io.github.ailing2416.sentinel.desktop        # Desktop Entry
│   ├── io.github.ailing2416.sentinel.metainfo.xml   # AppStream 元数据
│   └── io.github.ailing2416.sentinel.gschema.xml    # GSettings Schema
├── po/                            # 国际化翻译
├── src/
│   ├── meson.build
│   ├── main.py                    # 应用入口
│   ├── application.py             # Adw.Application 子类
│   ├── views/                     # 视图组件（包含 Python 纯代码构建的 UI 逻辑）
│   │   ├── main_window.py
│   │   ├── connection_list.py
│   │   ├── chrome_tab_bar.py      # 自定义 Chromium 风格标签栏
│   │   ├── terminal_view.py
│   │   ├── dialogs.py
│   │   └── vault_settings_dialog.py
│   ├── models/                    # 数据模型
│   │   ├── connection.py
│   │   ├── connection_group.py
│   │   ├── host_key.py
│   │   └── forward_rule.py
│   ├── services/                  # 业务逻辑服务
│   │   ├── ssh_service.py         # SSH 连接管理
│   │   ├── key_service.py         # SSH 密钥管理
│   │   ├── sftp_service.py        # SFTP 文件传输
│   │   └── forward_service.py     # 端口转发管理
│   ├── vault/                     # 密码管理器抽象层
│   │   ├── __init__.py
│   │   ├── base.py                # VaultBackend 抽象基类
│   │   ├── bitwarden.py           # Bitwarden CLI 后端
│   │   ├── libsecret.py           # GNOME Keyring 后端
│   │   └── models.py              # 保险库条目模型
│   ├── sync/                      # 同步模块
│   │   ├── exporter.py            # 配置导出
│   │   ├── importer.py            # 配置导入
│   │   └── openssh_compat.py      # OpenSSH config 兼容
│   └── db/                        # 数据库层
│       ├── database.py            # 数据库连接管理
│       └── migrations/            # Schema 迁移
├── tests/                         # 测试
│   ├── conftest.py
│   ├── unit/                      # 单元测试
│   │   ├── test_models.py
│   │   ├── test_ssh_service.py
│   │   ├── test_vault_bitwarden.py
│   │   ├── test_vault_libsecret.py
│   │   ├── test_sync.py
│   │   └── test_key_service.py
│   ├── integration/               # 集成测试
│   │   ├── test_db.py
│   │   ├── test_vault_integration.py
│   │   └── test_ssh_connection.py
│   └── security/                  # 安全测试
│       ├── test_credential_handling.py
│       ├── test_input_validation.py
│       ├── test_crypto.py
│       └── test_sandbox.py
└── flatpak/
    └── io.github.ailing2416.sentinel.yml    # Flatpak 清单
```

### 4.2 核心架构图

```
┌─────────────────────────────────────────┐
│               Adw.Application           │
├──────────┬──────────┬───────────────────┤
│ Views    │ Services │ Vault Backends    │
│ (UI+VTE) │ (SSH/    │ (Bitwarden /      │
│          │  SFTP/   │  libsecret)       │
│          │  Keys)   │                   │
├──────────┴──────────┴───────────────────┤
│           Models + Database             │
│             (SQLite / aiosqlite)        │
├─────────────────────────────────────────┤
│       asyncssh    │    VTE 4            │
└───────────────────┴─────────────────────┘
```

### 4.3 密码管理器集成架构

```python
# vault/base.py — 抽象接口
class VaultBackend(ABC):
    """密码管理器后端抽象基类"""

    @abstractmethod
    async def unlock(self, master_password: str) -> bool: ...

    @abstractmethod
    async def lock(self) -> None: ...

    @abstractmethod
    async def is_unlocked(self) -> bool: ...

    @abstractmethod
    async def search_credentials(
        self, hostname: str, username: str | None = None
    ) -> list[VaultCredential]: ...

    @abstractmethod
    async def get_ssh_key(self, item_id: str) -> SSHKeyMaterial: ...

    @abstractmethod
    async def store_connection_config(
        self, config: ConnectionConfig
    ) -> str: ...

    @abstractmethod
    async def retrieve_connection_configs(self) -> list[ConnectionConfig]: ...
```

---

## 5. 安全规格

### 5.1 威胁模型

| 威胁 | 风险等级 | 缓解措施 |
|------|---------|---------|
| 凭据明文泄露 | 🔴 严重 | 将凭据严格托管于 OS 级别的加密保险箱（GNOME Keyring/libsecret） |
| Bitwarden 会话令牌泄露 | 🔴 严重 | 令牌作为加密条目存入 libsecret，防止被其他无权限应用读取 |
| 中间人攻击 | 🟠 高 | 强制主机密钥验证；首次连接指纹确认；已知主机持久化 |
| 本地数据库被窃取 | 🟡 中 | SQLite 仅存储元数据（主机、端口、用户名）；密码与私钥存放于系统 Keyring |
| 命令注入 | 🟠 高 | 所有用户输入严格验证；subprocess 使用列表参数而非字符串 |
| 依赖链攻击 | 🟡 中 | 最小化依赖数量；Flatpak 沙盒隔离；依赖版本锁定 |
| 日志敏感信息泄露 | 🟡 中 | 日志过滤器自动脱敏；DEBUG 模式不记录凭据 |

### 5.2 安全设计原则

1. **依托 OS Keyring 的安全持久化**：应用自身的 SQLite 数据库（本地平面文件）**绝不存储**任何密码或私钥。对于从 Bitwarden 远程获取到的复杂凭据和慢速会话 Token，应用利用 GNOME Keyring (`libsecret`) 作为本地具备加密隔离能力的安全缓存层，保障性能与安全性的平衡。
2. **最小权限原则**：Flatpak 权限仅请求网络访问和必要的 D-Bus 接口。
3. **安全内存**：使用 `mlock()` 锁定敏感内存页，使用 `SecureBytes` 封装凭据并在作用域结束时清零。
4. **输入验证**：所有用户输入（主机名、端口、用户名等）通过白名单验证。
5. **进程隔离**：Bitwarden CLI 调用通过 `subprocess` 隔离执行，使用短超时。

### 5.3 安全内存管理

```python
# utils/secure.py
class SecureBytes:
    """安全字节串：用完归零，防止换页泄露"""

    def __init__(self, data: bytes):
        self._buf = bytearray(data)
        self._lock_memory()

    def _lock_memory(self):
        """锁定内存页，防止被交换到磁盘"""
        # 使用 ctypes 调用 mlock
        ...

    def get(self) -> bytes:
        return bytes(self._buf)

    def clear(self):
        for i in range(len(self._buf)):
            self._buf[i] = 0

    def __del__(self):
        self.clear()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.clear()
```

---

## 6. 自动化测试规范

### 6.1 测试分层

```
┌───────────────────────────────┐
│       Security Tests          │  ← bandit + 自定义安全断言
│   (凭据处理/输入验证/加密)     │
├───────────────────────────────┤
│     Integration Tests         │  ← 需要外部服务 (mock SSH server)
│   (数据库/保险库/SSH连接)      │
├───────────────────────────────┤
│        Unit Tests             │  ← 快速、隔离、无副作用
│   (模型/服务/工具函数)         │
└───────────────────────────────┘
```

### 6.2 单元测试

**覆盖率目标：≥ 85%**

```python
# tests/unit/test_models.py
class TestConnectionModel:
    def test_create_connection_with_valid_data(self): ...
    def test_reject_invalid_hostname(self): ...
    def test_reject_port_out_of_range(self): ...
    def test_reject_empty_username(self): ...
    def test_serialize_deserialize_roundtrip(self): ...
    def test_sensitive_fields_excluded_from_repr(self): ...

# tests/unit/test_vault_bitwarden.py
class TestBitwardenBackend:
    def test_unlock_with_valid_password(self): ...
    def test_unlock_with_invalid_password(self): ...
    def test_session_token_cleared_on_lock(self): ...
    def test_search_credentials_by_hostname(self): ...
    def test_cli_timeout_handling(self): ...
    def test_cli_not_found_error(self): ...
```

### 6.3 安全测试（关键）

```python
# tests/security/test_credential_handling.py
class TestCredentialHandling:
    """验证凭据在整个生命周期中的安全处理"""

    def test_password_not_in_process_memory_after_use(self):
        """使用后密码应从内存中清除"""

    def test_password_not_in_logs(self):
        """日志中不应出现明文密码"""

    def test_password_not_in_database(self):
        """SQLite 数据库中不应存储密码"""

    def test_password_not_in_exception_traceback(self):
        """异常回溯中不应包含密码"""

    def test_session_token_not_written_to_disk(self):
        """Bitwarden 会话令牌不应写入磁盘"""

    def test_secure_bytes_zeroed_after_context_exit(self):
        """SecureBytes 退出上下文后应全部归零"""

# tests/security/test_input_validation.py
class TestInputValidation:
    """验证所有用户输入的安全校验"""

    @pytest.mark.parametrize("hostname", [
        "valid.host.com", "192.168.1.1", "2001:db8::1",
    ])
    def test_accept_valid_hostnames(self, hostname): ...

    @pytest.mark.parametrize("hostname", [
        "host; rm -rf /", "host$(whoami)", "host`id`",
        "../../../etc/passwd", "host\nHOSTNAME=evil", "", "a" * 256,
    ])
    def test_reject_malicious_hostnames(self, hostname): ...

    @pytest.mark.parametrize("port", [-1, 0, 65536, 99999])
    def test_reject_invalid_ports(self, port): ...

    def test_reject_username_with_shell_metacharacters(self): ...
    def test_reject_connection_name_with_path_traversal(self): ...

# tests/security/test_crypto.py
class TestCrypto:
    def test_exported_config_is_encrypted(self): ...
    def test_exported_config_uses_strong_cipher(self): ...
    def test_host_key_fingerprint_verification(self): ...
    def test_reject_weak_ssh_key_types(self): ...
    def test_generated_keys_have_correct_permissions(self): ...

# tests/security/test_sandbox.py
class TestSandbox:
    def test_flatpak_manifest_no_filesystem_host(self): ...
    def test_flatpak_manifest_no_excessive_dbus(self): ...
    def test_bitwarden_cli_subprocess_has_timeout(self): ...
    def test_bitwarden_cli_subprocess_no_shell_true(self): ...
```

### 6.4 集成测试

```python
# tests/integration/test_ssh_connection.py
class TestSSHConnection:
    """使用 mock SSH 服务器进行端到端连接测试"""

    @pytest.fixture
    async def mock_ssh_server(self):
        """启动一个本地 asyncssh 测试服务器"""
        ...

    async def test_connect_with_password(self, mock_ssh_server): ...
    async def test_connect_with_key(self, mock_ssh_server): ...
    async def test_host_key_verification_failure(self, mock_ssh_server): ...
    async def test_connection_timeout(self, mock_ssh_server): ...
    async def test_reconnect_on_disconnect(self, mock_ssh_server): ...
```

### 6.5 静态安全扫描

| 工具 | 命令 | 说明 |
|-----|------|------|
| bandit | `bandit -r src/ -c bandit.yml` | Python 安全漏洞静态分析 |
| safety | `safety check --full-report` | 依赖已知漏洞检查 |
| mypy | `mypy src/ --strict` | 类型检查（捕获类型混淆漏洞） |
| ruff | `ruff check src/ tests/` | 代码风格与常见错误 |
| trivy | `trivy fs --security-checks vuln .` | 文件系统漏洞扫描 |

### 6.6 CI 流水线概要

```yaml
# .github/workflows/ci.yml
on: [push, pull_request]
jobs:
  lint:       # ruff check + mypy --strict
  test:       # pytest unit (≥85%) + integration + security
  security:   # bandit + safety + trivy
  build:      # meson + ninja + flatpak-builder (main 分支)
```

---

## 7. 密码管理器交互流程

### 7.1 Bitwarden 工作流

```
用户打开 Sentinel
    │
    ├─ 检测 `bw` CLI 是否已安装
    │   └─ 未安装 → 提示安装指引
    │
    ├─ 检查保险库状态 (`bw status`)
    │   ├─ unauthenticated → 引导登录 (`bw login`)
    │   ├─ locked → 显示解锁对话框
    │   └─ unlocked → 就绪
    │
    ├─ 用户选择连接
    │   └─ 连接配置中的 vault_item_id 指向 Bitwarden 条目
    │       └─ 实时获取凭据 (`bw get item <id>`)
    │           └─ 解析 JSON → 提取用户名/密码/密钥
    │               └─ 建立 SSH 连接
    │                   └─ 凭据从内存清除
    │
    └─ 超时 / 用户手动锁定
        └─ 清除会话令牌 → 需要重新解锁
```

### 7.2 凭据绝不在以下位置明文出现

- ❌ SQLite 数据库
- ❌ GSettings / dconf
- ❌ 日志文件
- ❌ 配置导出文件（必须分离敏感数据）
- ❌ 异常回溯信息
- ❌ 环境变量（子进程执行完毕后不驻留）

*注：凭据允许以加密存储的状态，合法沉淀在 GNOME Keyring (`libsecret`) 中作为加速缓存。*

---

## 8. UI/UX 设计指南

### 8.1 设计原则

- 遵循 [GNOME HIG](https://developer.gnome.org/hig/)
- 使用 libadwaita 自适应布局（支持窄屏 / 宽屏）
- 深色 / 浅色主题自动跟随系统设置
- 动画使用 libadwaita 内建过渡效果
- **极简的分组哲学**：不同于 Termius 复杂的无限嵌套目录树（Tree Navigation），GNOME HIG 更提倡轻量化的操作。本应用的分组将采用“打平的标签（Tags）” 或“一维的段落分隔（Section Headers）”，配合顶部的快速搜索来定位设备，避免界面引入复杂的折叠面板结构。

### 8.2 主要视图

1. **连接列表**（侧边栏）：分组展示、搜索、右键菜单
2. **终端区域**（主内容）：标签式多会话、状态指示器
3. **连接编辑器**（对话框/侧面板）：分步填写、实时验证
4. **偏好设置**（Adw.PreferencesWindow）：外观、终端、安全设置
5. **密钥管理器**（子页面）：密钥列表、生成向导

### 8.3 关键交互

| 快捷键 | 操作 |
|-------|------|
| 双击连接 | 新标签页打开终端 |
| `Ctrl+T` | 新建本地 Shell 标签页 |
| `Ctrl+W` | 关闭当前标签页 |
| `Ctrl+Shift+C/V` | 终端复制/粘贴 |

连接失败时显示 `Adw.Toast` 通知。

---

## 9. 数据模型

### 9.1 连接配置

```python
@dataclass
class Connection:
    id: str                         # UUID
    name: str                       # 显示名称
    hostname: str                   # 主机名或 IP
    port: int = 22                  # 端口
    username: str = ""              # 用户名
    auth_method: AuthMethod = AuthMethod.KEY  # 认证方式
    key_path: str | None = None     # 本地密钥文件路径
    vault_item_id: str | None = None  # 密码管理器条目 ID
    jump_host_id: str | None = None   # 跳板机 Connection ID
    group_id: str | None = None     # 所属分组 ID
    forward_rules: list[ForwardRule] = field(default_factory=list)
    notes: str = ""                 # 备注
    last_connected: datetime | None = None
    created_at: datetime = field(default_factory=datetime.now)
    sort_order: int = 0
```

### 9.2 数据库 Schema

```sql
CREATE TABLE connections (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    hostname TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 22,
    username TEXT NOT NULL DEFAULT '',
    auth_method TEXT NOT NULL DEFAULT 'key',
    key_path TEXT,
    vault_item_id TEXT,
    jump_host_id TEXT REFERENCES connections(id) ON DELETE SET NULL,
    group_id TEXT REFERENCES groups(id) ON DELETE SET NULL,
    notes TEXT DEFAULT '',
    last_connected TEXT,
    created_at TEXT NOT NULL,
    sort_order INTEGER DEFAULT 0
    -- 注意：无密码字段！
);

CREATE TABLE groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    parent_id TEXT REFERENCES groups(id) ON DELETE CASCADE,
    sort_order INTEGER DEFAULT 0,
    color TEXT
);

CREATE TABLE forward_rules (
    id TEXT PRIMARY KEY,
    connection_id TEXT NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
    type TEXT NOT NULL,  -- 'local' | 'remote' | 'dynamic'
    bind_address TEXT DEFAULT '127.0.0.1',
    bind_port INTEGER NOT NULL,
    remote_host TEXT,
    remote_port INTEGER,
    enabled INTEGER DEFAULT 1
);

CREATE TABLE known_hosts (
    hostname TEXT NOT NULL,
    port INTEGER NOT NULL,
    key_type TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    trusted INTEGER DEFAULT 0,
    PRIMARY KEY (hostname, port, key_type)
);
```

---

## 10. 开发阶段

### Phase 1 — 基础框架（约 2 周）
- [ ] Meson 构建系统 + Flatpak 清单
- [ ] Adw.Application 脚手架
- [ ] 主窗口布局（侧栏 + 内容区）
- [ ] SQLite 数据库层 + 迁移系统
- [ ] Connection 模型 + CRUD
- [ ] 单元测试框架搭建

### Phase 2 — SSH 连接 + 终端（约 2 周）
- [ ] asyncssh 连接服务
- [ ] VTE 终端集成
- [ ] 多标签页管理
- [ ] 主机密钥验证 UI
- [ ] 密码/密钥认证流程
- [ ] 连接错误处理

### Phase 3 — 密码管理器集成（约 2 周）
- [ ] VaultBackend 抽象接口
- [ ] Bitwarden CLI 后端实现
- [ ] libsecret 后端实现
- [ ] 保险库解锁 UI
- [ ] 凭据自动匹配
- [ ] 安全内存管理（SecureBytes）
- [ ] 安全测试全部通过

### Phase 4 — 同步与辅助功能（约 1 周）
- [ ] 连接配置导入/导出
- [ ] OpenSSH config 兼容
- [ ] Bitwarden Secure Notes 同步
- [ ] SSH 密钥管理 UI
- [ ] 端口转发管理

### Phase 5 — 打磨与发布（约 1 周）
- [ ] SFTP 文件传输
- [ ] 偏好设置完善
- [ ] i18n 国际化框架
- [ ] Flatpak 打包测试
- [ ] CI/CD 完善
- [ ] 安全审计清单验收

---

## 11. 依赖清单

### 运行时依赖
| 包 | 最低版本 |
|----|---------|
| python | 3.12 |
| gtk4 | 4.12 |
| libadwaita | 1.4 |
| vte-2.91-gtk4 | — |
| pygobject | 3.46 |
| asyncssh | 2.14 |
| aiosqlite | 0.19 |

### 开发依赖
| 包 | 最低版本 |
|----|---------|
| meson | 1.2 |
| ninja | — |
| pytest | 8.0 |
| pytest-asyncio | 0.23 |
| pytest-cov | — |
| bandit | 1.7 |
| ruff | 0.3 |
| mypy | 1.8 |
| safety | — |

### 可选运行时依赖
- `bw` (Bitwarden CLI) — 密码管理器集成

---

## 12. 许可协议

**GPL-3.0-or-later** — 与 GNOME 生态保持一致。

---

> **本文档为开发参考规范，随项目演进持续更新。**
