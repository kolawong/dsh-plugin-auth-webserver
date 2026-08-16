# dsh-plugin-auth-webserver

English | [简体中文](#简体中文)

A drop-in **DeepSeek Harness (`dsh`)** Cordis plugin providing **HTTP Basic Authentication**, **Remote IP & Mobile Device Access**, **Web Cryptography UUID Polyfills**, and **Privileged RPC Gateway Delegation** for self-hosted server deployments.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Cordis Plugin](https://img.shields.io/badge/Cordis-Plugin-blue.svg)](https://github.com/cordiverse/cordis)
[![Topic: dsh-plugin](https://img.shields.io/badge/topic-dsh--plugin-green.svg)](https://github.com/topics/dsh-plugin)

---

## 🚀 Key Features

* 🔒 **HTTP Basic Authentication**: Native browser popup login for cross-device web access (iPhone, iPad, Android, macOS, Windows).
* 🛡️ **Zero Code Modification**: 100% non-intrusive Cordis overlay patch; your upstream `deepseek-harness` git worktree stays completely clean for seamless `git pull` updates.
* 🌐 **Raw IP & Mobile Device Support**: Solves the browser `crypto.randomUUID is not a function` error on plain HTTP / public IP setups by injecting a compliant Web Cryptography UUID Polyfill at `<head>` load time.
* 🔑 **Settings & Presets RPC Trust**: Unlocks privileged settings endpoints (`settings.describe`, `agentPreset.*`) for authenticated remote IP clients without triggering HTTP 403.
* ⚡ **WebSocket Downlinks Protection**: Securely guards live streaming chat connections and event multiplexing.

---

## 📦 Installation

### Step 1: Clone the plugin to your DSH plugins directory

```bash
mkdir -p ~/.dsh/plugins
git clone https://github.com/kolawong/dsh-plugin-auth-webserver.git ~/.dsh/plugins/dsh-plugin-auth-webserver
```

### Step 2: Register package link in DSH environment

```bash
mkdir -p ~/.dsh/node_modules/@custom
ln -sfn ~/.dsh/plugins/dsh-plugin-auth-webserver ~/.dsh/node_modules/@custom/dsh-plugin-auth-webserver
```

### Step 3: Enable the patch overlay

Add the following configuration to `~/.dsh/profiles/web/cordis.patch.yml` (create the file if it does not exist):

```yaml
# Disable default unauthenticated webserver
- id: webserver
  disabled: true

# Insert authenticated webserver
- insert:
    - id: webserver-auth
      name: '@custom/dsh-plugin-auth-webserver'
      inject:
        - webStartup
      config:
        host: '0.0.0.0'
        port: 3080
        username: 'admin'
        password: 'YourStrongPasswordHere'
        realm: 'DeepSeek Harness'
```

### Step 4: Start DeepSeek Harness

```bash
dsh web --port 3080 --trusted-host your-server-ip:3080
```

> **Tip (Environment Variables)**: You can also specify credentials via environment variables:
> ```bash
> export DSH_AUTH_USER="admin"
> export DSH_AUTH_PASS="YourStrongPasswordHere"
> ```

---

## ⚙️ Configuration Reference

| Parameter | Type | Default | Description |
|---|---|---|---|
| `host` | `string` | `'0.0.0.0'` | Bind network interface (`'0.0.0.0'` for all interfaces, `'127.0.0.1'` for local only) |
| `port` | `number` | `3080` | Listening port for the web server |
| `username` | `string` | `'admin'` | Basic Auth username (or use `DSH_AUTH_USER`) |
| `password` | `string` | `''` | Basic Auth password (or use `DSH_AUTH_PASS`). If empty, authentication is disabled |
| `realm` | `string` | `'DeepSeek Harness Authentication'` | HTTP Basic Auth realm prompt displayed by browsers |

---

<br/>

---

# 简体中文

适用于 **DeepSeek Harness (`dsh`)** 的一站式服务器远程部署与密码认证 Cordis 插件。

为自建服务器 / VPS / 移动专线部署提供 **HTTP Basic 密码认证**、**跨设备与原生 IP 支持**、**前端 UUID 兼容补丁** 以及 **管理接口特权放行**。

## 🌟 核心优势

1. **多设备原生密码保护**：手机（iOS Safari、Android Chrome）、平板、电脑打开网页时，自动弹出原生账号密码框，输一次即可保持登录。
2. **零源码侵入（Zero Modification）**：基于 Cordis 分层补丁机制，主仓库 `deepseek-harness` 保持 100% 纯净，后续 `git pull` 升级绝无冲突。
3. **修复纯 IP 访问报错**：解决浏览器在非 HTTPS / 纯 IP 环境下因缺少 `crypto.randomUUID` 导致「Agent 预设」、「权限」无法加载的问题。
4. **管理接口安全放行**：通过内部安全代理映射，放行经过认证的外部 IP 访问 `settings.describe` 和 `agentPreset` 等敏感管理接口（免除 403 拦截）。

## 📖 快速上手

### 1. 克隆插件到 DSH 用户目录

```bash
mkdir -p ~/.dsh/plugins
git clone https://github.com/kolawong/dsh-plugin-auth-webserver.git ~/.dsh/plugins/dsh-plugin-auth-webserver
```

### 2. 建立包映射软链接

```bash
mkdir -p ~/.dsh/node_modules/@custom
ln -sfn ~/.dsh/plugins/dsh-plugin-auth-webserver ~/.dsh/node_modules/@custom/dsh-plugin-auth-webserver
```

### 3. 配置补丁文件

编辑 `~/.dsh/profiles/web/cordis.patch.yml`：

```yaml
- id: webserver
  disabled: true

- insert:
    - id: webserver-auth
      name: '@custom/dsh-plugin-auth-webserver'
      inject:
        - webStartup
      config:
        host: '0.0.0.0'
        port: 3080
        username: 'admin'
        password: '你的自定义密码'
```

### 4. 启动或重启服务

```bash
dsh web --port 3080 --trusted-host 你的服务器IP:3080
```

---

## 📄 开源许可

本项目基于 [MIT License](LICENSE) 开源。欢迎提交 Issue 与 Pull Request！
