# dsh-plugin-auth-webserver

[![GitHub license](https://img.shields.io/github/license/kolawong/dsh-plugin-auth-webserver?style=flat-square)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/kolawong/dsh-plugin-auth-webserver?style=flat-square)](https://github.com/kolawong/dsh-plugin-auth-webserver/stargazers)
[![DeepSeek Harness](https://img.shields.io/badge/DeepSeek%20Harness-Cordis%20Plugin-blue?style=flat-square)](https://github.com/deepseek-ai/deepseek-harness)

**DeepSeek Harness (DSH)** 专属的 Web 安全认证与登录插件。为公网服务器部署、局域网共享和多设备远程访问提供原生外观的 **Web 登录界面 (Web Login Page)**、**Cookie/Session 会话保持**、**HTTP Basic Auth 兼容**、**Web UI 可视化设置卡片** 以及 **非 HTTPS / 裸 IP 环境 Web Crypto UUID 自动 Polyfill**。

---

## ✨ 核心特性 (Features)

1. **🎨 深度匹配 DSH 原生美学的 Web 登录界面**：
   - 告别浏览器简陋的弹窗，提供暗黑毛玻璃质感、微光边框、DeepSeek 风格专属定制的网页登录页面。
   - 响应式设计，完美适配 PC 与手机端浏览器。
   - 支持密码显示/隐藏切换、错误抖动提示与一键回车提交。
2. **🍪 安全无缝的 Cookie / Session 会话机制**：
   - 登录成功后自动生成 30 天加密 HMAC 会话 Token，无需反复输入账号密码。
   - 提供 `/api/auth.logout` 一键退出登录接口。
3. **⚙️ Web GUI 可视化设置卡片**：
   - 在 DSH 网页端 **「设置」->「插件（Plugins）」** 中直接查看与修改登录账号密码。
   - 修改后立即热生效并自动回写持久化配置文件，无需重启服务。
4. **🔌 全兼容机制**：
   - 同时支持 `Cookie` 会话与 `HTTP Basic Auth` 标头，方便命令行脚本、API 与自动化工具无缝调用。
   - 包含完整的 WebSocket (`upgrade`) 安全鉴权。
5. **🛡️ 远端 IP 特权 RPC 网关信任委托**：
   - 自动处理请求 `Host` / `Origin` 映射，彻底解决通过公网 IP 访问时 `settings.describe` 与 `agentPreset.*` 报 `HTTP 403 Forbidden` 的问题。
6. **🔑 Web Crypto UUID 自动 Polyfill**：
   - 自动在 Web 页面 `<head>` 中注入安全的 UUID 生成器，彻底解决非 HTTPS 或直接通过 IP 访问时客户端崩溃的问题。

---

## 📦 安装与配置 (Installation)

### 1. 安装插件到 DSH 插件目录

在 DSH 运行环境的插件目录下安装：

```bash
mkdir -p ~/.dsh/plugins/dsh-plugin-auth-webserver
cd ~/.dsh/plugins/dsh-plugin-auth-webserver
git clone https://github.com/kolawong/dsh-plugin-auth-webserver.git .
```

### 2. 配置 Web Profile 补丁

在 `~/.dsh/profiles/web/cordis.patch.yml` 中添加：

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
        port: !!js ctx.webStartup.port ?? 3080
        username: 'admin'
        password: 'your_secure_password'
```

### 3. 重启 DSH 服务

```bash
# 如果使用 systemd 管理
systemctl restart deepseek-harness

# 或直接运行
dsh web --port 3080
```

打开浏览器访问 `http://your-server-ip:3080`，即可看到全新的 DSH 原生风格登录页面！

---

## 📄 开源许可证 (License)

本项目采用 [MIT 许可证](LICENSE)。
