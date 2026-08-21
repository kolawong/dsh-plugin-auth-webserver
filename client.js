/**
 * dsh-plugin-auth-webserver — client half (the Web UI settings card).
 *
 * Registers the auth card into the Plugins settings section through the
 * `settings.plugin.item` slot, aligned with official DSH card design.
 */

window.__ModuleLoader__.load({
  id: "dsh-plugin-auth-webserver",
  factory: (require) => {
    const exports = {};
    const React = require("react");
    const { useState, useEffect } = React;
    const { jsxs, jsx } = require("react/jsx-runtime");
    const { IconChevronDownOutline14, IconCheckOutline16, IconWarningOutline16 } = require("@deepseek-ai/dsh-client-ui-primitives");

    /** Locale namespace owning this card's copy. */
    const NS = "settings.plugin.auth-webserver";

    const zh = {
      activeStatus: "已启用",
      protectedStatus: "密码保护中",
      unprotectedStatus: "无密码保护",
      title: "Web 访问认证",
      description: "配置登录凭据、密码保护与登录会话",
      usernameLabel: "登录用户名",
      passwordLabel: "登录密码",
      passwordPlaceholder: "留空则关闭密码保护",
      passwordHint: "修改后立即生效；未登录用户访问 Web 界面时会看到登录页面。",
      show: "显示",
      hide: "隐藏",
      unsaved: "未保存",
      logout: "退出登录",
      logoutConfirm: "确定要退出当前登录吗？",
      discard: "放弃更改",
      save: "保存设置",
      saving: "保存中…",
      saveSuccess: "账号密码已更新并立即生效。",
      saveFailed: "保存失败：{message}",
      requestFailed: "请求失败：{message}",
    };

    const en = {
      activeStatus: "Enabled",
      protectedStatus: "Protected",
      unprotectedStatus: "No Password",
      title: "Web authentication",
      description: "Configure login credentials, password protection, and sessions",
      usernameLabel: "Username",
      passwordLabel: "Password",
      passwordPlaceholder: "Leave blank to disable password protection",
      passwordHint: "Changes apply immediately; unauthenticated visitors see the login page.",
      show: "Show",
      hide: "Hide",
      unsaved: "Unsaved",
      logout: "Sign out",
      logoutConfirm: "Sign out of the current session?",
      discard: "Discard",
      save: "Save settings",
      saving: "Saving…",
      saveSuccess: "Credentials updated and applied immediately.",
      saveFailed: "Save failed: {message}",
      requestFailed: "Request failed: {message}",
    };

    /** Inline lock mark for the card header */
    function LockIcon(props) {
      return jsx("svg", {
        fill: "none",
        viewBox: "0 0 24 24",
        stroke: "currentColor",
        "aria-hidden": true,
        style: { width: 16, height: 16, flexShrink: 0, color: "var(--dsw-alias-brand-primary, #60a5fa)", ...props.style },
        children: jsx("path", {
          strokeLinecap: "round",
          strokeLinejoin: "round",
          strokeWidth: 2,
          d: "M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z",
        }),
      });
    }

    function AuthCard({ t }) {
      const [open, setOpen] = useState(false);
      const [username, setUsername] = useState("");
      const [password, setPassword] = useState("");
      const [showPassword, setShowPassword] = useState(false);
      const [dirty, setDirty] = useState(false);
      const [saving, setSaving] = useState(false);
      const [msg, setMsg] = useState(null);

      const loadAuth = () => {
        fetch("/api/auth.get")
          .then(r => r.json())
          .then(data => {
            if (data && data.ok) {
              setUsername(data.username || "");
              setPassword(data.password || "");
              setDirty(false);
            }
          })
          .catch(() => {});
      };

      useEffect(() => {
        loadAuth();
      }, []);

      const handleSave = () => {
        setSaving(true);
        setMsg(null);
        fetch("/api/auth.update", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password })
        })
          .then(r => r.json())
          .then(data => {
            setSaving(false);
            if (data && data.ok) {
              setDirty(false);
              setMsg({ type: "success", text: t("saveSuccess") });
            } else {
              setMsg({ type: "error", text: t("saveFailed", { message: data && data.error ? data.error : "?" }) });
            }
          })
          .catch(err => {
            setSaving(false);
            setMsg({ type: "error", text: t("requestFailed", { message: err.message }) });
          });
      };

      const handleDiscard = () => {
        loadAuth();
        setMsg(null);
      };

      const handleLogout = () => {
        if (confirm(t("logoutConfirm"))) {
          fetch("/api/auth.logout", { method: "POST" })
            .then(() => {
              window.location.reload();
            })
            .catch(() => {
              window.location.reload();
            });
        }
      };

      const isProtected = Boolean(password);

      return jsx("li", {
        style: {
          listStyle: "none",
          border: "1px solid " + (open ? "var(--dsw-alias-label-dimmed, #4b5563)" : "var(--dsw-alias-border-l2, #333)"),
          borderRadius: "12px",
          background: open ? "var(--dsw-alias-bg-layer-2, #1e1e1e)" : "var(--dsw-alias-bg-layer-3, #242424)",
          transition: "border-color .16s, background .16s",
        },
        children: jsxs("div", {
          children: [
            jsxs("button", {
              type: "button",
              onClick: () => setOpen(!open),
              "aria-expanded": open,
              style: {
                width: "100%",
                appearance: "none",
                border: 0,
                background: "none",
                font: "inherit",
                color: "inherit",
                textAlign: "left",
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                gap: "12px",
                padding: "14px 16px",
                borderRadius: "12px",
              },
              children: [
                jsxs("span", {
                  style: {
                    flex: 1,
                    minWidth: 0,
                    display: "flex",
                    flexDirection: "column",
                    gap: "4px",
                  },
                  children: [
                    jsxs("span", {
                      style: {
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "8px",
                        fontSize: "15px",
                        fontWeight: "600",
                        lineHeight: 1.4,
                        color: "var(--dsw-alias-label-primary, #f3f4f6)",
                      },
                      children: [
                        jsx(LockIcon, {}),
                        jsx("span", { children: t("title") }),
                      ],
                    }),
                    jsx("span", {
                      style: {
                        fontSize: "13px",
                        lineHeight: 1.5,
                        color: "var(--dsw-alias-label-tertiary, #9ca3af)",
                      },
                      children: t("description"),
                    }),
                  ],
                }),
                dirty
                  ? jsx("span", {
                      style: {
                        flex: "none",
                        borderRadius: "999px",
                        padding: "1px 8px",
                        fontSize: "11px",
                        lineHeight: "17px",
                        fontWeight: "500",
                        whiteSpace: "nowrap",
                        background: "var(--dsw-alias-bg-module-platform, rgba(255,255,255,0.08))",
                        color: "var(--dsw-alias-label-secondary, #d1d5db)",
                      },
                      children: t("unsaved"),
                    })
                  : jsx("span", {
                      style: {
                        flex: "none",
                        borderRadius: "999px",
                        padding: "1px 8px",
                        fontSize: "11px",
                        lineHeight: "17px",
                        fontWeight: "500",
                        whiteSpace: "nowrap",
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "5px",
                        background: isProtected ? "rgba(16, 185, 129, 0.12)" : "rgba(156, 163, 175, 0.12)",
                        color: isProtected ? "#10b981" : "#9ca3af",
                        border: isProtected ? "1px solid rgba(16, 185, 129, 0.25)" : "1px solid rgba(156, 163, 175, 0.2)",
                      },
                      children: [
                        jsx("span", {
                          style: {
                            width: 6,
                            height: 6,
                            borderRadius: "50%",
                            background: isProtected ? "#10b981" : "#9ca3af",
                            display: "inline-block",
                          },
                        }),
                        jsx("span", { children: isProtected ? t("protectedStatus") : t("unprotectedStatus") }),
                      ],
                    }),
                jsx(IconChevronDownOutline14, {
                  style: {
                    flex: "none",
                    color: "var(--dsw-alias-label-tertiary, #9ca3af)",
                    transform: open ? "rotate(180deg)" : "rotate(0deg)",
                    transition: "transform .16s",
                  },
                }),
              ],
            }),
            open
              ? jsxs("div", {
                  style: {
                    borderTop: "1px solid var(--dsw-alias-border-l2, #333)",
                    margin: "0 16px",
                    paddingTop: "14px",
                    paddingBottom: "8px",
                    display: "flex",
                    flexDirection: "column",
                    gap: "14px",
                  },
                  children: [
                    jsxs("div", {
                      style: { display: "flex", flexDirection: "column", gap: "6px" },
                      children: [
                        jsx("label", {
                          style: { fontSize: "13px", fontWeight: "500", lineHeight: 1.5, color: "var(--dsw-alias-label-primary, #f3f4f6)" },
                          children: t("usernameLabel"),
                        }),
                        jsx("input", {
                          type: "text",
                          value: username,
                          onChange: (e) => { setUsername(e.target.value); setDirty(true); },
                          style: {
                            height: "34px",
                            padding: "0 12px",
                            borderRadius: "8px",
                            border: "1px solid var(--dsw-alias-border-l2, #374151)",
                            background: "var(--dsw-alias-bg-layer-3, #1f2937)",
                            color: "var(--dsw-alias-label-primary, #f3f4f6)",
                            font: "inherit",
                            fontSize: "13px",
                            outline: "none",
                          },
                        }),
                      ],
                    }),
                    jsxs("div", {
                      style: { display: "flex", flexDirection: "column", gap: "6px" },
                      children: [
                        jsx("label", {
                          style: { fontSize: "13px", fontWeight: "500", lineHeight: 1.5, color: "var(--dsw-alias-label-primary, #f3f4f6)" },
                          children: t("passwordLabel"),
                        }),
                        jsxs("div", {
                          style: { display: "flex", gap: "8px" },
                          children: [
                            jsx("input", {
                              type: showPassword ? "text" : "password",
                              value: password,
                              onChange: (e) => { setPassword(e.target.value); setDirty(true); },
                              placeholder: t("passwordPlaceholder"),
                              style: {
                                flex: 1,
                                height: "34px",
                                padding: "0 12px",
                                borderRadius: "8px",
                                border: "1px solid var(--dsw-alias-border-l2, #374151)",
                                background: "var(--dsw-alias-bg-layer-3, #1f2937)",
                                color: "var(--dsw-alias-label-primary, #f3f4f6)",
                                font: "inherit",
                                fontSize: "13px",
                                outline: "none",
                              },
                            }),
                            jsx("button", {
                              type: "button",
                              onClick: () => setShowPassword(!showPassword),
                              style: {
                                padding: "0 12px",
                                height: "34px",
                                borderRadius: "8px",
                                border: "1px solid var(--dsw-alias-border-l2, #374151)",
                                background: "none",
                                color: "var(--dsw-alias-label-secondary, #d1d5db)",
                                cursor: "pointer",
                                fontSize: "12px",
                                font: "inherit",
                              },
                              children: showPassword ? t("hide") : t("show"),
                            }),
                          ],
                        }),
                        jsx("p", {
                          style: { margin: 0, fontSize: "12px", lineHeight: 1.5, color: "var(--dsw-alias-label-tertiary, #9ca3af)" },
                          children: t("passwordHint"),
                        }),
                      ],
                    }),
                    msg
                      ? jsx("div", {
                          style: {
                            padding: "8px 12px",
                            borderRadius: "8px",
                            fontSize: "12px",
                            lineHeight: 1.5,
                            display: "flex",
                            alignItems: "center",
                            gap: "8px",
                            background: msg.type === "success" ? "rgba(16, 185, 129, 0.12)" : "rgba(239, 68, 68, 0.12)",
                            color: msg.type === "success" ? "#10b981" : "#ef4444",
                            border: msg.type === "success" ? "1px solid rgba(16, 185, 129, 0.25)" : "1px solid rgba(239, 68, 68, 0.25)",
                          },
                          children: [
                            msg.type === "success"
                              ? jsx(IconCheckOutline16, { size: 16 })
                              : jsx(IconWarningOutline16, { size: 16 }),
                            jsx("span", { children: msg.text }),
                          ],
                        })
                      : null,
                    jsxs("div", {
                      style: {
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        padding: "12px 0 4px",
                        borderTop: "1px solid var(--dsw-alias-border-l2, #333)",
                      },
                      children: [
                        jsx("button", {
                          type: "button",
                          onClick: handleLogout,
                          style: {
                            appearance: "none",
                            border: "1px solid rgba(239, 68, 68, 0.3)",
                            borderRadius: "8px",
                            padding: "5px 14px",
                            background: "rgba(239, 68, 68, 0.08)",
                            color: "#ef4444",
                            cursor: "pointer",
                            fontSize: "13px",
                            lineHeight: 1.5,
                            font: "inherit",
                          },
                          children: t("logout"),
                        }),
                        jsxs("div", {
                          style: { display: "flex", gap: "8px" },
                          children: [
                            jsx("button", {
                              type: "button",
                              disabled: !dirty || saving,
                              onClick: handleDiscard,
                              style: {
                                appearance: "none",
                                border: "1px solid var(--dsw-alias-border-l2, #374151)",
                                borderRadius: "8px",
                                padding: "5px 14px",
                                background: "none",
                                color: "var(--dsw-alias-label-secondary, #d1d5db)",
                                cursor: dirty && !saving ? "pointer" : "default",
                                opacity: dirty && !saving ? 1 : 0.4,
                                fontSize: "13px",
                                lineHeight: 1.5,
                                font: "inherit",
                              },
                              children: t("discard"),
                            }),
                            jsx("button", {
                              type: "button",
                              disabled: !dirty || saving,
                              onClick: handleSave,
                              style: {
                                appearance: "none",
                                border: "1px solid transparent",
                                borderRadius: "8px",
                                padding: "5px 14px",
                                background: "var(--dsw-alias-label-primary, #f3f4f6)",
                                color: "var(--dsw-alias-bg-layer-3, #111827)",
                                fontWeight: "500",
                                cursor: dirty && !saving ? "pointer" : "default",
                                opacity: dirty && !saving ? 1 : 0.4,
                                fontSize: "13px",
                                lineHeight: 1.5,
                                font: "inherit",
                              },
                              children: saving ? t("saving") : t("save"),
                            }),
                          ],
                        }),
                      ],
                    }),
                  ],
                })
              : null,
          ],
        }),
      });
    }

    exports.inject = ["locale", "slots"];

    exports.apply = function (ctx) {
      ctx.locale.register(NS, { zh, en });
      ctx.slots.inject("settings.plugin.item", function* () {
        yield ctx.slots.register({
          name: "settings.plugin.item",
          key: "auth-webserver",
          id: "auth-webserver",
          order: -1,
          locale: NS,
        }, AuthCard);
      });
    };

    return exports;
  },
});
