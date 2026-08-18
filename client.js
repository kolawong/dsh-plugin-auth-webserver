/**
 * dsh-plugin-auth-webserver — client half (the Web UI settings card).
 *
 * Registers the auth card into the Plugins settings section through the
 * `settings.plugin.item` slot, with bilingual copy installed through the
 * client locale service (`ctx.locale.register`) and the slot's `locale:`
 * seat synthesizing the `t` prop. Icons come from
 * `@deepseek-ai/dsh-client-ui-primitives` plus one inline SVG lock mark.
 *
 * The handoff id must equal the loader entry name (the package name), which
 * is also the graph row id served at /plugins/<id>/client.js.
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
      title: "Web authentication",
      description: "Configure the login credentials, password protection, and session state",
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

    /** Inline lock mark for the card header (kept local: no emoji, no extra deps). */
    function LockIcon(props) {
      return jsx("svg", {
        fill: "none",
        viewBox: "0 0 24 24",
        stroke: "currentColor",
        "aria-hidden": true,
        style: { width: 16, height: 16, flexShrink: 0, color: "#60a5fa", ...props.style },
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

      return jsx("li", {
        style: {
          border: "1px solid var(--dsw-alias-border-l2, #333)",
          borderRadius: "8px",
          background: "var(--dsw-alias-bg-layer-2, #1e1e1e)",
          marginBottom: "12px",
          overflow: "hidden",
          listStyle: "none"
        },
        children: jsxs("div", {
          children: [
            jsxs("button", {
              type: "button",
              onClick: () => setOpen(!open),
              style: {
                width: "100%",
                padding: "14px 16px",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                background: "transparent",
                border: "none",
                color: "inherit",
                cursor: "pointer",
                textAlign: "left"
              },
              children: [
                jsxs("div", {
                  style: { display: "flex", alignItems: "center", gap: "12px" },
                  children: [
                    jsx("div", {
                      style: {
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        width: "32px",
                        height: "32px",
                        borderRadius: "6px",
                        background: "rgba(59, 130, 246, 0.15)",
                        color: "#60a5fa",
                        flexShrink: 0
                      },
                      children: jsx(LockIcon, {})
                    }),
                    jsxs("div", {
                      style: { display: "flex", flexDirection: "column", gap: "3px" },
                      children: [
                        jsx("span", {
                          style: { fontWeight: "600", fontSize: "14px", color: "var(--dsw-alias-label-primary, #fff)" },
                          children: t("title")
                        }),
                        jsx("span", {
                          style: { fontSize: "12px", color: "var(--dsw-alias-label-secondary, #aaa)" },
                          children: t("description")
                        })
                      ]
                    })
                  ]
                }),
                jsxs("div", {
                  style: { display: "flex", alignItems: "center", gap: "10px" },
                  children: [
                    dirty ? jsx("span", {
                      style: {
                        fontSize: "11px",
                        background: "rgba(255, 170, 0, 0.2)",
                        color: "#ffaa00",
                        padding: "2px 6px",
                        borderRadius: "4px"
                      },
                      children: t("unsaved")
                    }) : null,
                    jsxs("span", {
                      style: {
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "5px",
                        padding: "2px 9px",
                        borderRadius: "9999px",
                        background: "rgba(16, 185, 129, 0.12)",
                        color: "#10b981",
                        border: "1px solid rgba(16, 185, 129, 0.25)",
                        fontSize: "11px",
                        fontWeight: "500",
                        whiteSpace: "nowrap"
                      },
                      children: [
                        jsx("span", { style: { width: "5px", height: "5px", borderRadius: "50%", background: "#10b981" } }),
                        t("activeStatus", "已启用")
                      ]
                    }),
                    jsx(IconChevronDownOutline14, {
                      style: {
                        transform: open ? "rotate(180deg)" : "rotate(0deg)",
                        transition: "transform 0.2s",
                        color: "var(--dsw-alias-label-secondary, #aaa)"
                      }
                    })
                  ]
                })
              ]
            }),
                    jsx("span", {
                      style: { fontSize: "12px", color: "var(--dsw-alias-label-secondary, #aaa)" },
                      children: t("description")
                    })
                  ]
                }),
                jsxs("div", {
                  style: { display: "flex", alignItems: "center", gap: "8px" },
                  children: [
                    dirty ? jsx("span", {
                      style: {
                        fontSize: "11px",
                        background: "rgba(255, 170, 0, 0.2)",
                        color: "#ffaa00",
                        padding: "2px 6px",
                        borderRadius: "4px"
                      },
                      children: t("unsaved")
                    }) : null,
                    jsx(IconChevronDownOutline14, {
                      style: {
                        transform: open ? "rotate(180deg)" : "rotate(0deg)",
                        transition: "transform 0.2s"
                      }
                    })
                  ]
                })
              ]
            }),
            open ? jsxs("div", {
              style: {
                padding: "0 16px 16px 16px",
                borderTop: "1px solid var(--dsw-alias-border-l2, #333)",
                display: "flex",
                flexDirection: "column",
                gap: "14px",
                paddingTop: "14px"
              },
              children: [
                jsxs("div", {
                  style: { display: "flex", flexDirection: "column", gap: "6px" },
                  children: [
                    jsx("label", {
                      style: { fontSize: "13px", fontWeight: "500", color: "var(--dsw-alias-label-primary, #eee)" },
                      children: t("usernameLabel")
                    }),
                    jsx("input", {
                      type: "text",
                      value: username,
                      onChange: (e) => { setUsername(e.target.value); setDirty(true); },
                      style: {
                        height: "36px",
                        padding: "0 12px",
                        borderRadius: "6px",
                        border: "1px solid var(--dsw-alias-border-l2, #444)",
                        background: "var(--dsw-alias-bg-layer-3, #2a2a2a)",
                        color: "inherit",
                        fontSize: "13px"
                      }
                    })
                  ]
                }),
                jsxs("div", {
                  style: { display: "flex", flexDirection: "column", gap: "6px" },
                  children: [
                    jsx("label", {
                      style: { fontSize: "13px", fontWeight: "500", color: "var(--dsw-alias-label-primary, #eee)" },
                      children: t("passwordLabel")
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
                            height: "36px",
                            padding: "0 12px",
                            borderRadius: "6px",
                            border: "1px solid var(--dsw-alias-border-l2, #444)",
                            background: "var(--dsw-alias-bg-layer-3, #2a2a2a)",
                            color: "inherit",
                            fontSize: "13px"
                          }
                        }),
                        jsx("button", {
                          type: "button",
                          onClick: () => setShowPassword(!showPassword),
                          style: {
                            padding: "0 12px",
                            borderRadius: "6px",
                            border: "1px solid var(--dsw-alias-border-l2, #444)",
                            background: "var(--dsw-alias-bg-layer-3, #2a2a2a)",
                            color: "inherit",
                            cursor: "pointer",
                            fontSize: "12px"
                          },
                          children: showPassword ? t("hide") : t("show")
                        })
                      ]
                    }),
                    jsx("span", {
                      style: { fontSize: "11px", color: "var(--dsw-alias-label-tertiary, #888)" },
                      children: t("passwordHint")
                    })
                  ]
                }),
                msg ? jsx("div", {
                  style: {
                    padding: "8px 12px",
                    borderRadius: "6px",
                    fontSize: "12px",
                    display: "flex",
                    alignItems: "center",
                    gap: "8px",
                    background: msg.type === "success" ? "rgba(0, 200, 80, 0.15)" : "rgba(255, 60, 60, 0.15)",
                    color: msg.type === "success" ? "#00e676" : "#ff5252"
                  },
                  children: [
                    msg.type === "success"
                      ? jsx(IconCheckOutline16, { size: 16 })
                      : jsx(IconWarningOutline16, { size: 16 }),
                    jsx("span", { children: msg.text })
                  ]
                }) : null,
                jsxs("div", {
                  style: { display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "6px" },
                  children: [
                    jsx("button", {
                      type: "button",
                      onClick: handleLogout,
                      style: {
                        padding: "6px 14px",
                        borderRadius: "6px",
                        border: "1px solid rgba(255, 80, 80, 0.4)",
                        background: "rgba(255, 60, 60, 0.1)",
                        color: "#ff6b6b",
                        cursor: "pointer",
                        fontSize: "13px"
                      },
                      children: t("logout")
                    }),
                    jsxs("div", {
                      style: { display: "flex", gap: "10px" },
                      children: [
                        jsx("button", {
                          type: "button",
                          disabled: !dirty || saving,
                          onClick: handleDiscard,
                          style: {
                            padding: "6px 14px",
                            borderRadius: "6px",
                            border: "1px solid var(--dsw-alias-border-l2, #444)",
                            background: "transparent",
                            color: "inherit",
                            cursor: dirty && !saving ? "pointer" : "default",
                            opacity: dirty && !saving ? 1 : 0.5,
                            fontSize: "13px"
                          },
                          children: t("discard")
                        }),
                        jsx("button", {
                          type: "button",
                          disabled: !dirty || saving,
                          onClick: handleSave,
                          style: {
                            padding: "6px 16px",
                            borderRadius: "6px",
                            border: "none",
                            background: "#3b82f6",
                            color: "#fff",
                            fontWeight: "500",
                            cursor: dirty && !saving ? "pointer" : "default",
                            opacity: dirty && !saving ? 1 : 0.5,
                            fontSize: "13px"
                          },
                          children: saving ? t("saving") : t("save")
                        })
                      ]
                    })
                  ]
                })
              ]
            }) : null
          ]
        })
      });
    }

    exports.inject = ["locale", "slots"];

    exports.apply = function (ctx) {
      // Bilingual dictionaries, registered before the slot so the renderer's
      // `t` seat can resolve them once the card mounts.
      ctx.locale.register(NS, { zh, en });
      ctx.slots.inject("settings.plugin.item", function* () {
        yield ctx.slots.register({
          name: "settings.plugin.item",
          key: "auth-webserver",
          id: "auth-webserver",
          order: -1,
          locale: NS
        }, AuthCard);
      });
    };

    return exports;
  }
});
