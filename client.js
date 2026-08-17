window.__ModuleLoader__.load({
  id: "@custom/dsh-plugin-auth-webserver",
  factory: (require) => {
    const exports = {};
    const React = require("react");
    const { useState, useEffect } = React;
    const { jsxs, jsx } = require("react/jsx-runtime");
    const { IconChevronDownOutline14 } = require("@deepseek-ai/dsh-client-ui-primitives");

    function AuthCard() {
      const [open, setOpen] = useState(false);
      const [username, setUsername] = useState("");
      const [password, setPassword] = useState("");
      const [realm, setRealm] = useState("");
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
              setRealm(data.realm || "DeepSeek Harness Authentication");
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
          body: JSON.stringify({ username, password, realm })
        })
          .then(r => r.json())
          .then(data => {
            setSaving(false);
            if (data && data.ok) {
              setDirty(false);
              setMsg({ type: "success", text: "✅ 账号密码已更新并立即生效！" });
            } else {
              setMsg({ type: "error", text: "❌ 保存失败: " + (data && data.error ? data.error : "未知错误") });
            }
          })
          .catch(err => {
            setSaving(false);
            setMsg({ type: "error", text: "❌ 请求失败: " + err.message });
          });
      };

      const handleDiscard = () => {
        loadAuth();
        setMsg(null);
      };

      const handleLogout = () => {
        if (confirm("确定要退出当前登录吗？")) {
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
                  style: { display: "flex", flexDirection: "column", gap: "4px" },
                  children: [
                    jsx("span", {
                      style: { fontWeight: "600", fontSize: "14px", color: "var(--dsw-alias-label-primary, #fff)" },
                      children: "🔒 Web 访问密码认证 (Web Authentication)"
                    }),
                    jsx("span", {
                      style: { fontSize: "12px", color: "var(--dsw-alias-label-secondary, #aaa)" },
                      children: "配置远程访问、Web 登录界面密码与会话状态"
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
                      children: "未保存"
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
                      children: "登录用户名 (Username)"
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
                      children: "登录密码 (Password)"
                    }),
                    jsxs("div", {
                      style: { display: "flex", gap: "8px" },
                      children: [
                        jsx("input", {
                          type: showPassword ? "text" : "password",
                          value: password,
                          onChange: (e) => { setPassword(e.target.value); setDirty(true); },
                          placeholder: "留空则关闭密码保护",
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
                          children: showPassword ? "隐藏" : "显示"
                        })
                      ]
                    }),
                    jsx("span", {
                      style: { fontSize: "11px", color: "var(--dsw-alias-label-tertiary, #888)" },
                      children: "提示：修改密码后自动生效，未登录的用户在访问 Web 界面时将看到 DeepSeek 风格的登录页面。"
                    })
                  ]
                }),
                msg ? jsx("div", {
                  style: {
                    padding: "8px 12px",
                    borderRadius: "6px",
                    fontSize: "12px",
                    background: msg.type === "success" ? "rgba(0, 200, 80, 0.15)" : "rgba(255, 60, 60, 0.15)",
                    color: msg.type === "success" ? "#00e676" : "#ff5252"
                  },
                  children: msg.text
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
                      children: "退出登录"
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
                          children: "放弃更改"
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
                          children: saving ? "保存中..." : "保存设置"
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

    exports.apply = function(ctx) {
      ctx.inject(["slots"], (sctx) => {
        sctx.slots.inject("settings.plugin.item", function* () {
          yield sctx.slots.register({
            name: "settings.plugin.item",
            id: "auth-webserver",
            order: -1
          }, AuthCard);
        });
      });
    };

    return exports;
  }
});
