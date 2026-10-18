# SunApi-Auto

NewAPI 站点自动签到脚本，默认适配 `https://sunapi.5201201314.top`。

支持账号密码登录、Turnstile 人机验证、PoW 工作量证明、多账号和 GitHub Actions 定时执行。

## 变量配置

在仓库 `Settings → Secrets and variables → Actions` 新建 Secret：

| 名称 | 内容 |
|---|---|
| `NEWAPI_ACCOUNTS` | 账号配置 JSON 数组 |

数组字段：

| 字段 | 必填 | 说明 |
|---|---|---|
| `login_username` | 是 | 登录用户名或邮箱 |
| `login_password` | 是 | 登录密码 |
| `name` | 否 | 日志备注，默认使用用户名 |
| `url` | 否 | 站点地址，默认 `https://sunapi.5201201314.top` |

单账号：

```json
[{"login_username":"你的用户名","login_password":"你的密码","name":"账号1"}]
```

多账号：

```json
[
  {"login_username":"a@example.com","login_password":"密码1","name":"账号1"},
  {"login_username":"b@example.com","login_password":"密码2","name":"账号2"}
]
```

## 运行

Actions 页面选择 `NewAPI 自动签到` → `Run workflow` 手动执行，或等待每天北京时间 08:00 自动运行。

本地运行：

```bash
pip install -r requirements.txt
playwright install chromium --with-deps
export NEWAPI_ACCOUNTS='[{"login_username":"用户名","login_password":"密码"}]'
xvfb-run --auto-servernum python checkin.py
```

## 安全

- 密码只通过 Secret 或环境变量传入，不写入代码
- 日志会对站点、用户名、备注做脱敏
- **建议将仓库设为 Private**：公开仓库的 Actions 日志任何人都能查看
- 脚本会绕过人机验证，存在账号被风控的风险，请遵守站点服务条款
