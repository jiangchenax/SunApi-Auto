# NewAPI 自动签到

专为 **https://sunapi.5201201314.top** 开发的自动签到脚本。

**账号密码**认证

## 功能

- ✅ 账号密码自动登录（浏览器内解 Turnstile，自动获取 Bearer JWT）
- ✅ 签到自动解 Turnstile 人机验证
- ✅ PoW 工作量证明自动解算
- ✅ 多账号签到
- ✅ GitHub Actions 每天北京时间 08:00 定时执行
- ✅ 配置全部走环境变量，密码不写入代码/仓库

## 快速开始（GitHub Actions 定时运行）

### 1. 配置 Secret

仓库 `Settings → Secrets and variables → Actions → New repository secret` 新建：

| Secret 名称 | 值 |
|---|---|
| `NEWAPI_ACCOUNTS` | 账号配置 JSON（见下） |

单账号（`url` 可省略，默认即本站点）：

```json
[{"login_username":"你的用户名","login_password":"你的密码","name":"账号1"}]
```

多账号：

```json
[
  {"login_username":"admin","login_password":"密码1","name":"账号1"},
  {"login_username":"a@qq.com","login_password":"密码2","name":"账号2"}
]
```

### 2. 启用并手动测试

进入 `Actions` 页面启用工作流，选择 `NewAPI 自动签到` → `Run workflow` 手动触发，查看日志确认签到成功。

### 3. 定时执行

工作流默认每天 **北京时间 08:00**（UTC 00:00）自动执行。修改时间在 `.github/workflows/checkin.yml` 中调整 cron：

```yaml
schedule:
  - cron: '0 0 * * *'   # UTC 00:00 = 北京时间 08:00
```

## 本地运行

```bash
# 1. 安装依赖（首次需安装浏览器）
pip install -r requirements.txt
playwright install chromium --with-deps

# 2. 配置环境变量（二选一）
export NEWAPI_ACCOUNTS='[{"login_username":"你的用户名","login_password":"你的密码","name":"账号1"}]'
# 或复制 .env.example 为 .env 填写

# 3. 运行（无桌面环境需 xvfb 虚拟显示；有桌面直接运行）
xvfb-run --auto-servernum python checkin.py
```

## 工作原理

| 环节 | 处理方式 |
|---|---|
| Turnstile 人机验证 | 启动真实 Chrome（无自动化标记）+ CDP 连接，组件正常渲染后按坐标模拟点击，自动取 token |
| 账号密码登录 | 页面内解验证后提交 `POST /api/user/login?turnstile=<token>`，返回 Bearer JWT 写入请求头 |
| 签到 | `POST /api/user/checkin`，需要 Turnstile 时浏览器页面内完成验证+签到 |
| PoW 工作量证明 | 本地解算 SHA-256 nonce |

登录与签到需要解 Turnstile，GitHub Actions 中通过 `xvfb-run` 提供虚拟显示，工作流已内置 `playwright install chromium` 步骤。

## 目录结构

| 文件 | 说明 |
|---|---|
| `checkin.py` | 主签到脚本（账号密码登录 + 签到，多账号） |
| `turnstile_solver.py` | Turnstile 自动求解器（真实 Chrome + CDP） |
| `requirements.txt` | Python 依赖 |
| `.env.example` | 环境变量配置模板 |
| `.github/workflows/checkin.yml` | GitHub Actions 定时工作流 |

## 安全提示

- 密码通过环境变量/Secret 注入，**切勿把真实密码写入代码或提交到仓库**
- 仓库建议设为 Private
- 请遵守站点服务条款，合理使用自动签到功能

## 许可证

MIT License
