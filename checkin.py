#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NewAPI 自动签到（专为 https://sunapi.5201201314.top 开发）

- 仅支持账号密码登录（环境变量 NEWAPI_ACCOUNTS 配置），无需 Session/系统访问令牌
- 站点强制 Turnstile 人机验证，登录和签到均由真实浏览器自动解验证
- 多账号签到：NEWAPI_ACCOUNTS 为 JSON 数组
- 适配 GitHub Actions 定时执行（每天北京时间 08:00）

运行方式：
    1. 配置环境变量 NEWAPI_ACCOUNTS（或写入同目录 .env）
    2. 执行：python checkin.py（无桌面环境用 xvfb-run）
"""

import os
import sys
import json
import requests
from datetime import datetime
from typing import Optional

# 本仓库唯一适配站点（NEWAPI_ACCOUNTS 中 url 缺省时使用）
DEFAULT_BASE_URL = 'https://sunapi.5201201314.top'


def _get_system_proxy() -> Optional[str]:
    """读取系统代理，保证浏览器与 requests 走同一出口（Windows 会读注册表）"""
    try:
        import urllib.request
        proxies = urllib.request.getproxies()
        return proxies.get('https') or proxies.get('http')
    except Exception:
        return None


class NewAPICheckin:
    """NewAPI 签到类（仅账号密码认证）"""

    def __init__(self, base_url: str, login_username: str, login_password: str):
        self.base_url = base_url.rstrip('/')
        self.login_username = login_username
        self.login_password = login_password
        self.access_token = None          # 登录成功后为 'Bearer <JWT>'
        self.user_id = None               # 登录成功后自动补齐
        self.session = requests.Session()
        proxy = _get_system_proxy()
        if proxy:
            self.session.proxies.update({'http': proxy, 'https': proxy})
        self.session.headers.update({
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Cache-Control': 'no-store',
            'Pragma': 'no-cache',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        })

    # ---------- 登录 ----------

    def _browser_login(self, force: bool = False) -> bool:
        """
        账号密码登录：真实 Chrome 解 Turnstile 后在页面内提交登录，获取 Bearer JWT。

        本站点登录强制 Turnstile，requests 无法直连，必须走浏览器。

        Args:
            force: 强制重新登录（令牌已失效时使用，忽略现有 access_token）
        """
        if not self.login_username or not self.login_password:
            return False

        # 本次运行内已有访问令牌则无需重复登录（force=True 时跳过此判断）
        if self.access_token and not force:
            return True

        # 强制重登前清空旧令牌，避免带着失效凭证重试 / 复用
        if force:
            self.access_token = None
            self.user_id = None
            self.session.headers.pop('Authorization', None)
            self.session.headers.pop('new-api-user', None)

        try:
            from turnstile_solver import login_and_get_token
        except ImportError:
            print('  [登录] 缺少依赖 (playwright + Chrome)，无法登录')
            return False

        print('  [登录] 浏览器内账号密码登录（自动解 Turnstile，会弹出 Chrome 窗口）...')
        data = login_and_get_token(self.base_url, self.login_username, self.login_password)

        if not data:
            print('  [登录] 浏览器登录失败')
            return False

        access_token = data.get('access_token')
        if not access_token:
            print('  [登录] 登录响应缺少 access_token')
            return False

        token_type = data.get('token_type') or 'Bearer'
        self.access_token = f'{token_type} {access_token}'
        self.session.headers['Authorization'] = self.access_token

        user = data.get('user') or {}
        if user.get('id'):
            self.user_id = str(user['id'])
            self.session.headers['new-api-user'] = str(user['id'])

        print(f'  [登录] 浏览器登录成功，已更新访问令牌 (type={token_type})')
        return True

    # ---------- 用户信息 ----------

    def get_user_info(self, verbose: bool = False) -> Optional[dict]:
        """获取用户信息；认证失败时自动浏览器登录后重试"""
        try:
            resp = self.session.get(f'{self.base_url}/api/user/self', timeout=30)

            if verbose:
                print(f'  [调试] HTTP 状态码: {resp.status_code}')
                print(f'  [调试] 响应内容预览: {resp.text[:200]}...')

            # 认证失败：尝试自动登录
            if resp.status_code == 401:
                print('[错误] 认证失败 (401)，尝试重新登录...')
                if not self._browser_login(force=True):
                    print('  [登录] 尝试登录不成功')
                    return None
                print('  [登录] 重试获取用户信息...')
                resp = self.session.get(f'{self.base_url}/api/user/self', timeout=30)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if data.get('success'):
                            user_data = data.get('data')
                            if user_data and 'id' in user_data:
                                self.user_id = user_data['id']
                                self.session.headers.update({'new-api-user': str(self.user_id)})
                            return user_data
                    except Exception:
                        pass
                print('  [登录] 重试后仍无法获取用户信息')
                return None

            try:
                data = resp.json()
            except json.JSONDecodeError:
                content_preview = resp.text[:200] if resp.text else '(空响应)'
                print(f'[错误] 响应格式错误 (HTTP {resp.status_code}): {content_preview}')
                return None

            if resp.status_code == 200 and data.get('success'):
                user_data = data.get('data')
                if user_data and 'id' in user_data:
                    self.user_id = user_data['id']
                    self.session.headers.update({'new-api-user': str(self.user_id)})
                return user_data

            if verbose:
                print(f'  [调试] API 返回失败: {data.get("message", "未知错误")}')
            return None

        except requests.exceptions.Timeout:
            print('[错误] 请求超时')
            return None
        except requests.exceptions.RequestException as e:
            print(f'[错误] 网络请求失败: {e}')
            return None
        except Exception as e:
            print(f'[错误] 未知错误: {e}')
            if verbose:
                import traceback
                traceback.print_exc()
            return None

    # ---------- 签到 ----------

    def checkin(self) -> dict:
        """
        执行签到

        流程：
        1. requests 直连签到（快速模式）
        2. 返回 Turnstile 要求时真实浏览器解验证后重签
        3. 返回 PoW 要求时本地解算后重签
        """
        result = {'success': False, 'message': '', 'checkin_date': None, 'quota_awarded': None}

        try:
            resp = self.session.post(f'{self.base_url}/api/user/checkin', timeout=30)

            # 认证失败：自动登录后重签
            if resp.status_code == 401:
                result['message'] = '认证失败: 访问令牌已过期'
                print('  [登录] 访问令牌已失效，强制重新登录...')
                if not self._browser_login(force=True):
                    result['message'] = '认证失败: 访问令牌已过期，且自动登录未成功'
                    return result
                print('  [登录] 重试签到...')
                resp = self.session.post(f'{self.base_url}/api/user/checkin', timeout=30)
                # 重登后依然 401 才判定认证失败；其余响应交给下方统一解析，
                # 以便正常处理「已签到 / Turnstile / PoW」等业务状态
                if resp.status_code == 401:
                    result['message'] = '重新登录后依然认证失败'
                    return result

            try:
                data = resp.json()
            except json.JSONDecodeError:
                content_preview = resp.text[:200] if resp.text else '(空响应)'
                result['message'] = f'响应格式错误 (HTTP {resp.status_code}): {content_preview}'
                return result

            if resp.status_code == 200 and data.get('success'):
                result['success'] = True
                result['message'] = data.get('message', '签到成功')
                checkin_data = data.get('data', {})
                if isinstance(checkin_data, dict):
                    result['checkin_date'] = checkin_data.get('checkin_date')
                    result['quota_awarded'] = checkin_data.get('quota_awarded')
                return result

            message = data.get('message', '签到失败')
            already_keywords = ['已签到', '已经签到', 'already', '重复签到']
            if any(k in message for k in already_keywords):
                result['success'] = True
                result['message'] = message
            elif 'turnstile' in message.lower():
                # 站点开启 Turnstile 人机验证，走真实浏览器解验证后重签
                print(f'[Turnstile] 站点要求人机验证: {message}')
                return self._turnstile_checkin(result)
            elif 'pow' in message.lower():
                # 站点开启 PoW 工作量证明，本地直接解算后重签
                print(f'[PoW] 站点要求工作量证明: {message}')
                return self._checkin_with_pow(result)
            else:
                result['message'] = message

        except requests.exceptions.Timeout:
            result['message'] = '请求超时'
        except requests.exceptions.RequestException as e:
            result['message'] = f'网络请求失败: {e}'
        except Exception as e:
            result['message'] = f'未知错误: {e}'

        return result

    @staticmethod
    def _solve_pow(prefix: str, difficulty: int) -> str:
        """计算 PoW nonce：SHA-256(prefix + nonce) 的前 difficulty 个比特全为 0"""
        import hashlib
        counter = 0
        full, rem = divmod(difficulty, 8)
        mask = ((0xFF << (8 - rem)) & 0xFF) if rem else 0
        prefix_bytes = prefix.encode()
        while True:
            nonce = f'{counter:08x}'
            digest = hashlib.sha256(prefix_bytes + nonce.encode()).digest()
            if all(b == 0 for b in digest[:full]):
                if rem == 0 or full >= len(digest) or (digest[full] & mask) == 0:
                    return nonce
            counter += 1
            if counter > 0xffffffff:
                raise RuntimeError('PoW 超过最大尝试次数')

    def _checkin_with_pow(self, result: dict, _depth: int = 0) -> dict:
        """PoW 工作量证明签到（new-api 新版防滥用机制，pow_mode=replace 时替代 Turnstile）"""
        try:
            r = self.session.get(f'{self.base_url}/api/user/pow/challenge',
                                 params={'action': 'checkin'}, timeout=30)
            data = r.json()
            if not data.get('success'):
                result['message'] = f"获取 PoW 挑战失败: {data.get('message', '未知错误')}"
                return result
            ch = data['data']
            difficulty = int(ch['difficulty'])
            print(f'[PoW] 解算挑战 (difficulty={difficulty})...')
            nonce = self._solve_pow(ch['prefix'], difficulty)
            print(f'[PoW] 解算完成: nonce={nonce}')

            resp = self.session.post(
                f'{self.base_url}/api/user/checkin',
                params={'pow_challenge': ch['challenge_id'], 'pow_nonce': nonce},
                timeout=30)
            data = resp.json()
            message = data.get('message', '签到失败')
            already_keywords = ['已签到', '已经签到', 'already', '重复签到']
            if data.get('success') or any(k in message for k in already_keywords):
                result['success'] = True
                result['message'] = f'{message} (PoW)'
                cd = data.get('data', {})
                if isinstance(cd, dict):
                    result['checkin_date'] = cd.get('checkin_date')
                    result['quota_awarded'] = cd.get('quota_awarded')
            elif 'turnstile' in message.lower() and _depth < 1:
                # 站点同时启用 PoW 与 Turnstile：解完 PoW 后转人机验证再签一次
                print('[Turnstile] PoW 后仍需人机验证，转 Turnstile 流程...')
                return self._turnstile_checkin(result, _depth + 1)
            else:
                result['message'] = f'PoW 签到失败: {message}'
        except Exception as e:
            result['message'] = f'PoW 签到异常: {e}'
        return result

    def _turnstile_checkin(self, result: dict, _depth: int = 0) -> dict:
        """
        Turnstile 人机验证回退流程

        站点开启 Turnstile 校验时（/api/user/checkin 返回「Turnstile token 为空」），
        用真实 Chrome 渲染验证组件并自动点击，在站点页面内携带 token 签到。
        """
        try:
            from turnstile_solver import solve_and_checkin
        except ImportError:
            result['message'] = '站点要求 Turnstile 验证但缺少依赖 (playwright + Chrome)'
            return result

        headers = {}
        # 尚未登录时，先浏览器自动登录获取 JWT
        if not self.access_token:
            print('[Turnstile] 尚未登录，先浏览器账号密码登录...')
            self._browser_login()
        if self.access_token:
            headers['Authorization'] = self.access_token
        if self.user_id:
            headers['New-Api-User'] = str(self.user_id)

        print('[Turnstile] 启动真实浏览器解验证（会弹出 Chrome 窗口）...')
        resp_data = solve_and_checkin(self.base_url, auth_headers=headers)

        if not resp_data:
            result['message'] = 'Turnstile 验证失败: 未能获取 token 或签到请求失败'
            return result

        message = resp_data.get('message', '签到失败')
        already_keywords = ['已签到', '已经签到', 'already', '重复签到']
        if resp_data.get('success') or any(k in message for k in already_keywords):
            result['success'] = True
            result['message'] = f'{message} (Turnstile)'
            checkin_data = resp_data.get('data', {})
            if isinstance(checkin_data, dict):
                result['checkin_date'] = checkin_data.get('checkin_date')
                result['quota_awarded'] = checkin_data.get('quota_awarded')
        elif 'pow' in message.lower() and _depth < 1:
            # 站点同时启用 Turnstile 与 PoW：过完人机验证后转 PoW 再签一次
            print('[PoW] Turnstile 后仍需工作量证明，转 PoW 流程...')
            return self._checkin_with_pow(result, _depth + 1)
        else:
            result['message'] = f'Turnstile 验证后签到失败: {message}'

        return result

    def get_checkin_history(self, month: str = None) -> Optional[dict]:
        """获取签到历史（本月统计用，月份按北京时间计算）"""
        if month is None:
            from datetime import timedelta, timezone
            month = (datetime.now(timezone.utc) + timedelta(hours=8)).strftime('%Y-%m')
        try:
            resp = self.session.get(
                f'{self.base_url}/api/user/checkin',
                params={'month': month},
                timeout=30
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get('success'):
                    return data.get('data')
            return None
        except Exception as e:
            print(f'[错误] 获取签到历史失败: {e}')
            return None


def parse_accounts(accounts_str: str) -> list:
    """
    解析账号配置（仅 JSON 数组格式）

    示例:
    [{"url":"https://newapi.chinahk.qzz.io","login_username":"admin","login_password":"xxx","name":"账号1"},
     {"login_username":"a@qq.com","login_password":"yyy","name":"账号2"}]

    url 缺省时使用 DEFAULT_BASE_URL
    """
    accounts = []
    if not accounts_str:
        return accounts

    try:
        data = json.loads(accounts_str)
    except json.JSONDecodeError:
        return accounts

    if not isinstance(data, list):
        return accounts

    for item in data:
        if not isinstance(item, dict):
            continue
        username = item.get('login_username', '')
        password = item.get('login_password', '')
        if not username or not password:
            continue
        accounts.append({
            'url': (item.get('url') or DEFAULT_BASE_URL).strip(),
            'login_username': username,
            'login_password': password,
            'name': item.get('name', ''),
        })
    return accounts


def load_env_file():
    """加载脚本同目录下的 .env 文件到环境变量（不覆盖已有环境变量）"""
    env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    if os.path.isfile(env_file):
        # utf-8-sig 兼容 Windows 记事本保存的 BOM
        with open(env_file, 'r', encoding='utf-8-sig') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                key, _, value = line.partition('=')
                key = key.strip()
                value = value.strip()
                # 去掉成对引号（.env 常见写法）
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                    value = value[1:-1]
                if key and value:
                    os.environ.setdefault(key, value)


def _mask_url(url: str) -> str:
    """脱敏 URL（日志输出用）"""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url if '://' in url else 'https://' + url)
        parts = (parsed.hostname or '').split('.')
        if len(parts) >= 2:
            masked = f'{parts[0]}.***.{parts[-1]}'
        else:
            masked = '***'
        return f'{parsed.scheme}://{masked}'
    except Exception:
        return 'https://***'


def _mask_account(text) -> str:
    """账号/备注脱敏（日志与 Actions 输出用）"""
    text = str(text or '')
    if not text:
        return '***'
    if '@' in text:
        local, _, domain = text.partition('@')
        head = local[:1] if local else '*'
        return f'{head}***@{domain}'
    if len(text) <= 3:
        return '***'
    return text[:3] + '***'


def _format_quota(quota) -> str:
    """格式化额度显示"""
    if not quota:
        return ''
    if quota >= 1000000:
        return f'{quota / 1000000:.2f}M'
    if quota >= 1000:
        return f'{quota / 1000:.2f}K'
    return str(quota)


def main():
    """主函数"""
    load_env_file()
    import pytz
    beijing_tz = pytz.timezone('Asia/Shanghai')
    execution_time = datetime.now(beijing_tz).strftime('%Y-%m-%d %H:%M:%S')
    print('=' * 50)
    print('NewAPI 自动签到')
    print(f'执行时间: {execution_time} (北京时间)')
    print('=' * 50)

    accounts_str = os.environ.get('NEWAPI_ACCOUNTS', '')
    if not accounts_str:
        print('[错误] 未配置账号信息')
        print('请设置环境变量 NEWAPI_ACCOUNTS（JSON 数组，见 .env.example）')
        sys.exit(1)

    accounts = parse_accounts(accounts_str)
    if not accounts:
        print('[错误] 账号配置解析失败（JSON 需包含 login_username / login_password）')
        sys.exit(1)

    print(f'共 {len(accounts)} 个账号待签到\n')

    success_count = 0
    fail_count = 0

    for i, account in enumerate(accounts, 1):
        url = account['url']
        login_username = account['login_username']
        login_password = account['login_password']
        name = account.get('name') or login_username

        print(f'[{i}/{len(accounts)}] {_mask_account(name)}')
        print(f'  站点: {_mask_url(url)}')

        client = NewAPICheckin(url, login_username, login_password)

        # 获取用户信息（未登录时自动浏览器登录）
        user_info = client.get_user_info()
        if user_info:
            print(f'  用户: {_mask_account(user_info.get("username", "未知"))}')
        elif not client.access_token:
            # 完全未登录，继续签到只会再启动一次浏览器重试，直接跳过
            fail_count += 1
            print('  结果: ❌ 登录失败（账号密码错误或站点不可达），跳过签到')
            print()
            continue
        else:
            print('  用户: 获取失败，继续尝试签到')

        # 执行签到
        result = client.checkin()

        if result['success']:
            success_count += 1
            print(f'  结果: ✅ {result["message"]}')
            if result['checkin_date']:
                print(f'  日期: {result["checkin_date"]}')
            quota_str = _format_quota(result['quota_awarded'])
            if quota_str:
                print(f'  奖励: +{quota_str} 额度 ({result["quota_awarded"]:,} tokens)')

            # 本月签到统计
            history = client.get_checkin_history()
            if history and history.get('stats'):
                stats = history['stats']
                checkin_count = stats.get('checkin_count', 0)
                total_str = _format_quota(stats.get('total_quota', 0))
                print(f'  统计: 本月已签 {checkin_count} 天，累计 {total_str} 额度')
        else:
            fail_count += 1
            print(f'  结果: ❌ {result["message"]}')

        print()

    print('=' * 50)
    print(f'签到完成: 成功 {success_count}, 失败 {fail_count}')
    print('=' * 50)

    # 任一账号失败都让 Actions 标红，便于及时发现问题
    if fail_count > 0:
        sys.exit(1)


if __name__ == '__main__':
    main()
