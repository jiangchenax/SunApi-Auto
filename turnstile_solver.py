#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare Turnstile 交互式验证求解器

原理:
- Turnstile 在 Playwright/patchright 等自动化浏览器中会被静默卡死（CDP 检测），
  组件 shell 渲染了但挑战 iframe 永远不加载
- 但用【真实 Chrome】（无自动化注入）+ CDP 连接时，组件能完整运行
- 交互式勾选框的 UI 渲染在 closed shadow DOM 里，DOM 查询不可见，
  但组件固定 300x65（本地化文案时更宽），勾选框固定在左侧中间，
  用坐标模拟真实鼠标点击即可通过

两种使用方式:
- get_turnstile_token(sitekey): 本地页面渲染组件，仅返回 token
- solve_and_checkin(base_url, ...): 在站点页面内完成 取sitekey -> 解验证 -> 签到 全流程，
  适用于 requests 被 CF 拦截的环境（如 GitHub Actions）
- login_and_get_token(base_url, username, password): 浏览器内账号密码登录（自动解 Turnstile），
  返回新版 NewAPI 登录响应的 data（含 Bearer access_token），解决系统访问令牌无法生成的问题
"""
import atexit
import http.server
import json
import os
import socket
import subprocess
import tempfile
import threading
import time

CHROME_CANDIDATES = [
    os.environ.get('TURNSTILE_CHROME_PATH'),
    r'C:\Program Files\Google\Chrome\Application\chrome.exe',
    r'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/google-chrome',
    '/opt/google/chrome/chrome',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
]

LOCAL_HTML = ('<html><head><title>ts</title></head>'
              '<body style="margin:0"><div id="ts" style="padding:10px"></div></body></html>')

# CF 验证中的页面标题（中英文都要认，否则中文界面会被误判为已通过）
CF_CHALLENGE_TITLES = ('Just a moment', 'Attention Required', '请稍候', '正在验证',
                       'Verifying', 'Checking your browser')

# 本次运行产生的临时目录/文件，进程退出时统一清理
_TEMP_PATHS = []
_cleanup_registered = False

RENDER_JS = '''async (sitekey) => {
    if (!document.getElementById('ts')) {
        const holder = document.createElement('div');
        holder.id = 'ts';
        holder.style.cssText = 'position:fixed;top:10px;left:10px;z-index:99999;';
        document.body.appendChild(holder);
    }
    if (!document.querySelector('script[src*="challenges.cloudflare.com/turnstile"]')) {
        const s = document.createElement('script');
        s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
        document.head.appendChild(s);
    }
    for (let i = 0; i < 40; i++) {
        if (window.turnstile && window.turnstile.render) break;
        await new Promise(r => setTimeout(r, 500));
    }
    if (!window.turnstile) throw new Error('turnstile api 初始化失败');
    const holder = document.getElementById('ts');
    // 清理上一次渲染的组件，否则重复求解时点击坐标会指向已失效的旧组件
    try { if (window.__wid != null) turnstile.remove(window.__wid); } catch (e) {}
    holder.innerHTML = '';
    window.__t = null; window.__e = null; window.__inter = false;
    window.__sitekey = sitekey;
    window.__wid = turnstile.render(holder, {
        sitekey: sitekey,
        callback: t => window.__t = t,
        'error-callback': c => window.__e = String(c),
        'before-interactive-callback': () => window.__inter = true,
    });
}'''

RESET_JS = '''() => {
    try { turnstile.remove(window.__wid); } catch (e) {}
    window.__e = null; window.__t = null; window.__inter = false;
    window.__wid = turnstile.render(document.getElementById('ts'), {
        sitekey: window.__sitekey,
        callback: t => window.__t = t,
        'error-callback': c => window.__e = String(c),
        'before-interactive-callback': () => window.__inter = true,
    });
}'''

# 渲染 -> 等交互回调 -> 坐标点击 -> 拿 token；每轮只点一次，失败重置重试
SOLVE_JS_POLL = '''() => ({
    token: window.__t || null,
    err: window.__e,
    interactive: !!window.__inter,
    box: (() => {
        const host = document.querySelector('#ts > div');
        if (!host) return null;
        const r = host.getBoundingClientRect();
        return { x: r.x, y: r.y, w: r.width, h: r.height };
    })(),
})'''

# 页面内账号密码登录：自动处理密码加密开关（与新版 NewAPI 前端一致），
# 带 turnstile 参数提交 /api/user/login，返回接口 JSON
LOGIN_JS = '''async (args) => {
    const {username, password, turnstile} = args;
    const b64u = (buf) => { let s = ''; const u8 = new Uint8Array(buf); for (const c of u8) s += String.fromCharCode(c); return btoa(s); };
    let body;
    try {
        const ekResp = await fetch('/api/user/login/encryption-key');
        const ek = await ekResp.json();
        const enabled = !!(ek && ek.success && ek.data && ek.data.enabled);
        if (!enabled) {
            body = {username, password};
        } else {
            const {kid, public_key} = ek.data;
            const pem = public_key.replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '').replace(/\\s+/g, '');
            const bin = atob(pem);
            const arr = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
            const publicKey = await crypto.subtle.importKey('spki', arr.buffer, {name: 'RSA-OAEP', hash: 'SHA-256'}, false, ['encrypt']);
            const text = new TextEncoder().encode(password);
            const modLen = publicKey.algorithm.modulusLength;
            if (text.byteLength > modLen / 8 - 66) {
                const ekKey = crypto.getRandomValues(new Uint8Array(32));
                const iv = crypto.getRandomValues(new Uint8Array(12));
                const aesKey = await crypto.subtle.importKey('raw', ekKey, 'AES-GCM', false, ['encrypt']);
                const [c1, c2] = await Promise.all([
                    crypto.subtle.encrypt({name: 'RSA-OAEP', label: new TextEncoder().encode('password-v2')}, publicKey, ekKey),
                    crypto.subtle.encrypt({name: 'AES-GCM', iv, additionalData: new TextEncoder().encode('password-v2:' + kid)}, aesKey, text)
                ]);
                body = {username, password_encrypted: ['v2', b64u(c1), b64u(iv.buffer), b64u(c2)].join('.'), encryption_key_id: kid};
            } else {
                const c = await crypto.subtle.encrypt({name: 'RSA-OAEP'}, publicKey, text);
                body = {username, password_encrypted: b64u(c), encryption_key_id: kid};
            }
        }
    } catch (e) {
        body = {username, password};
    }
    const resp = await fetch('/api/user/login?turnstile=' + encodeURIComponent(turnstile || ''), {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(body),
        credentials: 'include',
    });
    const text = await resp.text();
    try { return JSON.parse(text); }
    catch (e) { return {success: false, message: '响应非JSON: ' + text.substring(0, 120)}; }
}'''

FETCH_SITEKEY_JS = '''async () => {
    try {
        const r = await fetch('/api/status');
        const j = await r.json();
        return (j.data && j.data.turnstile_site_key) || null;
    } catch (e) { return null; }
}'''

SOLVE_POW_JS = '''async (headers) => {
    const r = await fetch('/api/user/pow/challenge?action=checkin', {
        credentials: 'include', headers: headers
    });
    const j = await r.json();
    if (!j.success) throw new Error(j.message || '获取 PoW 挑战失败');
    const {challenge_id, prefix, difficulty} = j.data;
    let n = 0;
    for (;;) {
        const nonce = n.toString(16).padStart(8, '0');
        const h = new Uint8Array(await crypto.subtle.digest('SHA-256',
            new TextEncoder().encode(prefix + nonce)));
        const full = Math.floor(difficulty / 8), rem = difficulty % 8;
        let ok = true;
        for (let i = 0; i < full; i++) if (h[i] !== 0) { ok = false; break; }
        if (ok && rem > 0 && (h[full] & (255 << (8 - rem))) !== 0) ok = false;
        if (ok) return {challenge_id, nonce};
        n++;
        if (n > 0xffffffff) throw new Error('超过最大尝试次数');
    }
}'''

POST_JS = '''async (args) => {
    const headers = Object.assign({'Content-Type': 'application/json'}, args.headers);
    const resp = await fetch('/api/user/checkin' + (args.query || ''), {
        method: 'POST',
        headers: headers,
        body: JSON.stringify(args.body || {}),
        credentials: 'include',
    });
    const text = await resp.text();
    try { return JSON.parse(text); }
    catch (e) { return { success: false, message: '响应非JSON: ' + text.substring(0, 120) }; }
}'''


def find_chrome():
    for path in CHROME_CANDIDATES:
        if path and os.path.exists(path):
            return path
    # Playwright 缓存的 Chromium（本地 pip install playwright && playwright install chromium 场景）
    try:
        import glob as _glob
        cache_root = os.path.join(os.path.expanduser('~'), '.cache', 'ms-playwright')
        for pattern in (os.path.join(cache_root, 'chromium-*', 'chrome-linux*', 'chrome'),
                        os.path.join(cache_root, 'chromium-*', 'chrome-linux', 'chrome')):
            for p in _glob.glob(pattern):
                if os.path.isfile(p):
                    return p
    except Exception:
        pass
    return None


def _get_system_proxy():
    """读取系统代理（Windows 注册表 / 环境变量），浏览器必须与 requests 走同一出口"""
    try:
        import urllib.request
        proxies = urllib.request.getproxies()
        return proxies.get('https') or proxies.get('http')
    except Exception:
        return None


def _free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _register_cleanup(*paths):
    """登记临时文件/目录，进程退出时自动清理"""
    global _cleanup_registered
    _TEMP_PATHS.extend(p for p in paths if p)
    if not _cleanup_registered:
        atexit.register(_cleanup_temp)
        _cleanup_registered = True


def _cleanup_temp():
    import shutil
    for path in _TEMP_PATHS:
        try:
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
            elif os.path.exists(path):
                os.remove(path)
        except Exception:
            pass


class _LocalHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(LOCAL_HTML.encode())

    def log_message(self, *a):
        pass


def _launch_chrome(proxy=None, url=None):
    """启动真实 Chrome 并返回 (proc, dbg_port)"""
    chrome = find_chrome()
    if not chrome:
        raise RuntimeError('未找到 Chrome 浏览器，无法通过 Turnstile 验证')
    dbg_port = _free_port()
    udd = tempfile.mkdtemp(prefix='ts_solver_')
    chrome_log = tempfile.NamedTemporaryFile(prefix='chrome_', suffix='.log', delete=False)
    _register_cleanup(udd, chrome_log.name)
    args = [
        chrome,
        f'--remote-debugging-port={dbg_port}',
        f'--user-data-dir={udd}',
        '--no-first-run', '--no-default-browser-check',
        '--no-sandbox', '--disable-dev-shm-usage',
        '--disable-gpu',
        '--remote-allow-origins=*',
        '--window-size=700,500',
    ]
    if proxy:
        args.append(f'--proxy-server={proxy}')
    args.append(url or 'about:blank')
    proc = subprocess.Popen(args, stdout=chrome_log, stderr=chrome_log)

    # 轮询等待 CDP 端口就绪（冷启动可能远超 4 秒，固定 sleep 会 ECONNREFUSED）
    import socket as _socket
    try:
        deadline = time.time() + 40
        while time.time() < deadline:
            if proc.poll() is not None:
                chrome_log.flush()
                with open(chrome_log.name, errors='ignore') as lf:
                    tail = lf.read()[-400:]
                raise RuntimeError(f'Chrome 启动失败（退出码 {proc.returncode}）：{tail}')
            try:
                with _socket.create_connection(('127.0.0.1', dbg_port), timeout=2):
                    time.sleep(0.5)
                    return proc, dbg_port
            except OSError:
                time.sleep(0.5)
        raise RuntimeError('等待 Chrome CDP 端口超时（40s）')
    except Exception:
        # 启动失败时回收已拉起的进程，避免残留 Chrome 僵尸进程
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        raise


def _solve_in_page(page, sitekey, max_wait=90, verbose=True):
    """在当前页面渲染 Turnstile 并自动点击，返回 token 或 None"""
    page.evaluate(RENDER_JS, sitekey)

    clicked = False
    round_started = 0.0
    rounds = 0
    start = time.time()
    while time.time() - start < max_wait:
        time.sleep(1)
        attempt = int(time.time() - start)
        st = page.evaluate(SOLVE_JS_POLL)

        if st['token']:
            if verbose:
                print(f'[Turnstile] token 获取成功 (耗时 {attempt}s)')
            return st['token']

        # 300xxx = 挑战执行失败（如重复点击破坏挑战），重置组件重试
        if st['err']:
            if verbose:
                print(f'[Turnstile] 挑战失败 ({st["err"]})，重置组件重试...')
            page.evaluate(RESET_JS)
            clicked = False
            rounds += 1
            if rounds >= 4:
                if verbose:
                    print('[Turnstile] 多轮重试均失败')
                return None
            continue

        box, interactive = st['box'], st['interactive']
        # 每轮只点击一次：等交互回调出现并稍作停顿后点击，之后耐心等待结果
        if box and box['w'] > 50 and interactive and not clicked:
            time.sleep(2)
            cx, cy = box['x'] + 30, box['y'] + box['h'] / 2
            if verbose:
                print(f'[Turnstile] 交互验证框出现，模拟点击勾选框 ({cx:.0f}, {cy:.0f})')
            page.mouse.move(cx - 15, cy - 8)
            time.sleep(0.4)
            page.mouse.move(cx - 3, cy)
            time.sleep(0.4)
            page.mouse.click(cx, cy)
            clicked = True
            round_started = time.time()
        elif clicked and time.time() - round_started > 30:
            # 点击后 30s 无结果且无报错，视为挑战卡死，重置重试
            page.evaluate(RESET_JS)
            clicked = False
            rounds += 1
            if rounds >= 4:
                if verbose:
                    print('[Turnstile] 多轮重试均失败')
                return None
    if verbose:
        print('[Turnstile] 等待超时')
    return None


def _wait_cf_pass(page, base_url, timeout=60, verbose=True):
    """导航到站点并等待 CF 验证通过，返回是否成功"""
    page.goto(base_url, wait_until='domcontentloaded', timeout=45000)
    start = time.time()
    while time.time() - start < timeout:
        title = page.title()
        if not any(k in title for k in CF_CHALLENGE_TITLES):
            return True
        if verbose:
            print(f'[Turnstile] 等待 CF 验证通过: {title[:40]}')
        time.sleep(5)
    return False


def _connect_cdp(p, dbg_port):
    """连接已启动的 Chrome，重试 3 次"""
    browser = None
    last_err = None
    for _ in range(3):
        try:
            browser = p.chromium.connect_over_cdp(f'http://127.0.0.1:{dbg_port}')
            break
        except Exception as e:
            last_err = e
            time.sleep(3)
    if browser is None:
        raise RuntimeError(f'CDP 连接失败: {last_err}')
    return browser


def _fetch_sitekey(page, verbose=True):
    """从 /api/status 读取 Turnstile sitekey"""
    sitekey = page.evaluate(FETCH_SITEKEY_JS)
    if verbose:
        print(f'[Turnstile] sitekey: {sitekey}')
    return sitekey


def _checkin_in_page(page, auth_headers, sitekey=None, max_wait=120,
                     verbose=True, pre_solve=False):
    """
    在已打开的页面内完成签到。

    Args:
        pre_solve: True 时先解一次 Turnstile 再提交，避免先发一个必然被拦的裸请求
    Returns:
        签到接口 JSON dict
    """
    from urllib.parse import quote
    auth_headers = auth_headers or {}
    ts_token = None
    pow_params = None

    if pre_solve:
        if not sitekey:
            sitekey = _fetch_sitekey(page, verbose)
        if not sitekey:
            return {'success': False, 'message': '站点未提供 Turnstile sitekey'}
        ts_token = _solve_in_page(page, sitekey, max_wait=max_wait, verbose=verbose)
        if not ts_token:
            return {'success': False, 'message': 'Turnstile 解验证失败'}

    def submit():
        query = ''
        body = {}
        if ts_token:
            query += ('&' if query else '?') + 'turnstile=' + quote(ts_token)
            body['turnstile'] = ts_token
        if pow_params:
            query += ('&' if query else '?') + ('pow_challenge=' + quote(pow_params['challenge_id']) +
                                                '&pow_nonce=' + quote(pow_params['nonce']))
        return page.evaluate(POST_JS, {'headers': auth_headers, 'query': query, 'body': body})

    result = submit()
    # 服务端追加 PoW / Turnstile 要求时补验证，最多两轮
    for _ in range(2):
        if not isinstance(result, dict) or result.get('success'):
            break
        msg = str(result.get('message', '')).lower()
        if 'pow' in msg and pow_params is None:
            if verbose:
                print('[Turnstile] 服务端要求 PoW 工作量证明，页面内解算...')
            pow_params = page.evaluate(SOLVE_POW_JS, auth_headers)
            if verbose:
                print(f"[Turnstile] PoW 解算完成: nonce={pow_params['nonce']}")
        elif 'turnstile' in msg:
            if not sitekey:
                sitekey = _fetch_sitekey(page, verbose)
            if not sitekey:
                break
            ts_token = _solve_in_page(page, sitekey, max_wait=max_wait, verbose=verbose)
            if not ts_token:
                break
        else:
            break
        result = submit()
    return result


def solve_and_checkin(base_url: str, sitekey: str = None, auth_headers: dict = None,
                      proxy: str = None, max_wait: int = 120, verbose: bool = True,
                      pre_solve: bool = False):
    """
    在站点页面内完成签到（requests 被 CF 拦也能走通）

    Args:
        base_url: 站点地址
        sitekey: Turnstile sitekey，不传则自动从 /api/status 获取
        auth_headers: 签到请求头（Authorization / New-Api-User）
        proxy: 代理地址；默认自动读系统代理（GHA 无代理则为 None）
        pre_solve: 先解 Turnstile 再提交，避免空请求
    Returns:
        签到接口的 JSON 响应 dict，失败返回 None
    """
    if proxy is None:
        proxy = _get_system_proxy()
    auth_headers = auth_headers or {}

    proc, dbg_port = _launch_chrome(proxy, url=base_url)
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = _connect_cdp(p, dbg_port)
            ctx = browser.contexts[0]
            page = ctx.pages[0] if ctx.pages else ctx.new_page()

            if not _wait_cf_pass(page, base_url, verbose=verbose):
                if verbose:
                    print('[Turnstile] CF 验证未通过')
                return None

            result = _checkin_in_page(page, auth_headers, sitekey, max_wait, verbose, pre_solve)
            browser.close()
            return result
    except Exception as e:
        print(f'[Turnstile] 求解失败: {e}')
        return None
    finally:
        try:
            proc.terminate()
        except Exception:
            pass


def login_and_checkin(base_url: str, username: str, password: str, sitekey: str = None,
                      proxy: str = None, max_wait: int = 120, verbose: bool = True):
    """
    登录 + 签到（一次调用完成）。

    登录与签到各自需要一个新的 Turnstile token。实测同一 Chrome 进程内
    连续解两次时，第二个 token 会被服务端判为无效，因此两步各用独立进程。

    Returns:
        {'checkin': dict, 'access_token': str, 'user_id': str} 或 None
    """
    data = login_and_get_token(base_url, username, password, sitekey,
                               proxy, max_wait, verbose)
    if not data:
        return None

    token = data.get('access_token')
    if not token:
        return None

    token_type = data.get('token_type') or 'Bearer'
    auth_headers = {'Authorization': f'{token_type} {token}'}
    user = data.get('user') or {}
    if user.get('id'):
        auth_headers['New-Api-User'] = str(user['id'])

    # NewAPI 需要先收到一次签到请求才会建立 Turnstile 校验上下文，
    # 预生成的 token 会被判空，因此这里保留一次探测请求
    result = solve_and_checkin(base_url, sitekey, auth_headers, proxy,
                               max_wait, verbose, pre_solve=False)
    return {
        'checkin': result,
        'access_token': auth_headers['Authorization'],
        'user_id': auth_headers.get('New-Api-User'),
        'user': user,
    }


def get_turnstile_token(sitekey: str, proxy: str = None, max_wait: int = 90, verbose: bool = True):
    """本地页面渲染 Turnstile 组件并自动点击，返回 token（调试用）"""
    if proxy is None:
        proxy = _get_system_proxy()

    port_http = _free_port()
    server = http.server.ThreadingHTTPServer(('127.0.0.1', port_http), _LocalHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    proc = None
    token = None
    try:
        proc, dbg_port = _launch_chrome(proxy, url=f'http://127.0.0.1:{port_http}/')
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = None
            last_err = None
            for _ in range(3):
                try:
                    browser = p.chromium.connect_over_cdp(f'http://127.0.0.1:{dbg_port}')
                    break
                except Exception as e:
                    last_err = e
                    time.sleep(3)
            if browser is None:
                raise RuntimeError(f'CDP 连接失败: {last_err}')
            ctx = browser.contexts[0]
            page = ctx.pages[0] if ctx.pages else ctx.new_page()
            token = _solve_in_page(page, sitekey, max_wait=max_wait, verbose=verbose)
            browser.close()
    except Exception as e:
        print(f'[Turnstile] 求解失败: {e}')
    finally:
        if proc:
            try:
                proc.terminate()
            except Exception:
                pass
        server.shutdown()
    return token


def login_and_get_token(base_url: str, username: str, password: str, sitekey: str = None,
                        proxy: str = None, max_wait: int = 120, verbose: bool = True):
    """
    浏览器内账号密码登录（自动解 Turnstile），返回登录响应的 data dict（含 access_token）。

    适配新版 NewAPI：登录接口 POST /api/user/login?turnstile=<token>，
    返回 data.access_token（Bearer JWT，15 分钟有效）。
    用于系统访问令牌无法手动生成的站点，改为账号密码自动登录获取令牌。

    Args:
        base_url: 站点地址
        username: 登录用户名
        password: 登录密码（站点未开密码加密时直接明文传输）
        sitekey: Turnstile sitekey，不传则自动从 /api/status 获取
        proxy: 代理地址；默认自动读系统代理
    Returns:
        登录响应 data dict（含 access_token / token_type / session / user），失败返回 None
    """
    if proxy is None:
        proxy = _get_system_proxy()

    proc, dbg_port = _launch_chrome(proxy, url=base_url)
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = None
            last_err = None
            for _ in range(3):
                try:
                    browser = p.chromium.connect_over_cdp(f'http://127.0.0.1:{dbg_port}')
                    break
                except Exception as e:
                    last_err = e
                    time.sleep(3)
            if browser is None:
                raise RuntimeError(f'CDP 连接失败: {last_err}')
            ctx = browser.contexts[0]
            page = ctx.pages[0] if ctx.pages else ctx.new_page()

            if not _wait_cf_pass(page, base_url, verbose=verbose):
                if verbose:
                    print('[登录] CF 验证未通过')
                return None

            if not sitekey:
                sitekey = page.evaluate('''async () => {
                    try {
                        const r = await fetch('/api/status');
                        const j = await r.json();
                        return (j.data && j.data.turnstile_site_key) || null;
                    } catch (e) { return null; }
                }''')
                if verbose:
                    print(f'[登录] sitekey: {sitekey}')
            if not sitekey:
                if verbose:
                    print('[登录] 无法获取 Turnstile sitekey')
                return None

            ts_token = _solve_in_page(page, sitekey, max_wait=max_wait, verbose=verbose)
            if not ts_token:
                if verbose:
                    print('[登录] Turnstile 解验证失败')
                return None

            args = {'username': username, 'password': password, 'turnstile': ts_token}
            result = page.evaluate(LOGIN_JS, args)
            if not result:
                if verbose:
                    print('[登录] 登录请求无响应')
                return None

            if result.get('success') and result.get('data', {}).get('access_token'):
                if verbose:
                    print('[登录] 登录成功，已获取访问令牌')
                return result.get('data')

            msg = str(result.get('message', ''))
            if verbose:
                print(f'[登录] 登录失败: {msg}')

            # Turnstile token 可能已失效，重置组件重新求解后再试一次
            if 'turnstile' in msg.lower():
                if verbose:
                    print('[登录] 重置 Turnstile 组件重新求解...')
                ts_token = _solve_in_page(page, sitekey, max_wait=max_wait, verbose=verbose)
                if ts_token:
                    args['turnstile'] = ts_token
                    result = page.evaluate(LOGIN_JS, args)
                    if result and result.get('success') and result.get('data', {}).get('access_token'):
                        if verbose:
                            print('[登录] 重试成功，已获取访问令牌')
                        return result.get('data')
                    if verbose:
                        print(f'[登录] 重试后仍失败: {str(result.get("message", ""))}')
            return None
    except Exception as e:
        print(f'[登录] 浏览器登录异常: {e}')
        return None
    finally:
        try:
            proc.terminate()
        except Exception:
            pass
