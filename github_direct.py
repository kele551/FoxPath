# -*- coding: utf-8 -*-
"""
GitHub 直连助手 —— 绿色单文件版 (v1.0.0)

干什么
------
电信宽带到 GitHub 的路径一直在漂: 某个 IP 今天 0.8 秒, 明天就彻底不通,
DNS 给的官方地址在这条线上也时好时坏。手工改 hosts 只能管两三天, 而且改
hosts 还要管理员权限。

这个程序不碰 hosts、不碰 DNS、不要管理员权限:
  1. 在本机开一个小代理, 只接管 github.com 一类的流量;
  2. 由它直连当前**实测能握手**的 GitHub 官方 IP;
  3. 死掉的 IP 立刻踢掉, 每 5 分钟重测一轮补回来;
  4. 系统代理设成它自带的 PAC, 只有 GitHub 域名走代理, 其他一律直连。

怎么判断一个 IP 是真 GitHub
--------------------------
不是 ping(很多机器禁 ICMP, 而且 ping 通不代表能开网页), 而是真做 TLS
握手并校验证书: 证书里必须带 github.com。证书不对一律判死。

为什么不用管理员
----------------
代理监听 127.0.0.1 的高端口, 改的是 HKCU 下的 Internet Settings(当前用户),
开机自启写的是 HKCU 的 Run 项。都在用户权限范围内。

用法
----
    双击 exe              -> 自动打开控制面板
    exe --silent          -> 不弹窗, 后台静默运行(开机自启用这个)
    控制面板里「停用并还原」-> 把系统代理恢复成你原来的样子
"""

import atexit
import ctypes
import json
import os
import queue
import select
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

APP_NAME = '狐径'
APP_VERSION = '1.0.0'
PROXY_PORT = 8787
PANEL_PORT = 8788
CHECK_INTERVAL = 300          # 5 分钟重测一轮

# GitHub 官方 IP 池。140.82.112.0/20 是 GitHub 主站段, 20.x 那几个是官方
# 在 api.github.com/meta 里单独列出的 web 地址。启动时会联网补充 /meta。
CANDIDATE_IPS = [
    '140.82.112.3', '140.82.112.4',
    '140.82.113.3', '140.82.113.4',
    '140.82.114.3', '140.82.114.4',
    '140.82.115.3', '140.82.115.4',
    '140.82.116.3', '140.82.116.4',
    '20.27.177.113', '20.27.177.114',
    '20.200.245.247', '20.205.243.166',
    '20.201.28.151',
]

GITHUB_SUFFIXES = ('github.com',)

REG_INTERNET = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
REG_RUN = r'Software\Microsoft\Windows\CurrentVersion\Run'

_log_q = queue.Queue()


def log(msg):
    line = '[%s] %s' % (time.strftime('%H:%M:%S'), msg)
    _log_q.put(line)
    try:
        print(line, flush=True)
    except Exception:
        pass


def recent_logs(n=200):
    out = []
    try:
        while True:
            out.append(_log_q.get_nowait())
    except queue.Empty:
        pass
    return out[-n:]


def is_github_host(host):
    host = (host or '').lower().split(':')[0]
    return any(host == s or host.endswith('.' + s) for s in GITHUB_SUFFIXES)


# ------------------------------------------------------------------- 注册表

def reg_set(path, name, value, vtype=None):
    import winreg
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_WRITE) as k:
        if value is None:
            try:
                winreg.DeleteValue(k, name)
            except FileNotFoundError:
                pass
        else:
            import winreg as w
            winreg.SetValueEx(k, name, 0, vtype or w.REG_SZ, value)


def reg_get(path, name):
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ) as k:
            return winreg.QueryValueEx(k, name)[0]
    except (FileNotFoundError, OSError):
        return None


def notify_proxy_change():
    try:
        wininet = ctypes.WinDLL('wininet')
        wininet.InternetSetOptionW(0, 39, None, 0)   # SETTINGS_CHANGED
        wininet.InternetSetOptionW(0, 37, None, 0)   # REFRESH
    except Exception:
        pass


# ------------------------------------------------------------------- IP 体检

class Health(object):
    def __init__(self):
        self._lock = threading.Lock()
        self._good = []
        self._last = 0.0

    @staticmethod
    def _probe(ip, timeout=3.0):
        t0 = time.time()
        try:
            raw = socket.create_connection((ip, 443), timeout=timeout)
        except OSError:
            return None
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(raw, server_hostname='github.com') as s:
                cert = s.getpeercert() or {}
                names = [v for (_k, v) in cert.get('subjectAltName', ())]
                ok = any('github.com' in n for n in names)
                if not ok:
                    return None
                # TLS 握手通了还不够: 某些 IP 的证书对, 但只跑 API/CDN,
                # 直接访问 github.com 会返回 4xx, 这种不能要。
                # 这里用 HEAD 试一发; 如果 HTTP 测试自己超时(偶尔发生),
                # 不因此判死, 毕竟 TLS 已经验证通过, 但返回 4xx/5xx 就判死。
                try:
                    s.settimeout(2.0)
                    s.sendall(b'GET / HTTP/1.1\r\nHost: github.com\r\n'
                              b'User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n')
                    first = s.recv(64)
                    if first:
                        parts = first.split()
                        if len(parts) >= 2:
                            status = parts[1]
                            if status.startswith(b'4') or status.startswith(b'5'):
                                return None
                except (socket.timeout, TimeoutError, OSError):
                    pass
            return int((time.time() - t0) * 1000)
        except Exception:
            return None
        finally:
            try:
                raw.close()
            except Exception:
                pass

    def refresh(self, ips=None, timeout=3.0):
        ips = ips or CANDIDATE_IPS
        with ThreadPoolExecutor(max_workers=12) as pool:
            res = list(pool.map(lambda ip: (ip, self._probe(ip, timeout)), ips))
        good = sorted([(i, m) for i, m in res if m is not None], key=lambda x: x[1])
        with self._lock:
            self._good = good
            self._last = time.time()
        return good

    def snapshot(self):
        with self._lock:
            return list(self._good), self._last

    def candidates(self):
        with self._lock:
            return [ip for ip, _m in self._good]

    def drop(self, ip):
        with self._lock:
            self._good = [(i, m) for i, m in self._good if i != ip]


HEALTH = Health()
CANDIDATES = list(CANDIDATE_IPS)


_last_meta_ok = [0.0]      # 上次成功拉到官方 IP 表的时间


def fetch_official_ips():
    """从 api.github.com/meta 拿官方 web IP。注意: api.github.com 和
    github.com 不是同一批地址, 前者一直通, 所以这里通常拿得到。"""
    global CANDIDATES
    try:
        req = urllib.request.Request('https://api.github.com/meta',
                                     headers={'User-Agent': 'github-direct-helper'})
        with urllib.request.urlopen(req, timeout=6) as r:
            data = json.loads(r.read().decode('utf-8'))
        ips = []
        for cidr in data.get('web', []):
            ip = cidr.split('/')[0]
            if ':' not in ip and (ip.count('.') == 3):
                ips.append(ip)
        for third in (112, 113, 114, 115, 116):
            for last in (3, 4):
                ips.append('140.82.%d.%d' % (third, last))
        seen, out = set(), []
        for ip in ips + CANDIDATE_IPS:
            if ip not in seen:
                seen.add(ip)
                out.append(ip)
        CANDIDATES = out
        _last_meta_ok[0] = time.time()
        log('已同步官方 IP 表: 候选 %d 个' % len(out))
        return out
    except Exception as e:
        log('同步官方 IP 表失败(%s), 用现有 %d 个候选' % (e, len(CANDIDATES)))
        return list(CANDIDATES)


def dns_fallback_ips():
    """手上 IP 全死时的最后一条路: 问系统 DNS github.com 现在指向哪。
    DNS 给的多半也是死的, 但值得一试, 而且换了宽带/换了 DNS 就可能是活的。"""
    out = []
    for host in ('github.com', 'www.github.com'):
        try:
            for info in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP):
                ip = info[4][0]
                if ':' not in ip and ip not in out:
                    out.append(ip)
        except Exception:
            pass
    return out


def recover():
    """IP 全灭时的自愈流程: 重拉官方表 + 问 DNS + 放宽超时再测一轮。
    三步都试完还是不通, 才算真不通(那就退回系统解析, 和没装本程序一样)。"""
    log('全部候选失效, 启动自愈: 重拉官方 IP 表')
    global CANDIDATES
    ips = fetch_official_ips()

    log('放宽超时到 6 秒, 重测 %d 个' % len(ips))
    good = HEALTH.refresh(ips, timeout=6.0)
    if good:
        return good

    extra = [i for i in dns_fallback_ips() if i not in ips]
    if extra:
        log('再问系统 DNS, 拿到 %d 个新地址: %s' % (len(extra), ', '.join(extra[:5])))
        good = HEALTH.refresh(extra, timeout=6.0)
        if good:
            CANDIDATES = list(dict.fromkeys(list(CANDIDATES) + extra))
            return good

    log('自愈失败: 官方表和 DNS 都不通, 保持原样等下一轮')
    return []


# ------------------------------------------------------------------- 代理

PAC_TEMPLATE = """function FindProxyForURL(url, host) {
    host = host.toLowerCase();
    // Only github.com goes through the local proxy.
    // GitHub CSS/JS/images live on githubassets.com and githubusercontent.com,
    // which work fine over a direct connection; proxying them breaks page scripts.
    if (host === "github.com" || host === "www.github.com") {
        return "PROXY 127.0.0.1:%d; DIRECT";
    }
    return "DIRECT";
}
"""


class ProxyHandler(socketserver.StreamRequestHandler):
    timeout = 30

    def handle(self):
        try:
            first = self.rfile.readline(65537).decode('latin-1').strip()
        except Exception:
            return
        if not first:
            return
        up = first.upper()
        if up.startswith('CONNECT'):
            self._tunnel(first.split()[1])
        elif up.startswith('GET'):
            self._read_headers()
            self._send(502, b'Bad Gateway')
        else:
            self._read_headers()
            self._send(405, b'Method Not Allowed')

    def _read_headers(self):
        while True:
            line = self.rfile.readline(65537)
            if not line or line in (b'\r\n', b'\n'):
                break

    def _send(self, code, body=b''):
        try:
            self.wfile.write(('HTTP/1.1 %d\r\nContent-Length: %d\r\nConnection: close\r\n\r\n'
                              % (code, len(body))).encode('ascii') + body)
            self.wfile.flush()
        except Exception:
            pass

    def _connect(self, host, port):
        if is_github_host(host):
            for ip in HEALTH.candidates()[:4]:
                try:
                    return socket.create_connection((ip, port), timeout=5), ip
                except OSError:
                    HEALTH.drop(ip)
                    continue
            log('候选 IP 全军覆没, 本次退回系统解析')
        try:
            return socket.create_connection((host, port), timeout=10), None
        except OSError as e:
            log('连接 %s 失败: %s' % (host, e))
            return None, None

    def _tunnel(self, target):
        host, _, p = target.partition(':')
        port = int(p or 443)
        self._read_headers()
        up, used = self._connect(host, port)
        if up is None:
            self._send(502, b'Bad Gateway')
            return
        try:
            self.wfile.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
            self.wfile.flush()
        except Exception:
            up.close()
            return
        if used:
            log('%s -> %s' % (host, used))
        self._relay(up)

    def _relay(self, up):
        conn = self.connection
        pair = [conn, up]
        try:
            while True:
                r, _, e = select.select(pair, [], pair, 120)
                if e:
                    break
                stop = False
                for s in r:
                    try:
                        data = s.recv(65536)
                    except OSError:
                        stop = True
                        break
                    if not data:
                        stop = True
                        break
                    try:
                        (up if s is conn else conn).sendall(data)
                    except OSError:
                        stop = True
                        break
                if stop:
                    break
        except Exception:
            pass
        finally:
            for s in pair:
                try:
                    s.close()
                except Exception:
                    pass


class ProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_proxy():
    srv = ProxyServer(('127.0.0.1', PROXY_PORT), ProxyHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    log('代理已启动 127.0.0.1:%d' % PROXY_PORT)


# ------------------------------------------------------------------- 开关

def _backup_file():
    if getattr(sys, 'frozen', False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    if not os.access(base, os.W_OK):
        base = os.path.join(os.path.expanduser('~'), 'GitHubDirectFix')
        os.makedirs(base, exist_ok=True)
    return os.path.join(base, '.proxy-backup.json')


def enable_proxy():
    saved = {
        'AutoConfigURL': reg_get(REG_INTERNET, 'AutoConfigURL'),
        'ProxyEnable': reg_get(REG_INTERNET, 'ProxyEnable'),
        'ProxyServer': reg_get(REG_INTERNET, 'ProxyServer'),
    }
    try:
        with open(_backup_file(), 'w', encoding='utf-8') as f:
            json.dump(saved, f, ensure_ascii=False)
    except Exception:
        pass
    reg_set(REG_INTERNET, 'AutoConfigURL', 'http://127.0.0.1:%d/pac' % PANEL_PORT)
    notify_proxy_change()
    log('加速已开启')
    return True


def disable_proxy():
    saved = {}
    try:
        with open(_backup_file(), 'r', encoding='utf-8') as f:
            saved = json.load(f)
    except Exception:
        pass
    reg_set(REG_INTERNET, 'AutoConfigURL', saved.get('AutoConfigURL') or None)
    if saved.get('ProxyServer'):
        reg_set(REG_INTERNET, 'ProxyServer', saved['ProxyServer'])
    if saved.get('ProxyEnable') is not None:
        reg_set(REG_INTERNET, 'ProxyEnable', saved['ProxyEnable'], 4)
    notify_proxy_change()
    log('加速已关闭, 系统代理已还原')
    return True


def proxy_on():
    cur = reg_get(REG_INTERNET, 'AutoConfigURL') or ''
    return ('127.0.0.1:%d' % PANEL_PORT) in cur


def _exe_cmd(silent=True):
    if getattr(sys, 'frozen', False):
        exe = sys.executable
    else:
        exe = os.path.abspath(__file__)
        return '"%s" "%s"%s' % (sys.executable, exe, ' --silent' if silent else '')
    return '"%s"%s' % (exe, ' --silent' if silent else '')


def set_autostart(on):
    if on:
        reg_set(REG_RUN, 'GitHubDirectFix', _exe_cmd(True))
        log('已设为开机自启')
    else:
        reg_set(REG_RUN, 'GitHubDirectFix', None)
        log('已取消开机自启')
    return on


def autostart_on():
    return bool(reg_get(REG_RUN, 'GitHubDirectFix'))


# ------------------------------------------------------------------- 控制面板

PANEL_HTML = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>狐径 FoxPath v1.0.0</title>
<style>
 *{box-sizing:border-box}
 body{margin:0;padding:28px;background:#fff;color:#1a1a1a;
      font:14px/1.6 "Microsoft YaHei UI",system-ui,sans-serif;max-width:860px}
 h1{font-size:20px;margin:0 0 4px;font-weight:600}
 .sub{color:#6b7280;font-size:13px;margin-bottom:22px}
 .card{border:1px solid #e5e7eb;border-radius:8px;padding:16px 18px;margin-bottom:16px}
 .row{display:flex;gap:14px;flex-wrap:wrap;align-items:center}
 .k{color:#6b7280;width:88px;display:inline-block}
 .big{font-size:17px;font-weight:600;color:#0f766e}
 .off{color:#b91c1c}
 button{padding:8px 16px;border:1px solid #d1d5db;background:#fff;border-radius:6px;
        cursor:pointer;font-size:14px;font-family:inherit}
 button:hover{background:#f3f4f6}
 button.primary{background:#0f766e;color:#fff;border-color:#0f766e}
 button.primary:hover{background:#0d5f59}
 button.danger{background:#b91c1c;color:#fff;border-color:#b91c1c}
 button.danger:hover{background:#991b1b}
 label{display:flex;align-items:center;gap:6px;cursor:pointer}
 table{width:100%;border-collapse:collapse;font-size:13px}
 th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #f0f0f0}
 th{color:#6b7280;font-weight:500}
 pre{background:#f8fafc;border:1px solid #e5e7eb;border-radius:6px;padding:12px;
     height:190px;overflow:auto;font:12px/1.7 Consolas,monospace;margin:0;color:#374151}
</style></head><body>
<h1>狐径 FoxPath v1.0.0</h1>
<div class="sub">本机代理接管 GitHub 流量，直连当前实测可用的官方 IP。不改 hosts、不用管理员权限。</div>

<div class="card">
  <div class="row" style="margin-bottom:10px">
    <span class="k">出口 IP</span><span class="big" id="ip">检测中…</span>
    <span class="k">加速状态</span><span class="big" id="state">-</span>
    <span class="k">上次体检</span><span id="time">-</span>
  </div>
  <div class="row">
    <button class="primary" id="btnEnable">启用加速</button>
    <button id="btnDisable">停用并还原</button>
    <button id="btnTest">立即重测</button>
    <label><input type="checkbox" id="auto"> 开机自启</label>
    <button class="danger" id="btnQuit">退出并还原</button>
  </div>
</div>

<div class="card">
  <div style="margin-bottom:8px"><b>当前可用 IP</b>（按延迟排序）</div>
  <table><thead><tr><th>IP</th><th>延迟</th></tr></thead><tbody id="ips"></tbody></table>
</div>

<div class="card"><div style="margin-bottom:8px"><b>日志</b></div><pre id="log"></pre></div>

<script>
function api(u){return fetch(u).then(r=>r.json())}
function act(u){return fetch(u,{method:'POST'}).then(r=>r.json())}
function refresh(){
  api('/api/status').then(d=>{
    document.getElementById('ip').textContent = d.ip ? d.ip+' ('+d.ms+' ms)' : '暂无可用 IP';
    const s=document.getElementById('state');
    s.textContent = d.enabled ? '已启用' : '未启用';
    s.className = d.enabled ? 'big' : 'big off';
    document.getElementById('time').textContent = d.last || '-';
    document.getElementById('auto').checked = d.autostart;
    document.getElementById('ips').innerHTML = (d.good||[])
      .map(x=>'<tr><td>'+x[0]+'</td><td>'+x[1]+' ms</td></tr>').join('') ||
      '<tr><td colspan="2">一个都不通</td></tr>';
    document.getElementById('log').textContent = (d.logs||[]).join('\\n');
    const p=document.getElementById('log'); p.scrollTop=p.scrollHeight;
  }).catch(()=>{});
}
document.getElementById('btnEnable').onclick = ()=>act('/api/enable').then(refresh);
document.getElementById('btnDisable').onclick = ()=>act('/api/disable').then(refresh);
document.getElementById('btnTest').onclick = ()=>{
  document.getElementById('btnTest').disabled=true;
  act('/api/retest').then(()=>{document.getElementById('btnTest').disabled=false;refresh()});
};
document.getElementById('auto').onchange = (e)=>
  act('/api/autostart?on='+(e.target.checked?1:0)).then(refresh);
document.getElementById('btnQuit').onclick = ()=>{
  if(confirm('退出后 GitHub 将恢复原有连接方式，确定退出？')){
    act('/api/quit').then(()=>{ document.getElementById('state').textContent='正在退出...'; });
  }
};
refresh(); setInterval(refresh,3000);
</script></body></html>
"""


class PanelHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype='text/html; charset=utf-8'):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def do_GET(self):
        path = self.path.split('?')[0]
        if path == '/pac':
            self._send(200, (PAC_TEMPLATE % PROXY_PORT).encode('ascii'),
                       'application/x-ns-proxy-autoconfig')
        elif path in ('/', '/ui'):
            self._send(200, PANEL_HTML.encode('utf-8'))
        elif path == '/api/status':
            good, ts = HEALTH.snapshot()
            data = {
                'ip': good[0][0] if good else None,
                'ms': good[0][1] if good else None,
                'good': good[:10],
                'enabled': proxy_on(),
                'autostart': autostart_on(),
                'last': time.strftime('%H:%M:%S', time.localtime(ts)) if ts else None,
                'logs': recent_logs(),
            }
            self._send(200, json.dumps(data, ensure_ascii=False).encode('utf-8'),
                       'application/json; charset=utf-8')
        else:
            self._send(404, b'not found')

    def do_POST(self):
        path = self.path.split('?')[0]
        query = self.path.split('?')[1] if '?' in self.path else ''
        if path == '/api/enable':
            enable_proxy()
        elif path == '/api/disable':
            disable_proxy()
        elif path == '/api/retest':
            threading.Thread(target=lambda: HEALTH.refresh(CANDIDATES), daemon=True).start()
            log('手动重测已触发')
        elif path == '/api/quit':
            log('收到退出指令, 正在还原系统代理')
            disable_proxy()
            threading.Thread(target=lambda: (time.sleep(0.3), os._exit(0)), daemon=True).start()
        elif path == '/api/autostart':
            set_autostart('on=1' in query)
        length = int(self.headers.get('Content-Length') or 0)
        if length:
            self.rfile.read(length)
        self._send(200, b'{"ok":true}', 'application/json')


def start_panel():
    srv = ThreadingHTTPServer(('127.0.0.1', PANEL_PORT), PanelHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    log('控制面板 http://127.0.0.1:%d' % PANEL_PORT)
    return srv


_last_meta_ts = [0.0]
META_TTL = 6 * 3600      # 官方 IP 表最多缓存 6 小时


def refresh_meta(force=False):
    """需要时重拉 api.github.com/meta。返回本轮候选池。"""
    global _last_meta_ts
    if force or (time.time() - _last_meta_ts[0]) > META_TTL:
        if fetch_official_ips():
            _last_meta_ts[0] = time.time()
    return CANDIDATES


def health_loop():
    while True:
        # 官方 IP 表每 6 小时同步一次; 可用数量少于 3 个也顺手同步一次,
        # 免得 GitHub 换了地址我们还抱着旧表。
        need_meta = (time.time() - _last_meta_ok[0]) > 6 * 3600
        good = HEALTH.refresh(CANDIDATES)
        if need_meta or len(good) < 3:
            fetch_official_ips()
            good = HEALTH.refresh(CANDIDATES)

        if good:
            log('体检: 可用 %d/%d -> %s' % (
                len(good), len(CANDIDATES),
                ', '.join('%s(%dms)' % (i, m) for i, m in good[:3])))
        else:
            good = recover()
            if good:
                log('自愈成功: 可用 %d 个, 最快 %s(%dms)'
                    % (len(good), good[0][0], good[0][1]))

        time.sleep(CHECK_INTERVAL)


def on_exit():
    """程序退出时, 如果我们正在管理系统代理, 把它还原成之前的样子。"""
    try:
        if proxy_on():
            log('程序退出, 还原系统代理')
            disable_proxy()
    except Exception:
        pass


def main():
    args = [a.lower() for a in sys.argv[1:]]
    log('%s v%s 启动' % (APP_NAME, APP_VERSION))
    start_proxy()
    start_panel()
    fetch_official_ips()
    threading.Thread(target=health_loop, daemon=True).start()

    if '--silent' in args:
        if not proxy_on():
            enable_proxy()
        log('静默模式, 每 5 分钟自动体检')
        while True:
            time.sleep(60)
    else:
        if not proxy_on():
            enable_proxy()
        atexit.register(on_exit)
        try:
            webbrowser.open('http://127.0.0.1:%d/ui' % PANEL_PORT)
        except Exception:
            pass
        log('控制面板已打开: http://127.0.0.1:%d/ui' % PANEL_PORT)
        log('想常驻后台请勾「开机自启」; 点「退出并还原」可安全关闭本程序')
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    main()
