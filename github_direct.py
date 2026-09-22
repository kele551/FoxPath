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
import ipaddress
import json
import os
import queue
import select
import socket
import socketserver
import ssl
import sys
import threading
import time
import urllib.request
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

APP_NAME = '狐径'
APP_VERSION = '1.0.1'
PROXY_PORT = 8787
PANEL_PORT = 8788
CHECK_INTERVAL = 300          # 5 分钟重测一轮

# PAC 只代理这两个主机；代理内部也用同一份名单，保证"PAC 会送来的"和
# "代理愿意走 IP 池的"完全一致。githubassets/githubusercontent/api.github.com
# 一律 DIRECT —— 它们直连本来就通，走代理反而会坏（见 README 已知边界）。
PROXY_HOSTS = ('github.com', 'www.github.com')

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

REG_INTERNET = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
REG_RUN = r'Software\Microsoft\Windows\CurrentVersion\Run'

_log_q = queue.Queue()
_START_TS = [0.0]          # 进程启动时刻, 体检日志里用它显示"已运行多久"


def alert(title, text):
    """exe 是 --noconsole 的: 致命错误只写日志的话, 用户双击后看到的是"没反应"。
    有控制台时不弹窗(免得命令行下被打断), 只在冻结的 exe 或没有 stdout 时弹。"""
    try:
        if getattr(sys, 'frozen', False) or sys.stdout is None:
            ctypes.windll.user32.MessageBoxW(None, text, title, 0x10)   # MB_ICONERROR
    except Exception:
        pass


def _data_dir():
    """本程序自己的数据目录: %LOCALAPPDATA%\\FoxPath。

    以前备份和日志都写在 exe 同级, 而 exe 可能被放在只读目录、U 盘或
    Program Files 下 —— 备份写失败时旧代码是静默 continue, 于是退出时
    还原不了系统代理, 注册表里就留下一个指向死端口的 PAC。
    (2026-09-22 实测: 程序已删除, AutoConfigURL 仍指向 127.0.0.1:8788/pac)
    """
    base = os.environ.get('LOCALAPPDATA') or os.path.expanduser('~')
    d = os.path.join(base, 'FoxPath')
    try:
        os.makedirs(d, exist_ok=True)
        return d
    except Exception:
        return os.path.expanduser('~')


DATA_DIR = _data_dir()
LOG_FILE = os.path.join(DATA_DIR, 'foxpath.log')
BACKUP_FILE = os.path.join(DATA_DIR, 'proxy-backup.json')
LOG_MAX = 512 * 1024


def _log_to_file(line):
    """exe 是 --noconsole 的, 屏幕上看不到任何东西; 日志必须落文件。"""
    try:
        if os.path.isfile(LOG_FILE) and os.path.getsize(LOG_FILE) > LOG_MAX:
            with open(LOG_FILE, 'r', encoding='utf-8', errors='replace') as f:
                tail = f.readlines()[-500:]
            with open(LOG_FILE, 'w', encoding='utf-8') as f:
                f.writelines(tail)
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(line + '\n')
    except Exception:
        pass


def log(msg):
    line = '[%s] %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), msg)
    _log_q.put(line)
    _log_to_file(line)
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
    """只认 PAC 会送来的那两个主机(精确匹配)。

    旧版是 endswith('.github.com') —— 那会把 api.github.com / gist.github.com
    也当成"该走 IP 池"的, 而候选池里全是 **web** 段地址, 拿它去连 api 是不对的。
    现在与 PAC 用同一份 PROXY_HOSTS, 名单只有一个来源。
    """
    host = (host or '').lower().split(':')[0]
    return host in PROXY_HOSTS


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
                # 这里发一发 GET /; 如果 HTTP 测试自己超时(偶尔发生),
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
                            # README 写的是"必须返回 2xx/3xx", 这里也照此收紧:
                            # 只拒 4xx/5xx 的话, 1xx 和畸形状态码会被放进来。
                            if not (status.startswith(b'2') or status.startswith(b'3')):
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
            # 只取 IPv4 网段的**第一个可用主机地址**。旧代码是 cidr.split('/')[0],
            # 对 140.82.112.0/20 拿到的是网段地址 140.82.112.0 —— 它永远探测失败,
            # 白占一个并发名额。
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if net.version != 4:
                continue
            first = next(net.hosts(), None) or net.network_address
            ips.append(str(first))
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
    # Windows 上 SO_REUSEADDR 允许**第二个** socket 抢占同一端口, 行为未定义;
    # 正常情况下应该用 SO_EXCLUSIVEADDRUSE 让第二个实例直接失败。这里靠
    # 下面的 single_instance() 命名互斥来保证只有一个实例, 更直接。
    allow_reuse_address = True
    daemon_threads = True


def single_instance():
    """Windows 命名互斥: 已经有一个在跑就返回 False。

    没有这道闸时, 连点两次 exe 会起两个实例, 两个都去 bind 8787/8788,
    还会各写一遍注册表 —— 退出哪个、还原到哪一份都是随机的。
    """
    if os.name != 'nt':
        return True
    try:
        k32 = ctypes.WinDLL('kernel32', use_last_error=True)
        k32.CreateMutexW(None, False, 'Local\\FoxPath_SingleInstance')
        if ctypes.get_last_error() == 183:      # ERROR_ALREADY_EXISTS
            return False
        return True
    except Exception:
        return True


def start_proxy():
    try:
        srv = ProxyServer(('127.0.0.1', PROXY_PORT), ProxyHandler)
    except OSError as e:
        log('!! 端口 %d 被占用, 代理起不来: %s' % (PROXY_PORT, e))
        tip = ('多半是上一个狐径没退干净。请在任务管理器结束它, 或先跑一次:\n'
               '    %s --restore' % os.path.basename(
                   sys.executable if getattr(sys, 'frozen', False) else __file__))
        log('   ' + tip.replace('\n', ' '))
        alert('狐径: 端口被占用', '本机 %d 端口已被占用, 狐径起不来。\n\n%s\n\n日志: %s'
              % (PROXY_PORT, tip, LOG_FILE))
        raise SystemExit(2)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    log('代理已启动 127.0.0.1:%d' % PROXY_PORT)


# ------------------------------------------------------------------- 开关

def _legacy_backup_file():
    """v1.0.0 曾把备份写在 exe 同级(.proxy-backup.json), 仍兼容读取一次。"""
    if getattr(sys, 'frozen', False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, '.proxy-backup.json')


def _load_backup():
    for p in (BACKUP_FILE, _legacy_backup_file()):
        try:
            with open(p, 'r', encoding='utf-8') as f:
                d = json.load(f)
            if isinstance(d, dict):
                return d
        except Exception:
            continue
    return None


def enable_proxy():
    # 已经在启用状态就不要再"备份"一次 —— 否则备份里存的会是我们自己的
    # PAC 地址, 之后「停用并还原」只会把我们的地址写回去, 等于永远还原不了。
    # (旧版每次点「启用加速」都会覆盖备份, 这是最容易复现的一处缺陷。)
    if proxy_on():
        log('加速已处于启用状态, 不重复备份 / 不改写')
        return True
    saved = {
        'AutoConfigURL': reg_get(REG_INTERNET, 'AutoConfigURL'),
        'ProxyEnable': reg_get(REG_INTERNET, 'ProxyEnable'),
        'ProxyServer': reg_get(REG_INTERNET, 'ProxyServer'),
    }
    try:
        with open(BACKUP_FILE, 'w', encoding='utf-8') as f:
            json.dump(saved, f, ensure_ascii=False)
    except Exception as e:
        # 备份写不进去就绝不改注册表 —— 否则退出时无法还原, 用户会被留在
        # "PAC 指向死端口"的状态里(这正是 v1.0.0 踩过的坑)。
        log('!! 无法保存还原备份(%s), 为安全起见不改系统代理' % e)
        return False
    if saved.get('ProxyEnable') and saved.get('ProxyServer'):
        # 一旦设置了 PAC, WinINET 会优先用它, 静态代理(ProxyEnable=1)就被旁路了。
        # 家用场景一般没有静态代理; 万一有, 至少要让用户知道发生了什么。
        log('注意: 你原本设了静态代理 %s —— 启用期间 PAC 优先级更高, '
            '其它网站会直连而不是走原代理; 停用时会自动还原'
            % saved.get('ProxyServer'))
    reg_set(REG_INTERNET, 'AutoConfigURL', 'http://127.0.0.1:%d/pac' % PANEL_PORT)
    notify_proxy_change()
    log('加速已开启 (原设置已备份到 %s)' % BACKUP_FILE)
    return True


def disable_proxy():
    saved = _load_backup()
    if saved is None:
        # 没有备份时要分两种情况, 不能一律删:
        #   a) 当前值确实指向本程序 -> 是本程序留下的残留, 清掉(用户删程序后
        #      系统里永远是死端口的 PAC, 2026-09-22 实测就是这种状态);
        #   b) 当前值指向别处(公司 PAC / 其它工具下发的) -> **保持原样**。
        #      那份地址我们既没备份也无从得知, 删了就永久回不来。
        if not proxy_on():
            log('没有还原备份, 且当前系统代理不是本程序所设 —— 保持原样, 不做任何修改')
            return False
        log('没有找到还原备份, 只清掉本程序的 PAC 设置(原值已无从得知)')
        saved = {}
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
<title>狐径 FoxPath __VERSION__</title>
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
<h1>狐径 FoxPath __VERSION__</h1>
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


PANEL_PAGE = PANEL_HTML.replace('__VERSION__', APP_VERSION)


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
            self._send(200, PANEL_PAGE.encode('utf-8'))
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

    def _same_origin(self):
        """只接受来自本机面板页面的请求。

        面板虽然只监听 127.0.0.1, 但**任何本机程序或网页**都能往这个端口发 POST
        (简单请求不触发预检)。校验 Host 与 Origin, 挡掉网页 CSRF 与 DNS rebinding ——
        否则一个恶意页面就能把加速关掉, 甚至在无备份时清掉用户的 PAC。
        """
        host = (self.headers.get('Host') or '').lower()
        if host not in ('127.0.0.1:%d' % PANEL_PORT, 'localhost:%d' % PANEL_PORT):
            return False
        origin = self.headers.get('Origin')
        if not origin:
            return True          # 同源 fetch 有些浏览器不带 Origin; Host 已经校验过
        o = origin.lower()
        return (o == 'http://127.0.0.1:%d' % PANEL_PORT
                or o == 'http://localhost:%d' % PANEL_PORT)

    def do_POST(self):
        if not self._same_origin():
            log('已拒绝一个非同源的面板请求(Host/Origin 校验未通过)')
            self._send(403, b'forbidden', 'text/plain; charset=utf-8')
            return
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
    try:
        srv = ThreadingHTTPServer(('127.0.0.1', PANEL_PORT), PanelHandler)
    except OSError as e:
        log('!! 端口 %d 被占用, 控制面板起不来: %s' % (PANEL_PORT, e))
        alert('狐径: 端口被占用', '本机 %d 端口已被占用, 控制面板起不来。\n\n'
              '多半是上一个狐径没退干净, 请在任务管理器结束它。\n\n日志: %s'
              % (PANEL_PORT, LOG_FILE))
        raise SystemExit(2)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    log('控制面板 http://127.0.0.1:%d' % PANEL_PORT)
    return srv


def health_loop():
    while True:
        # 官方 IP 表每 6 小时同步一次; 可用数量少于 3 个也顺手同步一次,
        # 免得 GitHub 换了地址我们还抱着旧表。
        need_meta = (time.time() - _last_meta_ok[0]) > 6 * 3600
        good = HEALTH.refresh(CANDIDATES)
        if need_meta or len(good) < 3:
            fetch_official_ips()
            good = HEALTH.refresh(CANDIDATES)

        # 体检日志就是狐径的心跳: 带上"已运行多久", 长跑日志才能一眼看出
        # 它是持续在跑、还是中途死过又重开。
        up_min = int((time.time() - _START_TS[0]) / 60) if _START_TS[0] else 0
        if good:
            log('体检: 可用 %d/%d 已运行%d分钟 -> %s' % (
                len(good), len(CANDIDATES), up_min,
                ', '.join('%s(%dms)' % (i, m) for i, m in good[:3])))
        else:
            good = recover()
            if good:
                log('自愈成功(已运行%d分钟): 可用 %d 个, 最快 %s(%dms)'
                    % (up_min, len(good), good[0][0], good[0][1]))

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
    _START_TS[0] = time.time()
    log('%s v%s 启动 (日志: %s)' % (APP_NAME, APP_VERSION, LOG_FILE))

    # 只做还原, 不起代理/面板 —— 用于"程序已经删了 / 起不来, 但注册表里
    # 还留着指向 127.0.0.1:8788 的 PAC"这种死局的一键自救。
    if ('--restore' in args) or ('--repair' in args):
        log('只做还原: 清理本程序的系统代理设置')
        disable_proxy()
        return

    # 焊死历史坑: PAC 模板必须是纯 ASCII。带上中文注释后 encode('ascii') 会抛
    # UnicodeEncodeError -> /pac 返回 500 -> 浏览器拿不到 PAC -> 加速完全失效,
    # 而且症状是"页面能开、按钮点不动", 极难定位。
    try:
        PAC_TEMPLATE.encode('ascii')
    except UnicodeEncodeError as e:
        # 只记日志是不够的: 那样程序照常启用 PAC, /pac 却因 encode('ascii') 抛异常
        # 返回 500, 浏览器拿不到 PAC, 症状是"网页能开但按钮点不动", 极难定位。
        # 所以这里直接拒绝启动。
        msg = ('PAC 模板含非 ASCII 字符(位置 %d)。\n\n'
               '这会让 /pac 接口返回 500, 浏览器取不到 PAC, 加速完全失效。\n'
               '请把 PAC_TEMPLATE 里的注释改回英文后重新打包。' % e.start)
        log('!! ' + msg.replace('\n', ' '))
        alert('狐径: 内部错误', msg)
        raise SystemExit(3)

    if not single_instance():
        log('已有实例在运行, 本次直接退出(不动系统代理)')
        return

    start_proxy()
    start_panel()
    fetch_official_ips()
    threading.Thread(target=health_loop, daemon=True).start()

    if '--silent' in args:
        # 静默模式(开机自启用)以前**没有**注册退出还原 —— 这正是"程序关了,
        # PAC 却留在注册表里"的根因。现在两种模式都注册。
        atexit.register(on_exit)
        if not proxy_on():
            enable_proxy()
        elif _load_backup() is None:
            log('注意: 系统代理已指向本程序, 但没有还原备份 —— 退出时会直接清除该 PAC')
        log('静默模式, 每 5 分钟自动体检')
        while True:
            time.sleep(60)
    else:
        atexit.register(on_exit)
        if not proxy_on():
            enable_proxy()
        elif _load_backup() is None:
            log('注意: 系统代理已指向本程序, 但没有还原备份 —— 退出时会直接清除该 PAC')
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
    try:
        main()
    except SystemExit:
        raise
    except BaseException:
        import traceback
        tb = traceback.format_exc()
        log('启动/运行失败:\n' + tb)
        alert('狐径: 启动失败', '程序启动时出错, 已写入日志:\n%s\n\n%s'
              % (LOG_FILE, tb[-800:]))
        raise
