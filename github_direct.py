# -*- coding: utf-8 -*-
"""
GitHub 直连助手 —— 绿色单文件版

作者:  海风（kele551）    https://gitee.com/kele551/FoxPath
协作:  小腾（只在源码里留档，不出现在界面上）

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
import urllib.parse
import urllib.request
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

APP_NAME = '狐径'
APP_VERSION = '1.0.6'
# 署名（一处定义，界面/日志/属性/README 都用它，避免各写各的）
AUTHOR = '海风（kele551）'
AUTHOR_ASCII = 'HaiFeng (kele551)'
HOMEPAGE = 'gitee.com/kele551/FoxPath'
PROXY_PORT = 8787
PANEL_PORT = 8788
CHECK_INTERVAL = 300          # 5 分钟重测一轮

# PAC 只代理这两个主机；代理内部也用同一份名单，保证"PAC 会送来的"和
# "代理愿意走 IP 池的"完全一致。githubassets/githubusercontent/api.github.com
# 一律 DIRECT —— 它们直连本来就通，走代理反而会坏（见 README 已知边界）。
PROXY_HOSTS = ('github.com', 'www.github.com')

# 2026-10-08 按用户需求（GitHub issue #1）增加：raw 文件与发布附件下载。
# **它们必须走自己的 IP 池**（见下面 CANDIDATE_IPS_RAW）：官方 meta 里
# 185.199.108.0/22 才是这些主机的段；塞进 github.com 的池子会连到错误服务器，
# 页面脚本会全废（这正是以前"不能代理 githubusercontent"的真正原因）。
# 注意：这里刻意**不含** avatars / camo / githubassets —— 那些是页面渲染用的，
# 保持直连，就不会重演当年的坑。
PROXY_HOSTS_RAW = ('raw.githubusercontent.com', 'objects.githubusercontent.com')

# GitHub 官方 IP 池（2026-10-08 从 api.github.com/meta 全量对齐）。
# 以前只有 15 个手写地址：联通/移动拉不到 /meta 时就只剩这些旧地址，
# 很多已经不通 —— 那正是"某些线路用不了"的根因。现在把官方公布的全带上，
# 即使在线同步失败也有足够多的候选。IPv6 单独一组：移动/联通的 IPv6
# 常常反而是通的，而以前的代码直接 continue 掉了 IPv6。
CANDIDATE_IPS = [
    '20.201.28.151', '20.205.243.166', '20.205.243.161', '20.87.245.0',
    '20.87.245.2', '4.237.22.38', '4.237.22.36', '4.228.31.150',
    '4.228.31.144', '20.207.73.82', '20.207.73.81', '20.27.177.113',
    '20.27.177.119', '20.200.245.247', '20.200.245.244', '20.175.192.147',
    '20.233.83.145', '20.233.83.148', '20.29.134.23', '20.29.134.22',
    '20.199.39.232', '20.217.135.5', '20.217.135.1', '4.225.11.194',
    '4.225.11.199', '4.208.26.197', '4.208.26.193', '20.26.156.215',
    '20.26.156.213', '172.182.252.133', '172.182.252.130', '4.249.131.164',
    '48.202.248.40', '48.204.201.5', '140.82.112.3', '140.82.112.4',
    '140.82.113.3', '140.82.113.4', '140.82.114.3', '140.82.114.4',
    '140.82.115.3', '140.82.115.4', '140.82.116.3', '140.82.116.4',
    '20.27.177.114',
]

# github.com 的真实 IPv6 地址。官方 JSON 里只给网段（2606:50c0::/32），
# 国内 DNS 又拿不到 AAAA，所以这里写实测可用的地址；
# 移动/联通的 IPv6 常常反而是通的，IPv4 全灭时这一组就是活路。
# 本机实测3个握手通过
# raw.githubusercontent.com / objects.githubusercontent.com 专用池
# （官方 web 段里的 185.199.108.0/22；本机已用 SNI=raw.githubusercontent.com
#   实测证书覆盖 githubusercontent.com，见 CHANGELOG）
CANDIDATE_IPS_RAW = [
    '185.199.108.133',
    '185.199.109.133',
    '185.199.110.133',
    '185.199.111.133',
]

# IPv6 候选（**目前为空是有意的**）：
# 2026-10-08 实测：官方 meta 只给网段（2606:50c0::/32、2a0a:a440::/29），
# 照着网段猜出来的地址在 HTTP 层返回 "500 Domain Not Found" —— 说明它们并不真的
# 服务 github.com，写进去只会白占探测名额。真实地址从两个地方来：
#   1) 用户自己 DNS 解析出的 AAAA（见 dns_fallback_ips，很多家宽 DNS 会给）；
#   2) 将来我们往 meta.json 的 web6 字段里放实测可用的地址。
CANDIDATE_IPS_V6 = []

# ── 手动指定 IP（2026-10-08 加）──────────────────────────────────────────────
# 现场救急用：自动探测一个都不通时，让用户填一个他这条线能连上的官方 IP。
# 存在数据目录里，重启后仍然生效；填空 = 清除。
MANUAL_IP_FILE = 'manual-ip.txt'
_MANUAL_IP = ['']          # 内存缓存，免得每次都用磁盘
_META_SOURCE = ['']        # 上次成功同步 IP 表的来源（体检信息里要报出来）


def _manual_ip_path():
    return os.path.join(_data_dir(), MANUAL_IP_FILE)


def _valid_ip(s):
    try:
        ipaddress.ip_address((s or '').strip())
        return True
    except Exception:
        return False


def load_manual_ip():
    try:
        with open(_manual_ip_path(), encoding='utf-8') as f:
            ip = f.read().strip()
    except Exception:
        return ''
    return ip if _valid_ip(ip) else ''


def save_manual_ip(ip):
    """保存/清除手动 IP，返回 (成功?, 一句话说明)。"""
    ip = (ip or '').strip()
    if ip and not _valid_ip(ip):
        return False, '不是合法的 IP 地址：%s' % ip
    try:
        if ip:
            with open(_manual_ip_path(), 'w', encoding='utf-8') as f:
                f.write(ip)
        else:
            try:
                os.remove(_manual_ip_path())
            except OSError:
                pass
    except Exception as e:
        return False, '写入失败：%s' % e
    _MANUAL_IP[0] = ip
    return True, ('已记住手动 IP %s（会优先使用）' % ip) if ip else '已清除手动 IP'


def candidate_list():
    """当前候选：手动指定的 IP 永远排第一，其余用池子（含 IPv6）。"""
    if not _MANUAL_IP[0]:
        _MANUAL_IP[0] = load_manual_ip()
    out = list(CANDIDATES)
    for ip in (CANDIDATE_IPS_V6 or []):
        if ip not in out:
            out.append(ip)
    if _MANUAL_IP[0] and _MANUAL_IP[0] in out:
        out.remove(_MANUAL_IP[0])
    return ([_MANUAL_IP[0]] if _MANUAL_IP[0] else []) + out


def diag_text():
    """一行"线路体检"—— 客户复制这一行发来，就能定位卡在哪一环。"""
    good, ts = HEALTH.snapshot()
    v4 = [g for g in good if ':' not in g[0]]
    v6 = [g for g in good if ':' in g[0]]
    cand = candidate_list()
    all4 = [ip for ip in cand if ':' not in ip]
    all6 = [ip for ip in cand if ':' in ip]
    fastest = ('%s(%dms)' % (good[0][0], good[0][1])) if good else '无'
    up_min = int((time.time() - _START_TS[0]) / 60) if _START_TS[0] else 0
    last = time.strftime('%m-%d %H:%M:%S', time.localtime(ts)) if ts else '还没体检过'
    raw_good, _ = HEALTH_RAW.snapshot()
    head = ('狐径体检 v%s | IPv4 可用 %d/%d | IPv6 可用 %d/%d | raw 可用 %d/%d | '
            '表源 %s | 最快 %s | 系统代理 %s | 手动IP %s | 上次体检 %s | 已运行 %d 分钟'
            % (APP_VERSION, len(v4), len(all4), len(v6), len(all6),
               len(raw_good), len(CANDIDATE_IPS_RAW),
               _META_SOURCE[0] or '未同步(用内置表)', fastest,
               '已开启' if proxy_on() else '未开启', _MANUAL_IP[0] or '无', last, up_min))
    detail = ('停用' if not good else
              '可用清单: ' + ', '.join('%s(%dms)' % (i, m) for i, m in good[:8]))
    return head + '\n' + detail


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


def is_raw_host(host):
    """raw 文件 / 发布附件下载（走自己的 IP 池）。"""
    host = (host or '').lower().split(':')[0]
    return host in PROXY_HOSTS_RAW


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

class _SkipHttp(Exception):
    """内部用：跳过 HTTP 状态检查。"""


class Health(object):
    def __init__(self, sni='github.com', expect='github.com', http_path='/'):
        self._lock = threading.Lock()
        self._good = []
        self._last = 0.0
        # 2026-10-08: 不同主机群用不同的 SNI 与证书期望值 ——
        # github.com 池: SNI=github.com, 证书要含 github.com;
        # raw/附件池:    SNI=raw.githubusercontent.com, 证书要含 githubusercontent.com。
        self.sni = sni
        self.expect = expect
        # HTTP 检查用的路径；None = 只验 TLS+证书（raw 池就是这样：
        # raw.githubusercontent.com 的根路径必然返回 400，用它判死会误杀好 IP）
        self.http_path = http_path

    def _probe(self, ip, timeout=3.0):
        t0 = time.time()
        try:
            raw = socket.create_connection((ip, 443), timeout=timeout)
        except OSError:
            return None
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(raw, server_hostname=self.sni) as s:
                cert = s.getpeercert() or {}
                names = [v for (_k, v) in cert.get('subjectAltName', ())]
                ok = any(self.expect in n for n in names)
                if not ok:
                    return None
                # TLS 握手通了还不够: 某些 IP 的证书对, 但只跑 API/CDN,
                # 直接访问 github.com 会返回 4xx, 这种不能要。
                # 这里发一发 GET /; 如果 HTTP 测试自己超时(偶尔发生),
                # 不因此判死, 毕竟 TLS 已经验证通过, 但返回 4xx/5xx 就判死。
                try:
                    if self.http_path is None:
                        raise _SkipHttp()
                    s.settimeout(2.0)
                    s.sendall(('GET %s HTTP/1.1\r\nHost: %s\r\n'
                               % (self.http_path, self.sni)).encode('ascii') +
                              b'User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n')
                    first = s.recv(64)
                    if first:
                        parts = first.split()
                        if len(parts) >= 2:
                            status = parts[1]
                            # README 写的是"必须返回 2xx/3xx", 这里也照此收紧:
                            # 只拒 4xx/5xx 的话, 1xx 和畸形状态码会被放进来。
                            # 429 = 被限流：说明对面确实是 GitHub，只是让我们慢点。
                            # 2026-10-08 修：以前把它当死 IP，体检会莫名其妙地全灭。
                            if not (status.startswith(b'2') or status.startswith(b'3')
                                    or status == b'429'):
                                return None
                except _SkipHttp:
                    pass
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
HEALTH_RAW = Health(sni='raw.githubusercontent.com',
                      expect='githubusercontent.com', http_path=None)
CANDIDATES = list(CANDIDATE_IPS)


_last_meta_ok = [0.0]      # 上次成功拉到官方 IP 表的时间


def fetch_official_ips():
    """同步官方 IP 表。**三个源依次试**：

    1. api.github.com/meta —— 官方最准，但在联通/移动的部分线路上根本不通；
    2. Gitee 上本项目仓库里的 meta.json —— 国内三网都能拉 Gitee，这是关键兜底；
    3. GitHub raw 的同一份 meta.json。

    以前只有一个源（api.github.com），拉不到就只剩内置那十几个旧地址 ——
    这就是"某些运营商的用户用不了"的直接原因。
    """
    global CANDIDATES
    urls = (
        'https://api.github.com/meta',
        'https://gitee.com/kele551/FoxPath/raw/main/meta.json',
        'https://raw.githubusercontent.com/kele551/FoxPath/main/meta.json',
    )
    last_err = None
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'foxpath-helper'})
            with urllib.request.urlopen(req, timeout=6) as r:
                data = json.loads(r.read().decode('utf-8'))
        except Exception as e:
            last_err = e
            continue
        ips, v6s = [], []
        # 我们自己发的 meta.json 里可以带一份"策展过的" ips（优先用）
        for ip in (data.get('ips') or []):
            if _valid_ip(ip):
                (v6s if ':' in ip else ips).append(ip)
        for cidr in (data.get('web') or []):
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            first = next(net.hosts(), None) or net.network_address
            if net.version == 4:
                ips.append(str(first))
            # IPv6 网段的首地址不是真实主机（实测 HTTP 层 Domain Not Found），
            # 所以这里**故意不收集**；真实 IPv6 只从 DNS / meta.json 的 web6 来。
        # 140.82.112.0/20 只取网段首地址是没用的（那是网段地址），手工补齐真实主机
        for third in (112, 113, 114, 115, 116):
            for last in (3, 4):
                ips.append('140.82.%d.%d' % (third, last))
        seen, out = set(), []
        for ip in ips + CANDIDATE_IPS:
            if ip not in seen:
                seen.add(ip)
                out.append(ip)
        CANDIDATES = out
        # 真实 IPv6 地址：官方只给网段，取网段首地址多半不通；我们发的 meta.json
        # 里带了实测解析出来的地址，优先用它们。
        extra6 = [ip for ip in (data.get('web6') or []) if _valid_ip(ip)]
        for ip in (extra6 or CANDIDATE_IPS_V6 or []) + v6s:
            if ip not in CANDIDATES:
                CANDIDATES.append(ip)
        _last_meta_ok[0] = time.time()
        _META_SOURCE[0] = ('官方' if 'api.github.com' in url else
                           'Gitee' if 'gitee.com' in url else 'GitHub')
        log('已同步官方 IP 表(%s): 候选 %d 个(含 IPv6 %d 个)'
            % (_META_SOURCE[0], len(CANDIDATES),
               len([x for x in CANDIDATES if ':' in x])))
        return out
    log('同步官方 IP 表失败(%s), 用内置 %d 个候选' % (last_err, len(CANDIDATES)))
    return list(CANDIDATES)


def dns_fallback_ips():
    """手上 IP 全死时的最后一条路: 问系统 DNS github.com 现在指向哪。
    DNS 给的多半也是死的, 但值得一试, 而且换了宽带/换了 DNS 就可能是活的。"""
    out = []
    for host in ('github.com', 'www.github.com'):
        try:
            for info in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP):
                ip = info[4][0]
                # 2026-10-08: 以前这里把 IPv6 直接丢掉（': ' in ip 就 continue）。
                # 但"用户自己的 DNS 给的地址"恰恰是最值得试的 —— 移动/联通的
                # IPv6 常常反而是通的。IPv4 排在前面，IPv6 跟在后面。
                if ip not in out:
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
    // github.com -> local proxy.
    // raw/objects.githubusercontent.com -> local proxy as well, but they use
    // their OWN ip pool inside the proxy (185.199.108.0/22). Sending them to the
    // github.com pool lands on the wrong server and breaks the download.
    // avatars/camo/githubassets stay DIRECT on purpose: they render the pages,
    // and proxying them with the wrong pool is what broke pages in the past.
    if (host === "github.com" || host === "www.github.com" ||
        host === "raw.githubusercontent.com" ||
        host === "objects.githubusercontent.com") {
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
        if is_raw_host(host):
            # raw 文件 / 发布附件：走 185.199.108.0/22 那段专属池。
            # 以前没有这段，所以 githubusercontent 只能直连（用户提的 issue #1）。
            for ip in HEALTH_RAW.candidates()[:4]:
                try:
                    return socket.create_connection((ip, port), timeout=5), ip
                except OSError:
                    HEALTH_RAW.drop(ip)
                    continue
            log('raw 候选 IP 全灭, 本次退回系统解析')
        elif is_github_host(host):
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

# ------------------------------------------------------------------ 在线升级
# 用户 2026-09-22 要求:「第二个程序做升级功能」。
# 狐径跟壁纸助手不一样: 它没有"脚本层", 程序就是一个 exe —— 升级就是换 exe。
# 做法: 下载到 <exe>.new -> 校验 sha256 -> 交给一个独立小助手
#       (先让旧程序自己退出并还原代理 -> 覆盖 -> 再启动新的)。
# 不需要管理员权限: D:\Program Files 的 ACL 允许普通用户写(实测过)。
# 升级源: 仓库里的 version.json, Gitee raw 优先、GitHub 兜底;
#         测试时可在数据目录放一个 update_url.txt 指到本地文件。
UPDATE_URLS = (
    'https://gitee.com/kele551/FoxPath/raw/main/version.json',
    'https://raw.githubusercontent.com/kele551/FoxPath/main/version.json',
)
UPDATE_CACHE = os.path.join(DATA_DIR, 'update.json')
UPDATE_URL_TXT = os.path.join(DATA_DIR, 'update_url.txt')
UPDATE_LOCK = threading.Lock()
UPDATE = {
    'phase': 'idle',      # idle / checking / downloading / verifying / applying / done / failed
    'got': 0, 'total': 0, 'pct': 0, 'msg': '', 'error': '',
    'local': APP_VERSION, 'remote': '', 'notes': '', 'exe_url': '', 'exe_sha': '',
}


def ver_tuple(v):
    try:
        return tuple(int(x) for x in str(v).strip().split('.'))
    except Exception:
        return (0,)


def cmp_ver(a, b):
    """比大小: a>b 返回 1, 相等 0, a<b 返回 -1。"""
    ta, tb = ver_tuple(a), ver_tuple(b)
    n = max(len(ta), len(tb))
    ta = ta + (0,) * (n - len(ta))
    tb = tb + (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def _update_set(**kw):
    with UPDATE_LOCK:
        UPDATE.update(kw)


def _update_get():
    with UPDATE_LOCK:
        return dict(UPDATE)


def read_update_info(use_cache=True):
    """读升级信息; use_cache=True 时 6 小时内不重复联网。"""
    if use_cache and os.path.isfile(UPDATE_CACHE):
        try:
            with open(UPDATE_CACHE, encoding='utf-8') as f:
                c = json.load(f)
            if time.time() - float(c.get('_checked', 0)) < 6 * 3600:
                return c
        except Exception:
            pass
    urls = list(UPDATE_URLS)
    try:
        if os.path.isfile(UPDATE_URL_TXT):
            with open(UPDATE_URL_TXT, encoding='utf-8') as f:
                u = f.read().strip()
            if u:
                urls = [u]
    except Exception:
        pass
    for u in urls:
        try:
            if u.startswith(('http://', 'https://')):
                req = urllib.request.Request(u, headers={'User-Agent': 'FoxPath'})
                with urllib.request.urlopen(req, timeout=20) as r:
                    raw = r.read().decode('utf-8', 'replace')
            else:
                with open(u, encoding='utf-8') as f:
                    raw = f.read()
            info = json.loads(raw)
            if not info.get('version'):
                continue
            info['_checked'] = time.time()
            info['_source'] = u
            try:
                with open(UPDATE_CACHE, 'w', encoding='utf-8') as f:
                    json.dump(info, f, ensure_ascii=False)
            except Exception:
                pass
            return info
        except Exception as e:
            log('升级检查失败(%s): %s' % (u, e))
            continue
    return None


def update_exe_node(info):
    """取"要换的 exe"; 兼容 exe / launcher 两种字段名。"""
    for k in ('exe', 'launcher'):
        n = (info or {}).get(k)
        if isinstance(n, dict) and n.get('url'):
            return n
    return None


def do_update_check():
    _update_set(phase='checking', msg='正在检查升级源…', error='')
    info = read_update_info()
    if not info:
        _update_set(phase='failed', error='net', msg='连不上升级源(或还没发布升级信息)')
        return _update_get()
    node = update_exe_node(info) or {}
    remote = str(info.get('version') or '')
    newer = cmp_ver(remote, APP_VERSION) > 0
    _update_set(local=APP_VERSION, remote=remote, notes=str(info.get('notes') or ''),
                phase='idle', exe_url=node.get('url', ''), exe_sha=str(node.get('sha256') or '').upper(),
                total=int(node.get('size') or 0),
                msg=('有新版本 v' + remote + ' 可以升级') if newer else '已是最新版')
    return _update_get()


def _download_to(path, url, total_hint=0):
    """边下边报进度; 返回 (sha256, None) 或 (None, 错误说明)。"""
    import hashlib
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'FoxPath'})
        h = hashlib.sha256()
        got = 0
        with urllib.request.urlopen(req, timeout=60) as r:
            total = int(r.headers.get('Content-Length') or total_hint or 0)
            _update_set(total=total)
            with open(path, 'wb') as f:
                while True:
                    chunk = r.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    h.update(chunk)
                    got += len(chunk)
                    _update_set(got=got, pct=(int(got * 100 / total) if total else 0),
                                phase='downloading', msg='正在下载新版本')
        return h.hexdigest().upper(), None
    except Exception as e:
        return None, str(e)


def _spawn_helper(exe, new, ver):
    """独立小助手(PowerShell, UTF-8 带 BOM): 等本进程退出 -> 覆盖 -> 再启动。
    不用 .cmd —— cmd.exe 按控制台代码页读 .cmd, 中文路径会变问号(壁纸助手那边实测过)。"""
    import subprocess
    helper = os.path.join(DATA_DIR, 'update-apply.ps1')
    logf = os.path.join(DATA_DIR, 'update.log')
    q = lambda s: "'" + str(s).replace("'", "''") + "'"
    lines = [
        "$ErrorActionPreference = 'Continue'",
        '$exe = ' + q(exe),
        '$new = ' + q(new),
        '$log = ' + q(logf),
        "$newver = '" + str(ver) + "'",
        "function W($m) { try { Add-Content -LiteralPath $log -Value ('[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] ' + $m) -Encoding UTF8 } catch {} }",
        "function Panel {",
        "  # 面板是否有人应答（不区分新旧实例）",
        "  try { $r = Invoke-WebRequest 'http://127.0.0.1:" + str(PANEL_PORT) + "/api/status' -TimeoutSec 3 -UseBasicParsing",
        "        return ($r.StatusCode -eq 200) } catch { return $false }",
        "}",
        "function Up {",
        "  # 2026-10-08 起：判断「新版本真的起来了」靠两步，别只看看板通不通 ——",
        "  # 旧实例还没退干净时看板也是通的，会被误判成已起来，于是不再重试，",
        "  # 用户就真的没程序可用了（发版前自检抓到过这个假阳性）。",
        "  # 所以：启动前先等看板彻底不通，启动后只要通了就一定是新实例。",
        "  return (Panel)",
        "}",
        "W '开始覆盖主程序 (新版本 v" + str(ver) + ")'",
        "Start-Sleep -Seconds 2",
        "try { Invoke-WebRequest 'http://127.0.0.1:" + str(PANEL_PORT) + "/api/quit' -Method POST -TimeoutSec 8 -UseBasicParsing | Out-Null } catch { W ('调 /api/quit 出错: ' + $_.Exception.Message) }",
        "$nm = [System.IO.Path]::GetFileNameWithoutExtension($exe)",
        "$n = 0",
        "while ($n -lt 90) { if (-not (Get-Process -Name $nm -ErrorAction SilentlyContinue)) { break }; Start-Sleep -Seconds 1; $n++ }",
        "W ('进程已退出, 等了 ' + $n + ' 秒')",
        "try { Move-Item -LiteralPath $new -Destination $exe -Force; W '已覆盖主程序' } catch { W ('覆盖失败: ' + $_.Exception.Message) }",
        "# 2026-10-08: 覆盖后先等 3 秒 —— 新文件刚落地时杀软正在扫, 立刻启动会出现",
        "# 'Failed to load Python DLL'(实测被火绒拦过), 表现为程序打不开。",
        "Start-Sleep -Seconds 3",
        "# 关键一步：确认旧实例真的退干净了（看板不通），否则后面的 Up 会误判。",
        "$d = 0",
        "while ($d -lt 30) { if (-not (Panel)) { break }; Start-Sleep -Seconds 1; $d++ }",
        "W ('旧实例已停 (等了 ' + $d + ' 秒, 看板不通=' + (-not (Panel)) + ')')",
        "# 启动并确认真的起来了: 轮询面板。实测杀软(火绒)对「它第一次见到的全新",
        "# 二进制」会先拦一下 —— 第一次启动常常失败(报 Failed to load Python DLL),",
        "# 等一会儿再试就好了。所以间隔递增重试 6 次, 总共覆盖约 6 分钟。",
        "$ok = $false",
        "$waits = @(5, 10, 15, 20, 30)",
        "for ($k = 1; $k -le $waits.Count; $k++) {",
        "  W ('第 ' + $k + ' 次启动新版本')",
        "  try { Start-Process -FilePath $exe } catch { W ('Start-Process 失败: ' + $_.Exception.Message) }",
        "  $w = 0",
        "  while ($w -lt 20) { if (Up) { $ok = $true; break }; Start-Sleep -Seconds 1; $w++ }",
        "  if ($ok) { W ('新版本已起来 (等了 ' + $w + ' 秒)'); break }",
        "  W ('第 ' + $k + ' 次没起来 (20 秒内面板无响应), 结束卡住的进程, 等 ' + $waits[$k-1] + ' 秒再试')",
        "  try { Stop-Process -Name $nm -Force -ErrorAction SilentlyContinue } catch {}",
        "  Start-Sleep -Seconds $waits[$k-1]",
        "}",
        "if ($ok) { W '已用新版本重新启动' } else {",
        "  W '五次都没能自动启动, 已提示用户手动双击（弹窗）'",
        "  try { (New-Object -ComObject Wscript.Shell).Popup(",
        "        '狐径已升级到新版本，但自动重启没成功（多半是杀毒软件拦了第一次解包）。' + [char]13 + [char]10 + [char]13 + [char]10 + '请手动双击 FoxPath.exe 启动即可，不影响使用。',",
        "        90, '狐径 FoxPath', 48) | Out-Null } catch {}",
        "}",
        "# 顺手清理解包残留(只清 24 小时前的、且没进程在用的), 这堆东西能占几个 GB",
        "$cut = (Get-Date).AddHours(-24)",
        "$inuse = @{}",
        "Get-Process -ErrorAction SilentlyContinue | ForEach-Object {",
        "  try { foreach ($m in $_.Modules) { if ($m.FileName -like '*\\_MEI*') { foreach ($p in $m.FileName.Split('\\')) { if ($p -like '_MEI*') { $inuse[$p] = 1 } } } } } catch {}",
        "}",
        "$freed = 0; $cnt = 0",
        "Get-ChildItem $env:TEMP -Directory -Filter '_MEI*' -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $cut -and -not $inuse.ContainsKey($_.Name) } | ForEach-Object {",
        "  try {",
        "    $sz = (Get-ChildItem $_.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum",
        "    Remove-Item $_.FullName -Recurse -Force -ErrorAction Stop",
        "    $freed += $sz; $cnt++",
        "  } catch {}",
        "}",
        "if ($cnt -gt 0) { W ('顺手清理解包残留 ' + $cnt + ' 个, 释放 ' + [math]::Round($freed/1MB) + ' MB') }",
        "$k = 0",
        "while ($k -lt 10) { try { Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction Stop; break } catch { Start-Sleep -Milliseconds 500; $k++ } }",
    ]
    try:
        with open(helper, 'w', encoding='utf-8-sig', newline='\r\n') as f:
            f.write('\n'.join(lines) + '\n')
        # 只用 CREATE_NO_WINDOW(0x08000000), **不要** DETACHED_PROCESS:
        # 后者让 powershell.exe 拿不到控制台, 进程会立刻退出、脚本一行都不执行
        # (沙箱实测: 同一个脚本手动跑完全正常, 换成 DETACHED 就一条日志都没有)。
        flags = 0x08000000 if os.name == 'nt' else 0
        devnull = open(os.devnull, 'wb')
        subprocess.Popen(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                          '-WindowStyle', 'Hidden', '-File', helper],
                         creationflags=flags, stdin=devnull, stdout=devnull,
                         stderr=devnull, close_fds=True)
        return True
    except Exception as e:
        log('升级: 放小助手失败 %s' % e)
        return False


def apply_update_async():
    """后台线程: 下载 -> 校验 -> 叫小助手覆盖并重启。"""
    info = read_update_info()
    node = update_exe_node(info)
    if not node:
        _update_set(phase='failed', error='no_info', msg='升级信息里没有下载地址')
        return
    exe = os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__)
    new = exe + '.new'
    _update_set(phase='downloading', got=0, pct=0, error='', msg='正在下载新版本')
    sha, err = _download_to(new, node['url'], int(node.get('size') or 0))
    if not sha:
        _update_set(phase='failed', error=err, msg='下载失败: %s' % err)
        log('升级: 下载失败 %s' % err)
        return
    _update_set(phase='verifying', msg='正在校验安装包')
    want = str(node.get('sha256') or '').upper().strip()
    if want and sha != want:
        _update_set(phase='failed', error='sha', msg='校验不过(期望 %s, 实际 %s), 已放弃' % (want[:16], sha[:16]))
        log('升级: 校验不过, 已放弃; 期望 %s 实际 %s' % (want[:16], sha[:16]))
        try:
            os.remove(new)
        except Exception:
            pass
        return
    if not _spawn_helper(exe, new, node.get('version') or (info or {}).get('version') or ''):
        _update_set(phase='failed', error='helper', msg='放小助手失败')
        return
    _update_set(phase='applying', pct=100, msg='校验通过, 正在覆盖并重启…')
    log('升级: 已下好 %d 字节 (sha256=%s) 并通过校验, 交给小助手覆盖'
        % (os.path.getsize(new), sha[:16]))

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
 .upd-ver{font:600 15px/1.5 Consolas,monospace;color:#0f766e}
 .upd-track{font:600 15px/1.5 Consolas,monospace;color:#cbd5e1;white-space:pre}
 .upd-bar{height:10px;background:#eef2f4;border-radius:6px;overflow:hidden;margin-top:10px}
 .upd-bar > i{display:block;height:100%;width:0;background:linear-gradient(90deg,#0f766e,#22c1ae);
   transition:width .25s ease}
 .upd-note{color:#6b7280;font-size:13px;margin-top:8px}
 .upd-ok{color:#0f766e;font-weight:600}
 .upd-err{color:#b91c1c;font-weight:600}</style></head><body>
<h1>狐径 FoxPath __VERSION__</h1>
<div class="sub">本机代理接管 GitHub 流量，直连当前实测可用的官方 IP。不改 hosts、不用管理员权限。</div>

<div class="card" id="updCard">
  <div class="row" style="margin-bottom:6px">
    <span class="k">版本</span>
    <span class="upd-ver" id="uvLocal">__VERSION__</span>
    <span class="upd-track" id="uvArrow">   =====>   </span>
    <span class="upd-ver" id="uvRemote">—</span>
    <button class="primary" id="btnUpdCheck">检查更新</button>
    <button class="primary" id="btnUpdGo" style="display:none">立即升级</button>
  </div>
  <div class="upd-bar" id="updBarWrap" style="display:none"><i id="updBar"></i></div>
  <div class="upd-note" id="updMsg">点「检查更新」看看有没有新版本。</div>
</div>
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

<div class="card">
  <div style="margin-bottom:8px"><b>线路体检</b>
    <span style="color:#6b7280">—— 点「复制诊断信息」把这一行发给作者，就能定位卡在哪一环</span></div>
  <div id="diag" style="font-family:Consolas,monospace;font-size:12px;background:#f6f8fa;
       padding:8px;border-radius:6px;word-break:break-all;white-space:pre-wrap">读取中…</div>
  <div class="row" style="margin-top:8px">
    <button class="primary" id="btnDiagCopy">复制诊断信息</button>
    <button id="btnDiagRe">刷新体检</button>
    <span id="diagMsg" style="margin-left:8px;color:#16a34a"></span>
  </div>
</div>

<div class="card">
  <div style="margin-bottom:8px"><b>手动指定 IP</b>
    <span style="color:#6b7280">—— 自动探测一个都不通时用：填一个你这条线能连上的 GitHub 官方 IP</span></div>
  <div class="row">
    <input id="ipInput" placeholder="例如 20.205.243.166" style="min-width:220px;padding:4px 6px">
    <button class="primary" id="btnIpSave">保存并重测</button>
    <button id="btnIpClear">清除</button>
    <span id="ipMsg" style="margin-left:8px;color:#6b7280"></span>
  </div>
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
function loadDiag(){
  fetch('/api/diag').then(r=>r.text()).then(t=>{
    document.getElementById('diag').textContent = t;
  }).catch(()=>{});
}
function _say(id,txt){const e=document.getElementById(id);if(e){e.textContent=txt;setTimeout(()=>{e.textContent=''},2500);}}
function copyDiag(){
  const t=document.getElementById('diag').textContent||'';
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(t).then(()=>_say('diagMsg','已复制，直接粘贴发给作者就行'))
      .catch(()=>fallbackCopy(t));
  } else { fallbackCopy(t); }
}
function fallbackCopy(t){
  const ta=document.createElement('textarea'); ta.value=t; document.body.appendChild(ta);
  ta.select(); try{document.execCommand('copy'); _say('diagMsg','已复制');}catch(e){_say('diagMsg','复制失败，请手动选中复制');}
  document.body.removeChild(ta);
}
document.getElementById('btnDiagCopy').onclick = copyDiag;
document.getElementById('btnDiagRe').onclick = ()=>{loadDiag();refresh();};
document.getElementById('btnIpSave').onclick = ()=>{
  const v=document.getElementById('ipInput').value.trim();
  if(!v){_say('ipMsg','先填一个 IP');return;}
  act('/api/set-ip?ip='+encodeURIComponent(v)).then(()=>{
    _say('ipMsg','已保存，正在重测…'); loadDiag(); refresh();
  });
};
document.getElementById('btnIpClear').onclick = ()=>{
  act('/api/set-ip?ip=').then(()=>{_say('ipMsg','已清除');loadDiag();refresh();});
};
loadDiag(); setInterval(loadDiag,10000);
refresh(); setInterval(refresh,3000);
</script>
<script>
/* 在线升级: 版本迁移动画 + 渐变进度条 + 状态轮询 */
(function(){
  var U={bar:document.getElementById('updBar'),wrap:document.getElementById('updBarWrap'),
         msg:document.getElementById('updMsg'),remote:document.getElementById('uvRemote'),
         arrow:document.getElementById('uvArrow'),go:document.getElementById('btnUpdGo'),
         local:document.getElementById('uvLocal'),anim:null,timer:null};
  if(!U.msg) return;
  function spin(on){
    if(U.anim){clearInterval(U.anim);U.anim=null;}
    if(!on){U.arrow.textContent='   =====>   ';return;}
    var fr=['o--------->','=o-------->','==o------->','===o------>','====o----->',
            '=====o---->','======o--->','=======o-->','========o->','=========>'];
    var i=0; U.anim=setInterval(function(){U.arrow.textContent='   '+fr[i%fr.length]+'   ';i++;},85);
  }
  function kb(n){return Math.round((n||0)/1024)+' KB';}
  function paint(v){
    U.remote.textContent = v.remote ? ('v'+v.remote) : '—';
    var busy = (v.phase==='downloading'||v.phase==='verifying'||v.phase==='applying');
    spin(v.phase==='checking');
    if(v.phase==='downloading'){
      U.wrap.style.display='block';
      U.bar.style.width=(v.pct||0)+'%';
      U.msg.textContent='正在下载新版本  '+kb(v.got)+(v.total?(' / '+kb(v.total)+'   '+(v.pct||0)+'%'):'');
      U.go.style.display='none';
    } else if(v.phase==='verifying'||v.phase==='applying'){
      U.wrap.style.display='block'; U.bar.style.width='100%';
      U.msg.innerHTML='<span class="upd-ok">'+v.msg+'</span>';
      U.go.style.display='none';
    } else if(v.phase==='failed'){
      U.wrap.style.display='block';
      U.msg.innerHTML='<span class="upd-err">升级没有完成：'+(v.msg||'')+'</span>';
    } else if(v.remote && v.remote!==v.local){
      U.msg.innerHTML='<span class="upd-ok">发现新版本 v'+v.remote+'</span>'+(v.notes?('  '+v.notes):'');
      U.go.style.display=''; U.wrap.style.display='none'; U.bar.style.width='0';
    } else {
      U.msg.textContent=v.msg||'已是最新版';
      U.go.style.display='none'; U.wrap.style.display='none';
    }
    var b=(v.phase!=='idle'&&v.phase!=='failed');
    if(b&&!U.timer){U.timer=setInterval(tick,400);}
    if(!b&&U.timer){clearInterval(U.timer);U.timer=null;}
  }
  function tick(){ api('/api/update/status').then(paint); }
  document.getElementById('btnUpdCheck').onclick=function(){
    U.msg.textContent='正在检查升级源…'; spin(true);
    act('/api/update/check').then(tick);
  };
  document.getElementById('btnUpdGo').onclick=function(){
    U.go.style.display='none'; U.wrap.style.display='block'; U.bar.style.width='0';
    act('/api/update/start').then(tick);
  };
  tick();
})();
</script><div style="margin:16px 0 6px;text-align:center;font-size:12px;color:#8a8a8f">狐径 FoxPath · 作者 __AUTHOR__ · __HOMEPAGE__</div>
</body></html>
"""


PANEL_PAGE = (PANEL_HTML.replace('__VERSION__', APP_VERSION)
              .replace('__AUTHOR__', AUTHOR).replace('__HOMEPAGE__', HOMEPAGE))


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
        elif path == '/api/diag':
            self._send(200, diag_text().encode('utf-8'), 'text/plain; charset=utf-8')
        elif path == '/api/update/status':
            self._send(200, json.dumps(_update_get(), ensure_ascii=False).encode('utf-8'),
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
            threading.Thread(target=lambda: (HEALTH.refresh(candidate_list()),
                                              HEALTH_RAW.refresh(CANDIDATE_IPS_RAW)),
                             daemon=True).start()
            log('手动重测已触发(含 raw 池)')
        elif path == '/api/quit':
            log('收到退出指令, 正在还原系统代理')
            disable_proxy()
            threading.Thread(target=lambda: (time.sleep(0.3), os._exit(0)), daemon=True).start()
        elif path == '/api/update/check':
            st = do_update_check()
            log('手动检查升级: ' + str(st.get('msg')))
        elif path == '/api/update/start':
            if UPDATE.get('phase') in ('downloading', 'verifying', 'applying'):
                pass
            else:
                threading.Thread(target=apply_update_async, daemon=True).start()
                log('收到升级指令, 开始下载新版本')
        elif path == '/api/set-ip':
            raw = ''
            for kv in query.split('&'):
                if kv.startswith('ip='):
                    raw = urllib.parse.unquote(kv[3:])
            ok, msg = save_manual_ip(raw)
            log('手动 IP: ' + msg)
            if ok:
                threading.Thread(target=lambda: HEALTH.refresh(candidate_list()),
                                 daemon=True).start()
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
        good = HEALTH.refresh(candidate_list())
        good_raw = HEALTH_RAW.refresh(CANDIDATE_IPS_RAW)
        if need_meta or len(good) < 3:
            fetch_official_ips()
            good = HEALTH.refresh(candidate_list())

        # 体检日志就是狐径的心跳: 带上"已运行多久", 长跑日志才能一眼看出
        # 它是持续在跑、还是中途死过又重开。
        up_min = int((time.time() - _START_TS[0]) / 60) if _START_TS[0] else 0
        if good:
            log('体检: 可用 %d/%d 已运行%d分钟 -> %s' % (
                len(good), len(CANDIDATES), up_min,
                ', '.join('%s(%dms)' % (i, m) for i, m in good[:3])))
        elif good_raw:
            log('raw 体检: 可用 %d/%d -> %s'
                % (len(good_raw), len(CANDIDATE_IPS_RAW),
                   ', '.join('%s(%dms)' % (i, m) for i, m in good_raw[:2])))
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
    log('作者: %s   https://%s' % (AUTHOR, HOMEPAGE))

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
        log('已有实例在运行')
        # 2026-09-22 修: 以前这里直接 return。程序是 --noconsole 的、又没有托盘图标,
        # 用户第二次双击时屏幕上什么都不会出现 —— 只能判断成"程序打不开"。
        # 现在把**已经在跑的那个控制面板**交给默认浏览器打开, 并写清日志。
        if '--silent' not in args:
            try:
                webbrowser.open('http://127.0.0.1:%d' % PANEL_PORT)
                log('已把正在运行的控制面板交给浏览器打开(本次不再重复启动)')
            except Exception as e:
                log('打开控制面板失败: %s' % e)
        else:
            log('静默模式: 已有实例在运行, 本次直接退出(不动系统代理)')
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
