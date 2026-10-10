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
import re
import select
import socket
import socketserver
import ssl
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from ctypes import wintypes          # 升级结果气泡要用(Shell_NotifyIcon 的结构体)
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

APP_NAME = '狐径'
APP_VERSION = '1.0.8'
# 署名（一处定义，界面/日志/属性/README 都用它，避免各写各的）
AUTHOR = '海风（kele551）'
AUTHOR_ASCII = 'HaiFeng (kele551)'
HOMEPAGE = 'gitee.com/kele551/FoxPath'
PROXY_PORT = 8787
PANEL_PORT = 8788
CHECK_INTERVAL = 300          # 5 分钟重测一轮
# 转发通道的"空闲上限": 只要两端还有数据流动就一直续期, 不是总时长上限(审查 H-4)。
RELAY_IDLE_TIMEOUT = 600

# PAC 只代理这两个主机；代理内部也用同一份名单，保证"PAC 会送来的"和
# "代理愿意走 IP 池的"完全一致。githubassets/githubusercontent/api.github.com
# 一律 DIRECT —— 它们直连本来就通，走代理反而会坏（见 README 已知边界）。
PROXY_HOSTS = ('github.com', 'www.github.com')

# 2026-10-09 用户要求：把 GitHub Pages 也纳入接管范围。
# 页面挂在 *.github.io 上（用户名.github.io），用的还是 185.199.108.0/22 那一段，
# 所以与 raw/附件**共用同一份 IP 池**；但**证书期望值必须单独设** ——
# 实测这一段服务的是 *.github.io 证书，拿 githubusercontent.com 那套去校验，
# 会把这一池的好 IP 全部误杀（见下面的 HEALTH_PAGES）。
GITHUB_IO_SUFFIX = '.github.io'

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


def _manual_ip_reject(ip):
    """手动 IP 的合法性检查(审查 M-14): 只收公网单播地址。

    留手填是为了救急, 但填 192.168.x.x / 127.0.0.1 / fe80:: 这类地址只会白试一场
    (对面的证书必然不匹配), 所以直接挡掉并给一句人话, 而不是写进去让程序空转。
    返回 '' 表示可以收。
    """
    try:
        a = ipaddress.ip_address(str(ip or '').strip())
    except Exception:
        return '不是合法的 IP 地址: %s' % (ip or '(空)')
    if a.is_loopback:
        return '这是本机回环地址(%s), 不是 GitHub 的服务器地址' % a
    if a.is_private:
        return '这是内网地址(%s), 不是 GitHub 的服务器地址' % a
    if a.is_link_local:
        return '这是链路本地地址(%s), 不是 GitHub 的服务器地址' % a
    if a.is_multicast or a.is_reserved or a.is_unspecified:
        return '这个地址(%s)不能当作服务器地址用' % a
    return ''


def load_manual_ip():
    try:
        with open(_manual_ip_path(), encoding='utf-8') as f:
            ip = f.read().strip()
    except Exception:
        return ''
    if not _valid_ip(ip) or _manual_ip_reject(ip):
        return ''                  # 以前写进去的私网/回环地址也一并作废(审查 M-14)
    return ip


def save_manual_ip(ip):
    """保存/清除手动 IP，返回 (成功?, 一句话说明)。"""
    ip = (ip or '').strip()
    if ip:
        why = _manual_ip_reject(ip)     # 审查 M-14: 私网/回环等一律拒收
        if why:
            return False, why
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


def _mask_ip(ip):
    """把地址的末段换成 x（审查 M-6: 诊断文本可能被复制外发, 不外传完整 IP）。

    只留前两段(IPv4)或第一段(IPv6), 足够看出"是哪一段地址在通", 又不构成可用地址。
    """
    ip = str(ip or '')
    if ':' in ip:
        return ip.split(':')[0] + ':****'
    parts = ip.split('.')
    if len(parts) == 4:
        return '%s.%s.x.x' % (parts[0], parts[1])
    return ip


def diag_text(redact=True):
    """一行"线路体检"—— 客户复制这一行发来，就能定位卡在哪一环。"""
    good, ts = HEALTH.snapshot()
    # 审查 M-6: redact=True(/api/diag 走这条)时**不带完整 IP** —— 这段文本会被
    # 用户复制外发, 而 /api/diag 是 GET 接口。面板上"当前可用 IP"那张表仍按原样
    # 显示(走 /api/status, 是给用户自己看的)。
    v4 = [g for g in good if ':' not in g[0]]
    v6 = [g for g in good if ':' in g[0]]
    cand = candidate_list()
    all4 = [ip for ip in cand if ':' not in ip]
    all6 = [ip for ip in cand if ':' in ip]
    hide = _mask_ip if redact else (lambda x: x)
    fastest = ('%s(%dms)' % (hide(good[0][0]), good[0][1])) if good else '无'
    up_min = int((time.time() - _START_TS[0]) / 60) if _START_TS[0] else 0
    last = time.strftime('%m-%d %H:%M:%S', time.localtime(ts)) if ts else '还没体检过'
    raw_good, _ = HEALTH_RAW.snapshot()
    pages_good, _ = HEALTH_PAGES.snapshot()
    head = ('狐径体检 v%s | IPv4 可用 %d/%d | IPv6 可用 %d/%d | raw 可用 %d/%d | '
            'pages 可用 %d/%d | 表源 %s | 最快 %s | 系统代理 %s | 手动IP %s | '
            '上次体检 %s | 已运行 %d 分钟'
            % (APP_VERSION, len(v4), len(all4), len(v6), len(all6),
               len(raw_good), len(CANDIDATE_IPS_RAW),
               len(pages_good), len(CANDIDATE_IPS_RAW),
               _META_SOURCE[0] or '未同步(用内置表)', fastest,
               '已开启' if proxy_on() else '未开启', _MANUAL_IP[0] or '无', last, up_min))
    detail = ('停用' if not good else
              '可用清单: ' + ', '.join('%s(%dms)' % (hide(i), m) for i, m in good[:8]))
    return head + '\n' + detail


REG_INTERNET = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
REG_RUN = r'Software\Microsoft\Windows\CurrentVersion\Run'

# 改系统代理的互斥锁(审查 H-3): 面板是 ThreadingHTTPServer, 两个 POST 会真并发。
# 没有这把锁时「读原值 -> 写备份 -> 写注册表」不是原子的: 快速连点两次「启用加速」,
# 第二份请求会在第一份写好 PAC 之后才读到"原值", 于是把我们自己的 PAC 地址写进
# 备份 —— 退出还原就永远回不到原始状态(v1.0.0 踩过, 现在以竞态形式复活)。
_REG_LOCK = threading.Lock()

# 面板最后一次被请求的时刻(自动升级前用它判断"用户是不是正开着面板")
_LAST_ACT = [0.0]

_log_q = queue.Queue()
_START_TS = [0.0]          # 进程启动时刻, 体检日志里用它显示"已运行多久"


# ── 启动阶段绝不弹模态对话框(★★ 2026-10-09 线上事故的加固)──────────────────
# 升级小助手判"新版本起没起来"看的是**控制面板有没有应答**; 而 MessageBox 是模态的 ——
# 启动路上任何一个弹窗都会把进程挂在那儿等人点"确定", 面板就一直起不来,
# 小助手于是判定失败、结束卡住的进程、反复重启, 用户升级完就"没有程序可用"。
# 所以定一条硬规矩: 启动宽限期内(STARTUP_MODAL_GRACE 秒)、以及"这次是升级交接上来的"
# 整个进程, 一律**不弹模态框** —— 失败只写日志 + 在面板/气泡里显示。
STARTUP_MODAL_GRACE = 120.0
_HANDOFF_STARTUP = [False]      # 本次启动是不是"刚被升级换上新版本"的那一次


def modal_allowed():
    """现在允许弹模态框吗? 启动阶段与升级交接后一律不许(见上面的说明)。"""
    if _HANDOFF_STARTUP[0]:
        return False
    t0 = _START_TS[0] or 0.0
    return (time.time() - t0) > STARTUP_MODAL_GRACE


def alert(title, text):
    """重要提示。启动阶段(尤其升级交接后)**不弹模态框**, 只写日志 + 弹一个非模态气泡。

    exe 是 --noconsole 的: 致命错误只写日志的话, 用户双击后看到的是"没反应" —— 所以
    该提示还是要提示, 只是不再用会挂住启动的模态框; 命令行跑源码时屏幕上看得到, 不弹。
    """
    try:
        if (not getattr(sys, 'frozen', False)) and sys.stdout is not None:
            return                          # 有控制台: 命令行下不该被打断
        if modal_allowed():
            ctypes.windll.user32.MessageBoxW(None, text, title, 0x10)   # MB_ICONERROR
            return
        log('提示(启动阶段不弹模态框, 只写日志+气泡): %s | %s'
            % (title, ' '.join(str(text).split())))
        try:
            if bubble_on():                 # 非模态气泡: 看一眼就没了, 不会挂住启动
                _spawn_bubble(str(title), str(text))
        except Exception:
            pass
    except Exception:
        pass


_alert_lock = threading.Lock()
_alert_seen = {}


def alert_once(key, title, text, window=15.0):
    """同一件事短时间内只提示一次(审查 M-4)。

    enable_proxy 回读失败时会提示一次, 面板的 /api/enable 分支还有一道兜底 ——
    两处都走这里, 靠它去重: 同一个错误不会连着提示两次。启动阶段由 alert() 决定
    "写日志+气泡"还是"弹模态框"(升级交接后的启动一律不弹模态框)。
    """
    now = time.time()
    with _alert_lock:
        if now - _alert_seen.get(key, 0.0) < window:
            return False
        _alert_seen[key] = now
    alert(title, text)
    return True


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
LOG_TAIL_BYTES = 128 * 1024   # 超过上限时保留的尾部**字节数**(审查 M-9: 不再按行)
LOG_PANEL_LINES = 200      # 面板 /api/status 只回尾部这么多行
LOG_QUEUE_MAX = 2000       # 面板没打开时队列也要有个上限, 不然会一直涨
# 连接级日志(每转发一次写一行)的降级参数(审查 H-5): 正常浏览 GitHub 几十秒就能
# 产生几百行, 而面板只显示尾部 200 行、文件只留尾部一块(按字节) —— 不降级的话,
# 体检/自愈/升级/还原这些关键行会被直接挤出可视范围。
CONN_LOG_SAMPLE = 20       # 每 N 次连接才写一行明细(进面板/进文件), 其余只进控制台
CONN_LOG_WINDOW = 60       # 每 N 秒补一行"这段时间转发了几次"的聚合行


def _log_to_file(line):
    """exe 是 --noconsole 的, 屏幕上看不到任何东西; 日志必须落文件。"""
    try:
        if os.path.isfile(LOG_FILE) and os.path.getsize(LOG_FILE) > LOG_MAX:
            # 审查 M-9: 截断改成**按字节**读尾再 decode。以前是 readlines() 取尾部
            # 500 "行", 口径与 512 KB 的上限对不上 —— 遇到超长行(异常堆栈、超长 URL)
            # 会一次读进来一大片; 而且多字节字符按行切也不保险。
            with open(LOG_FILE, 'rb') as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - LOG_TAIL_BYTES), os.SEEK_SET)
                tail = f.read().decode('utf-8', 'ignore')
            nl = tail.find('\n')
            if nl >= 0:
                tail = tail[nl + 1:]        # 从第一个换行之后开始, 不留半行
            # 读回来的是字节, 里面已经带着 \r\n; 文本模式写回时会再翻译一次
            # (变成 \r\r\n, 每轮转一次多一个 \r)。这里先统一成 \n 再交回文本模式。
            tail = tail.replace('\r\n', '\n').replace('\r', '\n')
            with open(LOG_FILE, 'w', encoding='utf-8') as f:
                f.write(tail)
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(line + '\n')
    except Exception:
        pass


def log(msg, debug=False):
    """关键行日志: 面板队列与文件都写。

    debug=True 是连接级明细里"被抽样掉"的那一档: 只打控制台, 不进面板队列、
    不进文件 —— 否则每次连接一行, 几十秒就能把体检/自愈/升级/还原这些关键行
    挤出面板的 200 行与文件尾部 500 行(审查 H-5)。
    """
    line = '[%s] %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), msg)
    if not debug:
        if _log_q.qsize() >= LOG_QUEUE_MAX:
            try:
                _log_q.get_nowait()          # 面板没开时丢最旧的, 别无限涨
            except queue.Empty:
                pass
        _log_q.put(line)
        _log_to_file(line)
    try:
        print(line, flush=True)
    except Exception:
        pass


_conn_lock = threading.Lock()
_conn_total = [0]            # 累计转发次数, 只用于日志抽样
_conn_window = [0.0, 0]      # [本窗口起点, 本窗口内的次数]


def log_conn(msg):
    """连接级日志: 抽样 + 聚合(审查 H-5)。

    第 1 次和之后每 CONN_LOG_SAMPLE 次写一行明细(进面板、进文件), 每个
    CONN_LOG_WINDOW 秒再补一行聚合, 让面板里始终看得出"代理在转发";
    其余只进控制台。失败/异常路径不走这里, 仍用 log() 全量保留。
    返回 True 表示这一行进了面板与文件(方便自测断言)。
    """
    agg = ''
    with _conn_lock:
        _conn_total[0] += 1
        n = _conn_total[0]
        now = time.time()
        if not _conn_window[0]:
            _conn_window[0] = now
        _conn_window[1] += 1
        sample = (n == 1) or (n % CONN_LOG_SAMPLE == 0)
        if now - _conn_window[0] >= CONN_LOG_WINDOW:
            agg = ('连接日志聚合: 最近 %d 秒转发 %d 次(明细按 1/%d 抽样, 完整明细见控制台)'
                   % (int(now - _conn_window[0]), _conn_window[1], CONN_LOG_SAMPLE))
            _conn_window[0] = now
            _conn_window[1] = 0
    log(msg, debug=not sample)
    if agg:
        log(agg)
    return sample


def recent_logs(n=LOG_PANEL_LINES):
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


def is_pages_host(host):
    """GitHub Pages: github.io 及其所有子域(user.github.io)。

    与 PAC 里的判断保持一致(同一份名单、同一个语义), 名单只有一个来源。
    """
    host = (host or '').lower().split(':')[0]
    return host == 'github.io' or host.endswith(GITHUB_IO_SUFFIX)


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


def cert_matches(names, expect):
    """证书里的名字有没有覆盖 expect（纯函数, 便于单测）。

    三个池的期望值各不一样: github.com / githubusercontent.com / github.io,
    **混用就会把好 IP 判死**。只认后缀匹配, 不再像旧版那样做子串包含 ——
    'github.com' in 'github.com.evil.example' 会把别人的证书当成 GitHub 的。
    """
    want = str(expect or '').lower().strip()
    if not want:
        return False
    for n in (names or ()):
        n = str(n).lower().strip()
        if n == want or n.endswith('.' + want):
            return True
        if n.startswith('*.') and n[2:] == want:
            return True
    return False


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
                # 三个池的证书期望值各不相同: github.com / githubusercontent.com /
                # github.io(证书里是 *.github.io)。混用会把好 IP 判死。
                if not cert_matches(names, self.expect):
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
# GitHub Pages(2026-10-09 新增): 与 raw/附件同一段 IP(185.199.108.0/22),
# 但**证书不一样** —— 这里必须是 github.io(证书里是 *.github.io),
# 不能用 githubusercontent 那套, 也不能用 github.com 那套, 否则这一池 IP 全被判死。
# http_path=None: 只验 TLS + 证书(拿 IP 直接 GET 根路径本来就不是 2xx/3xx, 会误杀好 IP)。
HEALTH_PAGES = Health(sni='github.io', expect='github.io', http_path=None)
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
        # 审查 M-2: 这一份表到底解析出东西没有 —— 只有**真的解析出地址**才算同步成功。
        # 以前不管解析出几个, 都会把内置的 140.82.x.x 补进来凑数, 于是"接口 200 但表是
        # 空的 / 字段被改名"也会被记成「已同步官方 IP 表」, 而且**不再往下试 Gitee 兜底**;
        # 用户那边的表现就是"同步成功却一个 IP 都不通"。现在空表直接换下一个源。
        if not ips and not v6s:
            last_err = '%s 里没有解析出任何 IP(字段缺失或被改写)' % url
            log('同步源 %s 返回成功但没有 IP, 换下一个源' % url)
            continue
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
        # 审查 M-3: 自愈成功必须**回写候选表**。只把结果留在 HEALTH._good 里的话,
        # 下一轮 candidate_list() 又变回旧表, 自愈等于每轮白做一遍。
        CANDIDATES = list(dict.fromkeys(list(CANDIDATES) + list(ips)))
        log('自愈成功并已回写候选表: 候选 %d 个' % len(CANDIDATES))
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
    // github.io and *.github.io (GitHub Pages) also go through the local proxy.
    // They share the 185.199.108.0/22 pool with raw/objects, but the proxy checks
    // them against the *.github.io certificate, NOT the githubusercontent one.
    if (host === "github.com" || host === "www.github.com" ||
        host === "raw.githubusercontent.com" ||
        host === "objects.githubusercontent.com" ||
        host === "github.io" || dnsDomainIs(host, ".github.io")) {
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
        elif is_pages_host(host):
            # GitHub Pages: 与 raw/附件同一段 IP(185.199.108.0/22), 但证书是 *.github.io,
            # 所以走**按 github.io 证书体检过**的那一池(HEALTH_PAGES)。
            for ip in HEALTH_PAGES.candidates()[:4]:
                try:
                    return socket.create_connection((ip, port), timeout=5), ip
                except OSError:
                    HEALTH_PAGES.drop(ip)
                    continue
            log('github.io 候选 IP 全灭, 本次退回系统解析')
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
            log_conn('%s -> %s' % (host, used))
        self._relay(up)

    def _relay(self, up):
        conn = self.connection
        pair = [conn, up]
        # 转发阶段由 select 统一管超时, 先把两端 socket 的超时都放宽到同一个空闲
        # 上限: 客户端那端带着 StreamRequestHandler 的 30 秒(self.timeout), 上游
        # 那端还是建连时 create_connection 留下的 5 秒 —— 大附件(raw /
        # objects.githubusercontent.com)慢速传输时会被这两个短超时中途掐断,
        # 用户看到的是"下载中断、文件损坏"(审查 H-4)。
        for s in pair:
            try:
                s.settimeout(RELAY_IDLE_TIMEOUT)
            except Exception:
                pass
        try:
            while True:
                r, _, e = select.select(pair, [], pair, RELAY_IDLE_TIMEOUT)
                if e:
                    break
                if not r:
                    # 双方都静默满一个空闲上限才收摊, 而且写进日志 ——
                    # 不再像以前那样不声不响地把流掐掉。
                    log('转发空闲超过 %d 秒, 关闭这条连接(对端可能已放弃)' % RELAY_IDLE_TIMEOUT)
                    break
                stop = False
                for s in r:
                    try:
                        data = s.recv(65536)
                    except TimeoutError:
                        # 3.10 起 socket.timeout 就是 TimeoutError
                        log('转发等待数据超过 %d 秒, 关闭这条连接' % RELAY_IDLE_TIMEOUT)
                        stop = True
                        break
                    except OSError:
                        stop = True
                        break
                    if not data:
                        stop = True
                        break
                    try:
                        (up if s is conn else conn).sendall(data)
                    except TimeoutError:
                        log('转发写入超过 %d 秒仍未完成, 关闭这条连接' % RELAY_IDLE_TIMEOUT)
                        stop = True
                        break
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


def _probe_own_panel(timeout=2.0):
    """探一探 127.0.0.1:8788 上跑的**是不是我们自己的**控制面板(审查 M-13)。

    单实例用的是带 Local 前缀的命名互斥: 同一台机器上不同登录会话(远程桌面 + 本机)
    各能起一个, 后起的那个会撞端口, 以前直接弹错误框退出 —— 用户看到"程序坏了",
    其实只是另一个会话里已经在跑。撞端口先问一句"是不是自己人"。
    """
    try:
        req = urllib.request.Request('http://127.0.0.1:%d/api/status' % PANEL_PORT,
                                     headers={'User-Agent': 'FoxPath'})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if int(getattr(r, 'status', 200) or 0) != 200:
                return False
            d = json.loads(r.read().decode('utf-8', 'replace'))
    except Exception:
        return False
    return isinstance(d, dict) and ('logs' in d) and ('enabled' in d)


def _port_taken(port, err, what):
    """端口被占用时的统一处理(审查 M-13): 先认"是不是自己的实例", 是就提示复用。

    这个函数**一定抛 SystemExit**: 要么按"已有实例"安静退出(0),
    要么沿用原来的弹窗 + 退出(2)。
    """
    if _probe_own_panel():
        log('!! 端口 %d 被占用(%s), 但 8788 上的控制面板有应答 —— 判定为同一个狐径的'
            '另一个实例(多半在另一个登录会话里先起的), 本次不再重复启动' % (port, what))
        if '--silent' not in [a.lower() for a in sys.argv[1:]]:
            try:
                webbrowser.open('http://127.0.0.1:%d' % PANEL_PORT)
                log('已把正在运行的那个控制面板交给浏览器打开')
            except Exception as e:
                log('打开控制面板失败: %s' % e)
        raise SystemExit(0)
    log('!! 端口 %d 被占用, %s起不来: %s' % (port, what, err))
    tip = ('多半是上一个狐径没退干净。请在任务管理器结束它, 或先跑一次:\n'
           '    %s --restore' % os.path.basename(
               sys.executable if getattr(sys, 'frozen', False) else __file__))
    log('   ' + tip.replace('\n', ' '))
    alert('狐径: 端口被占用', '本机 %d 端口已被占用, 狐径起不来。\n\n%s\n\n日志: %s'
          % (port, tip, LOG_FILE))
    raise SystemExit(2)


def start_proxy():
    try:
        srv = ProxyServer(('127.0.0.1', PROXY_PORT), ProxyHandler)
    except OSError as e:
        # 审查 M-13: 先探"是不是自己的实例", 是就提示/复用, 而不是弹错退出
        _port_taken(PROXY_PORT, e, '代理')
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
    """启用加速, 返回 (ok, msg) —— 面板要按 ok 明确告诉用户成没成(审查 H-2)。

    整段「读原值 -> 写备份 -> 写注册表」在同一把 _REG_LOCK 里完成(审查 H-3):
    并发/连点时后一个请求会在前一个写完之后才判断, 不会拿我们自己的 PAC 当原值
    写进备份, 备份因此只写一次、且永远是"进入本程序管理之前"的原始值。
    """
    with _REG_LOCK:
        # 已经在启用状态就不要再"备份"一次 —— 否则备份里存的会是我们自己的
        # PAC 地址, 之后「停用并还原」只会把我们的地址写回去, 等于永远还原不了。
        # (旧版每次点「启用加速」都会覆盖备份, 这是最容易复现的一处缺陷。)
        if proxy_on():
            log('加速已处于启用状态, 不重复备份 / 不改写')
            return True, '加速已处于启用状态'
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
            msg = ('无法保存还原备份(%s), 为安全起见没有修改系统代理 —— 加速未生效。'
                   '请检查这个目录能不能写: %s' % (e, DATA_DIR))
            log('!! ' + msg.replace('\n', ' '))
            return False, msg
        if saved.get('ProxyEnable') and saved.get('ProxyServer'):
            # 一旦设置了 PAC, WinINET 会优先用它, 静态代理(ProxyEnable=1)就被旁路了。
            # 家用场景一般没有静态代理; 万一有, 至少要让用户知道发生了什么。
            log('注意: 你原本设了静态代理 %s —— 启用期间 PAC 优先级更高, '
                '其它网站会直连而不是走原代理; 停用时会自动还原'
                % saved.get('ProxyServer'))
        pac_url = _pac_url()
        reg_set(REG_INTERNET, 'AutoConfigURL', pac_url)
        # 审查 M-4: 写完必须**回读一眼**。注册表被组策略/安全软件锁住时,
        # 写操作可能悄悄不生效(或写进去又被改回), 而用户看到的是"已启用"、
        # 实际一点用都没有 —— 这种沉默失败最坑人。
        got = reg_get(REG_INTERNET, 'AutoConfigURL') or ''
        if got != pac_url:
            msg = ('系统代理写入后回读不一致(写入 %s, 读回 %s)—— 多半是安全软件或组策略'
                   '锁住了注册表, 加速没有生效。' % (pac_url, got or '(空)'))
            log('!! ' + msg)
            alert_once('enable-readback', '狐径: 启用加速失败', msg)
            return False, msg
        notify_proxy_change()
        log('加速已开启 (原设置已备份到 %s)' % BACKUP_FILE)
        return True, '加速已开启, 原系统代理设置已备份'


def disable_proxy():
    """停用并还原, 返回 (ok, msg) —— 失败原因要在面板上写清楚(审查 H-2)。

    与 enable_proxy 共用同一把 _REG_LOCK(审查 H-3): 启用与还原不会交叉执行,
    否则"刚写好的还原备份"可能被并发的还原流程读成半截。
    """
    with _REG_LOCK:
        saved = _load_backup()
        if saved is None:
            # 没有备份时要分两种情况, 不能一律删:
            #   a) 当前值确实指向本程序 -> 是本程序留下的残留, 清掉(用户删程序后
            #      系统里永远是死端口的 PAC, 2026-09-22 实测就是这种状态);
            #   b) 当前值指向别处(公司 PAC / 其它工具下发的) -> **保持原样**。
            #      那份地址我们既没备份也无从得知, 删了就永久回不来。
            if not proxy_on():
                log('没有还原备份, 且当前系统代理不是本程序所设 —— 保持原样, 不做任何修改')
                return False, ('当前系统代理不是狐径所设, 也没有找到还原备份 —— '
                               '已保持原样, 没有做任何修改')
            log('没有找到还原备份, 只清掉本程序的 PAC 设置(原值已无从得知)')
            # 审查 M-1: 没有备份时 ProxyEnable / ProxyServer 的原值同样无从得知 ——
            # 按"未知即不动"处理, 这里**显式跳过并写日志**, 而不是顺手清掉:
            # 那会把用户原本的静态代理设置永久抹掉, 再也找不回来。
            for name in ('ProxyEnable', 'ProxyServer'):
                cur = reg_get(REG_INTERNET, name)
                log('没有还原备份: %s=%s 保持原样不动(原值未知, 乱还原比不动更危险)'
                    % (name, '(未设置)' if cur is None else cur))
            saved = {'AutoConfigURL': None, '__no_backup__': True}
        no_backup = bool(saved.get('__no_backup__'))
        reg_set(REG_INTERNET, 'AutoConfigURL', saved.get('AutoConfigURL') or None)
        if no_backup:
            pass            # 上面已经逐项写过日志: 这两项一个字节都不动
        else:
            if saved.get('ProxyServer'):
                reg_set(REG_INTERNET, 'ProxyServer', saved['ProxyServer'])
            if saved.get('ProxyEnable') is not None:
                reg_set(REG_INTERNET, 'ProxyEnable', saved['ProxyEnable'], 4)
        notify_proxy_change()
        log('加速已关闭, 系统代理已还原')
        if no_backup:
            return True, ('已停用: 清掉了本程序写的 PAC；ProxyEnable / ProxyServer '
                          '原值未知, 按"未知即不动"保持原样')
        return True, '已停用, 系统代理已还原'


def _pac_url():
    """本程序写进注册表的 PAC 地址（只此一处定义）。"""
    return 'http://127.0.0.1:%d/pac' % PANEL_PORT


def proxy_on():
    """系统 PAC 是不是**本程序**设的。

    审查 M-8: 以前是子串判断 `'127.0.0.1:8788' in cur` —— 用户原来的 PAC 串里
    只要恰好含这一小段(或别的路径), 就会被误判成"是我们设的"; 退出/还原时
    可能把别人的设置当自己的清掉。现在解析 URL, 按 host:port **精确比较**。
    """
    cur = (reg_get(REG_INTERNET, 'AutoConfigURL') or '').strip()
    if not cur:
        return False
    try:
        u = urllib.parse.urlsplit(cur)
    except Exception:
        return False
    if (u.scheme or '').lower() not in ('http', 'https'):
        return False
    host = (u.hostname or '').lower()
    try:
        port = u.port or (443 if (u.scheme or '').lower() == 'https' else 80)
    except ValueError:
        return False
    return host in ('127.0.0.1', 'localhost') and port == PANEL_PORT


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
    'auto': False,        # 这次升级是不是「按设置自动升的」(面板上要区别显示)
    # 远程 vs 本地的关系与结论(2026-10-09 线上事故后加): 面板照 relation / newer
    # 渲染, 服务端也照它决定放不放行 —— 不再让任何一处拿 remote != local 当"有新版本"。
    'relation': '', 'newer': False, 'block_msg': '',
}

# 静默检查新版本（2026-10-08 加；2026-10-09 改成**默认自动升级**）——
# 老用户不会主动点「检查更新」，所以：启动后立刻看一眼，之后每 12 小时再看一眼。
# 复用的是 read_update_info 的 6 小时缓存，所以基本不打网络。
AUTO_CHECK_INTERVAL = 12 * 3600
_last_auto_check = [0.0]

# ── 默认自动升级（2026-10-09 用户要求：不弹确认框）──────────────────────────
# 行为：启动后静默检查 -> 有新版本就自动下载 -> 校验 SHA256 -> 交小助手替换 -> 重启,
#       全程不打断用户; 面板上只留一行「已自动升级到 vX.Y.Z」; 日志写清每一步。
# 开关：设置里的 auto_update, **默认开**; 关掉就回到「发现新版只提示」的老行为。
# 安全底线（与 H-1 一致, 不许破）:
#   ① sha256 缺失/不符一律拒绝并保留旧版本(_verify_download);
#   ② 覆盖前先把旧 exe 备份成 FoxPath.exe.old(小助手脚本里做);
#   ③ 替换失败仍走原来的递增重试, 最终失败才弹窗提示, 不会把用户搞成没程序可用。
SETTINGS_FILE = os.path.join(DATA_DIR, 'settings.json')
SETTINGS_LOCK = threading.Lock()
AUTO_UPDATE_DEFAULT = True                 # 默认开（用户明确要求）
NOTIFY_DEFAULT = True                      # 升级结果气泡, 默认开（同上）
SETTINGS = {'auto_update': AUTO_UPDATE_DEFAULT, 'notify_bubble': NOTIFY_DEFAULT}
AUTO_UPDATE_MAX_TRIES = 2                  # 同一个版本 24 小时内最多自动试几次
AUTO_UPDATE_TRIES_FILE = os.path.join(DATA_DIR, 'update-tries.json')
UPDATE_DONE_FILE = os.path.join(DATA_DIR, 'update-done.json')
# 升级相关存档(update-done.json / update-result.json)的**格式号**(2026-10-09 加):
# 写的时候带上它 + 写它的程序版本; 读的时候只认自己认识的字段, 不认识的忽略、
# 少了字段用默认值, **绝不因为存档格式报错** —— 升级/回滚时新旧版本互相读对方的
# 存档是常态, 存档不该成为"新版本起不来"的原因。
UPDATE_STATE_SCHEMA = 2
_AUTO_UPGRADED = [None]                    # 本次启动是"刚被升级上来的"就记在这里

# ── 升级结果气泡（2026-10-09 用户要求：升级完成/失败在右下角弹一下）──────────
# 只在**真的有结果**时弹：升级成功弹一次「狐径已自动升级到 vX.Y.Z」；
# 升级失败弹一次人话 + 一句怎么办。**检查到已是最新、或没在升级时绝不弹**。
# 开关：设置里的 notify_bubble, 默认开；关掉就完全不弹（面板那行状态照留）。
# 通知走 Windows 自己的气泡：优先 ctypes + Shell_NotifyIcon(NIF_INFO) —— 隐藏窗口 +
# 消息循环都放在**独立后台线程**里，主流程一步都不等；万一原生那条不成就退回
# 短命 powershell.exe 的 NotifyIcon.ShowBalloonTip（隐藏窗口 + 超时自杀）。
# 铁律：**通知失败绝不能让升级失败** —— 所有异常一律吞掉并写日志。
BUBBLE_WAIT = 7.0                          # 气泡线程最多守多久(秒)，到点自己收摊
BUBBLE_TIP_MS = 6000                       # 气泡停留时间(Windows 有下限, 实际按系统设置)
BUBBLE_DEDUP = 20.0                        # 同一件事 20 秒内只弹一次
UPDATE_RESULT_FILE = os.path.join(DATA_DIR, 'update-result.json')
_LAST_RESULT = [None]                      # 上次升级结果(内存 + 磁盘都给面板看)
_BUBBLE_LOCK = threading.Lock()
_BUBBLE_SEEN = {}                          # 结果 -> 上次弹的时刻(去重)


def ver_tuple(v):
    """把版本号拆成"分段整数"元组: '1.0.10' -> (1, 0, 10)。

    2026-10-09 线上事故后加固(当时本地 1.0.7 对着线上 1.0.6 提示"发现新版本"):
      ① 必须**分段当数字比**, 绝不按字符串比 —— 按字符串 '1.0.10' < '1.0.9' 是错的,
         分段比数字才是 1.0.10 > 1.0.9;
      ② 段里的非数字尾巴(1.0.7-beta / 1.0.7+build)按语义忽略, 不再让 int() 抛异常 ——
         老写法一喂 '1.0.7-beta' 就整串退化成 (0,), 于是"预发布版"比谁都不如;
      ③ 末尾的 0 段削掉, 于是 '1.0' 与 '1.0.0' 相等;
      ④ 空值 / 乱码统一给 (0,), 比大小永不抛异常。
    """
    out = []
    for part in str(v if v is not None else '').strip().lstrip('vV').split('.'):
        m = re.match(r'\s*(\d+)', part)
        out.append(int(m.group(1)) if m else 0)
    while out and out[-1] == 0:
        out.pop()
    return tuple(out) or (0,)


def cmp_ver(a, b):
    """按版本号语义比大小: a>b 返回 1, 相等 0, a<b 返回 -1(1.0.10 > 1.0.9)。"""
    ta, tb = ver_tuple(a), ver_tuple(b)
    n = max(len(ta), len(tb))
    ta = ta + (0,) * (n - len(ta))
    tb = tb + (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


# ── 远程 vs 本地: 三种关系一套措辞(面板 / 日志 / 接口共用, 免得各写各的)─────
VER_NEWER, VER_SAME, VER_OLDER, VER_UNKNOWN = 'newer', 'same', 'older', 'unknown'
VER_OLDER_TEXT = '本地版本比线上新（预发布/开发版本），线上暂未发布'


def ver_relation(remote, local=None):
    """远程版本 vs 本地版本 -> newer / same / older / unknown。"""
    r = str(remote if remote is not None else '').strip()
    if not r:
        return VER_UNKNOWN
    c = cmp_ver(r, APP_VERSION if local is None else local)
    return VER_NEWER if c > 0 else (VER_SAME if c == 0 else VER_OLDER)


def ver_verdict(remote, local=None):
    """一次「检查更新」的结论: (关系, 能不能升级, 面板上那一句人话)。

    ★★ 2026-10-09 线上事故的教训就落在这个函数里(本机装 1.0.7、线上发布的是 1.0.6,
    面板却提示「发现新版本 v1.0.6」, 用户一点「立即升级」真把 1.0.7 换成了 1.0.6):
      · 远程 **严格大于** 本地 -> 才叫「发现新版本」, 才允许升级;
      · 远程 **等于** 本地     -> 「已是最新版」;
      · 远程 **小于** 本地     -> 不提示升级, 直说"本地版本比线上新(预发布/开发版本)",
                                 并且**禁止升级**(服务端也要挡, 见 update_gate)。
    """
    local = APP_VERSION if local is None else str(local)
    rel = ver_relation(remote, local)
    if rel == VER_NEWER:
        return rel, True, '发现新版本 v%s（当前 v%s）' % (remote, local)
    if rel == VER_SAME:
        return rel, False, '已是最新版 v%s' % local
    if rel == VER_OLDER:
        return rel, False, '%s：本地 v%s，线上 v%s' % (VER_OLDER_TEXT, local, remote)
    return rel, False, '暂时读不到线上版本（升级源里没有版本号）'


def update_gate(remote, local=None):
    """升级闸门(纯函数, 单元测试直接调): (放行?, 拒绝原因人话, 要写进日志的那一行)。

    ★ 只把面板按钮置灰是不够的 —— 本机任何程序都能直接 POST /api/update/start。
    所以任何触发升级的入口(面板「立即升级」、启动时的静默自动升级、以后新加的入口)
    都必须先过这里; 拒绝时**写一行日志**, 降级那一档口径固定为
    「拒绝降级：远程 x < 本地 y」。
    """
    local = APP_VERSION if local is None else str(local)
    rel, allow, msg = ver_verdict(remote, local)
    if allow:
        return True, '', ''
    if rel == VER_OLDER:
        return False, msg, '拒绝降级：远程 %s < 本地 %s' % (remote, local)
    if rel == VER_SAME:
        return False, msg, '拒绝升级：远程 %s == 本地 %s（同版本不用升）' % (remote, local)
    return False, msg, '拒绝升级：升级源里没有版本号(远程 %r)' % (remote,)


def _update_set(**kw):
    with UPDATE_LOCK:
        UPDATE.update(kw)


def _update_get():
    with UPDATE_LOCK:
        return dict(UPDATE)


def load_settings():
    """读设置(auto_update / notify_bubble 都默认 True)。读不到就用默认值, 不让设置文件挡住启动。"""
    d = {'auto_update': AUTO_UPDATE_DEFAULT,
         'notify_bubble': NOTIFY_DEFAULT}       # 基准是默认值, 不是当前内存里的值
    try:
        with open(SETTINGS_FILE, encoding='utf-8') as f:
            raw = json.load(f)
        if isinstance(raw, dict):
            # 逐项读: 老版本的 settings.json 里没有 notify_bubble 时,
            # 它保持默认(开) —— 升级上来的用户不用手动去勾
            for k in ('auto_update', 'notify_bubble'):
                if k in raw:
                    d[k] = bool(raw[k])
    except Exception:
        pass
    with SETTINGS_LOCK:
        SETTINGS.update(d)
    return dict(SETTINGS)


def save_settings():
    try:
        with SETTINGS_LOCK:
            data = dict(SETTINGS)
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False)
        return True
    except Exception as e:
        log('保存设置失败: %s' % e)
        return False


def auto_update_on():
    with SETTINGS_LOCK:
        return bool(SETTINGS.get('auto_update', AUTO_UPDATE_DEFAULT))


def set_auto_update(on):
    """开关自动升级, 返回 (ok, 人话)。默认就是开着的。"""
    with SETTINGS_LOCK:
        SETTINGS['auto_update'] = bool(on)
    ok = save_settings()
    if on:
        msg = '已开启自动升级: 以后启动时发现新版本会自动下好并换上新版(不弹确认框)'
    else:
        msg = '已关闭自动升级: 发现新版本只在面板上提示, 点「立即升级」才升级'
    if not ok:
        msg += '(设置没能写进磁盘, 重启后会回到默认值)'
    log(msg)
    return True, msg


def bubble_on():
    """升级结果气泡开着吗(默认开)。关掉就完全不弹, 面板那行状态照样留着。"""
    with SETTINGS_LOCK:
        return bool(SETTINGS.get('notify_bubble', NOTIFY_DEFAULT))


def set_notify_bubble(on):
    """开关升级结果气泡, 返回 (ok, 人话)。默认就是开着的。"""
    with SETTINGS_LOCK:
        SETTINGS['notify_bubble'] = bool(on)
    ok = save_settings()
    if on:
        msg = '已开启升级结果气泡: 升级成功或失败会在右下角弹一下(平时不弹)'
    else:
        msg = '已关闭升级结果气泡: 以后只在面板「上次升级结果」那一行看升级结果'
    if not ok:
        msg += '(设置没能写进磁盘, 重启后会回到默认值)'
    log(msg)
    return True, msg


def _auto_update_guard(remote, url=''):
    """自动升级的护栏, 返回 (能不能自动升, 不能的原因)。

    1. 只有打包成 exe 才自动换文件 —— 源码方式运行时 __file__ 是 .py, 换不得;
    2. 只认 https 升级源 —— 数据目录里的 update_url.txt 是给发版自检用的本地源,
       绝不能让一个本地文件把线上 exe 换掉(本地源的升级演练走的仍是面板上的手动升级);
    3. 同一个版本 24 小时内最多自动试 AUTO_UPDATE_MAX_TRIES 次 —— 万一"下好了却换不上",
       不至于每次开机都重下一遍、来回折腾用户(超过就只提示, 让用户自己点)。
    """
    if not getattr(sys, 'frozen', False):
        return False, '当前是源码方式运行, 不自动替换文件(可在面板上手动升级)'
    if not str(url or '').lower().startswith('https://'):
        return False, '升级源不是 https, 按安全策略不自动升级(可在面板上手动升级)'
    now = time.time()
    rec = {}
    try:
        with open(AUTO_UPDATE_TRIES_FILE, encoding='utf-8') as f:
            rec = json.load(f) or {}
    except Exception:
        rec = {}
    cur = rec.get(str(remote)) or {}
    n = int(cur.get('n') or 0)
    if now - float(cur.get('ts') or 0) > 24 * 3600:
        n = 0                       # 超过 24 小时重新计数
    if n >= AUTO_UPDATE_MAX_TRIES:
        return False, ('v%s 在 24 小时内已经自动试过 %d 次都没成, 先停手不反复折腾'
                       '(可在面板上手动升级)' % (remote, n))
    return True, ''


def _auto_update_mark(remote):
    """记一次自动升级尝试(护栏 3 用)。失败不影响升级本身。"""
    try:
        rec = {}
        try:
            with open(AUTO_UPDATE_TRIES_FILE, encoding='utf-8') as f:
                rec = json.load(f) or {}
        except Exception:
            rec = {}
        cur = rec.get(str(remote)) or {}
        n = int(cur.get('n') or 0)
        if time.time() - float(cur.get('ts') or 0) > 24 * 3600:
            n = 0
        rec[str(remote)] = {'n': n + 1, 'ts': time.time()}
        with open(AUTO_UPDATE_TRIES_FILE, 'w', encoding='utf-8') as f:
            json.dump(rec, f, ensure_ascii=False)
    except Exception:
        pass


def _write_update_done(from_ver, to_ver, auto, silent):
    """把"这次升级从哪来、升到哪、升级前用户是什么状态"留给**新版本**读。

    新实例起来后读它, 就能: ①在面板上留一行「已自动升级到 vX.Y.Z」;
    ②把升级前的系统代理开关接着用, 不因为换了 exe 就把用户的选择重置(不丢状态)。

    ★ 2026-10-09 起: 存档里**带上格式号(schema)与写它的程序版本(app)**。
    升级链路上"新版本写、旧版本读"(比如降级、回滚)是常态, 所以读写两端都要
    向下兼容: 写的多加字段、读的只认认识的字段, 谁都不许因为存档格式摔一跤。
    """
    d = {'schema': UPDATE_STATE_SCHEMA, 'app': str(APP_VERSION),
         'from': str(from_ver), 'to': str(to_ver), 'auto': bool(auto),
         'silent': bool(silent), 'proxy_on': bool(proxy_on()),
         'autostart': bool(autostart_on()), 'ts': time.time()}
    try:
        with open(UPDATE_DONE_FILE, 'w', encoding='utf-8') as f:
            json.dump(d, f, ensure_ascii=False)
    except Exception as e:
        log('升级: 写升级状态文件失败(不影响升级本身): %s' % e)
    return d


def consume_update_done():
    """启动时读一次: 上一次升级到底成没成。返回 dict 或 None。

    读法按"向下兼容"来(2026-10-09 起): 只认自己认识的字段, 多了少了都不报错;
    存档里的 schema 比本程序认识的更新时, 也只写一行日志后照读认识的字段。
    """
    try:
        with open(UPDATE_DONE_FILE, encoding='utf-8') as f:
            d = json.load(f)
    except Exception:
        return None
    try:
        os.remove(UPDATE_DONE_FILE)
    except Exception:
        pass
    if not isinstance(d, dict):
        return None
    sch = d.get('schema')
    if isinstance(sch, int) and sch > UPDATE_STATE_SCHEMA:
        log('上次升级的存档格式是 v%d(比本程序认识的 v%d 新), 只读认识的字段, 不影响使用'
            % (sch, UPDATE_STATE_SCHEMA))
    to = str(d.get('to') or '')
    if to and to == APP_VERSION:
        _AUTO_UPGRADED[0] = {'to': to, 'from': str(d.get('from') or ''),
                             'auto': bool(d.get('auto'))}
        log('已%s升级到 v%s (原 v%s); 旧版本已备份为 FoxPath.exe.old'
            % ('自动' if d.get('auto') else '手动', to, d.get('from') or '?'))
    else:
        _AUTO_UPGRADED[0] = None
        log('上次升级到 v%s 没有生效(当前仍是 v%s), 已保留旧版本; 可在面板上重试'
            % (to or '?', APP_VERSION))
    return d


def upgraded_text():
    """面板上那一行状态: 「已自动升级到 v1.0.7（原 v1.0.6）」; 没升级过就是空串。"""
    d = _AUTO_UPGRADED[0]
    if not d:
        return ''
    return ('已%s升级到 v%s（原 v%s）'
            % ('自动' if d.get('auto') else '手动', d.get('to') or '?',
               d.get('from') or '?'))


# ── 上一次升级结果（面板「上次升级结果」那一行靠它, 不只靠气泡）──────────────
# 用户 2026-10-09 要求: 「面板里也留一行状态」—— 气泡看一眼就没了, 面板要能回看,
# 所以结果同时落盘(update-result.json), 重启后那一行还在。
RESULT_REASONS = {
    'nosha': '升级源没有提供校验值',
    'sha': '安装包校验没通过',
    'size': '安装包大小不对',
    'net': '下载没成功',
    'helper': '没能启动升级小助手',
    'no_info': '升级信息里没有下载地址',
    'noeffect': '重启后还是旧版本',
    # 2026-10-09 加: ①升级源版本不高于本地, 服务端直接拒绝; ②新版本起不来, 小助手回滚
    'downgrade': '线上版本不高于本地版本（已拒绝执行）',
    'rollback': '新版本没起来，已自动回滚到升级前的旧版本',
}


def _human_reason(code, msg=''):
    """把内部错误码换成一句人话; 认不出来就把原始说明截短(别把异常原文甩给用户)。"""
    why = RESULT_REASONS.get(str(code or '').strip())
    if why:
        return why
    s = ' '.join(str(msg or '').split())
    return s[:40] if s else '原因见日志'


def _write_update_result(ok, auto=False, from_ver='', to_ver='', why='', note=''):
    """把上一次升级结果落盘(面板要显示「成功/失败 + 时间」)。

    写不进去只写日志, 不影响升级本身 —— 跟气泡一样, 附属功能不许拖累主线。
    """
    d = {'schema': UPDATE_STATE_SCHEMA, 'app': str(APP_VERSION),
         'ok': bool(ok), 'auto': bool(auto), 'from': str(from_ver or ''),
         'to': str(to_ver or ''), 'why': str(why or ''), 'note': str(note or ''),
         'ts': time.time()}
    _LAST_RESULT[0] = d
    try:
        with open(UPDATE_RESULT_FILE, 'w', encoding='utf-8') as f:
            json.dump(d, f, ensure_ascii=False)
    except Exception as e:
        log('升级: 写升级结果文件失败(不影响升级本身): %s' % e)
    return d


def load_update_result():
    """启动时读一次上次的升级结果(给面板那一行用)。读不到就算了, 不挡启动。"""
    try:
        with open(UPDATE_RESULT_FILE, encoding='utf-8') as f:
            d = json.load(f)
        if isinstance(d, dict) and 'ok' in d:
            _LAST_RESULT[0] = d
    except Exception:
        pass
    return _LAST_RESULT[0]


def last_result_text():
    """面板「更新」卡片里那一行: 上次升级结果(成功/失败 + 时间 + 一句怎么办)。"""
    d = _LAST_RESULT[0]
    if not d:
        return ''
    try:
        when = time.strftime('%m-%d %H:%M',
                             time.localtime(float(d.get('ts') or 0)))
    except Exception:
        when = '--'
    who = '自动' if d.get('auto') else '手动'
    if d.get('ok'):
        to = str(d.get('to') or APP_VERSION)
        fr = str(d.get('from') or '')
        return ('上次升级结果：成功 · %s　已%s升级到 v%s%s'
                % (when, who, to, ('（原 v%s）' % fr) if fr else ''))
    return ('上次升级结果：失败 · %s　%s升级没有完成：%s；已保留旧版本 v%s，'
            '可点上面「立即升级」重试'
            % (when, who, _human_reason(d.get('why'), d.get('note')), APP_VERSION))


def _bubble_texts(ok, auto, to_ver='', why=''):
    """气泡的标题与正文。正文就是用户要看到的那一句人话(几秒后自己消失)。"""
    who = '自动' if auto else '手动'
    if ok:
        if auto:
            text = '狐径已自动升级到 v%s' % (to_ver or APP_VERSION)
        else:
            text = '狐径已升级到 v%s' % (to_ver or APP_VERSION)
        return ('狐径 升级完成', text)
    if str(why) == 'noeffect':
        head = '%s升级没有生效（重启后还是 v%s）' % (who, APP_VERSION)
    else:
        head = '%s升级失败（%s）' % (who, _human_reason(why))
    return ('狐径 升级没有完成',
            '%s，已保留旧版本；可打开面板点「立即升级」重试' % head)


# ── 气泡引擎 ①: Windows 自己的通知气泡(首选)────────────────────────────────
# Shell_NotifyIcon(NIM_ADD + NIM_MODIFY/NIF_INFO) 就是系统原生的右下角气泡:
# 不需要托盘常驻、不需要第三方库、也不会弹一个窗口出来抢焦点。
# 代价是得先有一个窗口(哪怕是隐藏的)和一小段消息循环 —— 这两样都放在**调用它的
# 那个后台线程**里, 主流程一步都不等它; 到点 NIM_DELETE 收摊, 通知区不留图标。
_NIM_ADD, _NIM_MODIFY, _NIM_DELETE = 0, 1, 2
_NIF_ICON, _NIF_TIP, _NIF_INFO = 0x02, 0x04, 0x10
_NIIF_INFO = 0x01
_WM_CLOSE, _WM_DESTROY = 0x0010, 0x0002
_PM_REMOVE = 0x0001
_IDI_INFORMATION = 32516                   # MAKEINTRESOURCE(IDI_INFORMATION)


class _GUID(ctypes.Structure):
    _fields_ = [('Data1', ctypes.c_ulong), ('Data2', ctypes.c_ushort),
                ('Data3', ctypes.c_ushort), ('Data4', ctypes.c_ubyte * 8)]


class _NOTIFYICONDATAW(ctypes.Structure):
    """NOTIFYICONDATAW(Vista 以后那版, cbSize 用整个结构体大小)。

    x64 上 sizeof=976, 各字段偏移与 Windows SDK 一致(自测里逐项断言过) ——
    这种结构体错一个字节就会"什么都没发生", 所以必须钉死。
    """
    _fields_ = [
        ('cbSize', wintypes.DWORD), ('hWnd', wintypes.HWND),
        ('uID', wintypes.UINT), ('uFlags', wintypes.UINT),
        ('uCallbackMessage', wintypes.UINT), ('hIcon', wintypes.HANDLE),
        ('szTip', ctypes.c_wchar * 128),
        ('dwState', wintypes.DWORD), ('dwStateMask', wintypes.DWORD),
        ('szInfo', ctypes.c_wchar * 256), ('uTimeout', wintypes.UINT),
        ('szInfoTitle', ctypes.c_wchar * 64), ('dwInfoFlags', wintypes.DWORD),
        ('guidItem', _GUID), ('hBalloonIcon', wintypes.HANDLE)]


class _WNDCLASSEXW(ctypes.Structure):
    _fields_ = [
        ('cbSize', wintypes.UINT), ('style', wintypes.UINT),
        ('lpfnWndProc', ctypes.c_void_p), ('cbClsExtra', ctypes.c_int),
        ('cbWndExtra', ctypes.c_int), ('hInstance', wintypes.HINSTANCE),
        ('hIcon', wintypes.HANDLE), ('hCursor', wintypes.HANDLE),
        ('hbrBackground', wintypes.HANDLE), ('lpszMenuName', wintypes.LPCWSTR),
        ('lpszClassName', wintypes.LPCWSTR), ('hIconSm', wintypes.HANDLE)]


def _bubble_native(title, text, timeout_ms=BUBBLE_TIP_MS):
    """用系统自己的通知气泡弹一下。弹出来了返回 True, 没成就返回 False。

    只在这个线程里干活: 建隐藏窗口 -> 把图标加进通知区 -> NIF_INFO 弹出气泡 ->
    跑消息循环守着 -> 到点删图标。窗口不带可见样式(dwStyle=0), 所以屏幕上不出现
    任何窗口, 也不抢焦点; 不要求用户点击, 几秒后自己消失。
    """
    if os.name != 'nt':
        return False
    user32 = ctypes.WinDLL('user32', use_last_error=True)
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    shell32 = ctypes.WinDLL('shell32', use_last_error=True)
    # 指针宽度的返回值必须显式声明 restype, 否则 64 位下会被截成 int
    user32.DefWindowProcW.restype = ctypes.c_ssize_t
    user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT,
                                      wintypes.WPARAM, wintypes.LPARAM]
    user32.CreateWindowExW.restype = wintypes.HWND
    user32.CreateWindowExW.argtypes = [
        wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
        ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
        wintypes.HWND, wintypes.HANDLE, wintypes.HINSTANCE, ctypes.c_void_p]
    user32.RegisterClassExW.restype = wintypes.ATOM
    user32.RegisterClassExW.argtypes = [ctypes.POINTER(_WNDCLASSEXW)]
    user32.UnregisterClassW.restype = wintypes.BOOL
    user32.UnregisterClassW.argtypes = [wintypes.LPCWSTR, wintypes.HINSTANCE]
    user32.LoadIconW.restype = wintypes.HANDLE
    user32.LoadIconW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR]
    user32.PeekMessageW.restype = wintypes.BOOL
    user32.PeekMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND,
                                    wintypes.UINT, wintypes.UINT, wintypes.UINT]
    user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
    user32.DispatchMessageW.restype = ctypes.c_ssize_t
    user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
    user32.DestroyWindow.argtypes = [wintypes.HWND]
    kernel32.GetModuleHandleW.restype = wintypes.HMODULE
    kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    shell32.Shell_NotifyIconW.restype = wintypes.BOOL
    shell32.Shell_NotifyIconW.argtypes = [wintypes.DWORD,
                                          ctypes.POINTER(_NOTIFYICONDATAW)]

    hinst = kernel32.GetModuleHandleW(None)
    cls = 'FoxPathBubble_%d_%d' % (os.getpid(), threading.get_ident())

    @ctypes.WINFUNCTYPE(ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT,
                        wintypes.WPARAM, wintypes.LPARAM)
    def _proc(hwnd, msg, wp, lp):
        if msg == _WM_CLOSE:
            user32.DestroyWindow(hwnd)
        elif msg == _WM_DESTROY:
            user32.PostQuitMessage(0)
        return user32.DefWindowProcW(hwnd, msg, wp, lp)

    wc = _WNDCLASSEXW()
    wc.cbSize = ctypes.sizeof(_WNDCLASSEXW)
    wc.lpfnWndProc = ctypes.cast(_proc, ctypes.c_void_p)
    wc.hInstance = hinst
    wc.lpszClassName = cls
    if not user32.RegisterClassExW(ctypes.byref(wc)):
        return False
    hwnd = None
    added = False
    nid = _NOTIFYICONDATAW()
    nid.cbSize = ctypes.sizeof(_NOTIFYICONDATAW)
    nid.uID = 1
    try:
        hwnd = user32.CreateWindowExW(0, cls, APP_NAME, 0, 0, 0, 0, 0,
                                      None, None, hinst, None)
        if not hwnd:
            return False
        nid.hWnd = hwnd
        nid.uFlags = _NIF_ICON | _NIF_TIP
        nid.hIcon = user32.LoadIconW(None, ctypes.c_wchar_p(_IDI_INFORMATION))
        nid.szTip = APP_NAME
        if not shell32.Shell_NotifyIconW(_NIM_ADD, ctypes.byref(nid)):
            return False
        added = True
        # 官方写法: 气泡不能用 NIM_ADD 一次带上, 必须 NIM_ADD 之后再 NIM_MODIFY
        nid.uFlags = _NIF_INFO
        nid.uTimeout = int(timeout_ms)
        nid.szInfoTitle = str(title)[:63]
        nid.szInfo = str(text)[:255]
        nid.dwInfoFlags = _NIIF_INFO
        if not shell32.Shell_NotifyIconW(_NIM_MODIFY, ctypes.byref(nid)):
            return False
        # 消息循环: 只为把"气泡被点了/超时了"这类回话收进来。用 PeekMessage
        # 而不是 GetMessage —— 到点能自己收摊, 不会卡死在这条线程里。
        end = time.time() + BUBBLE_WAIT
        msg = wintypes.MSG()
        while time.time() < end:
            while user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, _PM_REMOVE):
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
            time.sleep(0.05)
        return True
    finally:
        if added:
            try:
                shell32.Shell_NotifyIconW(_NIM_DELETE, ctypes.byref(nid))
            except Exception:
                pass
        if hwnd:
            try:
                user32.DestroyWindow(hwnd)
            except Exception:
                pass
        try:
            user32.UnregisterClassW(cls, hinst)
        except Exception:
            pass


# ── 气泡引擎 ②: 短命 powershell.exe 兜底(原生那条不成时才走)───────────────
# 三个要点, 缺一个就出问题:
#   ① CREATE_NO_WINDOW —— 不然会闪一个黑框(绝对不行);
#   ② 脚本用 -EncodedCommand(UTF-16LE + base64)传 —— 中文不受控制台代码页影响;
#   ③ 脚本自己跑 DoEvents 消息循环、到点 Dispose 退出 —— 不留后台进程、不要求点击。
# 标题/正文走环境变量(Windows 的环境块本身是 UTF-16, 中文安全)。
_PS_BUBBLE = r'''
$ErrorActionPreference = 'Stop'
try {
  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing
  $ni = New-Object System.Windows.Forms.NotifyIcon
  $ni.Icon = [System.Drawing.SystemIcons]::Information
  $ni.BalloonTipTitle = [string]$env:FOXPATH_BUBBLE_TITLE
  $ni.BalloonTipText  = [string]$env:FOXPATH_BUBBLE_TEXT
  $ni.Visible = $true
  [void]$ni.ShowBalloonTip(6000)
  $end = (Get-Date).AddSeconds(7)
  while ((Get-Date) -lt $end) {
    [System.Windows.Forms.Application]::DoEvents()
    Start-Sleep -Milliseconds 100
  }
} finally {
  if ($ni) { try { $ni.Visible = $false; $ni.Dispose() } catch {} }
}
'''


def _bubble_powershell(title, text):
    """退路: 起一个短命 powershell.exe, 用 NotifyIcon.ShowBalloonTip 弹一下。

    跑完自己退出(脚本里 7 秒到点), 这里在**后台线程**里等它, 主流程一点也不等。
    """
    import base64
    import subprocess
    ps = os.path.join(os.environ.get('SystemRoot') or r'C:\Windows',
                      'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
    if not os.path.isfile(ps):
        ps = 'powershell.exe'              # 系统装得特殊就交给 PATH, 不硬撑
    env = dict(os.environ)
    env['FOXPATH_BUBBLE_TITLE'] = str(title)
    env['FOXPATH_BUBBLE_TEXT'] = str(text)
    enc = base64.b64encode(_PS_BUBBLE.encode('utf-16-le')).decode('ascii')
    flags = 0x08000000 if os.name == 'nt' else 0     # CREATE_NO_WINDOW
    devnull = open(os.devnull, 'wb')
    try:
        p = subprocess.Popen([ps, '-NoProfile', '-NonInteractive',
                              '-WindowStyle', 'Hidden', '-EncodedCommand', enc],
                             creationflags=flags, stdin=devnull, stdout=devnull,
                             stderr=devnull, close_fds=True, env=env)
    finally:
        devnull.close()
    try:
        p.wait(timeout=20)
    except Exception:
        try:
            p.kill()
        except Exception:
            pass
    return True


def _bubble_worker(title, text):
    """气泡线程: 先试系统原生, 不成再退回短命 powershell。全程只写日志, 绝不外抛。"""
    try:
        if _bubble_native(title, text):
            return
        log('升级结果气泡: 系统原生通知没能弹出, 退回短命 PowerShell 通知')
    except Exception as e:
        log('升级结果气泡: 系统原生通知出错(改用 PowerShell 兜底): %s' % e)
    try:
        if not _bubble_powershell(title, text):
            log('升级结果气泡: 两种方式都没弹出通知(不影响升级本身)')
    except Exception as e:
        log('升级结果气泡: PowerShell 通知也出错了(不影响升级本身): %s' % e)


def _spawn_bubble(title, text):
    """把气泡丢进后台线程: 主流程一步都不等它(通知慢/卡都不影响升级)。"""
    t = threading.Thread(target=_bubble_worker, args=(title, text), daemon=True)
    t.start()
    return t


def report_update_result(ok, auto=False, from_ver='', to_ver='', why='', note=''):
    """升级有结果了: ①结果落盘(面板那一行); ②按开关弹一次气泡。

    ok=True 是"换上新版、并且新实例已经起来了"; ok=False 是任意一种没成的情况。
    **绝不抛异常** —— 它是升级流程的尾巴, 不许反过来把升级搞失败。
    """
    try:
        _write_update_result(ok, auto=auto, from_ver=from_ver, to_ver=to_ver,
                             why=why, note=note)
        log('升级结果: %s%s%s' % ('成功' if ok else '失败',
                                  (' -> v%s' % to_ver) if (ok and to_ver) else '',
                                  '' if ok else ' (%s)' % _human_reason(why, note)))
        if not bubble_on():
            log('升级结果气泡: 已按设置关闭, 本次不弹(面板那行状态照留)')
            return False
        key = (bool(ok), str(to_ver or ''), str(why or ''))
        now = time.time()
        with _BUBBLE_LOCK:
            if now - _BUBBLE_SEEN.get(key, 0.0) < BUBBLE_DEDUP:
                return False                # 同一件事短时间内只弹一次
            _BUBBLE_SEEN[key] = now
        title, text = _bubble_texts(ok, auto, to_ver, why)
        _spawn_bubble(title, text)
        return True
    except Exception as e:
        try:
            log('升级结果气泡: 出错了(不影响升级本身): %s' % e)
        except Exception:
            pass
        return False


def report_prev_update(prev):
    """启动时把"上一次升级到底成没成"报一次(面板那行 + 一次气泡)。

    prev 是 consume_update_done() 的返回值; 没升级过就是 None, 此时什么都不做 ——
    「平时绝不弹」这条就落在这一句上。
    """
    if not prev:
        return None
    ok = bool(_AUTO_UPGRADED[0])
    # 小助手已经写过一条「已自动回滚」时, 不要用泛泛的「重启后还是旧版本」把它盖掉 ——
    # 回滚是它实际做的事, 说清楚了用户才知道自己没被升坏(2026-10-09 加)。
    prev_res = _LAST_RESULT[0] or {}
    if (not ok) and str(prev_res.get('why') or '') == 'rollback':
        log('上次升级是小助手回滚掉的, 面板/气泡保留「已自动回滚」这条说明')
        return report_update_result(
            False, auto=bool(prev.get('auto')),
            from_ver=str(prev_res.get('from') or prev.get('from') or ''),
            to_ver=str(prev_res.get('to') or prev.get('to') or ''),
            why='rollback', note=str(prev_res.get('note') or ''))
    return report_update_result(
        ok, auto=bool(prev.get('auto')),
        from_ver=str(prev.get('from') or ''),
        to_ver=(APP_VERSION if ok else str(prev.get('to') or '')),
        why=('' if ok else 'noeffect'))


def _start_update(auto=False):
    """起一个升级线程; 返回 (有没有起来, 一句人话)。

    auto=True 是默认自动升级那条路, auto=False 是用户在面板上点「立即升级」。

    ★★ 闸门就设在这里(2026-10-09 线上事故后): 不管从哪个入口进来, 只要升级源里的
    版本**不高于**本地版本, 一律拒绝执行并写日志。前端把「立即升级」置灰只是提示,
    真正的门必须在服务端 —— 本机任何程序都能直接 POST /api/update/start。
    """
    info = read_update_info()
    remote = str((info or {}).get('version') or '') or str(UPDATE.get('remote') or '')
    rel = ver_relation(remote, APP_VERSION)
    allow, why, logline = update_gate(remote, APP_VERSION)
    if not allow:
        _update_set(phase='idle', error='', remote=remote, relation=rel, newer=False,
                    block_msg=why, msg=why)
        if logline:
            log(logline)
        if auto:
            log('自动升级: %s' % why)
        return False, why
    with UPDATE_LOCK:
        if UPDATE.get('phase') in ('downloading', 'verifying', 'applying'):
            return False, '已经在升级了，不用重复点'
        UPDATE['phase'] = 'downloading'
        UPDATE['got'] = 0
        UPDATE['pct'] = 0
        UPDATE['error'] = ''
        UPDATE['auto'] = bool(auto)
        UPDATE['msg'] = '正在下载新版本'
        UPDATE['remote'] = remote
        UPDATE['relation'] = rel
        UPDATE['newer'] = True
        UPDATE['block_msg'] = ''
    threading.Thread(target=apply_update_async, kwargs={'auto': bool(auto)},
                     daemon=True).start()
    return True, '正在下载新版本'


load_settings()          # 启动即生效: 默认 auto_update=True, notify_bubble=True
load_update_result()     # 上次升级结果(面板那一行要用; 读不到就算了, 不挡启动)


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
    # 正在下载/校验/覆盖时不要插一脚: 以前这里会把 phase 改回 idle,
    # 面板的「立即升级」就可能在升级进行中再起一个线程。
    if UPDATE.get('phase') in ('downloading', 'verifying', 'applying'):
        return _update_get()
    _update_set(phase='checking', msg='正在检查升级源…', error='')
    info = read_update_info()
    if not info:
        _update_set(phase='failed', error='net', msg='连不上升级源(或还没发布升级信息)')
        return _update_get()
    node = update_exe_node(info) or {}
    remote = str(info.get('version') or '')
    # ★ 结论只按版本号语义下(2026-10-09 线上事故): 只有**远程严格大于本地**才是
    # 「发现新版本」。面板拿 relation / newer 两个字段渲染, 不再自己比字符串。
    rel, newer, msg = ver_verdict(remote, APP_VERSION)
    _update_set(local=APP_VERSION, remote=remote, notes=str(info.get('notes') or ''),
                phase='idle', exe_url=node.get('url', ''), exe_sha=str(node.get('sha256') or '').upper(),
                total=int(node.get('size') or 0),
                relation=rel, newer=bool(newer),
                block_msg=('' if newer else msg),
                msg=('有新版本 v' + remote + ' 可以升级') if newer else msg)
    if rel == VER_OLDER:
        log('检查更新: 本地 v%s 比线上 v%s 新（预发布/开发版本），不提示升级、也不允许升级'
            % (APP_VERSION, remote))
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


# ── 升级交接的环境卫生(★★ 2026-10-09 真机事故的真因, 详见 clean_pyi_env)────────
PYI_ENV_PREFIXES = ('_PYI_',)
PYI_ENV_NAMES = ('_MEIPASS', '_MEIPASS2')


def clean_pyi_env(env=None):
    """返回一份**去掉 PyInstaller 记账变量**的环境(不传就基于 os.environ 复制)。

    ★★ 2026-10-09 真机事故的真因(用实验钉死的, 见 logs\\升级护栏-20261009.md 第 3 节):
    PyInstaller 单文件 exe 的引导程序会给它的 Python 子进程塞
    `_PYI_PARENT_PROCESS_LEVEL` / `_PYI_APPLICATION_HOME_DIR` / `_PYI_ARCHIVE_FILE` / `_MEIPASS*`。
    这些变量会被**主程序启的每一个子进程**继承 —— 包括升级小助手; 小助手再去启动"新版本"时,
    新版的引导程序一看到 `_PYI_PARENT_PROCESS_LEVEL` 就认为"我是子进程、已经解过包了",
    于是**跳过解包**、去找那个早已随旧实例退出被删掉的解包目录, 结果是:
    应用一行日志都不写、端口不监听、只弹一个标题为 `Error` 的引导程序模态框 ——
    真机上就是这么连续两次起不来的(而用户手工双击没有这些变量, 所以能起来)。
    """
    src = dict(os.environ if env is None else env)
    for k in list(src):
        if k.startswith(PYI_ENV_PREFIXES) or k in PYI_ENV_NAMES:
            src.pop(k, None)
    return src


def _spawn_helper(exe, new, ver, silent=False):
    """独立小助手(PowerShell, UTF-8 带 BOM): 等本进程退出 -> 备份旧版 -> 覆盖 -> 再启动。
    不用 .cmd —— cmd.exe 按控制台代码页读 .cmd, 中文路径会变问号(壁纸助手那边实测过)。

    silent: 原来是不是静默模式(开机自启)。升级后按原样启动, 不因为换了 exe 就
    突然给用户弹一个浏览器窗口。
    """
    import subprocess
    # 2026-10-10: 版本号来自升级源 version.json，是**外部输入**，而且是这个函数里唯一
    # 没走 q() 转义的变量（见下面 $newver）。真被塞进单引号会让整个助手脚本语法错误，
    # 于是备份/覆盖/重试/三重兜底/回滚一行都跑不到，用户侧只看到"点了升级没反应"，
    # 还会把 .new 留在 exe 旁边。这里先按字符集卡死，不合法直接拒绝（fail-closed）。
    _v = str(ver)
    if not (_v and _v.isascii() and all(c.isalnum() or c in '.+-' for c in _v)):
        log('拒绝升级: 升级源里的版本号含非法字符 %r' % (ver,))
        return False
    # 审查 M-15: 助手脚本改成**一次性随机名** —— 固定叫 update-apply.ps1 时,
    # 数据目录里任何一个同用户程序都能提前把它替换掉。脚本跑完会删掉自己(见末尾)。
    helper = os.path.join(DATA_DIR, 'update-apply-%s.ps1' % uuid.uuid4().hex[:8])
    logf = os.path.join(DATA_DIR, 'update.log')
    q = lambda s: "'" + str(s).replace("'", "''") + "'"
    lines = [
        "$ErrorActionPreference = 'Continue'",
        '$exe = ' + q(exe),
        '$new = ' + q(new),
        '$log = ' + q(logf),
        "$newver = " + q(ver),
        "$silent = " + ('$true' if silent else '$false'),
        "$args0 = " + ("'--silent'" if silent else "''"),
        "# ★★ 先把自己环境里的 PyInstaller 记账变量删干净, 再启动任何狐径 exe(2026-10-09 真机事故):",
        "# 单文件 exe 的引导程序会给它的 Python 子进程塞 _PYI_PARENT_PROCESS_LEVEL /",
        "# _PYI_APPLICATION_HOME_DIR / _PYI_ARCHIVE_FILE / _MEIPASS*; 这些变量会被小助手继承,",
        "# 于是小助手启动的新版本一看到 _PYI_PARENT_PROCESS_LEVEL 就以为「我是子进程、已经解过包了」,",
        "# **跳过解包**去找那个早就被删掉的旧解包目录 -> 起不来(只弹一个标题为 Error 的框,",
        "# 应用一行代码都跑不到)。手工双击没有这些变量, 所以能起来 —— 这就是真机那次连续两次没起来的真因。",
        "foreach ($n in '_PYI_PARENT_PROCESS_LEVEL','_PYI_APPLICATION_HOME_DIR','_PYI_ARCHIVE_FILE','_PYI_SPLASH_IPC','_MEIPASS','_MEIPASS2') {",
        "  try { Remove-Item -LiteralPath ('Env:' + $n) -ErrorAction SilentlyContinue } catch {}",
        "}",
        "function W($m) { try { Add-Content -LiteralPath $log -Value ('[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] ' + $m) -Encoding UTF8 } catch {} }",
        "function Panel {",
        "  # 面板有没有人应答(不区分新旧实例; 判「新版本起来了」请用 Ver/WaitVer)",
        "  try { $r = Invoke-WebRequest 'http://127.0.0.1:" + str(PANEL_PORT) + "/api/status' -TimeoutSec 2 -UseBasicParsing",
        "        return ($r.StatusCode -eq 200) } catch { return $false }",
        "}",
        "function Ver {",
        "  # 现在应答的那个实例**自己的版本号**: /api/update/status 的 local 字段",
        "  # (1.0.5 起就有这个字段), 拿不到再退回 /api/status 的 version 字段。",
        "  try { $r = Invoke-WebRequest 'http://127.0.0.1:" + str(PANEL_PORT) + "/api/update/status' -TimeoutSec 2 -UseBasicParsing",
        "        $j = $r.Content | ConvertFrom-Json; if ($j.local) { return [string]$j.local } } catch {}",
        "  try { $r2 = Invoke-WebRequest 'http://127.0.0.1:" + str(PANEL_PORT) + "/api/status' -TimeoutSec 2 -UseBasicParsing",
        "        $j2 = $r2.Content | ConvertFrom-Json; if ($j2.version) { return [string]$j2.version } } catch {}",
        "  return ''",
        "}",
        "function WaitVer {",
        "  # ★★ 2026-10-09 线上事故的核心加固: 判「新版本起没起来」必须**按版本号认**, 不能",
        "  # 只看面板通不通 —— 当时用户手动把旧版 1.0.7 起回来, 面板一应答, 小助手就宣布",
        "  # 「新版本已起来」, 于是该重试的不重试、该回滚的不回滚, 用户手里还是旧版本。",
        "  # 返回等到的版本号; 等到 $Want 才算成功, 超时返回空串。",
        "  param([string]$Want, [int]$Sec)",
        "  $deadline = (Get-Date).AddSeconds($Sec)",
        "  while ((Get-Date) -lt $deadline) {",
        "    $v = Ver",
        "    if ($v -and ($v -eq $Want)) { return $v }",
        "    Start-Sleep -Milliseconds 500",
        "  }",
        "  $v = Ver",
        "  if ($v -and ($v -eq $Want)) { return $v }",
        "  return ''",
        "}",
        "function AnyVer {",
        "  # 回滚后用它确认「旧版本真的起来了」: 只要有人应答, 就把它自己的版本号报回来。",
        "  param([int]$Sec)",
        "  $deadline = (Get-Date).AddSeconds($Sec)",
        "  while ((Get-Date) -lt $deadline) {",
        "    $v = Ver",
        "    if ($v) { return $v }",
        "    Start-Sleep -Milliseconds 500",
        "  }",
        "  $v = Ver",
        "  if ($v) { return $v }",
        "  return ''",
        "}",
        "function Balloon($title, $text) {",
        "  # 非模态气泡: 看一眼就消失, **绝不弹模态框** —— 升级链路上任何模态框都会把",
        "  # 交接后的启动挂住(2026-10-09 线上事故), 提示宁可轻一点也不能挂住程序。",
        "  try {",
        "    Add-Type -AssemblyName System.Windows.Forms | Out-Null",
        "    Add-Type -AssemblyName System.Drawing | Out-Null",
        "    $ni = New-Object System.Windows.Forms.NotifyIcon",
        "    $ni.Icon = [System.Drawing.SystemIcons]::Information",
        "    $ni.BalloonTipTitle = [string]$title",
        "    $ni.BalloonTipText = [string]$text",
        "    $ni.Visible = $true",
        "    $ni.ShowBalloonTip(8000)",
        "    Start-Sleep -Seconds 8",
        "    $ni.Dispose()",
        "  } catch { W ('气泡没弹出来(不影响别的): ' + $_.Exception.Message) }",
        "}",
        "function WriteResult($why, $note) {",
        "  # 把这次失败落盘成 update-result.json(格式与主程序一致, 带 schema 与版本号):",
        "  # 回滚后起来的旧版本一读, 面板上就会出现「上次升级结果：失败 · … 已保留旧版本」。",
        "  try {",
        "    $sec = [int][double]::Parse((Get-Date -UFormat %s))",
        "    $j = '{\"schema\":2,\"app\":\"' + $oldver + '\",\"ok\":false,\"auto\":false,\"from\":\"' + $oldver + '\",\"to\":\"' + $newver + '\",\"why\":\"' + $why + '\",\"note\":\"' + $note + '\",\"ts\":' + $sec + '}'",
        "    $rp = Join-Path (Split-Path -Parent $log) 'update-result.json'",
        "    [System.IO.File]::WriteAllText($rp, $j, (New-Object System.Text.UTF8Encoding($false)))",
        "  } catch { W ('写升级结果文件失败(不影响别的): ' + $_.Exception.Message) }",
        "}",
        "# 先把**当前正在跑的版本号**记下来(回滚要用它报账), 这时旧实例还活着。",
        "$oldver = ''",
        "try { $oldver = (AnyVer 5) } catch {}",
        "W ('开始覆盖主程序 (新版本 v" + str(ver) + ", 升级前跑的是 v' + $oldver + ')')",
        "Start-Sleep -Seconds 2",
        "try { Invoke-WebRequest 'http://127.0.0.1:" + str(PANEL_PORT) + "/api/quit' -Method POST -TimeoutSec 8 -UseBasicParsing | Out-Null } catch { W ('调 /api/quit 出错: ' + $_.Exception.Message) }",
        "# 审查 M-5: 判断旧进程还在不在, 不能再用 Get-Process -Name —— 中文 exe 名的",
        "# ProcessName 匹配不可靠(改名后就认不出来了)。改成按**可执行文件完整路径**匹配:",
        "# Get-CimInstance Win32_Process 拿 ExecutablePath, 中文路径也照配不误。",
        "function Find-Same {",
        "  param([string]$ExePath)",
        "  $full = ''",
        "  try { $full = [System.IO.Path]::GetFullPath($ExePath) } catch { return @() }",
        "  $hit = @()",
        "  try { $hit = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { $_.ExecutablePath -and ([System.IO.Path]::GetFullPath($_.ExecutablePath) -ieq $full) }) } catch { $hit = @() }",
        "  if (@($hit).Count -eq 0) {",
        "    try { $hit = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and ([System.IO.Path]::GetFullPath($_.Path) -ieq $full) }) } catch { $hit = @() }",
        "  }",
        "  return @($hit)",
        "}",
        "$n = 0",
        "while ($n -lt 90) { if (@(Find-Same $exe).Count -eq 0) { break }; Start-Sleep -Seconds 1; $n++ }",
        "W ('进程已退出, 等了 ' + $n + ' 秒')",
        "# 覆盖之前先把旧版本留一份(exe 同级的 .old): 换坏了还能人工回退",
        "try { Copy-Item -LiteralPath $exe -Destination ($exe + '.old') -Force; W ('已备份旧版本 -> ' + $exe + '.old') } catch { W ('备份旧版本失败(继续覆盖): ' + $_.Exception.Message) }",
        "try { Move-Item -LiteralPath $new -Destination $exe -Force; W '已覆盖主程序' } catch { W ('覆盖失败: ' + $_.Exception.Message) }",
        "# 覆盖后先等 3 秒(让杀软把新文件扫完, 也等行业务句柄彻底放开)。",
        "# 注: 2026-10-08 那次'刚覆盖就启动会报 Failed to load Python DLL'曾被记成'被火绒拦了', ",
        "# 2026-10-09 查清了 —— 真因是小助手继承了 PyInstaller 的 _PYI_* 变量(见脚本开头),",
        "# 与杀软无关; 这句等待留着无害, 但别再拿它当解释。",
        "Start-Sleep -Seconds 3",
        "# 关键一步: 确认旧实例真的退干净了(看板不通), 否则新实例的版本号可能读成旧的,",
        "# WaitVer 会一直等不到自己的版本号。",
        "$d = 0",
        "while ($d -lt 30) { if (-not (Panel)) { break }; Start-Sleep -Seconds 1; $d++ }",
        "W ('旧实例已停 (等了 ' + $d + ' 秒, 看板不通=' + (-not (Panel)) + ')')",
        "# 启动并确认真的起来了 —— 两件事一起做: ①首次启动给足时间(刚落地的二进制可能被杀软",
        "# 扫一遍、也可能要解包 18 MB, 20 秒根本不够); ②按**版本号**确认, 不再只看面板通不通。",
        "# 三次都不成 -> 回滚到备份的旧版本并把它拉起来(第 1/2/3 步都写日志)。",
        "$ok = $false",
        "$polls = @(90, 60, 60)",
        "$waits = @(5, 10)",
        "for ($k = 1; $k -le $polls.Count; $k++) {",
        "  W ('第 ' + $k + ' 次启动新版本 v' + $newver + ' (最多等 ' + $polls[$k-1] + ' 秒)')",
        "  if ($silent) { try { Start-Process -FilePath $exe -ArgumentList $args0 } catch { W ('Start-Process 失败: ' + $_.Exception.Message) } }",
        "  else { try { Start-Process -FilePath $exe } catch { W ('Start-Process 失败: ' + $_.Exception.Message) } }",
        "  $t0 = Get-Date",
        "  $got = WaitVer $newver $polls[$k-1]",
        "  if ($got) { $ok = $true; W ('新版本已起来 (v' + $got + ', 等了 ' + [int]((Get-Date) - $t0).TotalSeconds + ' 秒)'); break }",
        "  $seen = ''",
        "  try { $seen = (Ver) } catch {}",
        "  $seenTxt = '面板一直没有响应'",
        "  if ($seen) { $seenTxt = ('应答的是 v' + $seen + ', 不是新版本') }",
        "  $tail = ''",
        "  if ($k -lt $polls.Count) { $tail = ', 等 ' + $waits[$k-1] + ' 秒再试' }",
        "  W ('第 ' + $k + ' 次没起来: ' + $polls[$k-1] + ' 秒内没有 v' + $newver + ' 应答, ' + $seenTxt + '; 结束卡住的进程' + $tail)",
        "  try { foreach ($p in @(Find-Same $exe)) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue } } catch {}",
        "  if ($k -lt $polls.Count) { Start-Sleep -Seconds $waits[$k-1] }",
        "}",
        "if ($ok) {",
        "  W '已用新版本重新启动'",
        "} else {",
        "  # ── 三步兜底: ①新版起不来 -> ②回滚到备份的旧版本 -> ③把旧版本拉起来 ────────",
        "  W ('三步兜底第 1 步: ' + $polls.Count + ' 次都没能让 v' + $newver + ' 起来')",
        "  $bak = $exe + '.old'",
        "  $rolled = $false",
        "  if (Test-Path -LiteralPath $bak) {",
        "    # 刚 Stop-Process 完, 文件可能还被占着(镜像段要过一会儿才真正释放, 杀软也可能",
        "    # 正拿着它扫) —— 所以回滚这一下要**重试**, 不能一次不成就算了。",
        "    for ($r = 1; $r -le 5; $r++) {",
        "      try { Copy-Item -LiteralPath $bak -Destination $exe -Force -ErrorAction Stop; $rolled = $true; break }",
        "      catch { W ('三步兜底第 2 步: 回滚第 ' + $r + ' 次没成(' + $_.Exception.Message + '), 等 1 秒再试'); Start-Sleep -Seconds 1 }",
        "    }",
        "    if ($rolled) { W ('三步兜底第 2 步: 回滚 —— 已用备份覆盖回升级前的旧版本 (v' + $oldver + ')') }",
        "    else { W '三步兜底第 2 步: 回滚失败 —— 备份文件覆盖不回去(见上面几次的报错)' }",
        "  } else { W ('三步兜底第 2 步: 回滚不了 —— 找不到备份 ' + $bak) }",
        "  $back = ''",
        "  if ($rolled) {",
        "    Start-Sleep -Seconds 3",
        "    for ($k = 1; $k -le 2; $k++) {",
        "      W ('回滚后第 ' + $k + ' 次启动旧版本')",
        "      if ($silent) { try { Start-Process -FilePath $exe -ArgumentList $args0 } catch { W ('Start-Process 失败: ' + $_.Exception.Message) } }",
        "      else { try { Start-Process -FilePath $exe } catch { W ('Start-Process 失败: ' + $_.Exception.Message) } }",
        "      $back = AnyVer 60",
        "      if ($back -and ($back -ne $newver)) { break }",
        "      try { foreach ($p in @(Find-Same $exe)) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue } } catch {}",
        "      Start-Sleep -Seconds 5",
        "    }",
        "  }",
        "  if ($back -and ($back -ne $newver)) {",
        "    W ('三步兜底第 3 步: 旧版本已起来 (v' + $back + ') —— 升级已回滚, 加速照常可用')",
        "    WriteResult 'rollback' ('新版本 v' + $newver + ' 起不来, 已自动回滚到 v' + $back)",
        "  } else {",
        "    W '三步兜底第 3 步: 旧版本也没能自动起来 —— 只能请用户手动双击 FoxPath.exe'",
        "    WriteResult 'rollback' ('新版本 v' + $newver + ' 起不来, 回滚后也没能自动启动; 备份在 ' + $bak)",
        "    Balloon '狐径 升级没有完成' ('新版本没能自动启动, 已经回滚到升级前的版本。若程序没出现, 手动双击 FoxPath.exe 即可, 不影响使用。')",
        "  }",
        "}",
        "# 顺手清理解包残留(只清 24 小时前的、且**确认没进程在用的**), 这堆东西能占几个 GB",
        "$cut = (Get-Date).AddHours(-24)",
        "$inuse = @{}",
        "$blind = 0",
        "Get-Process -ErrorAction SilentlyContinue | ForEach-Object {",
        "  try { foreach ($m in $_.Modules) { if ($m.FileName -like '*\\_MEI*') { foreach ($p in $m.FileName.Split('\\')) { if ($p -like '_MEI*') { $inuse[$p] = 1 } } } } }",
        "  catch {",
        "    # 审查 M-7: 读不到模块列表的进程(多半是提权进程)无法确认它是不是正在用某个",
        "    # _MEI* 目录。系统目录里的进程不会是解包目录的使用者, 不计入;",
        "    # 其它目录的(Program Files / 桌面 / U 盘……)一律计入 —— 此时一个都不删。",
        "    $bp = $_.Path",
        "    if (-not $bp -or ($bp -notlike ($env:SystemRoot + '\\*'))) { $blind++ }",
        "  }",
        "}",
        "$freed = 0; $cnt = 0",
        "if ($blind -gt 0) {",
        "  # 审查 M-7: 有进程的模块列表读不到(多半是提权进程), 那就无法确认它是不是正在用",
        "  # 某个 _MEI* 目录 —— 此时**一个都不删**(宁可留着, 也不误删别人正在用的解包目录)。",
        "  W ('有 ' + $blind + ' 个非系统进程读不到模块列表, 无法确认它们有没有在用解包目录, 为安全起见本次跳过清理')",
        "} else {",
        "  Get-ChildItem $env:TEMP -Directory -Filter '_MEI*' -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $cut -and -not $inuse.ContainsKey($_.Name) } | ForEach-Object {",
        "    try {",
        "      $sz = (Get-ChildItem $_.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum",
        "      Remove-Item $_.FullName -Recurse -Force -ErrorAction Stop",
        "      $freed += $sz; $cnt++",
        "    } catch {}",
        "  }",
        "  if ($cnt -gt 0) { W ('顺手清理解包残留 ' + $cnt + ' 个, 释放 ' + [math]::Round($freed/1MB) + ' MB') }",
        "}",
        "# 审查 M-15: 这个助手脚本是一次性随机名, 跑完就删(旧版固定叫 update-apply.ps1,",
        "# 同用户下别的程序可以提前把它换掉 —— 随机名 + 用完即删把这条面收窄)。",
        "$k = 0",
        "while ($k -lt 10) { try { Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction Stop; break } catch { Start-Sleep -Milliseconds 500; $k++ } }",
        "# 顺手扫掉上一次升级留下的旧助手脚本(只动本目录里 1 小时前的 update-apply*.ps1)",
        "try {",
        "  Get-ChildItem -LiteralPath (Split-Path -Parent $log) -Filter 'update-apply*.ps1' -ErrorAction SilentlyContinue |",
        "    Where-Object { $_.FullName -ne $PSCommandPath -and $_.LastWriteTime -lt (Get-Date).AddHours(-1) } |",
        "    ForEach-Object { try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop } catch {} }",
        "} catch {}",
    ]
    try:
        with open(helper, 'w', encoding='utf-8-sig', newline='\r\n') as f:
            f.write('\n'.join(lines) + '\n')
        # 只用 CREATE_NO_WINDOW(0x08000000), **不要** DETACHED_PROCESS:
        # 后者让 powershell.exe 拿不到控制台, 进程会立刻退出、脚本一行都不执行
        # (沙箱实测: 同一个脚本手动跑完全正常, 换成 DETACHED 就一条日志都没有)。
        flags = 0x08000000 if os.name == 'nt' else 0
        devnull = open(os.devnull, 'wb')
        # ★ 环境必须先擦一遍 _PYI_* 再给小助手(脚本里还会再擦一次, 双保险):
        # 小助手是用我们(单文件 exe 的 Python 子进程)的环境起来的, 而这份环境里有
        # PyInstaller 的记账变量; 它们会让"新版本"的引导程序误以为已经解过包。
        subprocess.Popen(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                          '-WindowStyle', 'Hidden', '-File', helper],
                         creationflags=flags, stdin=devnull, stdout=devnull,
                         stderr=devnull, close_fds=True, env=clean_pyi_env())
        return True
    except Exception as e:
        log('升级: 放小助手失败 %s' % e)
        return False


def _verify_download(path, node, sha):
    """升级包完整性校验(审查 H-1)。返回 (ok, err, msg)。

    sha256 是这条升级链上唯一的完整性凭证(HTTPS 之外没有签名), 所以升级源里
    没有 sha256 时必须拒绝 —— 不能像以前那样"want 为空就放行", 那会让漏写或
    被改写过的 exe 未经任何校验就覆盖到用户机器上。size 只要声明了也一并核对。
    """
    want = str(node.get('sha256') or '').upper().strip()
    if not want:
        return False, 'nosha', ('升级源没有提供 sha256 校验值, 为安全起见已拒绝升级'
                                '(当前版本保持不变)')
    if sha != want:
        return False, 'sha', '校验不过(期望 %s, 实际 %s), 已放弃' % (want[:16], sha[:16])
    want_size = int(node.get('size') or 0)
    if want_size:
        try:
            got = os.path.getsize(path)
        except OSError:
            got = -1
        if got != want_size:
            return False, 'size', ('下载大小不符(期望 %d 字节, 实际 %d 字节), '
                                   '已拒绝升级(当前版本保持不变)' % (want_size, got))
    return True, '', ''


def apply_update_async(auto=False):
    """后台线程: 下载 -> 校验 -> 叫小助手覆盖并重启。

    auto=True 是"默认自动升级"那条路(用户 2026-10-09 要求): 不弹任何确认框,
    校验不过就**静默保留旧版本**; 安全底线与手动升级完全一样。
    """
    info = read_update_info()
    node = update_exe_node(info)
    if not node:
        _update_set(phase='failed', error='no_info', msg='升级信息里没有下载地址')
        report_update_result(False, auto=auto, from_ver=APP_VERSION, why='no_info')
        return
    exe = os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__)
    new = exe + '.new'
    ver_to = str(node.get('version') or (info or {}).get('version') or '')
    # 纵深防御(2026-10-09 线上事故后加): 走到这一步也不许"降级安装"。正常路径已经被
    # _start_update 的闸门拦住了, 这里再挡一次 —— 以后谁加了新入口、或改了判断,
    # 都不会把用户手里更新的版本换成一个更旧的。
    if cmp_ver(ver_to, APP_VERSION) <= 0:
        c = cmp_ver(ver_to, APP_VERSION)
        msg = ('升级源里的版本 v%s 不高于当前版本 v%s, 已拒绝执行(不会动你的程序)'
               % (ver_to or '?', APP_VERSION))
        _update_set(phase='idle', error='', newer=False, block_msg=msg, msg=msg,
                    relation=ver_relation(ver_to, APP_VERSION))
        log(('%s：远程 %s %s 本地 %s'
             % ('拒绝降级' if c < 0 else '拒绝升级', ver_to or '?',
                '<' if c < 0 else '==', APP_VERSION)))
        report_update_result(False, auto=auto, from_ver=APP_VERSION,
                             to_ver=ver_to, why='downgrade', note=msg)
        return
    silent = '--silent' in [a.lower() for a in sys.argv[1:]]
    if auto:
        _auto_update_mark(ver_to)
        log('自动升级: 开始下载 v%s (不弹确认框; 校验不过会保留旧版本)' % ver_to)
    _update_set(phase='downloading', got=0, pct=0, error='', msg='正在下载新版本',
                auto=bool(auto))
    sha, err = _download_to(new, node['url'], int(node.get('size') or 0))
    if not sha:
        _update_set(phase='failed', error=err, msg='下载失败: %s' % err)
        log('升级: 下载失败 %s' % err)
        # 失败也要有回音: 弹一次人话气泡, 并在面板留一行(异常原文只进日志/结果文件)
        report_update_result(False, auto=auto, from_ver=APP_VERSION,
                             to_ver=ver_to, why='net', note=err)
        return
    _update_set(phase='verifying', msg='正在校验安装包')
    ok, verr, vmsg = _verify_download(new, node, sha)
    if not ok:
        _update_set(phase='failed', error=verr, msg=vmsg)
        log('升级: %s' % vmsg)
        try:
            os.remove(new)
        except Exception:
            pass
        report_update_result(False, auto=auto, from_ver=APP_VERSION,
                             to_ver=ver_to, why=verr)
        return
    # 交给小助手之前先把"这次升级 + 升级前的状态"存档: 新实例起来后会读它,
    # 在面板上留一行「已自动升级到 vX.Y.Z」, 并把系统代理开关接着用升级前的选择。
    _write_update_done(APP_VERSION, ver_to or APP_VERSION, auto, silent)
    if not _spawn_helper(exe, new, ver_to, silent=silent):
        _update_set(phase='failed', error='helper', msg='放小助手失败')
        report_update_result(False, auto=auto, from_ver=APP_VERSION,
                             to_ver=ver_to, why='helper')
        return
    _update_set(phase='applying', pct=100, msg='校验通过, 正在覆盖并重启…')
    log('升级: 已下好 %d 字节 (sha256=%s) 并通过校验, 交给小助手覆盖(升级前状态已存档)'
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
.upd-banner{margin-top:10px;padding:8px 10px;border-radius:6px;background:#fff7ed;
  border:1px solid #fed7aa;color:#9a3412;font-size:13px}
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
    <label><input type="checkbox" id="autoUpd"> 自动升级</label>
    <label><input type="checkbox" id="notifyBubble"> 升级结果气泡</label>
  </div>
  <div class="upd-bar" id="updBarWrap" style="display:none"><i id="updBar"></i></div>
  <div class="upd-banner" id="updBanner" style="display:none"></div>
  <div class="upd-note" id="updMsg">默认自动升级: 启动后发现有新版本会自动下好、校验、换上新版（不弹确认框）。</div>
  <div class="upd-note upd-ok" id="updAuto"></div>
  <div class="upd-note" id="updLast"></div>
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
    <span id="actMsg" style="font-size:13px;color:#16a34a"></span>
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
    // 自动升级开关 + 本次启动的升级结果(2026-10-09 用户要求: 默认自动升级、不弹提示)
    document.getElementById('autoUpd').checked = !!d.autoupd;
    document.getElementById('updAuto').textContent = d.upgraded || '';
    // 升级结果气泡开关(默认开) + 「上次升级结果」一行(成功/失败 + 时间, 不只靠气泡)
    document.getElementById('notifyBubble').checked = d.notify !== false;
    const lr = document.getElementById('updLast');
    lr.textContent = d.lastres || '';
    lr.className = 'upd-note ' + (d.lastres ? (d.lastok ? 'upd-ok' : 'upd-err') : '');
    // 有新版本时亮一条: 自动升级开着就说"会自动升", 关着才让用户自己点
    const nb = document.getElementById('updBanner');
    if (d.newver) {
      nb.style.display = 'block';
      nb.innerHTML = d.autoupd
        ? ('发现新版本 <b>v' + d.newver + '</b> —— 已按设置自动升级（不弹确认框, 校验不过会保留旧版）。')
        : ('发现新版本 <b>v' + d.newver + '</b> —— 自动升级已关闭, 点下面的「检查更新」再点「立即升级」。');
    } else {
      nb.style.display = 'none';
    }
    document.getElementById('ips').innerHTML = (d.good||[])
      .map(x=>'<tr><td>'+x[0]+'</td><td>'+x[1]+' ms</td></tr>').join('') ||
      '<tr><td colspan="2">一个都不通</td></tr>';
    document.getElementById('log').textContent = (d.logs||[]).join('\\n');
    const p=document.getElementById('log'); p.scrollTop=p.scrollHeight;
  }).catch(()=>{});
}
function doAct(u){
  act(u).then(r=>{
    // 后端的 ok/msg 必须显示出来: 启用失败时用户绝不能以为已经生效(审查 H-2)
    if(r&&r.ok===false){_say('actMsg',(r.msg||'操作没有成功'),12000,true);}
    else{_say('actMsg',(r&&r.msg)||'已完成',3000,false);}
    refresh();
  }).catch(()=>{_say('actMsg','面板没有响应, 操作结果未知',12000,true);refresh();});
}
document.getElementById('autoUpd').onchange = (e)=>{
  // 默认开; 关掉就只提示(设置存在数据目录的 settings.json 里)
  act('/api/autoupdate?on='+(e.target.checked?1:0)).then(r=>{
    _say('updMsg', (r&&r.msg)||'已保存', 6000, false); refresh();
  }).catch(()=>{_say('updMsg','设置没有保存成功',8000,true);refresh();});
};
document.getElementById('notifyBubble').onchange = (e)=>{
  // 升级结果气泡(默认开): 关掉就完全不弹, 面板「上次升级结果」那一行照留
  act('/api/notifybubble?on='+(e.target.checked?1:0)).then(r=>{
    _say('updMsg', (r&&r.msg)||'已保存', 6000, false); refresh();
  }).catch(()=>{_say('updMsg','设置没有保存成功',8000,true);refresh();});
};
document.getElementById('btnEnable').onclick = ()=>doAct('/api/enable');
document.getElementById('btnDisable').onclick = ()=>doAct('/api/disable');
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
  // /api/diag 现在是 JSON(审查 M-6: 不再是 text/plain, 免得被当脚本嗅探),
  // 而且里面不含完整 IP(出口地址这类敏感字段不进 diag)。
  api('/api/diag').then(d=>{
    document.getElementById('diag').textContent = (d&&d.diag)||'读取失败';
  }).catch(()=>{});
}
function _say(id,txt,ms,err){const e=document.getElementById(id);if(e){e.textContent=txt;
  e.style.color=err?'#b91c1c':'';setTimeout(()=>{e.textContent='';e.style.color='';},ms||2500);}}
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
  // 后端会拒收私网/回环地址并给人话(审查 M-14), 这里必须把原因显示出来, 不能一律说"已保存"
  act('/api/set-ip?ip='+encodeURIComponent(v)).then(r=>{
    if(r&&r.ok===false){_say('ipMsg',(r.msg||'这个地址不能用'),12000,true);return;}
    _say('ipMsg',(r&&r.msg)||'已保存，正在重测…'); loadDiag(); refresh();
  }).catch(()=>{_say('ipMsg','面板没有响应, 结果未知',12000,true);});
};
document.getElementById('btnIpClear').onclick = ()=>{
  act('/api/set-ip?ip=').then(r=>{
    _say('ipMsg',(r&&r.msg)||'已清除');loadDiag();refresh();
  }).catch(()=>{_say('ipMsg','面板没有响应',8000,true);});
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
      U.msg.textContent=(v.auto?'正在自动下载新版本（已按设置自动升级）  ':'正在下载新版本  ')+kb(v.got)+(v.total?(' / '+kb(v.total)+'   '+(v.pct||0)+'%'):'');
      U.go.style.display='none';
    } else if(v.phase==='verifying'||v.phase==='applying'){
      U.wrap.style.display='block'; U.bar.style.width='100%';
      U.msg.innerHTML='<span class="upd-ok">'+v.msg+'</span>';
      U.go.style.display='none';
    } else if(v.phase==='failed'){
      U.wrap.style.display='block';
      U.msg.innerHTML='<span class="upd-err">升级没有完成：'+(v.msg||'')+'</span>';
    } else if(v.newer){
      // ★ 只有服务端按**版本号语义**判出"远程严格大于本地"才提示升级、才放开按钮。
      // 2026-10-09 线上事故: 这里以前写的是 v.remote!==v.local, 于是本地 1.0.7
      // 对着线上 1.0.6 也提示「发现新版本 v1.0.6」, 用户一点就把 1.0.7 换成了 1.0.6。
      U.msg.innerHTML='<span class="upd-ok">发现新版本 v'+v.remote+'</span>'+(v.notes?('  '+v.notes):'');
      U.go.style.display=''; U.go.disabled=false; U.go.style.opacity='';
      U.wrap.style.display='none'; U.bar.style.width='0';
    } else if(v.relation==='older'){
      // 本地比线上新(预发布/开发版本): 不提示升级, 按钮置灰且点不动;
      // 就算有人跳过前端直接调接口, 服务端也会拒绝(见 update_gate)。
      U.msg.innerHTML='<span class="upd-err">本地版本比线上新（预发布/开发版本），线上暂未发布</span>'
        +'<span style="color:#6b7280">　本地 v'+(v.local||'')+' · 线上 v'+(v.remote||'')+'</span>';
      U.go.style.display=''; U.go.disabled=true; U.go.style.opacity='0.45';
      U.go.title='本地版本比线上新，不能升级（要退回旧版本请用手动方式）';
      U.wrap.style.display='none'; U.bar.style.width='0';
    } else {
      U.msg.textContent=v.msg||'还没检查过线上版本，点「检查更新」看一眼';
      U.go.style.display='none';
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
    if(U.go.disabled){return;}
    U.go.style.display='none'; U.wrap.style.display='block'; U.bar.style.width='0';
    act('/api/update/start').then(function(r){
      // 服务端闸门也会拒绝(远程不高于本地): 必须把原因显示出来, 不能"点了没反应"
      if(r&&r.ok===false){U.wrap.style.display='none';
        _say('updMsg', r.msg||'这次不能升级', 12000, true);}
      tick();
    }).catch(function(){U.wrap.style.display='none';
      _say('updMsg','面板没有响应, 升级结果未知',12000,true); tick();});
  };
  tick();
  // 面板开着的时候每 15 秒跟一次服务端结论: 用户什么都不点, 也能自己看到
  // 「发现新版本」或者「本地版本比线上新（预发布/开发版本）」(2026-10-09 加)。
  setInterval(tick, 15000);
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
        # 审查 M-6: 没有 nosniff 时, 浏览器可能把 text/plain 的接口回话当脚本嗅探执行
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def do_GET(self):
        # 审查 M-6: 以前只有 POST 校验同源, GET 是敞开的 —— 任意网页/被挂马页面
        # 都能触发这些接口(no-cors), 顺手把"本机可用地址、表源、已运行多久"这些
        # 信息读走。现在 GET 也一样先过 Host 校验。
        if not self._host_ok():
            log('已拒绝一个非同源的 GET 请求(Host 校验未通过): %s'
                % self.path.split('?')[0])
            self._send(403, b'forbidden', 'text/plain; charset=utf-8')
            return
        _LAST_ACT[0] = time.time()
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
                # 有新版本时给面板一个提示字段(★ 只有远程严格大于本地才算, 2026-10-09)
                'newver': (str(UPDATE.get('remote') or '')
                           if ver_relation(str(UPDATE.get('remote') or ''),
                                           APP_VERSION) == VER_NEWER else ''),
                # 版本关系也一并回给面板(older = 本地比线上新, 面板要显示成"线上暂未发布")
                'verrel': UPDATE.get('relation') or ver_relation(
                    str(UPDATE.get('remote') or ''), APP_VERSION),
                # /api/status 带上自己的版本号: 升级小助手靠它确认"起来的到底是不是新版本"
                # (2026-10-09 线上事故: 小助手只看看板通不通, 结果用户手动起回旧版也被算成
                #  "新版本已起来", 于是该重试不重试、该回滚不回滚)
                'version': APP_VERSION,
                # 自动升级开关(默认开) + 本次启动是不是"刚被升级上来的"
                'autoupd': auto_update_on(),
                'upgraded': upgraded_text(),
                # 升级结果气泡开关(默认开) + 上一次升级结果那一行(成功/失败 + 时间)
                'notify': bubble_on(),
                'lastres': last_result_text(),
                'lastok': bool(_LAST_RESULT[0] and _LAST_RESULT[0].get('ok')),
                'logs': recent_logs(),
            }
            self._send(200, json.dumps(data, ensure_ascii=False).encode('utf-8'),
                       'application/json; charset=utf-8')
        elif path == '/api/diag':
            # 审查 M-6: 这段文本以前是 text/plain 且不带任何同源校验, 浏览器可能
            # 把它当脚本嗅探执行。现在改成 application/json(+上面的 nosniff),
            # 且内容里不带完整 IP(出口地址这类敏感字段不进 diag)。
            body = json.dumps({'ok': True, 'diag': diag_text()},
                              ensure_ascii=False).encode('utf-8')
            self._send(200, body, 'application/json; charset=utf-8')
        elif path == '/api/update/status':
            self._send(200, json.dumps(_update_get(), ensure_ascii=False).encode('utf-8'),
                       'application/json; charset=utf-8')
        else:
            self._send(404, b'not found')

    def _host_ok(self):
        """请求的 Host 必须是本机面板自己(挡 DNS rebinding: 域名指向 127.0.0.1 时
        Host 会是那个域名, 这里就过不去)。GET 与 POST 都先过这一关(审查 M-6)。"""
        host = (self.headers.get('Host') or '').lower()
        return host in ('127.0.0.1:%d' % PANEL_PORT, 'localhost:%d' % PANEL_PORT)

    def _same_origin(self):
        """只接受来自本机面板页面的请求。

        面板虽然只监听 127.0.0.1, 但**任何本机程序或网页**都能往这个端口发 POST
        (简单请求不触发预检)。校验 Host 与 Origin, 挡掉网页 CSRF 与 DNS rebinding ——
        否则一个恶意页面就能把加速关掉, 甚至在无备份时清掉用户的 PAC。
        """
        if not self._host_ok():
            return False
        _LAST_ACT[0] = time.time()
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
        # 后端必须把 ok / 失败原因回给面板(审查 H-2): 原来返回值被丢在地上,
        # 用户点了「启用加速」没生效也看不出来。
        resp = {'ok': True, 'msg': ''}
        if path == '/api/enable':
            ok, msg = enable_proxy()
            resp = {'ok': ok, 'msg': msg}
        elif path == '/api/disable':
            ok, msg = disable_proxy()
            resp = {'ok': ok, 'msg': msg}
        elif path == '/api/retest':
            threading.Thread(target=lambda: (HEALTH.refresh(candidate_list()),
                                              HEALTH_RAW.refresh(CANDIDATE_IPS_RAW),
                                              HEALTH_PAGES.refresh(CANDIDATE_IPS_RAW)),
                             daemon=True).start()
            log('手动重测已触发(含 raw 与 github.io 池)')
        elif path == '/api/quit':
            log('收到退出指令, 正在还原系统代理')
            disable_proxy()
            threading.Thread(target=lambda: (time.sleep(0.3), os._exit(0)), daemon=True).start()
        elif path == '/api/update/check':
            st = do_update_check()
            log('手动检查升级: ' + str(st.get('msg')))
            # 把结论一起回给面板(2026-10-09): 降级场景下手动检查也必须给出
            # 「本地版本比线上新…」, 而不是一句"有新版本"。
            resp = {'ok': st.get('phase') != 'failed', 'msg': str(st.get('msg') or ''),
                    'relation': st.get('relation') or '', 'newer': bool(st.get('newer'))}
        elif path == '/api/update/start':
            # ★ 服务端闸门: 远程不高于本地时这里会拒绝(不再只靠面板把按钮置灰),
            # 面板把 ok/msg 显示出来, 用户看到的是"为什么不能升"而不是"点了没反应"。
            started, umsg = _start_update(auto=False)
            if started:
                log('收到升级指令, 开始下载新版本')
            resp = {'ok': bool(started), 'msg': umsg}
        elif path == '/api/autoupdate':
            # 设置里保留的开关(默认开): 关掉就回到"发现新版只提示"的老行为
            ok, msg = set_auto_update('on=1' in query)
            resp = {'ok': ok, 'msg': msg}
        elif path == '/api/notifybubble':
            # 升级结果气泡的开关(默认开): 关掉就完全不弹, 只留面板那行状态
            ok, msg = set_notify_bubble('on=1' in query)
            resp = {'ok': ok, 'msg': msg}
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
        self._send(200, json.dumps(resp, ensure_ascii=False).encode('utf-8'),
                   'application/json; charset=utf-8')
        if path == '/api/enable' and not resp['ok']:
            # 面板可能没被打开/没被看到 —— 沿用现有的弹窗机制再兜一次(审查 H-2)
            threading.Thread(target=alert_once,
                             args=('enable-readback', '狐径: 启用加速失败',
                                   resp['msg'] or '加速没有生效'),
                             daemon=True).start()


def start_panel():
    try:
        srv = ThreadingHTTPServer(('127.0.0.1', PANEL_PORT), PanelHandler)
    except OSError as e:
        _port_taken(PANEL_PORT, e, '控制面板')
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
        # GitHub Pages 与 raw/附件同一段 IP, 但证书记的是 *.github.io —— 单独体检
        good_pages = HEALTH_PAGES.refresh(CANDIDATE_IPS_RAW)
        if need_meta or len(good) < 3:
            fetch_official_ips()
            good = HEALTH.refresh(candidate_list())

        # 静默检查新版本 —— 启动后一次, 之后每 12 小时一次。
        # 2026-10-09 用户要求: 默认**自动升级、不弹确认框**; 关掉开关才回到"只提示"。
        if time.time() - _last_auto_check[0] > AUTO_CHECK_INTERVAL:
            _last_auto_check[0] = time.time()
            try:
                st = do_update_check()
                remote = str(st.get('remote') or '')
                if ver_relation(remote, APP_VERSION) == VER_NEWER:
                    if not auto_update_on():
                        log('发现新版本 v%s（自动升级已关闭, 面板上点「立即升级」即可）' % remote)
                    else:
                        go, why = _auto_update_guard(remote, st.get('exe_url') or '')
                        if go:
                            log('发现新版本 v%s, 按设置自动升级(不弹确认框; 校验不过会保留旧版)'
                                % remote)
                            if _LAST_ACT[0] and (time.time() - _LAST_ACT[0]) < 60:
                                log('面板 %d 秒前还有活动(用户可能正开着面板): 升级前的开关'
                                    '状态已存档, 面板标签页升级后会自己接上, 不丢状态'
                                    % int(time.time() - _LAST_ACT[0]))
                            started, smsg = _start_update(auto=True)
                            if not started:
                                log('自动升级没有开始: %s' % smsg)
                        else:
                            log('发现新版本 v%s, 但没有自动升级: %s' % (remote, why))
                else:
                    log('已是最新版 v%s' % APP_VERSION)
            except Exception as e:
                log('静默检查新版本失败: %s' % e)

        # 体检日志就是狐径的心跳: 带上"已运行多久", 长跑日志才能一眼看出
        # 它是持续在跑、还是中途死过又重开。
        up_min = int((time.time() - _START_TS[0]) / 60) if _START_TS[0] else 0
        if good:
            log('体检: 可用 %d/%d 已运行%d分钟 -> %s' % (
                len(good), len(CANDIDATES), up_min,
                ', '.join('%s(%dms)' % (i, m) for i, m in good[:3])))
        elif good_raw or good_pages:
            log('raw/pages 体检: 可用 %d/%d 与 %d/%d -> %s'
                % (len(good_raw), len(CANDIDATE_IPS_RAW),
                   len(good_pages), len(CANDIDATE_IPS_RAW),
                   ', '.join('%s(%dms)' % (i, m) for i, m in (good_raw or good_pages)[:2])))
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

    # 上一次升级留下的状态(用户 2026-10-09 要求: 不要丢状态):
    #   ① 面板上留一行"已自动升级到 vX.Y.Z"; ② 系统代理开关接着用升级前的选择;
    #   ③ 结果(成了/没成)在右下角弹一次气泡 —— 没升级过时这里什么都不做, 不打扰。
    prev = consume_update_done()
    # ★ 这次是"升级交接"上来的: 整个进程都不许弹模态框(2026-10-09 线上事故 —— 启动路上
    # 一弹窗, 面板就起不来, 小助手判定失败后反复重启, 用户就没程序可用了)。
    _HANDOFF_STARTUP[0] = bool(prev)
    if prev:
        log('本次是升级交接后的启动: 全程不弹模态框, 有问题只写日志并在面板/气泡里提示')
    report_prev_update(prev)
    keep_off = bool(_AUTO_UPGRADED[0]) and (prev or {}).get('proxy_on') is False
    if keep_off and proxy_on():
        log('升级前用户没有开启加速, 这里按原状态关掉, 不替他打开')
        disable_proxy()

    start_proxy()
    start_panel()
    fetch_official_ips()
    threading.Thread(target=health_loop, daemon=True).start()

    if '--silent' in args:
        # 静默模式(开机自启用)以前**没有**注册退出还原 —— 这正是"程序关了,
        # PAC 却留在注册表里"的根因。现在两种模式都注册。
        atexit.register(on_exit)
        if keep_off:
            log('按升级前的状态: 没有开启加速')
        elif not proxy_on():
            enable_proxy()
        elif _load_backup() is None:
            log('注意: 系统代理已指向本程序, 但没有还原备份 —— 退出时会直接清除该 PAC')
        log('静默模式, 每 5 分钟自动体检')
        while True:
            time.sleep(60)
    else:
        atexit.register(on_exit)
        if keep_off:
            log('按升级前的状态: 没有开启加速')
        elif not proxy_on():
            enable_proxy()
        elif _load_backup() is None:
            log('注意: 系统代理已指向本程序, 但没有还原备份 —— 退出时会直接清除该 PAC')
        if _AUTO_UPGRADED[0]:
            # 原来开着的面板页每 3 秒轮询一次, 新实例起来后它会自己接上 ——
            # 不再重复开一个浏览器窗口, 免得打断用户。
            log('这次是升级后自动重启: 原来开着的面板标签页会自己接上, 不再重复打开浏览器')
        else:
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
