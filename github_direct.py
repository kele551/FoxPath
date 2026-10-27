# -*- coding: utf-8 -*-
"""
GitHub 直连助手 —— 绿色单文件版

作者:  海风（kele551）    https://gitcode.com/kele551/FoxPath
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
import platform          # 一键反馈包: 系统版本要写清楚(2026-10-24)
import collections
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

# Ed25519 验签（升级通道加固，2026-10-16）：同目录的 _ed25519.py（纯 Python、零第三方依赖）。
# 用 try/except 包住是**故意**的：以后万一打包漏了它，程序照样能跑，只是升级这条路
# 一律拒绝（fail-closed，见 update_sig_available / _verify_update_sig）—— 绝不放行没验签的升级。
try:
    import _ed25519
    UPDATE_SIG_AVAILABLE = True
except Exception:
    _ed25519 = None
    UPDATE_SIG_AVAILABLE = False

APP_NAME = '狐径'
APP_VERSION = '1.2.3'
# 署名（一处定义，界面/日志/属性/README 都用它，避免各写各的）
AUTHOR = '海风（kele551）'
AUTHOR_ASCII = 'HaiFeng (kele551)'
HOMEPAGE = 'github.com/kele551/FoxPath'
PROXY_PORT = 8787
PANEL_PORT = 8788
CHECK_INTERVAL = 300          # 5 分钟重测一轮
# 转发通道的"空闲上限": 只要两端还有数据流动就一直续期, 不是总时长上限(审查 H-4)。
RELAY_IDLE_TIMEOUT = 600

# PAC 只代理这几台主机；代理内部也用同一份名单，保证"PAC 会送来的"和
# "代理愿意走 IP 池的"完全一致。githubassets / api.github.com 一律 DIRECT ——
# 它们直连本来就通，走代理反而会坏（见 README 已知边界）。
#
# 【2026-10-24 接管范围核实（UI 整改顺带做）—— 实测证据在 logs\UI整改-20261024\】
#   · codeload.github.com —— **纳入**。它跟 github.com 是同一批官方 web 服务器：
#     用候选池 IP + SNI=codeload.github.com 实测，证书覆盖 *.github.com、HTTP 301
#     （正常行为）。所以它走 HEALTH 池，**没有新增任何 IP**。
#   · gist.github.com —— **暂不纳入，列 TODO**。本机 DNS 被污染（解析出 2001::1 /
#     78.16.49.15），改用 6 个官方 IP、每个试 2 次，SNI=gist.github.com 一律在
#     握手阶段 ConnectionResetError；而同一批 IP 用 SNI=github.com 全部 200。
#     换 IP 解决不了这一层，接管过去也白搭 —— 不写占位 IP、也不假装能加速。
#   · githubassets.com —— **保持 DIRECT，列 TODO**。它解析到 185.199.108.215
#     （在官方 web 段 185.199.108.0/22 内），但证书是 *.githubassets.com，与 raw 池
#     校验的 githubusercontent 证书不同；本机实测 TLS 194ms、本来就快，没必要动。
# 【2026-10-26 加·uploads.github.com】发布附件**上传**用的域以前不在这份清单里，浏览器一律直连，
# 于是出现"页面能开、传附件却撞运气"（v1.2.3 发版当天实测：裸连 WinError 10060、走代理偶发 502）。
# 收进来的判据和当年 codeload 用的是同一条：拿池里的 IP + SNI=uploads.github.com 发一次 GET /，
# 实测 5 个地址（140.82.112.3 / 140.82.113.4 / 140.82.116.3 / 20.205.243.166 / 20.27.177.113）
# TLS 全部握手成功并回 **301**（而不是 500 Domain Not Found）—— 说明这些服务器真的服务这个域。
# api.github.com 仍然**故意不在**这个名单里：候选池全是 web 段地址，拿它连 api 是错的。
PROXY_HOSTS = ('github.com', 'www.github.com', 'codeload.github.com', 'uploads.github.com')

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
# 【2026-10-11 改·avatars/camo 纳入】本机实测推翻了上面"刻意直连"的老结论：
#   同一张 avatars 头像 282KB，直连 5.7~14.2s（均值 10.68s），
#   走本机代理 1.1~4.7s（均值 2.65s）——快约 4 倍，4 轮全胜。
# 原因：avatars / camo 与 raw/objects **同一段 185.199.108.0/22**（本机解析
#   全是 185.199.108~111.133），证书也是同一张 *.githubusercontent.com，
#   所以放进 raw 池既不会连错服务器、也不会撞证书。
# 意义：GitHub 页面上有几十个头像/camo 图片，它们直连被堵时，主站 HTML 就算
#   秒开，页面也会一直转圈 —— 这正是"加速了但网页还是打不开"的另一半原因。
# githubassets 仍保持直连：它不在 githubusercontent 域（证书不同），
#   且本机实测 0.27s 本来就快，没必要动。
PROXY_HOSTS_RAW = ('raw.githubusercontent.com', 'objects.githubusercontent.com',
                   'avatars.githubusercontent.com', 'camo.githubusercontent.com')

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

# 【2026-10-11 实测·IPv6 只有 raw 和 Pages 用得上, 主站用不上】
# 今天下午 IPv4 全线拥塞时实测的对比(同一个确定存在的资源
# raw.githubusercontent.com/github/gitignore/main/Python.gitignore):
#   IPv4 185.199.108.133 / 109.133 -> 超时失败
#   IPv6 2606:50c0:800x::154       -> 200, 5588 字节, 0.15~0.17 秒
# 同一时刻 github.io 也一样: IPv6 2606:50c0:800x::153 访问 facebook.github.io
# 返回 200, 而 IPv4 185.199.108.133 连不上 —— IPv6 走的是另一条路, 不跟 IPv4 一起堵。
# 反过来 **github.com 主站根本没有 IPv6**: 扫了 144 个候选(2606:50c0:8000~8003::140~175),
# 没有能对 github.com 返回 2xx/3xx 的(::153 是 Pages 的节点, 拿 github.com 去问一律 404)。
# 所以下面两组只喂给 raw / pages 池, 主站池(CANDIDATE_IPS_V6)继续留空。
CANDIDATE_IPS_RAW_V6 = [
    '2606:50c0:8000::154', '2606:50c0:8001::154',
    '2606:50c0:8002::154', '2606:50c0:8003::154',
]
CANDIDATE_IPS_PAGES_V6 = [
    '2606:50c0:8000::153', '2606:50c0:8001::153',
    '2606:50c0:8002::153', '2606:50c0:8003::153',
]
# 池子入参: raw 用"IPv4 + raw 的 IPv6", pages 用"IPv4 + pages 的 IPv6"。
# 两组不能混 —— ::154 的证书不含 *.github.io, 塞进 pages 池只会被判死、白占探测名额。
CANDIDATE_IPS_RAW_ALL = CANDIDATE_IPS_RAW + CANDIDATE_IPS_RAW_V6
CANDIDATE_IPS_PAGES_ALL = CANDIDATE_IPS_RAW + CANDIDATE_IPS_PAGES_V6

# 【2026-10-12 新增 · IPv6 闸门】本机没有 IPv6 出口线路时, IPv6 候选会整排超时:
# 每轮白占 8 个探测名额、体检变慢, "IPv6 可用 0/N" 也会永远难看。先探一下
# "本机到底有没有 IPv6 路由" —— UDP connect 不发任何包, 只查路由表, 立即返回,
# 开销约等于零。失败只关 60 秒(别被一次网络打嗝永久锁死), 成功缓存 5 分钟。
_IPV6_GATE = [None, 0.0]           # [结果, 上次探测时刻]
_IPV6_GATE_LOCK = threading.Lock()


def local_has_ipv6():
    now = time.time()
    with _IPV6_GATE_LOCK:
        res, ts = _IPV6_GATE
        if res is not None and now - ts < (300 if res else 60):
            return res
    ok = False
    for probe in ('2606:50c0:8000::154', '2a0a:a440::1'):
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            try:
                s.connect((probe, 443))     # UDP 不发包, 仅查 IPv6 路由
                ok = True
            finally:
                s.close()
            if ok:
                break
        except OSError:
            ok = False
    with _IPV6_GATE_LOCK:
        _IPV6_GATE[0], _IPV6_GATE[1] = ok, time.time()
    return ok

# ── 手动指定 IP（2026-10-08 加）──────────────────────────────────────────────
# 现场救急用：自动探测一个都不通时，让用户填一个他这条线能连上的官方 IP。
# 存在数据目录里，重启后仍然生效；填空 = 清除。
MANUAL_IP_FILE = 'manual-ip.txt'
_MANUAL_IP = ['']          # 内存缓存，免得每次都用磁盘
_META_SOURCE = ['']        # 上次成功同步 IP 表的来源（体检信息里要报出来）
# 【2026-10-11 修·"网页又打不开"的最后一公里】
# 体检排第一的 IP 常常在两次体检之间悄悄死掉。实测 12:18:06 体检报
# "20.27.177.119 = 224ms 排第一"，同一分钟直连它 TCP 就超时；而真正能通的
# 20.200.245.247 排在后面。转发若死守"体检名次"串行试错，就要先撞死 IP、
# 各等一轮超时 —— github 实测 8.15 秒才返回 200，浏览器体感就是"打不开"。
# 这里记下"上一次真正连通成功的 IP"，下次转发优先复用：同一个 IP 几分钟内
# 基本还是通的，于是首次连接就命中，不再串行试错。
_LAST_GOOD = {'github': '', 'raw': '', 'pages': ''}
# 【2026-10-11 修·失败计数降权】体检每 5 分钟重排一次名次, 会把刚被证实**已经连不上**
# 的 IP 又排回第一(实测: 12:23 体检把 20.27.177.113 排第一, 12:26 转发又去撞它)。
# 这里的失败计数**跨体检周期保留**: 连续失败过的往后靠, 一旦成功就清零。
# 于是"时好时坏"的 IP 会自动让位给稳定的, 不用等下一次体检。
_FAIL_CNT = {}
_FAIL_LOCK = threading.Lock()


def _fail_note(ip):
    with _FAIL_LOCK:
        _FAIL_CNT[ip] = _FAIL_CNT.get(ip, 0) + 1


def _fail_clear(ip):
    with _FAIL_LOCK:
        _FAIL_CNT.pop(ip, None)


def _fail_rank(ip):
    with _FAIL_LOCK:
        return _FAIL_CNT.get(ip, 0)


# ------------------------------------------------------- 这次是池子赢还是直连赢
# 让"直连参与竞速"这件事在面板上看得见: 否则用户只看到快了, 不知道为什么快,
# 出问题时也没法判断是池子选错了还是外面那条路本来就堵。
_ROUTE = {}          # key -> {'src': 'pool'|'sys', 'ip': ..., 'ts': ...}


def _note_route(key, ip, sys_ips):
    src = 'sys' if ip in (sys_ips or ()) else 'pool'
    _ROUTE[key] = {'src': src, 'ip': ip, 'ts': time.time()}
    return src


# ------------------------------------------------------- 连续全灭 = 别再傻等
# 【2026-10-24 新增·快速失败(用户批准的改法②)】
# 用户的原始痛点: "国外仓库一直打不开", 而每发请求都要走完
#   抢连 4 秒 + 兜底系统解析 10 秒 ≈ 14 秒才拿到一个"连不上"。
# 一次就算了, 可浏览器打开 github 会并发十几条请求, 每条都这么等, 体感就是
# 整个站点卡死。这里记"全灭"的次数: 上一条请求池子和兜底一起死了, 说明
# **这条链路此刻根本不通**, 下一条兜底时没必要再等满 10 秒 —— 压到 3 秒,
# 让请求快速失败、让浏览器自己重试; 一旦连上就立刻恢复原来的宽松预算。
#
# 【2026-10-26 修·账要按时间窗记, 不能"一连通就清零"】
# 装机版今天的日志把老写法的漏洞暴露得很清楚(12:35~12:38 四分钟里 6 次):
#   "连接 github.com 失败: timed out（兜底等了 10.0 秒, 连续第 1 次全灭）"
# 次次都是"第 1 次"、次次都等满 10 秒。原因是这条线是**时好时坏**而不是全死:
# 12:37:35 有一条请求"复用刚验过的通道"成功了 —— 按老规矩这一成功就把计数清零,
# 于是紧接着那几条撞死的请求又各自重新交一遍 10 秒学费(四分钟里白等 60 秒)。
# 现在改成记**时间戳**: 60 秒窗口内只要还有全灭的账, 预算就是 3 秒; 一次连通
# 只抹掉最旧的两笔(链路确实在好转), 全抹干净才恢复 10 秒。
_SYS_FAIL = {}              # key -> [全灭时刻, ...]（只留最近 _SYS_FAIL_WINDOW 秒内的）
_SYS_FAIL_LOCK = threading.Lock()
_SYS_FAIL_WINDOW = 60.0     # 记账窗口: 抽风一般持续几分钟, 60 秒内的账都还该起作用
_SYS_FAIL_HOLD = 20.0       # 一次连通只作废"距今超过 20 秒"的账, 20 秒内的仍然算数
_SYS_FAIL_SHORT_TIMEOUT = 3.0
_SYS_FAIL_FULL_TIMEOUT = 10.0


def _sys_fail_recent(key, now=None):
    """窗口内还有几笔全灭的账(0 = 这段时间一直是通的)。顺手把过期的账剪掉。"""
    if now is None:
        now = time.time()
    with _SYS_FAIL_LOCK:
        lst = _SYS_FAIL.get(key)
        if not lst:
            return 0
        keep = [t for t in lst if now - t <= _SYS_FAIL_WINDOW]
        if keep:
            _SYS_FAIL[key] = keep
        else:
            _SYS_FAIL.pop(key, None)
        return len(keep)


def _sys_fail_bump(key):
    """记一笔"刚刚整条链路全灭", 返回窗口内累计的第几笔。"""
    now = time.time()
    with _SYS_FAIL_LOCK:
        lst = [t for t in _SYS_FAIL.get(key, []) if now - t <= _SYS_FAIL_WINDOW]
        lst.append(now)
        _SYS_FAIL[key] = lst
        return len(lst)


def _sys_fail_reset(key):
    """连上了 —— 只作废"距今超过 _SYS_FAIL_HOLD 秒"的陈账, 20 秒内的仍然算数。

    老写法在这里是 `_SYS_FAIL[key] = (0, now)` 直接清零, 于是时好时坏的链路永远
    攒不起账: 今天 12:35~12:38 四分钟里 6 次"兜底等了 10.0 秒, 连续第 1 次全灭",
    每一次都是刚被别的一条请求的成功清零过。现在一次成功最多让时间往前翻一页,
    抹不掉刚刚那次全灭 —— 链路真恢复了(20 秒内没有新的全灭 + 又连通一次)才放宽。
    """
    now = time.time()
    with _SYS_FAIL_LOCK:
        lst = [t for t in _SYS_FAIL.get(key, []) if now - t <= _SYS_FAIL_WINDOW]
        lst = [t for t in lst if now - t < _SYS_FAIL_HOLD]
        if lst:
            _SYS_FAIL[key] = lst
        else:
            _SYS_FAIL.pop(key, None)
        return len(lst)


def _sys_fail_budget(key):
    """退回系统解析时最多等多久: 近期全灭过就压短。

    门槛为什么定"近期失败过"而不是"连着两次": 记的本来就是**整条链路全灭**
    (池子抢连 + 系统解析一起死)，一次就说明这条路径此刻不通，第二次再去等满
    10 秒纯属重复交学费。恢复期靠 `_sys_fail_reset` 的衰减逐步放宽。
    """
    if _sys_fail_recent(key) >= 1:
        return _SYS_FAIL_SHORT_TIMEOUT
    return _SYS_FAIL_FULL_TIMEOUT


# 轻探日志的节流: 页面一开就是十几条请求, 每条都记一行会把有用日志冲掉。
_FAST_LOG = {}
_FAST_LOG_LOCK = threading.Lock()


def _fast_log_ok(key, gap=30.0):
    now = time.time()
    with _FAST_LOG_LOCK:
        if now - _FAST_LOG.get(key, 0.0) < gap:
            return False
        _FAST_LOG[key] = now
    return True


# ------------------------------------------- 建连总时限 + 抢连闸门 (2026-10-26)
# 【为什么要限总时长】
# 本机 foxpath.log 12:35~12:38 那段抽风期里，一条打不开的请求要走完
#   抢连(4 秒) → 广撒网 16 个(1.5 秒) → 两轮轻探(1.5+2.2 / 2.2+2.6) → 兜底(10 秒)
# 端到端实测 **19.4 秒**才回一句"连不上"(AB 对照脚本 fp_ab_probe.py 第 14 轮)。
# 浏览器的耐心远短于此：转 20 秒用户就认为"网页打不开"，关掉标签走人。
# 现在给每次建连一个总预算，走完"最该试的那一手"就到点收摊、明确记一行
# "建连到点放弃" —— 失败还是失败，但从 20 秒缩到 8 秒以内，用户点一下刷新
# 就能赶上下一条刚被后台验活的通道。
_CONNECT_DEADLINE = 8.0

# 【为什么要给抢连上闸门】
# _prescan 早就是全局单闸门(一轮只允许一批 HTTP 实测)，可**TCP 抢连不是**：
# 浏览器开一个 GitHub 页面并发十几条 CONNECT，池子恰好没新鲜证据(fast)时，
# 每条请求各自对 6 个(全灭后广撒网是 16 个)IP 发起握手 —— 一条页面就是
# 90~250 个并发 SYN，全砸在同一条已经拥塞的国际链路上。10-11 记过的
# "并发 14 个探测互相挤占带宽"是同一个坑，只是规模这次由浏览器决定。
# 现在同一个池同时只放**一条**请求做抢连；其余的先等它的结论(最多 _RACE_WAIT
# 秒，抢到刚验活的通道就复用)，等不到就只单独轻试一个 IP，不再放第二批 SYN。
_RACE_LOCK = threading.Lock()
_RACE_BUSY = {}        # key -> 占用时刻(用来识别"占用者挂了没交还")
_RACE_STALE = 12.0     # 超过这么久没交还就当他已经不在了，闸门必须能自己解开
_RACE_WAIT = 2.5       # 别人在抢连时，我最多等它的结论这么久
_RACE_WAIT_SLICE = 0.1


def _race_take(key):
    """占住这个池的抢连名额；已经被别人占着就返回 False(不排队占坑，别拖)。"""
    now = time.time()
    with _RACE_LOCK:
        since = _RACE_BUSY.get(key)
        if since is not None and now - since < _RACE_STALE:
            return False
        _RACE_BUSY[key] = now
        return True


def _race_release(key):
    with _RACE_LOCK:
        _RACE_BUSY.pop(key, None)


def _race_gate_left(key):
    """名额什么时候能空出来(给人判断还要不要等); 没人占就是 0。"""
    now = time.time()
    with _RACE_LOCK:
        since = _RACE_BUSY.get(key)
        if since is None:
            return 0.0
        if now - since >= _RACE_STALE:
            return 0.0
        return max(0.0, _RACE_STALE - (now - since))


# ==================================================== 网页级实测台账 (2026-10-26)
# 【为什么要在体检之外再记一本账】
# 面板那格"可用 31/50"是**体检**数出来的: 挨个 IP 做 TCP + TLS + GET /, 答了话就算
# 可用。2026-10-26 下午把这把尺子的漏洞钉死了(本机 foxpath.log + 同一分钟手工实测):
#   · 16:42 体检报"可用 6/50", 同一分钟手工实测 github.com/kele551/hotnews 走代理:
#     6 发里 5 发直接被回 502, 剩下 1 发 13.5 秒才回首字节;
#   · 手工触发全池重测之后变 5 发 3 中(3.4s / 4.2s / 9.7s), 另外 2 发是
#     **收到 229KB / 278KB 之后断流** —— 握手对、证书对、GET / 也答了, 正文下到一半死。
# 结论: "IP 可用"和"网页打得开"是两本账, 后者才是用户感知的那一本。所以这里只记
# **真实转发**(浏览器那条 CONNECT)的结局, 一条探测都不掺:
#   ok      —— 隧道建起来、也确实往浏览器搬过数据, 最后由一端正常收尾
#   stall   —— 连上了但正文没搬动: 一个字节都没来 / 半途断流 / 空闲到点
#   refused —— 建连就没成, 代理只能回 502
#   badgw   —— 对面回 4xx/5xx 假前门(证书对、页面必定报错)
WEB_OK, WEB_STALL, WEB_REFUSED, WEB_BADGW = 'ok', 'stall', 'refused', 'badgw'
_WEB_LEDGER = {}           # key -> [(ts, kind, ms, nbytes)]  只留最近 _WEB_MAX 条
_WEB_LOCK = threading.Lock()
_WEB_WINDOW = 180.0        # 只按最近 3 分钟判定 —— 这条链路半衰期就几分钟, 老账会骗人
_WEB_MAX = 60
_WEB_MIN_SAMPLES = 3       # 少于 3 次不下结论, 只说"样本还少"

# 【2026-10-26 三点整改·① 配套的两个数】
_CONNECT_DEADLINE_MAX = 20.0    # 实测"慢但能成"时允许等多久(浏览器等得起, 用户等不起 30 秒)
_CONNECT_RETRY_ROUNDS = 2       # 一轮全灭之后, 预算还剩就再转几轮(每轮都过抢连闸门)
_CONNECT_RETRY_MIN_LEFT = 2.2   # 剩余预算少于这个就不再开新一轮
_CONNECT_RETRY_BACKOFF = 0.6    # 每轮起跑前等这么久, 给 hot_refresh/自愈把新鲜结论写进来的时间
_DIRECT_PROBE_FRESH = 150.0     # 直连探测结果的有效期(后台每 60 秒探一次, 取 2.5 个周期)


def _pool_key_for(host):
    """这个域名归哪个池管 —— 建连时限、网页台账、日志都要按池取, 别再各写一份判断。"""
    try:
        if is_raw_host(host):
            return 'raw'
        if is_pages_host(host):
            return 'pages'
        if is_github_host(host):
            return 'github'
    except Exception:
        return ''
    return ''


def _web_record(key, kind, ms=0.0, nbytes=0):
    """记一笔真实转发的结局。key 为空(非 GitHub 域名)时不记, 免得脏了三池的账。"""
    if not key or kind not in (WEB_OK, WEB_STALL, WEB_REFUSED, WEB_BADGW):
        return False
    now = time.time()
    with _WEB_LOCK:
        rows = _WEB_LEDGER.setdefault(key, [])
        rows.append((now, kind, max(0.0, float(ms or 0.0)), int(nbytes or 0)))
        if len(rows) > _WEB_MAX:
            del rows[:-_WEB_MAX]
        # 顺手剪掉过窗口的老账(只留 _WEB_WINDOW 秒内的)
        stale = [r for r in rows if now - r[0] > _WEB_WINDOW]
        if stale:
            _WEB_LEDGER[key] = rows = rows[len(stale):]
    return True


def _web_rows(key, now=None):
    """窗口内的真实转发样本( oldest → newest )。"""
    if now is None:
        now = time.time()
    with _WEB_LOCK:
        rows = list(_WEB_LEDGER.get(key) or [])
    return [r for r in rows if now - r[0] <= _WEB_WINDOW]


def _web_median_ms(rows):
    ok = sorted(r[2] for r in rows if r[1] == WEB_OK)
    if not ok:
        return None
    n = len(ok)
    return ok[n // 2] if n % 2 else (ok[n // 2 - 1] + ok[n // 2]) / 2.0


def _web_counts(key, now=None):
    """(总数, 成, 断流, 连不上, 假前门, 中位耗时秒 or None) —— 判定的唯一口径。"""
    rows = _web_rows(key, now)
    n = len(rows)
    ok = sum(1 for r in rows if r[1] == WEB_OK)
    stall = sum(1 for r in rows if r[1] == WEB_STALL)
    refused = sum(1 for r in rows if r[1] == WEB_REFUSED)
    badgw = sum(1 for r in rows if r[1] == WEB_BADGW)
    med = _web_median_ms(rows)
    return n, ok, stall, refused, badgw, (None if med is None else med / 1000.0)


def _web_verdict(key, now=None):
    """把真实转发的账换算成一句人话: (代码, 文字, 明细)。

    门槛为什么这么定: 这条链路是**时好时坏**, 一次成功说明不了什么, 一次失败也
    说明不了什么, 所以按窗口内的**成功占比**分档, 而不是"最后一条成没成"。
    样本不足 3 条时不下结论 —— 装机后第一次点开页面就被判"打不开"是冤枉。
    """
    n, ok, stall, refused, badgw, med = _web_counts(key, now)
    last = ('%.1f 秒' % med) if med is not None else '—'
    if n == 0:
        return ('unknown', '还没实测', '最近 %d 分钟没有真实网页请求' % int(_WEB_WINDOW / 60))
    rate = float(ok) / n
    if ok == 0:
        return ('down', '打不开',
                '%d 次全失败: 连不上 %d · 断流 %d · 假前门 %d' % (n, refused, stall, badgw))
    if n < _WEB_MIN_SAMPLES:
        return ('few', '样本还少', '最近只跑了 %d 次（成 %d），暂不下结论' % (n, ok))
    if rate >= 0.8:
        return ('good', '能打开', '最近 %d 次成 %d · 中位 %s' % (n, ok, last))
    if rate >= 0.5:
        # 措辞对着账走: 这一格现在唯一的职责是说实话。
        # 失败主要发生在握手阶段(refused)却说"常断流"，等于把用户往错误的方向上支使
        # (断流→刷新两下就好；连不上→多半是整条链路的事)。
        # 计数一律用"连不上"而不是"502": 502 是浏览器上看到的结果, 连不上才是原因,
        # 明细里再说一次 502 会让人以为有两种不同的故障。
        lab = max((('断流', stall), ('连不上', refused), ('假前门', badgw)),
                  key=lambda x: x[1])[0]
        return ('slow', '能打开，但常%s' % lab,
                '最近 %d 次成 %d · 断流 %d · 连不上 %d · 假前门 %d · 中位 %s'
                % (n, ok, stall, refused, badgw, last))
    return ('flaky', '时通时断',
            '最近 %d 次只成 %d · 连不上 %d · 断流 %d · 假前门 %d' % (n, ok, refused, stall, badgw))


def _web_status(key, now=None):
    """/api/status 与面板用的一等公民指标: 最近 3 分钟**真实转发**的结论。"""
    n, ok, stall, refused, badgw, med = _web_counts(key, now)
    code, text, detail = _web_verdict(key, now)
    return {'code': code, 'text': text, 'detail': detail, 'n': n, 'ok': ok,
            'stall': stall, 'refused': refused, 'badgw': badgw,
            'median_ms': (None if med is None else int(med * 1000)),
            'window': int(_WEB_WINDOW)}


def _web_dl_budget(key, base=None, now=None):
    """这次建连最多等多久 —— 用真实转发的账来定, 不再拍一个死数。

    · 最近成功的那几发本身就要 6~13 秒(本机 16:43 实测), 还按 8 秒一刀切就会把
      "再等两三秒就轮到刚验活的通道"那一批直接判死, 浏览器只收到一句 502;
      所以按实测中位给两倍余量, 上限 _CONNECT_DEADLINE_MAX。
    · 反过来, 窗口内几乎全灭时**不要**把预算抬到 20 秒: 那正是链路拥塞的时候,
      每条请求都等满 20 秒等于自己压自己(_prescan / hot_refresh 记过同一个坑),
      8 秒到点撒手、把带宽留给后台重测才对。
    """
    base = _CONNECT_DEADLINE if base is None else base
    rows = _web_rows(key, now)
    med = _web_median_ms(rows)
    out = base
    if med is not None:
        out = max(base, min(_CONNECT_DEADLINE_MAX, med / 1000.0 * 2.0))
    n = len(rows)
    fail = sum(1 for r in rows if r[1] != WEB_OK)
    if n >= 4 and fail and float(fail) / n >= 0.8:
        out = min(out, base)
    return out


def _direct_is_dead(key='github', now=None):
    """后台那条"绕开狐径直连 github"的探测刚说过不通 —— 就别把预算押在它身上。

    判据只用**新鲜**的探测结果(_DIRECT_PROBE_FRESH 秒内), 过期当"不知道",
    保持老行为去赌一把兜底: 那条路本来就是"和没装本程序一样"的退路。
    """
    if now is None:
        now = time.time()
    if _DIRECT_OK[0] is not False:
        return False
    return (now - (_DIRECT_OK[1] or 0.0)) <= _DIRECT_PROBE_FRESH


# ------------------------------------------------------- 断流 IP 的账(和握手失败分开)
# 【2026-10-26 三点整改·②】
# _FAIL_CNT 记的是"握手/建连失败", 一次失败降一名、几次失败靠边站, 这个口径没问题。
# 但"连上了、TLS 也做完了、正文下到一半死掉"是**另一回事**: 这种 IP 在 _FAIL_CNT 里
# 一分钱不欠(握手确实成功了), 于是体检名次照旧靠前、抢连一抢就赢, 赢完浏览器就转圈。
# 本机 2026-10-26 实测的两发就是这样: 收到 229KB / 278KB 之后断流。
# 这里单独记一本账, 只用来**降权**和**让它从池子里下岗**, 不学假前门那样拉黑 15 分钟
# —— 它是时好时坏, 拉黑太狠会把仅有的几个候选也清空(2026-10-25 记过"池子被清空要等
#  5 分钟才补上人"的坑)。
_STALL = {}                # ip -> [(时刻, 那次搬了多少字节), ...]
_STALL_LOCK = threading.Lock()
_STALL_WINDOW = 300.0      # 5 分钟内的断流还算数
_STALL_MIN_BYTES = 4096    # 不到 4KB 就断 = 根本没开始传, 比半途断流更差, 权重加倍
_STALL_DEMOTE_RANK = 1     # 有过一次断流就开始降权
_STALL_DROP_POOL = 2       # 窗口内两次断流 = 请出候选池(下一轮体检还会把它捞回来)


def _stall_note(ip, nbytes=0, now=None):
    if not ip:
        return 0
    if now is None:
        now = time.time()
    with _STALL_LOCK:
        lst = [x for x in _STALL.setdefault(ip, []) if now - x[0] <= _STALL_WINDOW]
        lst.append((now, int(nbytes or 0)))
        _STALL[ip] = lst
        return len(lst)


def _stall_rank(ip, now=None):
    """这个 IP 最近断流了几次(顺手把过期账剪掉)。用来和 _fail_rank 一起排候选。"""
    if not ip:
        return 0
    if now is None:
        now = time.time()
    with _STALL_LOCK:
        lst = _STALL.get(ip)
        if not lst:
            return 0
        keep = [x for x in lst if now - x[0] <= _STALL_WINDOW]
        if keep:
            _STALL[ip] = keep
        else:
            _STALL.pop(ip, None)
        return len(keep)


def _stall_bytes(ip, now=None):
    """最近一次断流时搬了多少字节(0 = 正文压根没来)。没账给 -1。"""
    if now is None:
        now = time.time()
    with _STALL_LOCK:
        lst = [x for x in (_STALL.get(ip) or []) if now - x[0] <= _STALL_WINDOW]
    return lst[-1][1] if lst else -1


def _stall_clear(ip):
    with _STALL_LOCK:
        _STALL.pop(ip, None)


# --------------------------------------------------------------- IP 寿命台账
# 【2026-10-11 修·"多久会被锁死、在锁死之前就换掉"】
# 用户的核心诉求不是"死了能救回来"，而是**别让它死在手上**：救回来要等超时
# (实测 8~16 秒)，浏览器体感就是"打不开"；而提前换掉是零感知的。
# 做法是给每个 IP 记一本寿命台账：
#   _IP_BORN  这个 IP 第一次**验证成功**的时刻
#   _LIFE_SAMPLES  它们各自"从出生到证实死亡"活了多久(秒)
# 于是能算出"这类 IP 平均能撑多久"，并在用到 80% 寿命时主动让位给热备 ——
# 也就是**在锁死之前下手**。
_IP_BORN = {}            # ip -> 出生时间戳
_LIFE_SAMPLES = []       # 每个元素 = 某个 IP 从出生到死亡的存活秒数
# 冷启动基准 = 300 秒。这不是拍脑袋: 用户实测"结束进程重启又打开了、大概维持了
# 5 分钟", 而第一轮自己的样本要等几个 IP 死掉才攒得出来 —— 在那之前先用这个
# 经验值顶上, 让预防性轮换**从第一次转发就生效**, 而不是先挨几轮锁死攒数据。
DEFAULT_LIFE = 300.0
_AVG_LIFE = [DEFAULT_LIFE]
_IP_LIFE_LOCK = threading.Lock()

# 热备池: 后台持续复检、保证"随时能顶上"的 IP。
# 体检是 5 分钟一轮的全池扫描, 中间那 5 分钟里名次是会过期的;
# 热备池只盯少数几个候选、20 秒复检一次, 始终有一批**刚刚验过**的 IP 待命。
_HOT = {'github': [], 'raw': [], 'pages': []}   # key -> [(ip, 复检时间戳)]
_HOT_LOCK = threading.Lock()

# ---- IP 吞吐台账: 每个 IP 量出来的真实下载速度 --------------------------------
# 【2026-10-11 修·把吞吐判据下沉到池内】
# 上一轮只修了"直连 vs 候选池"这一层对决, 池内几十个 IP 之间仍然按 TCP 握手
# 抢连 —— 于是实测出现"后台明明判池内有 194 KB/s, 端到端却走了 10.87 秒",
# 因为抢连让某个握手快、传不动的 IP 赢了。
# 现在给**每个验过的 IP** 都记一笔吞吐, 转发时先看台账: 谁实测最快就直连谁,
# 不再让握手速度替我们做决定。只测主站(github.com): raw / Pages 的 GET / 返回
# 404、拿不到字节, 硬测会误判成"传不动"。
_KBPS = {}                 # ip -> (kbps, ts)
_KBPS_LOCK = threading.Lock()
_KBPS_TTL = 150.0          # 吞吐会随时间变, 超过这个时间没重测就不作数
_KBPS_DIRECT_MIN = 60      # 低于这个速度谈不上"快", 不值得绕开抢连
_KBPS_WIN_RATIO = 1.15     # 池内取最快时要领先次快 15%, 否则可能是测量噪声

# 【2026-10-24 新增】"实测成过"的新鲜窗口。定 90 秒的依据是这台机器的实测:
# IP 寿命台账跑出来 148~227 秒(面板"IP 寿命基准"那一行), 而体检周期最长 5 分钟 ——
# 窗口取到寿命的一半以内, 才不会把"上一轮活着、这一轮早死了"的 IP 算成能打开页面。
_FRESH_WINDOW = 90.0

# 【2026-10-24 新增·"证书对、页面不给你"的那类 IP，实测拉黑】
# 起因：装机版跑起来后 github.com 满屏 400（"Bad request · GitHub"），可狐径自己一路绿灯。
# 实测（本地复现脚本 fx_probe_replica，一次性探针、不入库，连打 8 发）抓到两个这样的 IP：
#   20.200.245.244 → 8/8 次 400（握手最快，体检报 256ms）
#   20.205.243.161 → 8/8 次 400（体检报 281ms）
#   20.200.245.247 / 140.82.113.4 / 20.29.134.23 / 4.249.131.164 / 20.205.243.166 → 8/8 次 200
# 它们是 Azure 前门里**不负责 github.com 页面**的节点：TCP 通、TLS 通、证书里也确实有
# github.com，所以体检只要有一发把它放过去，抢连（只比握手快慢）就会反复选中它。
# 而转发是加密隧道，里面那个 400 我们根本看不见 —— 日志一切正常，用户却打不开仓库。
_BAD_EDGE = {}             # ip -> (拉黑到期时刻, 实测到的状态码)
_BAD_EDGE_TTL = 900.0      # 15 分钟后放它重新参加体检（这类节点会换人）
_BAD_EDGE_LOCK = threading.Lock()


def _bad_edge_note(ip, status=''):
    """实测回 4xx/5xx 的 IP 记进黑名单，带上状态码好从日志里看出为什么被拉黑。"""
    if not ip:
        return
    with _BAD_EDGE_LOCK:
        _BAD_EDGE[ip] = (time.time() + _BAD_EDGE_TTL, status)


def _bad_edge(ip):
    """这个 IP 还在黑名单里吗？过期就顺手清掉。"""
    with _BAD_EDGE_LOCK:
        exp = _BAD_EDGE.get(ip)
        if not exp:
            return False
        if time.time() >= exp[0]:
            _BAD_EDGE.pop(ip, None)
            return False
        return True


# 【2026-10-24 三修·④b 探针要有全局闸门】
# ④b 那轮"先发 GET / 问谁真答话"是**每条转发请求各自起一个并发 3~4 的批次**。
# 单看一条请求没错，可浏览器打开一个 GitHub 页面就是十几条并发请求：池子刚好
# 处于 fast(90 秒没 HTTP 证据)时，就是十几个批次同时探同一批 IP —— 探测自己把
# 国际链路挤拥塞，fast 就更解不开，单请求从 ~12 秒涨到 ~16 秒以上。
# 这和 10-11 记过的"并发 14 个探测互相拖慢"是同一个坑，只是这次规模由浏览器决定。
# 全局只放一轮在跑：抢不到闸门的那些请求**直接跳过实测**、按老路做 TCP 抢连，
# 不多等一秒(实测批次本身要 1.5~3.5 秒，串行排队只会更糟)。
_PRESCAN_LOCK = threading.Lock()
_PRESCAN_BUSY = [False]


def _prescan_take():
    """占④b 探针的坑；已经有人在测就返回 False(调用方跳过实测，别排队等)。"""
    with _PRESCAN_LOCK:
        if _PRESCAN_BUSY[0]:
            return False
        _PRESCAN_BUSY[0] = True
        return True


def _prescan_release():
    with _PRESCAN_LOCK:
        _PRESCAN_BUSY[0] = False


def _kbps_set(ip, kbps):
    if not ip or not kbps:
        return
    with _KBPS_LOCK:
        _KBPS[ip] = (kbps, time.time())


def _kbps_of(ip):
    """这个 IP 的实测吞吐; 没量过或已过期返回 None。"""
    if not ip:
        return None
    with _KBPS_LOCK:
        hit = _KBPS.get(ip)
    if not hit:
        return None
    kbps, ts = hit
    if time.time() - ts >= _KBPS_TTL:
        return None
    return kbps


def _kbps_ts(ip):
    with _KBPS_LOCK:
        hit = _KBPS.get(ip)
    return hit[1] if hit else 0.0


def _kbps_forget(ip):
    """这个 IP 刚让我们赌输了 —— 立刻作废它的证据, 别让下一次转发再赌一遍。

    【2026-10-11 修·赌输要付学费, 但只付一次】
    实测第 6 次经狐径 28.01s、直连只要 21.07s: 台账里那笔"107 KB/s"还在
    150 秒有效期内, 可链路其实已经断了, 于是每一发请求都先白等一轮超时。
    赌输一次就把它忘了, 代价从"每次都赔"降到"只赔一次"。
    """
    if not ip:
        return
    with _KBPS_LOCK:
        _KBPS.pop(ip, None)


def _kbps_pick(cand):
    """从候选里挑"实测吞吐最快"和"次快"的两个 —— 用来决定是否跳过抢连、直接连。

    没量过 / 证据过期 / 最近在连着失败的, 一律不参与。
    """
    best, second = None, None
    for x in cand or ():
        k = _kbps_of(x)
        if not k or _fail_rank(x):
            continue
        if best is None or k > best[1]:
            second, best = best, (x, k)
        elif second is None or k > second[1]:
            second = (x, k)
    return best, second


def _ip_born(ip):
    """IP 第一次被证实可用 —— 记下出生时刻。"""
    if not ip:
        return
    with _IP_LIFE_LOCK:
        if ip not in _IP_BORN:
            _IP_BORN[ip] = time.time()


def _ip_died(ip, sure=False):
    """IP 已证实失效: 结掉它这一生, 把"活了多久"记进样本。

    2026-10-11 实测抓到的漏子: 热备复检发现**当前正在用的那个 IP** 已经不通,
    把它从寿命台账里注销了, 却**没让它下岗** —— _LAST_GOOD 还指着它, 于是
    下次转发照样优先去撞这个死 IP, 而且面板还显示它"刚出生、还能撑满一整段"。
    所以这里一旦发现死的就是在用的那个, 立刻让它下岗。
    """
    if not ip:
        return
    for _k in ('github', 'raw', 'pages'):
        if _LAST_GOOD.get(_k) == ip:
            _LAST_GOOD[_k] = ''
            log('在用 IP %s 复检已不通, 提前下岗(下次转发改抢新鲜的)' % ip)
    with _IP_LIFE_LOCK:
        born = _IP_BORN.pop(ip, None)
        if not born:
            return
        life = time.time() - born
        # 太短的多半是偶发丢包误判, 计进去会把平均值拉得毫无意义
        if life >= 10:
            _LIFE_SAMPLES.append(life)
            if len(_LIFE_SAMPLES) > 40:
                _LIFE_SAMPLES.pop(0)
            _AVG_LIFE[0] = sum(_LIFE_SAMPLES) / len(_LIFE_SAMPLES)


def _avg_life():
    with _IP_LIFE_LOCK:
        return _AVG_LIFE[0]


def _life_samples():
    with _IP_LIFE_LOCK:
        return len(_LIFE_SAMPLES)


def _ip_age(ip):
    with _IP_LIFE_LOCK:
        b = _IP_BORN.get(ip)
    return (time.time() - b) if b else 0.0


def _ip_remaining(ip):
    """按历史规律, 这个 IP 还能撑多久(秒)。

    返回 None 有两种情况, 面板都要如实显示"未知"而不是编一个数字:
      ① 还没有寿命样本; ② 这个 IP 没有出生记录(已失效或从未用过)。
    """
    avg = _avg_life()
    if not avg:
        return None
    with _IP_LIFE_LOCK:
        if ip not in _IP_BORN:
            return None
    return avg - _ip_age(ip)


def _ip_expiring(ip):
    """是不是已经用掉了大半寿命 —— 是的话就该在它死之前让位。"""
    avg = _avg_life()
    if not avg or not ip:
        return False
    # 没有自己的样本时用 300 秒的冷启动基准(用户实测"大约维持 5 分钟"),
    # 攒到样本后自动换成这台机器上真实测出来的均值。
    return _ip_age(ip) >= avg * 0.8


def _hot_get(key, max_age=120.0):
    """取热备池里**最近 max_age 秒内验过**的 IP, 新鲜的排前面。"""
    now = time.time()
    with _HOT_LOCK:
        return [ip for ip, ts in _HOT.get(key, []) if now - ts <= max_age]


def _hot_drop(key, ip):
    with _HOT_LOCK:
        _HOT[key] = [(i, t) for i, t in _HOT.get(key, []) if i != ip]


# 【2026-10-25 新增】转发"全灭"后临时补热备的闸门: 同一池 30 秒内只补一次。
# 每条失败请求各起一个并发 4 的探针批次, 在链路本来就拥塞的时候等于自己给自己添堵
# (本机日志 19:47:27~30 一秒内 raw 连吃 7 条全灭 → 7 个批次 28 个探测同时上路)。
# 30 秒 = 热备复检(20 秒)一轮半, 足够让上一批探针跑完再决定要不要补第二批。
_HOT_REFILL_COOLDOWN = 30.0
_HOT_REFILL_TS = {}


def hot_refresh(key, pool, want=4):
    """复检热备池: 只盯少数候选(并发 4, 不惊动整条链路), 补满 want 个待命 IP。

    为什么不做全池扫描: 全池 49 个并发探测在国际链路上会自己把自己挤拥塞
    (实测并发 14 个时转发退化到 7~10 秒)。热备池只维持 4 个, 成本可忽略。
    """
    fresh = _hot_get(key)

    # 【2026-10-11 修·热备也要量吞吐, 而且要复测】
    # 光"能连上"不够 —— 连得上和传得动是两回事(握手 0.12s 却 25 秒下不完的 IP
    # 今天坑过一次)。所以进热备的 IP 都要量一次真实吞吐, 记进台账供转发决策。
    # 吞吐还会随时间变, 所以每轮顺手重测**证据最旧**的那个, 否则台账会一直
    # 停在几十秒前的老数字上。只对主站测: raw / Pages 的 GET / 拿不到字节。
    if key == 'github' and fresh:
        oldest = min(fresh, key=_kbps_ts)
        if _kbps_of(oldest) is None or time.time() - _kbps_ts(oldest) > _KBPS_TTL * 0.6:
            _measure_hot([oldest], 'github.com')
    if len(fresh) >= want:
        # 【2026-10-24 修·够数不等于证据新鲜】
        # 热备条目 120 秒内都算"热", 所以够数时这里原来直接 return —— 于是每个
        # 热备 IP 实际 2~3 分钟才被复验一次, 而"实测成过"的窗口只有 90 秒。
        # 隔离实测(18:50:48)复现到的现象: 一切正常、页面 200, 面板却写"实测成过 0"
        # —— 那是另一种说假话。够数的时候也复验**证据最旧**的那 1 个,
        # 成本 1 次探测 / 20 秒(远低于一轮全池体检), 换来"实测成过"始终有个下限。
        if pool.checks_http and fresh:
            _old = min(fresh, key=lambda i: pool.tier_of(i)[1])
            _ot, _ots = pool.tier_of(_old)
            if _ot != 'http' or time.time() - _ots > _FRESH_WINDOW * 0.6:
                pool._probe(_old, timeout=3.0)
        return fresh
    # 从体检名次里跨网段取样, 优先补"没在热备里"的, 一段全死还有别的段
    spread = _pick_spread(pool.candidates()[:20], per_group=1, limit=8)
    todo = [ip for ip in spread if ip not in fresh][:6]
    if not todo:
        return fresh
    ok = []

    def _chk(ip):
        # 完整验一遍: TCP + TLS + 证书 + GET / 要 2xx/3xx —— 与体检同一把尺子
        if pool._probe(ip, timeout=3.0) is not None:
            ok.append(ip)
            # 【2026-10-11 修·寿命台账也要给热备记出生】
            # 原先只有"转发成功"才 _ip_born, 于是用户不访问时(实测 36 分钟零转发)
            # 一个样本都攒不出来, 面板上的寿命基准**一直停在 300 秒经验值** ——
            # 用户问的"多久会被锁死"永远给不出这台机器的真答案。
            # 热备每 20 秒复检一次, 让它也记出生, 复检失败时就能结出样本,
            # 寿命基准很快收敛到真实值。
            _ip_born(ip)
        else:
            _ip_died(ip)

    try:
        with ThreadPoolExecutor(max_workers=4) as ex:
            list(ex.map(_chk, todo))
    except Exception:
        pass
    if ok and key == 'github':
        _measure_hot(ok, 'github.com')
    now = time.time()
    with _HOT_LOCK:
        have = {i for i, _t in _HOT.get(key, [])}
        for ip in ok:
            if ip not in have:
                _HOT[key].append((ip, now))
        _HOT[key] = [(i, t) for i, t in _HOT[key] if now - t <= 180][-8:]
        return [i for i, _t in _HOT[key]]


def _measure_hot(ips, host):
    """给少数几个 IP 量真实吞吐, 写进台账。

    并发刻意压到 2、窗口压到 1.2 秒: 国际链路上并发测速会**互相挤占带宽**,
    今天已经在"并发做 TLS 握手"上栽过一次(探测本身成了负担, 反而更慢)。
    """
    def _one(ip):
        try:
            r = _cap_test(host, ip, window=1.2, max_bytes=131072, min_ok=4096)
        except Exception:
            return
        if r and r.get('ok'):
            _kbps_set(ip, r['kbps'])
    try:
        with ThreadPoolExecutor(max_workers=2) as ex:
            list(ex.map(_one, list(ips)[:4]))
    except Exception:
        pass


# 【2026-10-11 修·让用户一眼分清"狐径坏了"还是"网络不通"】
# 用户反复报"打不开网页", 但同一时刻直连也是超时的 —— 那是线路在抽风, 狐径换什么
# IP 都没用。可用户看不到这一层, 只会觉得"狐径没用"。这里后台定期**绕开狐径**、
# 用系统 DNS 直连试一下 github.com: 直连也不通就在面板上明说, 别让用户自己猜。
_DIRECT_OK = [None, 0.0]     # [是否通, 上次探测时刻]


def direct_probe_once():
    """绕开代理, 用系统解析直连 github.com 探一次。通不通都记下来。"""
    try:
        raw = socket.create_connection(('github.com', 443), timeout=4.0)
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(raw, server_hostname='github.com') as s:
                s.settimeout(3.0)
                s.sendall(b'GET / HTTP/1.1\r\nHost: github.com\r\n'
                          b'User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n')
                first = s.recv(32)
            # 拿到任何 HTTP 响应都算"通"(4xx 也是对面答的, 只说明对面活着)
            ok = bool(first[:1] in (b'2', b'3', b'4'))
        except Exception:
            ok = False
        finally:
            try:
                raw.close()
            except Exception:
                pass
    except Exception:
        ok = False
    _DIRECT_OK[0] = ok
    _DIRECT_OK[1] = time.time()
    return ok


def direct_probe_loop():
    while True:
        try:
            direct_probe_once()
        except Exception:
            pass
        time.sleep(60)


# 【2026-10-11 补·"连得上"不等于"打得开"】
# 实测抓到的现场: TCP 握手 0.10 秒、TLS 握手 0.19 秒, 全都正常(说明 IP 没被锁死),
# 可同一个连接的页面数据要 6~25 秒才下得完 —— 浏览器表现就是转圈半天、最后超时,
# 用户看到的只有"打不开"。只测"通不通"会给假绿灯(握手成功 = 通), 所以这里再
# **真下载一小段首页**, 量出两个更贴近体感的数:
#   ① 首字节多久来(ttfb): 对面响不响应
#   ② 平均下载速度(KB/s): 数据下不下的来
# 而且**走狐径**和**直连**各测一次 —— 两者一对比, "是线路拥塞"还是"狐径没帮上忙"
# 就一目了然, 不用再靠猜。
_SPEED = {'direct': {'ts': 0.0}, 'proxy': {'ts': 0.0}}
_SPEED_BUSY = [False]
_SPEED_BUSY_LOCK = threading.Lock()


def _err_text(e):
    """异常转成人看得懂的短句。

    不能直接用 str(e): socket.timeout 的 str 经常是**空字符串**, 面板就会显示
    "失败(不通)" —— 看着像代理没开, 其实是超时。空的就退回异常类名并翻译成
    中文, 免得用户对着一个空括号猜。
    """
    s = (str(e) or '').strip()
    if not s:
        s = type(e).__name__
    trans = {'timeout': '超时', 'TimedOutError': '超时', 'gaierror': 'DNS 解析失败',
             'ConnectionRefusedError': '连接被拒绝', 'ConnectionResetError': '连接被重置',
             'OSError': '系统网络错误', 'SSLError': 'TLS 握手失败'}
    return trans.get(s, s)[:60]


def _speed_download(use_proxy, max_bytes=65536, overall=20.0):
    """连 github 首页真下载最多 64KB, 量首字节与速度。

    use_proxy=True 走本机狐径(对 127.0.0.1:PROXY_PORT 发 CONNECT), False 直连。
    下到一半超时不算失败 —— 照样如实记下"这么多秒只下了这么多", 因为那正是
    用户"转圈半天"的那一段, 记成失败反而看不到真相。
    """
    t0 = time.time()
    s = None
    peer = ''
    try:
        if use_proxy:
            raw = socket.create_connection(('127.0.0.1', PROXY_PORT), timeout=6.0)
            # create_connection 的 timeout 只管"连上"这一步, 连上之后 socket 又变回
            # 阻塞模式 —— 不给 recv 设超时的话, 对面不回就永远卡在这儿, 整个测速线程
            # 挂死(实测出现过: 一轮测速卡住, 直连那条一直没结果)。
            raw.settimeout(10.0)
            raw.sendall(b'CONNECT github.com:443 HTTP/1.1\r\n'
                        b'Host: github.com:443\r\n\r\n')
            head = b''
            while b'\r\n\r\n' not in head and time.time() - t0 < 10:
                c = raw.recv(1024)
                if not c:
                    break
                head += c
            if b'200' not in head.split(b'\r\n')[0]:
                return {'ok': False, 'err': '代理隧道没建起来', 'peer': '狐径'}
            peer = '狐径'
        else:
            raw = socket.create_connection(('github.com', 443), timeout=6.0)
            raw.settimeout(10.0)      # 同上: 连上之后也要给 recv 设上限
            try:
                peer = raw.getpeername()[0]
            except Exception:
                peer = ''
        try:
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(raw, server_hostname='github.com')
            s.settimeout(overall)
            t1 = time.time()
            s.sendall(b'GET / HTTP/1.1\r\nHost: github.com\r\n'
                      b'User-Agent: Mozilla/5.0\r\nAccept: */*\r\n'
                      b'Connection: close\r\n\r\n')
            got = 0
            ttfb = None
            while got < max_bytes:
                c = s.recv(8192)
                if not c:
                    break
                if ttfb is None:
                    ttfb = time.time() - t1
                got += len(c)
                if time.time() - t1 > overall:
                    break
            total = max(0.001, time.time() - t1)
            return {'ok': got > 0, 'bytes': got, 'total': round(total, 2),
                    'ttfb': None if ttfb is None else round(ttfb, 2),
                    'kbps': round(got / 1024.0 / total, 1), 'peer': peer}
        except Exception as e:
            return {'ok': False, 'err': _err_text(e), 'peer': peer}
        except Exception as e:
            return {'ok': False, 'err': _err_text(e), 'peer': peer}
    finally:
        try:
            if s is not None:
                s.close()
        except Exception:
            pass


def speed_probe_once():
    """走狐径、直连各测一次, 结果进 _SPEED 供面板显示。"""
    out = {}
    for name, use in (('proxy', True), ('direct', False)):
        try:
            r = _speed_download(use)
        except Exception as e:
            # 双保险: 测速是后台守护, 任何漏网的异常都不能让它写不进结果 ——
            # 写不进的话面板会一直显示上一轮(可能是很久以前)的数字, 反而误导人。
            r = {'ok': False, 'err': _err_text(e), 'peer': ''}
        r['ts'] = time.time()
        _SPEED[name] = r
        out[name] = r
    p, d = out['proxy'], out['direct']
    def _txt(r):
        if not r.get('ok'):
            if r.get('total'):
                # 连上了、隧道也建了, 却一个字节都没等到 —— 这正是"转圈半天最后
                # 打不开"的那一种。显示成"不通"会让人以为代理没开, 得说清是超时。
                return '超时(等了 %ss 零字节)' % r['total']
            return '失败(%s)' % (r.get('err') or '不通')
        return '%dKB/%ss ≈ %sKB/s(首字节 %ss)' % (
            int(r.get('bytes', 0) / 1024), r.get('total'),
            r.get('kbps'), r.get('ttfb'))
    try:
        log('线路测速: 经狐径 %s · 直连 %s' % (_txt(p), _txt(d)))
    except Exception:
        pass
    return out


def speed_probe_loop():
    # 启动先缓 25 秒: 别跟启动预体检抢带宽(那会儿正在并发探 49 个 IP)
    time.sleep(25)
    while True:
        try:
            speed_probe_once()
        except Exception as e:
            log('线路测速异常: %s' % e)
        time.sleep(150)


def speed_probe_async():
    """面板「立即测速」用: 后台测, 不卡住页面。"""
    with _SPEED_BUSY_LOCK:
        if _SPEED_BUSY[0]:
            return False
        _SPEED_BUSY[0] = True

    def _run():
        try:
            speed_probe_once()
        finally:
            _SPEED_BUSY[0] = False
    threading.Thread(target=_run, daemon=True).start()
    return True


# ------------------------------------------------- 直连的"传输能力"体检
# 【2026-10-11 修·握手快 ≠ 传得动】
# 第一版让系统解析的 IP 直接进抢连名单, 实测当场吃到一个 **30 秒超时**:
# 系统把 github.com 解析到 20.205.243.166, 它 TCP 握手只要 0.12s(全场最快),
# 于是赢下竞速; 可它的页面要 25 秒还下不完。而体检只 recv(64) 字节就判可用,
# 根本筛不掉这类"握手快、传不动"的 IP。
# 所以直连要参与竞速, 必须先拿出"真能传数据"的证据: 后台真下载一段再下结论。
_SYS_CAP = {}          # host -> {'ip','ok','kbps','bytes','cost','ts'}
_SYS_CAP_TTL = 120.0   # 证据有效期: 超过这个时间没复测就先不采信
_SYS_WIN_RATIO = 1.25  # 直连要快过候选池 25% 才值得换, 否则两边抖来抖去反而不稳
_SYS_MIN_KBPS = 60     # 直连自己低于这个速度就没必要绕开池子(60KB/s 约等于能开但会转圈)


def _cap_test(host, ip, window=2.5, max_bytes=262144, min_ok=8192, deadline=8.0,
              connect_timeout=6.0):
    """测某个 IP 到底能不能真的把数据传下来, 而不是只握得上。

    【2026-10-11 再修·测持续吞吐, 别测"凑够字节的时间"】
    上一版是"读满 32KB 就停", 日志里恒定显示 37KB。问题在于这测的是
    **达到阈值所花的时间**(含 TLS 后的首字节等待), 不是稳态速度, 会系统性
    **低估**快 IP: 同一个 20.205.243.166, 体检测出 48 KB/s, 实际跑 161 KB/s。
    低估直连 = 永远轮不到它上位。
    现在改成**固定读满 window 秒**, 到点或读够上限才收, 得到的是真实吞吐。

    【2026-10-24 三修·把连接超时也交出来】原来 connect 硬编码 6 秒、不跟 window 走，
    通道重匹配一轮 8 个样本最坏能磨到 ~56 秒(一池)、三池串起来 ~3 分钟，
    名义"每 10 分钟"实际变成 13 分钟，而且这 3 分钟一直在抢转发带宽。
    默认值维持 6.0(不改既有调用点的行为)，只让通道轮自己压到 2.5 秒。
    """
    try:
        raw = socket.create_connection((ip, 443), timeout=connect_timeout)
    except OSError:
        return None
    try:
        s = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
        s.settimeout(deadline)
        s.sendall(('GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n'
                   'Accept: text/html\r\nConnection: close\r\n\r\n' % host)
                  .encode('ascii'))
        got = 0
        t1 = time.time()
        while True:
            c = s.recv(65536)
            if not c:
                break
            got += len(c)
            if got >= max_bytes:
                break
            if time.time() - t1 >= window:
                break
        cost = max(0.001, time.time() - t1)
        r = {'bytes': got, 'cost': round(cost, 2), 'ok': got >= min_ok}
        if r['ok']:
            r['kbps'] = int(got / 1024 / cost)
        return r
    except Exception as e:
        return {'ok': False, 'bytes': 0, 'cost': 0, 'err': type(e).__name__}
    finally:
        try:
            raw.close()
        except Exception:
            pass


_POOL_CAP = {}         # host -> {'ip','ok','kbps','bytes','cost','ts'}  池内首选的对照体检


def sys_cap_loop():
    """后台定期测"系统解析出来的 IP 传不传得动", 有证据才让它进竞速名单。

    只测 github.com 主站: raw / Pages 的候选池里已有 IPv6 通道且表现很好,
    而它们的 GET / 会返回 404、拿不到可观的字节数, 硬测只会误判成"传不动"。

    【2026-10-11 再修·两边都测, 才好比】
    只测直连没法裁决 —— 没有对手就没有"谁更快"。现在**同一轮里连着测两次**:
    系统解析的 IP 一次、池内当前首选一次, 两边用同一把尺子(固定窗口吞吐)。
    转发时谁快用谁, 不再让抢连(比握手快慢)替我们做这个决定。
    """
    time.sleep(20)     # 别跟启动预体检抢带宽
    while True:
        try:
            host, key = 'github.com', 'github'
            ips = ProxyHandler._sys_ips(host, force=True)
            if ips:
                r = _cap_test(host, ips[0])
                if r:
                    r['ip'] = ips[0]
                    r['ts'] = time.time()
                    _SYS_CAP[host] = r
                else:
                    _SYS_CAP.pop(host, None)
            # 池内对手: 上次真正连通过的优先, 没有/撞车就退到体检名次里找。
            # 【2026-10-11 修·对手不能是自己】
            # 系统解析出来的 IP 往往也正是池子里刚连成功的那个(_LAST_GOOD),
            # 于是一轮里两个"对手"是同一个 IP: 68 vs 27 KB/s 全是噪声, 而 sys_wins
            # 恒为真 —— 对比形同虚设。所以池内必须挑一个**跟直连不同**的 IP。
            sys_ip = (ips or [''])[0]
            p_ip = _LAST_GOOD.get(key) or ''
            if (not p_ip) or p_ip == sys_ip:
                p_ip = ''
                try:
                    for c in (HEALTH.candidates() or []):
                        if c != sys_ip:
                            p_ip = c
                            break
                except Exception:
                    p_ip = ''
            if p_ip and p_ip != sys_ip:
                pr = _cap_test(host, p_ip)
                if pr:
                    pr['ip'] = p_ip
                    pr['ts'] = time.time()
                    _POOL_CAP[host] = pr
                else:
                    _POOL_CAP.pop(host, None)
            else:
                _POOL_CAP.pop(host, None)   # 没有可比的对手, 别拿旧证据糊弄
            s, p = _SYS_CAP.get(host), _POOL_CAP.get(host)
            # 两边都写进统一台账, 转发时跟热备一起按吞吐排序 —— 别各管一摊
            for r in (s, p):
                if r and r.get('ok') and r.get('ip'):
                    _kbps_set(r['ip'], r.get('kbps', 0))
            _t = lambda r: ('%d KB/s' % r.get('kbps', 0)) if (r and r.get('ok')) else \
                           ('传不动' if r else '连不上')
            log('吞吐对比 %s: 直连 %s(%s) vs 候选池 %s(%s) -> 选 %s' % (
                host,
                (s or {}).get('ip', '-'), _t(s),
                (p or {}).get('ip', '-'), _t(p),
                _cap_verdict(s, p)))
        except Exception as e:
            log('吞吐对比异常: %s' % e)
        time.sleep(60)


def _cap_fresh(r):
    """一份体检证据还作数吗（无效/没 IP/过了 TTL 都算没有，返回 None）。

    从 `_cap_of` 里拆出来：`_cap_of` 是"按 host 去表里查"，这一层是"手里这份还新不新"。
    日志那半份要把**刚才比的那两份**原样判一遍，不能再去查一次表。
    """
    if not r or not r.get('ok') or not r.get('ip'):
        return None
    if time.time() - (r.get('ts') or 0) >= _SYS_CAP_TTL:
        return None
    return r


def _cap_of(host, tbl):
    """取一份还新鲜的体检证据; 过期或无效返回 None。"""
    return _cap_fresh(tbl.get(host))


def _wins_by_evidence(s, p):
    """判据本体：拿着两份证据判"直连是不是**明显**快过候选池"。

    必须留余量(_SYS_WIN_RATIO): 两边速度本来就在抖, 谁高一点就切谁会导致
    来回横跳, 反而更不稳定。要快出一截才值得换。
    """
    if not s:
        return False
    if not p:
        return True                      # 池子没证据, 直连有 —— 可以试
    if s.get('ip') == p.get('ip'):
        return False                     # 对手是自己, 这轮对比不作数
    sp, pp = s.get('kbps', 0), p.get('kbps', 0)
    if sp < _SYS_MIN_KBPS:
        return False                     # 直连自己也不快, 没必要绕开池子
    return sp >= pp * _SYS_WIN_RATIO


def _sys_wins(host):
    """直连是不是**明显**快过候选池 —— 是就让它上位（判据见 `_wins_by_evidence`）。"""
    return _wins_by_evidence(_cap_of(host, _SYS_CAP), _cap_of(host, _POOL_CAP))


def _cap_verdict(s, p):
    """把这一轮吞吐对比说成一句人话（2026-10-25 待办 #64）。

    `s`/`p` 就是日志前半句里那两份证据（可能为 None），传进来而不是再查一遍表：
    印出来的结论必须和旁边的数字是同一次测量的，隔几秒重查表可能对不上。

    为什么要有"不作数"这两档：以前结尾无条件按 `_sys_wins()` 印，于是两边都没证据的
    那一轮也会印成「-> 选 候选池」—— 可这一轮什么都没比出来（判据走的是
    "直连没证据"那支返回 False），线路也根本没动。用户拿这句日志排查时就被带偏了。
    """
    if not s and not p:
        return '两边都没测到，本轮不作数'
    s, p = _cap_fresh(s), _cap_fresh(p)
    if not s and not p:
        return '两边都没测到，本轮不作数'
    if s and p and s.get('ip') == p.get('ip'):
        return '两边是同一个 IP，本轮不作数'
    return '直连' if _wins_by_evidence(s, p) else '候选池'


# ------------------------------------------------- 每 10 分钟重匹配"跑得通的通道"
# 【2026-10-24 新增·改法⑤】用户的要求很具体: "最好每隔 10 分钟自动刷新, 匹配可以跑通的 IP 通道"。
# 先把"为什么这不是重复造轮子"说清楚 —— 现有三套后台循环各管一层, 谁都不干这件事:
#   · 体检 health_loop(5 分钟): 排的是"延迟 + 证书对不对", 全程只 recv 64 字节看状态行,
#     一个 IP 有没有正文可传, 它不知道;
#   · 热备 hot_loop(20 秒): 只复检**已经在名单里**的那 4 个, 不会去池子里发现新通道;
#   · 吞吐对比 sys_cap_loop(60 秒): 一次只量 2 个 IP(系统解析 1 个 + 池内首选 1 个),
#     它是"直连要不要切边"的裁决器, 不是"池里谁最能跑"的普查。
# 也就是说: **没有任何一处**会把一批 IP 放到同一把尺子下真下载一遍、再按谁传得动换岗。
# 今晚的日志正好把这个缺口照出来了(21:47~22:05): 池子 20 来个 IP 全是 'tls' 证据、
# 真能吐正文的一个没有, 满屏"候选 IP 全军覆没"; 到 22:20 同一份代码 200 只要 2~6 秒。
# IP 会换人、通道会一段段死掉, 所以匹配必须**周期性重做**, 而不是等用户点开页面挨一次超时。
#
# 成本红线(每一条都是踩过坑才写死的, 见 _measure_hot / hot_refresh 的注释):
#   并发压到 2、单窗 2 秒、每池每轮最多 8 个样本、三个池错开 3 秒 ——
#   实测并发 14 个探测会自己把国际链路挤拥塞(转发退化到 7~10 秒), 那样就本末倒置了。
_CHAN_INTERVAL = 600.0    # 用户要的 10 分钟一轮
_CHAN_MIN_KBPS = 40       # 低于这个速度谈不上"跑得通": 首页勉强刷出来、图片开始转圈的分界
_CHAN_FALLBACK_KBPS = 8   # 全线拥塞时的底线: 至少真传得到字节, 才值得为它换岗
_CHAN_SAMPLES = 8         # 每池每轮最多真下载几个 IP(再多就是自己挤自己)
_CHAN_HYSTERESIS = 1.6    # 最佳要快过在用 60% 才值得换岗, 否则两边抖动会来回横跳


def _chan_skeleton(key, host):
    """一个池"还没测过"的初始快照。

    【2026-10-24 三修·键先占好】原来 `_CHAN = {}` 由通道线程第一轮时才插键,
    而面板那条 `/api/status` 正在迭代 `_CHAN.items()` —— 字典在迭代中变大是
    `RuntimeError: dictionary changed size during iteration`, 那一发刷新直接 500。
    键一开始就摆满三个, 之后只覆盖同键的值(CPython 里同键赋值不改大小), 这条
    竞态就不存在了; 顺带让面板/接口在没有数据时也有明确的"还没跑过"可显示。
    """
    return {'key': key, 'host': host, 'ts': 0, 'sampled': 0, 'pass': 0, 'weak': 0,
            'ip_best': '', 'kbps_best': 0, 'in_use': '', 'swapped': '', 'list': [],
            'note': '还没跑过第一轮(启动约 1 分钟后开测)', 'running': 0}


_CHAN = {k: _chan_skeleton(k, h) for k, h in (
    ('github', 'github.com'), ('raw', 'raw.githubusercontent.com'),
    ('pages', 'github.io'))}   # key -> 本轮结果快照(供 /api/status 与面板如实显示, 不粉饰)


def _chan_public(snap):
    """把内部快照转成给面板的副本: 列表要拷一份, 否则面板拿到的可能是正在被改的同一对象。"""
    out = dict(snap or {})
    out['samples'] = [dict(x) for x in (snap or {}).get('list') or []]
    out.pop('list', None)
    return out


def channel_scan_once(key, pool, host):
    """给一个池子做一轮"跑得通"重匹配: 跨网段取样 → 真下载 → 记台账 → 必要时主动换岗。

    取样为什么用 _pick_spread 而不是直接取名次最前的 8 个:
    候选是按延迟排的, 延迟低的往往扎堆在同一段(20.27.* 死的时候 140.82.* 还好好的),
    只取"前 N 个"会正好全落在死的那一段里, 于是这一轮白测。
    在用的那个 IP **一定要一起量**, 否则"最佳"是刚测的、"在用"是几分钟前的,
    拿新旧不同的证据比高低 = 必然误判换岗。
    """
    started = time.time()
    try:
        cands = pool.candidates() or []       # candidates() 已经把实测 4xx 的假边缘剔掉了
    except Exception:
        cands = []
    cur = _LAST_GOOD.get(key) or ''
    spread = _pick_spread(cands[:24], per_group=2, limit=_CHAN_SAMPLES)
    if cur and cur not in spread:
        spread = ([cur] + spread)[:_CHAN_SAMPLES]
    out = {'key': key, 'host': host, 'ts': started, 'sampled': len(spread),
           'pass': 0, 'weak': 0, 'ip_best': '', 'kbps_best': 0, 'in_use': cur,
           'swapped': '', 'list': [], 'note': '', 'running': 1}
    _CHAN[key] = out
    if not spread:
        out['note'] = '候选池为空(或全被实测拉黑), 本轮没得测'
        out['running'] = 0
        log('通道重匹配 %s: 候选池为空, 跳过本轮' % host)
        return out

    if key == 'github':
        def _one(ip):
            try:
                r = _cap_test(host, ip, window=2.0, max_bytes=196608,
                              min_ok=8192, deadline=6.0, connect_timeout=2.5)
            except Exception:
                r = None
            if r and r.get('ok'):
                _kbps_set(ip, r.get('kbps', 0))
                _ip_born(ip)                  # 热备/寿命台账也要收下这个样本
                return (ip, int(r.get('kbps', 0)))
            return (ip, 0)
        try:
            with ThreadPoolExecutor(max_workers=2) as ex:
                rows = list(ex.map(_one, spread))
        except Exception as e:
            log('通道重匹配 %s 异常: %s' % (host, e))
            rows = [(ip, 0) for ip in spread]
        ok_rows = sorted([r for r in rows if r[1] > 0], key=lambda r: -r[1])
        good_rows = [r for r in ok_rows if r[1] >= _CHAN_MIN_KBPS]
        out['pass'] = len(good_rows)
        out['weak'] = len(ok_rows) - len(good_rows)
        if good_rows:
            out['ip_best'], out['kbps_best'] = good_rows[0][0], good_rows[0][1]
        elif ok_rows:
            out['ip_best'], out['kbps_best'] = ok_rows[0][0], ok_rows[0][1]
        out['list'] = [{'ip': i, 'kbps': k} for i, k in ok_rows[:6]]
        # 【2026-10-24 三修·全轮零通过时不摘台账】原来每个"这一轮没传动"的样本都
        # 当场 _kbps_forget。可"8 个全传不动"最常见的解释是这条宽带整段在抽风
        # (装机版 22:59 与 23:0x 两轮实测就是 pass=0)，而不是 8 个 IP 恰好同时坏死。
        # 一把清干吞吐台账，等于连 2620 行那条"实测判直连更快"的快路一起废掉，
        # 接下来 10 分钟每条转发都要重新挨一轮 TCP 抢连 —— 越拥塞越慢，本末倒置。
        # 现在只在**本轮确实有人传得动**时才摘掉传不动的那些(有对照才谈得上淘汰)。
        if ok_rows:
            for _ip0, _k0 in rows:
                if _k0 <= 0:
                    _kbps_forget(_ip0)
        else:
            out['note'] = ('本轮 %d 个全传不动，判为链路拥塞，'
                           '保留既有吞吐台账与在用 IP' % out['sampled'])
        passers = [r[0] for r in good_rows]
    else:
        # raw / Pages 这两池按设计**不量吞吐**: 拿 IP 直接 GET 它们的根路径回的是 404、
        # 拿不到可观的字节数, 硬套吞吐尺子会把好 IP 误判成"传不动"(10-11 记过的坑,
        # sys_cap_loop 也因此只测主站)。这里退一步, 用体检同一把尺子复验
        # TCP + TLS + 证书归属, 并在面板上如实写"只验连通", 不假装有吞吐证据。
        def _one2(ip):
            try:
                m = pool._probe(ip, timeout=4.0)
            except Exception:
                m = None
            if m:
                _ip_born(ip)
                return (ip, int(m[0]))
            return (ip, -1)
        try:
            with ThreadPoolExecutor(max_workers=2) as ex:
                rows = list(ex.map(_one2, spread))
        except Exception as e:
            log('通道重匹配 %s 异常: %s' % (host, e))
            rows = [(ip, -1) for ip in spread]
        ok_rows = sorted([r for r in rows if r[1] >= 0], key=lambda r: r[1])
        out['pass'] = len(ok_rows)
        out['list'] = [{'ip': i, 'ms': m} for i, m in ok_rows[:6]]
        out['note'] = '只验连通(TLS+证书): 这两池没有公开正文, 不量吞吐'
        passers = [r[0] for r in ok_rows]
        if ok_rows:
            out['ip_best'] = ok_rows[0][0]

    # 跑通过的 IP 交回热备池(带新鲜时间戳): 20 秒那一轮不用重新发现,
    # 空闲期换岗也一开始就有米下锅 —— 这正是"用户隔半小时回来仍能秒开"的前提。
    now = time.time()
    if passers:
        with _HOT_LOCK:
            have = {i for i, _t in _HOT.get(key, [])}
            for ip in passers[:4]:
                if ip not in have:
                    _HOT[key].append((ip, now))
            _HOT[key] = [(i, t) for i, t in _HOT[key] if now - t <= 180][-8:]

    # 主动换岗: 只在"有更好证据"时动手, 且留够余量, 免得两边抖一下就来回横跳。
    cur_k = None
    for r in rows:
        if r[0] == cur:
            cur_k = r[1] if key == 'github' else (0 if r[1] >= 0 else -1)
            break
    # 优先在"跑得通"(≥ _CHAN_MIN_KBPS)的里面挑。一个都没过线时 —— 今晚 22:28~22:32
    # 实测就是这种全线拥塞的常态 —— 也允许在**确实传得到字节**的里面挑一个明显更快的:
    # 0 KB/s 和 13 KB/s 不是同一回事, 这时候抱着老 IP 只会让每次转发都先挨一轮超时。
    rank = list(passers)
    if key == 'github' and not rank:
        rank = [r[0] for r in ok_rows if r[1] >= _CHAN_FALLBACK_KBPS]
    best_k = out['kbps_best']
    new = ''
    if rank and rank[0] != cur:
        if key == 'github':
            if cur_k is None or cur_k < best_k / _CHAN_HYSTERESIS:
                new = rank[0]
        elif cur_k is None or cur_k < 0:
            new = rank[0]
    if new and new != cur:
        _LAST_GOOD[key] = new
        _ip_born(new)
        _fail_clear(new)
        out['swapped'] = new
        out['in_use'] = new
    elif ok_rows and not rank and cur and cur_k is not None and cur_k <= 0:
        # 一个都没跑通、而在用的这个**本轮亲口承认传不动** —— 别再把它当"上次成功的 IP"抱着。
        # 清空后下次转发会重新并发抢连(而不是优先去撞这具尸体); 判据是这一轮的实测,
        # 不是猜的: 没测到 cur(cur_k is None)时绝不清空, 免得把"没排上队"当成"死了"。
        # 【2026-10-24 三修】多加一道 `ok_rows` 前提: 本轮**有人传得动**才谈得上"这个该下岗"。
        # 8 个全传不动是链路在抽风, 此时清 _LAST_GOOD 只会让后面每条请求都多挨一轮抢连。
        _LAST_GOOD[key] = ''
        out['in_use'] = ''
        out['note'] = (out['note'] + '; ' if out['note'] else '') + '在用 IP 本轮实测传不动, 已让位重新抢连'

    out['running'] = 0        # 本轮实测结束: 面板可以按真实通过数说话了
    cost = int(time.time() - started)
    if key == 'github':
        log('通道重匹配 %s: 真下载 %d 个 → 跑得通 %d 个(偏慢 %d) · 最佳 %s %d KB/s · '
            '在用 %s%s (%ds)' % (
                host, out['sampled'], out['pass'], out['weak'],
                out['ip_best'] or '-', out['kbps_best'], cur or '-',
                (('，换岗 →' + new) if new else
                 ('' if cur_k is None else '，%d KB/s' % cur_k)), cost))
    else:
        log('通道重匹配 %s: 复验 %d 个 → 连通 %d 个 · 最快 %s · 在用 %s%s (%ds)' % (
            host, out['sampled'], out['pass'], out['ip_best'] or '-', cur or '-',
            (('，换岗 →' + new) if new else ''), cost))
    return out


def channel_loop():
    """每 10 分钟把三个池各重匹配一轮"跑得通的通道"(用户 2026-10-24 提的要求)。

    第一轮不等 10 分钟: 启动 45 秒后就跑 —— 因为启动后的头几分钟正是"候选池刚建好、
    用户马上要开浏览器"的时刻, 让他在打开页面之前就有实测证据垫底。

    【2026-10-24 装机版实测后补的一条】但第一轮要**等启动体检跑完**再开测:
    启动预体检是 49 个 IP × 12 并发, 我那 8 发吞吐实测撞上去会互相挤(22:49 装机版
    第一轮就是"测 8 通 0", 可同一时刻池子明明 24 个实测成过、真实请求 0.8 秒 200)。
    探测自己把链路挤拥塞、然后得出"全都跑不通"的假结论 —— 这是 10-11 记过的老坑,
    只不过这次是我和体检抢。所以: 体检出结果后再缓 20 秒开测, 最多等 3 分钟。
    """
    time.sleep(45)     # 别跟启动预体检抢带宽(那会儿正在并发探 49 个 IP)
    _t0 = time.time()
    while time.time() - _t0 < 180:                     # 最多再等 3 分钟
        try:
            _done = bool(HEALTH.snapshot()[1])         # 体检跑完一次才会有时间戳
        except Exception:
            _done = True
        if _done:
            break
        time.sleep(5)
    time.sleep(20)     # 体检刚跑完也缓一口, 让它派出去的探测先散场
    while True:
        empty = 0
        for key, pool, host in (('github', HEALTH, 'github.com'),
                                ('raw', HEALTH_RAW, 'raw.githubusercontent.com'),
                                ('pages', HEALTH_PAGES, 'github.io')):
            try:
                r = channel_scan_once(key, pool, host)
                if not (r or {}).get('sampled'):
                    empty += 1
            except Exception as e:
                log('通道重匹配异常(%s): %s' % (key, e))
            time.sleep(3)   # 三个池错开, 别让下载挤在同一秒互相拖慢
        # 三个池都空手而归, 说明启动体检还没出名单 —— 别死等 10 分钟, 2 分钟后再试
        time.sleep(120 if empty == 3 else _CHAN_INTERVAL)


def dns_warm_loop():
    """后台定时预解析常用域名 —— 真实请求来时缓存是热的, 不用现场等 DNS。

    【2026-10-11 修·别让直连输在起跑线】
    直连要参与竞速, 就得先知道"系统解析到哪个 IP"。要是等请求来了才解析,
    DNS 那几十毫秒先耗掉, 直连在抢连里天然落后半个身位 —— 竞速就成了摆设。
    这里提前解析好存着, 转发时直接取用。
    """
    hosts = ('github.com', 'raw.githubusercontent.com', 'github.io',
             'objects.githubusercontent.com', 'codeload.github.com',
             'api.github.com', 'avatars.githubusercontent.com',
             'github.githubassets.com')
    while True:
        try:
            for h in hosts:
                ProxyHandler._sys_ips(h, force=True)
        except Exception as e:
            log('DNS 预热异常: %s' % e)
        # 缓存 60 秒过期, 这里 45 秒刷一次 —— 永远赶在过期前, 取用时总是热的
        time.sleep(45)


def hot_loop():
    """后台守护: 每 20 秒给三个池补一次热备 + 空闲期主动换岗。

    【2026-10-11 修·空闲期也要换岗】
    预防性换 IP 原本只在**转发那一刻**判定 —— 可实测日志显示: 13:49 之后整整
    36 分钟没有任何一次转发(这期间没人开浏览器), 于是那个 IP 就这么"躺着变老",
    等用户隔一阵再来访问时, 拿到的还是个用了半小时的老 IP —— 一上来就撞上寿命
    尽头, 正是"用着用着就打不开"的典型场景。
    这里在**没有流量的时候**也盯一把: 在用的 IP 一到寿命就**直接换岗**给热备
    里新鲜的, 下次访问拿到的就是新的, 不需要用户先挨一次超时。
    """
    while True:
        try:
            hot_refresh('github', HEALTH)
            hot_refresh('raw', HEALTH_RAW)
            hot_refresh('pages', HEALTH_PAGES)
            for key in ('github', 'raw', 'pages'):
                cur = _LAST_GOOD.get(key) or ''
                if not cur or not _ip_expiring(cur):
                    continue
                alt = [x for x in _hot_get(key) if not _ip_expiring(x)]
                if alt:
                    _LAST_GOOD[key] = alt[0]
                    _ip_born(alt[0])
                    log('空闲期换岗: %s 已撑 %d 秒(基准 %d 秒), 让位给热备 %s'
                        % (cur, int(_ip_age(cur)), int(_avg_life()), alt[0]))
                else:
                    # 【2026-10-25 二修·别空手交枪】
                    # 原来这里把 _LAST_GOOD 清空, 但热备池经常是空的(本机 21:20 日志:
                    # "已撑 52 秒但暂时没有新鲜热备, 下次转发重新抢连")。清空之后下一次
                    # 请求要从零发现通道, 先吃 4~10 秒全灭 —— 用户体感就是"刚才还能开,
                    # 现在又慢"。换成: 没有替补就继续记着它, 让下面 2 秒试连/抢连
                    # 在真死的时候自然淘汰; 空闲期不再主动制造空窗。
                    log('空闲期换岗: %s 已撑 %d 秒, 暂无新鲜热备, 先继续用着它'
                        % (cur, int(_ip_age(cur))))
        except Exception:
            pass
        time.sleep(20)


def _pick_spread(cands, per_group=2, limit=10):
    # 【2026-10-11 修·跨网段取样】同一段(IP 前两段)最多取 per_group 个。
    # 实测: 20.27.* 那一整段连不上时, 140.82.* 段还好好的(140.82.116.3 = 874ms/200)。
    # 而候选是按延迟排的 —— 延迟低的恰好扎堆在同一段, 只取"前 N 个"就会
    # 正好全落在死的那一段里, 于是日志刷"候选 IP 全军覆没"、网页打不开。
    # 这里强制把候选摊到不同网段上, 一段全死还有别的段顶上。
    used = {}
    out = []
    for ip in cands:
        g = '.'.join(ip.split('.')[:2])
        if used.get(g, 0) < per_group:
            used[g] = used.get(g, 0) + 1
            out.append(ip)
    return out[:limit]


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


def _query_int(query, name, default, lo, hi):
    """从 "a=1&b=2" 里取一个整数并把范围夹住（面板传坏参数也不许把接口打成 500）。"""
    val = default
    for kv in (query or '').split('&'):
        if kv.startswith(name + '='):
            try:
                val = int(urllib.parse.unquote(kv[len(name) + 1:]))
            except (TypeError, ValueError):
                val = default
    return max(lo, min(hi, val))


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
    # 【2026-10-26 三点整改·③】这段文本是用户复制外发给我看的, 主语必须是"打不打得开"。
    # 以前这里只有"可用 N/M", 而 2026-10-26 实测过"可用 6/50 + 6 发 5 个 502"同时成立,
    # 光看 IP 数会把"坏了"读成"在干活"。
    _wv = _web_verdict('github')
    head = ('狐径体检 v%s | 网页实测 %s(%s) | IPv4 可用 %d/%d | IPv6 可用 %d/%d | '
            'raw 可用 %d/%d | '
            'pages 可用 %d/%d | 表源 %s | 最快 %s | 系统代理 %s | 手动IP %s | '
            '上次体检 %s | 已运行 %d 分钟'
            % (APP_VERSION, _wv[1], _wv[2],
               len(v4), len(all4), len(v6), len(all6),
               len(raw_good), len(CANDIDATE_IPS_RAW_ALL),
               len(pages_good), len(CANDIDATE_IPS_PAGES_ALL),
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
_BOOT_DIRTY = [None]       # 上次没正常退出留下的现场(见 startup_proxy)，没有戳就是 None


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
    """重要提示 —— **只写日志, 绝不往屏幕上送任何东西**。

    2026-10-11 用户明确要求: 双击完什么都别冒出来。以前这里过了启动宽限期就弹一个
    MessageBox(红叉错误框), 端口被占用、启动失败都会弹一下; 上一版换成右下角气泡,
    用户照样算它"弹窗"。现在一律只落日志, 去面板或日志文件里看。
    命令行跑源码时 stdout 看得到, 也不需要弹。
    """
    try:
        log('提示(按用户要求: 不弹窗口、不弹气泡): %s | %s'
            % (title, ' '.join(str(text).split())))
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

    发版前升级演练（§4.16）必须用**独立数据目录**：设环境变量 `FOXPATH_DATA`
    指向一个临时目录即可，本函数优先用它，演练完清场，绝不污染用户真实数据。
    """
    d = os.environ.get('FOXPATH_DATA')
    if not d:
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
# 2026-10-26 开机态自愈：起来就盖一个"我在跑"的戳，正常退出（on_exit）撤掉。
# 戳还在 = 上次进程没走还原就没了（被任务管理器结束 / 断电 / 重启），
# 下次启动据此说明"注册表里那条 PAC 是上次留下的"，而不是让用户自己猜。
RUN_MARK_FILE = os.path.join(DATA_DIR, 'running.json')
LOG_MAX = 512 * 1024
LOG_TAIL_BYTES = 128 * 1024   # 超过上限时保留的尾部**字节数**(审查 M-9: 不再按行)
LOG_PANEL_LINES = 200      # 面板 /api/status 只回尾部这么多行
LOG_QUEUE_MAX = 2000       # 面板没打开时队列也要有个上限, 不然会一直涨

# 【2026-10-10 修·面板「日志」卡实际是空的】面板那条日志原来读的是 _log_q，
# 而且是**读空式**读法（get_nowait 一路取到 Empty），面板 JS 又每 3 秒拿返回值
# **整体替换** #log —— 两者一叠加：首次打开能刷出历史，3 秒后就被换成"这 3 秒里
# 新产生的几行"。体检（5 分钟一轮）、自愈、升级、还原这些**关键行只会闪现 3 秒
# 然后消失**，绝大多数时候卡片是空白的；而 README 把它写成"foxpath.log 的尾部、
# 自动滚到最新"，并让用户"打不开 GitHub 先看这里"复制给作者 —— 实际拿到的基本没价值。
# 现在加一条**旁路环形缓冲**：log() 除了写队列与文件，再往这里塞一份；
# recent_logs() 只读它、**不清空** —— 面板随时都能看到最近 200 行关键日志。
# 必须定义在 LOG_PANEL_LINES 之后（maxlen 用它）。
_log_ring = collections.deque(maxlen=LOG_PANEL_LINES)
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
        _log_ring.append(line)               # 【2026-10-10】旁路环形缓冲, 面板只读它
        _log_to_file(line)
    try:
        print(line, flush=True)
    except Exception:
        pass



# ══════════════════════════════════════════════════════════════════════════
# 仪表盘用的三样新东西（2026-10-24 UI 整改，**只新增、不改旧行为**）
#   ① history_append / history_points —— 每轮体检落一行 JSON，画成延迟曲线
#   ② hit_count / _HITS              —— 本次会话"PAC 命中 / 退回直连"各多少次
#   ③ loss_probe_async / _LOSS       —— IP 表"丢包"列的真实抽样（只抽样，不选路）
# ══════════════════════════════════════════════════════════════════════════

# ① 延迟历史。口径: 每轮体检（每 5 分钟）追加一行; 保留 7 天，超过就裁掉;
#    文件落在数据目录（FOXPATH_DATA 可覆盖），**不上传、不外发**。
HISTORY_FILE = os.path.join(DATA_DIR, 'history.jsonl')
HISTORY_KEEP_DAYS = 7
HISTORY_STEP = 300            # 5 分钟一个点（与 CHECK_INTERVAL 一致）
_HISTORY_LOCK = threading.Lock()
_HISTORY_TRIM_TS = [0.0]


def _history_trim(now):
    """裁掉 7 天以前的采样。一小时最多裁一次，别每轮都重写文件。"""
    if now - _HISTORY_TRIM_TS[0] < 3600:
        return
    _HISTORY_TRIM_TS[0] = now
    keep_from = now - HISTORY_KEEP_DAYS * 86400
    try:
        if not os.path.isfile(HISTORY_FILE):
            return
        keep = []
        with open(HISTORY_FILE, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                try:
                    if float(rec.get('ts') or 0) >= keep_from:
                        keep.append(line)
                except (TypeError, ValueError):
                    continue
        tmp = HISTORY_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            f.write('\n'.join(keep) + ('\n' if keep else ''))
        os.replace(tmp, HISTORY_FILE)
    except Exception:
        pass


def history_append(good, good_raw=None, good_pages=None):
    """把这一轮体检的结果追加进 history.jsonl（一次一行）。

    ok 是这一轮的可用数量（**0 也照记** —— "全灭"本身就是最该看的那一格）；
    latency 取本轮最快那个 IP 的握手毫秒数，没有可用 IP 时给 null（面板画成红点）。
    """
    now = time.time()
    try:
        best_ip, best_ms = '', None
        if good:
            best_ip, best_ms = good[0][0], int(good[0][1])
        cand = [ip for ip in candidate_list() if ':' not in ip]
        rec = {'ts': int(now), 'ip': best_ip, 'latency': best_ms,
               'ok': len(good or []), 'total': len(cand),
               'raw_ok': len(good_raw or []), 'pages_ok': len(good_pages or [])}
        with _HISTORY_LOCK:
            with open(HISTORY_FILE, 'a', encoding='utf-8') as f:
                f.write(json.dumps(rec, ensure_ascii=False) + '\n')
            _history_trim(now)
        return rec
    except Exception as e:
        log('延迟历史写入失败(不影响加速): %s' % e)
        return None


def history_points(hours=3):
    """读最近 N 小时的采样（按时间正序）。坏行跳过，不因为一行坏了整条曲线就没了。"""
    cutoff = time.time() - max(1, int(hours)) * 3600
    out = []
    try:
        with open(HISTORY_FILE, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                try:
                    ts = float(rec.get('ts') or 0)
                except (TypeError, ValueError):
                    continue
                if ts >= cutoff:
                    rec['ts'] = int(ts)
                    out.append(rec)
    except (IOError, OSError):
        pass
    out.sort(key=lambda r: r.get('ts') or 0)
    return out


def history_summary(points):
    """最低 / 最高 / 中位延迟，还有"这轮全灭"的次数 —— 面板图例那一行用。"""
    lat = sorted([int(p['latency']) for p in (points or [])
                  if isinstance(p.get('latency'), (int, float))])
    n = len(lat)
    if not n:
        return {'n': 0, 'min': None, 'max': None, 'median': None, 'down': 0}
    median = lat[n // 2] if n % 2 else int((lat[n // 2 - 1] + lat[n // 2]) / 2)
    down = len([p for p in (points or []) if p.get('ok') == 0])
    return {'n': n, 'min': lat[0], 'max': lat[-1], 'median': median, 'down': down}


# ② 本次会话命中计数。pool = PAC 命中后走了候选池 IP；sys = 退回系统解析（直连）。
_HITS = {'pool': 0, 'sys': 0}
_HITS_LOCK = threading.Lock()


def hit_count(used_pool):
    with _HITS_LOCK:
        _HITS['pool' if used_pool else 'sys'] += 1


def hits_snapshot():
    with _HITS_LOCK:
        return {'pool': _HITS['pool'], 'sys': _HITS['sys'],
                'total': _HITS['pool'] + _HITS['sys']}


# ③ 丢包抽样。对体检排前 10 的 IP 各发 3 次 TCP:443 连接，失败比例就是"丢包"。
#    **只抽样、绝不参与选路** —— 不改任何体检结论（3 次握手的失败率 ≠ ICMP 丢包，
#    面板上写的就是「丢包(3 次握手)」，口径老实标出来）。
_LOSS = {}            # ip -> (丢包百分比, 采样时刻)
_LOSS_LOCK = threading.Lock()
_LOSS_BUSY = [False]
_LOSS_ROUNDS = 3
_LOSS_TOP = 10


def loss_probe_async(good):
    """后台抽一轮丢包样本（同一时刻只跑一轮，跑不完不排队）。"""
    ips = [ip for ip, _ms in (good or [])][:_LOSS_TOP]
    if not ips:
        return
    with _LOSS_LOCK:
        if _LOSS_BUSY[0]:
            return
        _LOSS_BUSY[0] = True

    def worker():
        try:
            def one(ip):
                bad = 0
                for _ in range(_LOSS_ROUNDS):
                    try:
                        s = socket.create_connection((ip, 443), timeout=2.0)
                        s.close()
                    except OSError:
                        bad += 1
                return ip, int(round(100.0 * bad / _LOSS_ROUNDS))
            with ThreadPoolExecutor(max_workers=10) as pool:
                res = list(pool.map(one, ips))
            now = time.time()
            with _LOSS_LOCK:
                for ip, pct in res:
                    _LOSS[ip] = (pct, now)
        except Exception:
            pass
        finally:
            with _LOSS_LOCK:
                _LOSS_BUSY[0] = False

    threading.Thread(target=worker, daemon=True).start()


def loss_of(ip):
    """这个 IP 的丢包抽样（百分比, 采样时刻）；没抽过返回 (None, 0)。"""
    with _LOSS_LOCK:
        hit = _LOSS.get(ip)
    return hit if hit else (None, 0.0)


# ── 面板「线路体检」每一行的数据（全部来自真实体检结果，不做任何估算）──
def _line_row(host, note, good, total, status=None, strong=None, key=''):
    n = len(good or [])
    fastest = min([m for _i, m in good]) if good else None
    # strong = 近 _FRESH_WINDOW 秒**真跑通过一次请求**的个数；None = 这一池不跑 HTTP
    # (raw/pages 池拿 GET / 必然不是 2xx，按设计只验证书，所以不给这个口径)。
    # 【2026-10-26 三点整改·③】再挂一份"网页实测"—— 这一行的红绿以后由它说话。
    web = _web_status(key) if key else None
    if status is None:
        if n == 0:
            status = 'bad'
        elif strong is not None and strong == 0:
            # 【2026-10-24】池子写着"可用 31 个"、可没有一个近期真答过话 ——
            # 这种状态对用户就是"打不开"，绝不能显示成 ok(绿点)。
            status = 'warn'
        elif fastest is not None and int(fastest) > 900:
            status = 'warn'
        elif total and n * 2 < total:
            status = 'warn'
        else:
            status = 'ok'
        # 体检给的是绿灯、真实转发却全灭/时通时断 —— 以用户感知为准往下压。
        # 反过来**不往上抬**: 网页账是"最近有人访问过"才有, 没人访问时不该抢答"通"。
        if web and web['code'] in ('down', 'flaky', 'slow'):
            status = 'bad' if web['code'] == 'down' else 'warn'
    return {'host': host, 'note': note, 'n': n, 'total': total,
            'strong': strong, 'web': web,
            'fastest': (int(fastest) if fastest is not None else None),
            'status': status}


def lines_status():
    """线路体检那 4 行：主站 / raw 那一组 / Pages / api（未接管，如实说明）。"""
    good, _ts = HEALTH.snapshot()
    raw_good, _ = HEALTH_RAW.snapshot()
    pages_good, _ = HEALTH_PAGES.snapshot()
    v4 = [ip for ip in candidate_list() if ':' not in ip]
    return [
        _line_row('github.com', '主站（codeload.github.com 同池）', good, len(v4),
                  strong=len(HEALTH.strong()), key='github'),
        _line_row('raw / objects / avatars / camo', 'raw 文件、发布附件、头像',
                  raw_good, len(CANDIDATE_IPS_RAW_ALL), key='raw'),
        _line_row('github.io', 'GitHub Pages（user.github.io）',
                  pages_good, len(CANDIDATE_IPS_PAGES_ALL), key='pages'),
        _line_row('api.github.com', '未接管（保持直连）', [], 0, status='off'),
    ]


def ips_detail(good, limit=10, pool=None):
    """面板 IP 表的真实数据：延迟 / 丢包抽样 / 连续失败次数 / 已存活秒数 / 证据强度。"""
    now = time.time()
    out = []
    for ip, ms in (good or [])[:limit]:
        loss, loss_ts = loss_of(ip)
        age = _ip_age(ip)
        tier, tier_ts = (pool or HEALTH).tier_of(ip)
        out.append({'ip': ip, 'ms': int(ms),
                    'loss': loss, 'loss_age': int(now - loss_ts) if loss_ts else None,
                    'fails': int(_fail_rank(ip)),
                    'age': int(age) if age else None,
                    # 'http' = 真跑通过一次请求; 'tls' = 只验到证书; None = 证据已出窗
                    'tier': tier if (tier and now - tier_ts <= _FRESH_WINDOW) else None,
                    'tier_age': int(now - tier_ts) if tier_ts else None})
    return out


# ── 一键反馈包（2026-10-24 新增）：版本 + 系统 + 可用 IP + 日志尾部 50 行 ──
# 只**复制到剪贴板**，不落共享文件、不上传任何地方；里面只有 GitHub 官方 IP
# 和本机日志（不含用户自己的外网地址）。
def feedback_text():
    good, ts = HEALTH.snapshot()
    raw_good, _ = HEALTH_RAW.snapshot()
    pages_good, _ = HEALTH_PAGES.snapshot()
    _strong_n = len(HEALTH.strong())        # 近 _FRESH_WINDOW 秒实测成过的个数
    _detail10 = ips_detail(good)
    up_min = int((time.time() - _START_TS[0]) / 60) if _START_TS[0] else 0
    packed = '单文件 exe' if getattr(sys, 'frozen', False) else '源码运行'
    os_txt = platform.platform()
    py_txt = 'Python %s (%s 位)' % (platform.python_version(),
                                    '64' if sys.maxsize > 2 ** 32 else '32')
    lines = [
        '狐径 FoxPath 反馈包（面板一键复制，不落文件、不上传）',
        '=' * 52,
        '版本: %s   形态: %s' % (APP_VERSION, packed),
        '系统: %s' % os_txt,
        '运行: %s' % py_txt,
        '时间: %s' % time.strftime('%Y-%m-%d %H:%M:%S'),
        '加速: %s' % ('已开启' if proxy_on() else '未开启'),
        '系统代理: PAC %s' % ('已指向本程序' if proxy_on() else '未接管'),
        '官方 IP 表: %s · 候选 %d 个（IPv4 %d / IPv6 %d）'
        % (_META_SOURCE[0] or '未同步(用内置表)', len(CANDIDATE_IPS),
           len([i for i in candidate_list() if ':' not in i]),
           len([i for i in candidate_list() if ':' in i])),
        '可用 IP: %d / %d · 最快 %s'
        % (len(good), len([i for i in candidate_list() if ':' not in i]),
           ('%s (%dms)' % (good[0][0], good[0][1])) if good else '无'),
        # 【2026-10-24】上面那行是"活着"的口径(TLS 证书验过就算)。真正决定
        # "页面能不能打开"的是这一行: 近 90 秒内真发过一次请求并拿到 2xx/3xx 的 IP。
        # 本机实测过两者差到 31 vs 1 —— 只看上面那行会误判成"加速在干活"。
        '实测成过(近 %d 秒真跑过一次请求): %d / %d%s'
        % (int(_FRESH_WINDOW), _strong_n, len(good),
           '' if _strong_n or not good
           else '  ← 池子里没有一个近期答过话, 现在打开页面只能靠直连兜底'),
        # 【2026-10-26 三点整改·②③】上面两行都是"体检"口径, 这一行才是用户体感:
        # 最近 3 分钟**真实转发**的结局(成/断流/502/假前门)。以后用户贴给我看的
        # 第一段就该读这句, 不用再靠"可用多少个 IP"猜。
        '网页实测(真实转发): %s —— %s' % _web_verdict('github')[1:3],
        '断流过 2 次以上的 IP(已从池子请出): %s' % (
            ', '.join('%s×%d' % (ip, _stall_rank(ip))
                      for ip in sorted(_STALL, key=lambda x: -_stall_rank(x))
                      if _stall_rank(ip) >= _STALL_DROP_POOL) or '无'),
        '可用清单(前 10): %s' % (', '.join(
            '%s(%dms%s)' % (i, m, {'http': '', 'tls': ', 仅证书', None: ', 证据已出窗'}
                            [d.get('tier')])
            for (i, m), d in zip(good[:10], _detail10)) or '无'),
        'raw 池: %d/%d · pages 池: %d/%d'
        % (len(raw_good), len(CANDIDATE_IPS_RAW_ALL),
           len(pages_good), len(CANDIDATE_IPS_PAGES_ALL)),
        '直连对照: %s' % ('通' if _DIRECT_OK[0] is True else
                          '不通' if _DIRECT_OK[0] is False else '还没探过'),
        '手动 IP: %s' % (_MANUAL_IP[0] or '无'),
        '上次体检: %s · 已运行 %d 分钟'
        % (time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts)) if ts else '还没体检过',
           up_min),
        '丢包抽样: %s' % ('; '.join(
            '%s %s%%' % (d['ip'], d['loss']) for d in _detail10 if d['loss'] is not None
        ) or '还没有样本'),
        '本次会话: PAC 命中 %d · 退回直连 %d' % (hits_snapshot()['pool'],
                                              hits_snapshot()['sys']),
        '',
        '--- 日志尾部 50 行 ---',
    ]
    lines.extend(recent_logs(50))
    return '\n'.join(lines)


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
    """面板「日志」卡要的最近 n 行。

    【2026-10-10 修·卡片实际是空的】以前是**读空** _log_q（get_nowait 一路取到
    Empty）；面板 JS 每 3 秒拿这个返回值**整体替换** #log 的文本，于是读完队列就空了
    —— 首次打开还能刷出历史，3 秒后只剩"这 3 秒里新产生的几行"。
    体检（5 分钟一轮）、自愈、升级、还原这些**关键行只闪现 3 秒就消失**，
    而 README 让用户"打不开 GitHub 先看这里"复制给作者 —— 实际拿到的基本没价值。
    现在只读**旁路环形缓冲**（log() 每次都往里塞一份）、**不清任何东西**，
    面板随时都能看到最近 200 行。
    """
    try:
        return list(_log_ring)[-n:]
    except Exception:
        return []


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


# 【2026-10-10 修 声明不符】本代理**只允许转发 GitHub 相关域名**。
#
# 为什么补这一道：对外声明（docs/COMPLIANCE.md）写的是
# 「只接管 GitHub 相关域名；**不提供代理服务、不转发他人流量**」，
# 而 `_connect()` 的兜底原来**对任何 host 都照常建隧道**（见下面那处修改），
# 本机任意程序、或用户照教程把系统代理手填成 127.0.0.1:8787，
# 就能把它当成通用转发用 —— 与声明直接冲突。
# `docs/SECURITY.md` 自己也把这一条列进"算漏洞"，只是代码一直没收。
#
# 名单口径：**基名完全相同 或 以「.基名」结尾**。
#   · github.com            -> github.com / www.github.com / api.github.com / gist.github.com
#   · githubusercontent.com -> raw. / objects. / avatars. / camo. …
#   · github.io             -> github.io 与 user.github.io
# 这样旧 PAC 缓存送来的 api.github.com 之类**仍能正常走直连**（不会因为收窄而误伤），
# 而 example.com、内网地址、任意第三方站点一律拒。
GITHUB_HOST_BASES = ('github.com', 'githubusercontent.com', 'github.io',
                     'githubassets.com', 'githubapp.com')


def is_github_related_host(host):
    """该主机是否属于"允许本代理转发的 GitHub 相关域名"。"""
    h = (host or '').lower().split(':')[0].strip().strip('.')
    if not h:
        return False
    for b in GITHUB_HOST_BASES:
        if h == b or h.endswith('.' + b):
            return True
    return False


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
        # 【2026-10-24 新增·"可用"必须分层】
        # 原来 _good 里只有一个"可用/不可用"，可实测发现两种"可用"完全不是一回事:
        #   · http —— 真发了一次 GET 并拿到 2xx/3xx/429，这个 IP 此刻**确实能做页面**;
        #   · tls  —— 只有 TCP + TLS + 证书过了，HTTP 那一步超时或没读到状态码。
        # 老写法把 tls 也当可用计数(见 _probe 里那句 except timeout: pass)，
        # 高丢包时一轮下来面板写着"可用 31/50"，可同一时刻挨个真发请求，
        # 十个里只剩一个答得出来(实测数据见 logs\UI整改-20261024\) ——
        # 用户看到的数字和浏览器实际遭遇的完全对不上，才叫"加速开着却打不开"。
        # 这里不改变"超时不判死"的原设计(那是 2026-10-11 换来的教训)，
        # 只是把证据记下来，让面板、反馈包和转发挑线路都用**新鲜程度**说话。
        # ip -> (层级 'http'/'tls', 验出的时刻)
        self._tier = {}
        # 这一池到底跑不跑 HTTP 预检。raw / Pages 池按设计不跑(拿 IP 直接 GET 根路径
        # 必然不是 2xx，会误杀好 IP)，所以它们永远只有 'tls' 这一档 ——
        # 转发的"快不过就撤"逻辑必须只对跑了预检的池子生效，否则 raw 下载每次都撤。
        self.checks_http = http_path is not None
        # 2026-10-08: 不同主机群用不同的 SNI 与证书期望值 ——
        # github.com 池: SNI=github.com, 证书要含 github.com;
        # raw/附件池:    SNI=raw.githubusercontent.com, 证书要含 githubusercontent.com。
        self.sni = sni
        self.expect = expect
        # HTTP 检查用的路径；None = 只验 TLS+证书（raw 池就是这样：
        # raw.githubusercontent.com 的根路径必然返回 400，用它判死会误杀好 IP）
        self.http_path = http_path

    def _probe(self, ip, timeout=3.0, http_timeout=2.0):
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
                # 【2026-10-10 修·用户最早报的那句"搜出来的 IP 延迟太久了"】
                # 延迟**在这里就定下来** —— TLS 握手完成、证书也验过的这一刻。
                # 因为"连上这个 IP 有多快"只取决于 TCP + TLS 这两步。
                # 下面那次 HTTP GET 是**通过/不通过的体检**，不该算进延迟：
                #   · 以前算的是"TCP + TLS + HTTP"三段之和；
                #   · 而 HTTP 那步超时（s.settimeout(2.0)）会被下面的 except 吞掉、
                #     IP 照样算可用 —— 可那 2 秒**算进了延迟**。于是好 IP 也能报出
                #     2200ms 左右（实测真实链路只有 200ms 上下），日志里那一簇
                #     2190~2240ms 就是这么来的；
                #   · 更糟的是候选池**按这个数排前 4**：链路快、只是 HTTP 那一拍慢的
                #     IP 会被排到后面，代理因此挑不到最好的那个。
                _lat = int((time.time() - t0) * 1000)
                # TLS 握手通了还不够: 某些 IP 的证书对, 但只跑 API/CDN,
                # 直接访问 github.com 会返回 4xx, 这种不能要。
                # 这里发一发 GET /; 如果 HTTP 测试自己超时(偶尔发生),
                # 不因此判死, 毕竟 TLS 已经验证通过, 但返回 4xx/5xx 就判死。
                tier = 'tls'          # 'tls' = 只验到证书; 'http' = 真跑通过一次请求
                try:
                    if self.http_path is None:
                        raise _SkipHttp()
                    s.settimeout(http_timeout)
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
                                # 【2026-10-24】证书对、页面回 4xx = 假边缘：
                                # 除了本轮判死，再实测拉黑 15 分钟，免得下一轮体检
                                # 或"上一轮活着先留着"那条规则把它捡回候选池。
                                _bad_edge_note(ip, status.decode('latin-1', 'replace'))
                                self.drop(ip)
                                return None
                            # 读到状态行**且**是 2xx/3xx/429 —— 这才算"实测成过"
                            tier = 'http'
                except _SkipHttp:
                    pass
                except (socket.timeout, TimeoutError, OSError):
                    # 超时维持"不判死"(见上面的历史教训)，但只给 'tls' 这一档:
                    # 面板不再把它算进"实测成过"，转发时也排到后面。
                    pass
            with self._lock:
                self._tier[ip] = (tier, time.time())
            return _lat, tier
        except Exception:
            return None
        finally:
            try:
                raw.close()
            except Exception:
                pass

    def refresh(self, ips=None, timeout=3.0):
        ips = ips or CANDIDATE_IPS
        # IPv6 闸门: 本机没有 IPv6 出口时不浪费探测名额(IPv6 候选保留在池子里,
        # 哪天 IPv6 通了/修好了, 下一轮体检自然把它们捡起来用)。
        if not local_has_ipv6():
            ips = [ip for ip in ips if ':' not in ip]
        with ThreadPoolExecutor(max_workers=12) as pool:
            res = list(pool.map(lambda ip: (ip, self._probe(ip, timeout)), ips))
        good = sorted([(i, m[0]) for i, m in res if m is not None
                       and not _bad_edge(i)], key=lambda x: x[1])
        with self._lock:
            # 【2026-10-11 修·别让一次糟糕的体检清空候选池】
            # 高丢包时一轮探测会把大半 IP 判成超时(实测: 49 个只测出 4 个可用),
            # 候选池骤减就没得挑了。上一轮**证实可用**的先留着压在后面兜底 ——
            # 真死了也没关系: 转发有失败降权 + 并发抢连, 死 IP 会被自然跳过。
            # 【2026-10-24 补一句】留过来的这些只作"备选"用，不再算"实测成过":
            # 它们的证据是上一轮(最长 5 分钟前)的，而实测 IP 寿命只有 150~230 秒。
            # 【2026-10-24 再补一句】实测拉黑的"假边缘"不许留过来 ——
            # 今天装机版满屏 400，就是它带着 20.200.245.244 一路复活到转发名单最前面。
            if self._good and len(good) < len(self._good) // 2:
                have = {i for i, _ in good}
                carried = [(i, m) for i, m in self._good
                           if i not in have and not _bad_edge(i)]
                for i, _m in carried:
                    t = self._tier.get(i)
                    if t:
                        self._tier[i] = (t[0], min(t[1], time.time() - _FRESH_WINDOW))
                good = good + carried
            self._good = good
            self._last = time.time()
            # 已经被踢出池子的 IP, 证据也别留着(否则面板数字虚高)
            live = {i for i, _m in good}
            self._tier = {i: v for i, v in self._tier.items() if i in live}
        return good

    def tier_of(self, ip):
        """这个 IP 最新的证据: ('http'|'tls', 验出时刻)；没有则 (None, 0)。"""
        with self._lock:
            return self._tier.get(ip) or (None, 0.0)

    def strong(self, window=None):
        """近 `window` 秒内**真跑通过一次请求**(tier='http')的 IP —— 这才是
        "此刻能打开页面"的口径。raw/pages 池不跑 HTTP, 它们的 http_path=None,
        按设计只能验到证书, 所以那边继续用 len(good) 说话(面板另有说明)。"""
        window = _FRESH_WINDOW if window is None else window
        now = time.time()
        with self._lock:
            return [ip for ip, ms in self._good
                    if self._tier.get(ip, (None, 0))[0] == 'http'
                    and now - self._tier.get(ip, (None, 0))[1] <= window]

    def tier_counts(self, window=None):
        """面板/反馈包用：{'http': n, 'tls': n} —— 两个都是"活着"的 IP, 差别只在证据强度。"""
        window = _FRESH_WINDOW if window is None else window
        now = time.time()
        out = {'http': 0, 'tls': 0}
        with self._lock:
            for ip, _m in self._good:
                tier, t = self._tier.get(ip, (None, 0))
                if tier and now - t <= window:
                    out[tier] = out.get(tier, 0) + 1
        return out

    def snapshot(self):
        with self._lock:
            return list(self._good), self._last

    def candidates(self):
        """转发/热备取候选的地方 —— 实测拉黑的"假边缘"一律不给，
        哪怕它刚从体检名次里排到最前（2026-10-24：就是它把用户带到 400 页面上的）。"""
        with self._lock:
            return [ip for ip, _m in self._good if not _bad_edge(ip)]

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
    2. GitCode 上本项目仓库里的 meta.json —— 国内三网都能拉 GitCode，这是关键兜底
       （2026-10-26 实测 HTTP 200、1326 B、ips=12 web=40，与仓库里那份同尺寸）；
    3. GitHub raw 的同一份 meta.json。

    以前只有一个源（api.github.com），拉不到就只剩内置那十几个旧地址 ——
    这就是"某些运营商的用户用不了"的直接原因。

    【2026-10-26 补上第 2 个源】注释里一直写着"三个源"，代码里其实只有两个，
    而那两个（api.github.com 与 raw.githubusercontent.com）走的**是同一条国际链路**：
    第 1 个断了，第 3 个多半也断 —— 等于国内线路的用户根本没有兜底。
    GitCode 插在中间才是真兜底，所以它排在 GitHub raw 前面。
    """
    global CANDIDATES
    urls = (
        'https://api.github.com/meta',
        # GitCode 没有裸 raw 直链，用它的 API raw 口（和升级源 version.json 同一个形状）
        'https://gitcode.com/api/v5/repos/kele551/FoxPath/raw/meta.json?ref=main',
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
            # 【2026-10-24 修·官方 IP 表同步在 Python 3.12 上会炸】
            # 官方 /meta 的 web 现在**几乎全是 /32 单地址**(实测 50 条里 40 多条是
            # "20.205.243.166/32" 这种)。而 ipaddress 在 3.12 里对 /32 走特例、
            # 返回的是 **list** 而不是迭代器(3.13 才是迭代器) ——
            # `next(net.hosts(), None)` 当场 TypeError: 'list' object is not an iterator。
            # 这一行在 try 外面, 所以炸掉的是**整个官方 IP 表同步**, 而在 3.12 下
            # 从源码跑时它还在 health_loop 的调用链上, 会把体检线程一起带死
            # (exe 用 3.13 打包, 所以装机版看不出来 —— 判据不该押在打包 Python 的版本上)。
            # 先 iter() 一下, list / 迭代器都吃得下。
            first = next(iter(net.hosts()), None) or net.network_address
            if net.version == 4:
                ips.append(str(first))
            # IPv6 网段的首地址不是真实主机（实测 HTTP 层 Domain Not Found），
            # 所以这里**故意不收集**；真实 IPv6 只从 DNS / meta.json 的 web6 来。
        # 审查 M-2: 这一份表到底解析出东西没有 —— 只有**真的解析出地址**才算同步成功。
        # 以前不管解析出几个, 都会把内置的 140.82.x.x 补进来凑数, 于是"接口 200 但表是
        # 空的 / 字段被改名"也会被记成「已同步官方 IP 表」, 而且**不再往下试后面的兜底源**;
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
                           'GitCode' if 'gitcode.com' in url else 'GitHub')
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

# 接管清单（**唯一来源**）：PAC 的判定条件、代理的路由判断、面板上"接管域名"那一格
# 的计数，全都从 PAC_HOSTS 来 —— 以前 PAC 里手写一份、PROXY_HOSTS 里再手写一份，
# 改一处忘一处（2026-10-24 加 codeload 时正好撞上，就并成一份了）。
# github.io 及其子域（*.github.io）由下面 PAC 里的 dnsDomainIs 单独覆盖。
PAC_HOSTS = PROXY_HOSTS + PROXY_HOSTS_RAW
_PAC_HOSTS_JS = ' || '.join('host === "%s"' % h for h in PAC_HOSTS)

PAC_TEMPLATE = """function FindProxyForURL(url, host) {
    host = host.toLowerCase();
    // github.com -> local proxy.
    // raw/objects.githubusercontent.com -> local proxy as well, but they use
    // their OWN ip pool inside the proxy (185.199.108.0/22). Sending them to the
    // github.com pool lands on the wrong server and breaks the download.
    // avatars./camo.githubusercontent.com also go through the local proxy now.
    // They are in the SAME 185.199.108.0/22 range as raw/objects and serve the
    // same *.githubusercontent.com certificate, so the raw pool fits them.
    // Measured on this machine (2026-10-11): one 282KB avatar took 5.7-14.2s
    // DIRECT but 1.1-4.7s through the proxy. githubassets stays DIRECT: it is a
    // different domain with a different certificate and is already fast (0.27s).
    // github.io and *.github.io (GitHub Pages) also go through the local proxy.
    // They share the 185.199.108.0/22 pool with raw/objects, but the proxy checks
    // them against the *.github.io certificate, NOT the githubusercontent one.
    // 2026-10-24: codeload.github.com joins the list (same web fleet and the same
    // *.github.com certificate as github.com; measured 301 on the pool IPs).
    // gist.github.com is NOT taken over yet: with SNI=gist.github.com every
    // official IP got a reset during the handshake, so another IP cannot help.
    // githubassets stays DIRECT (already fast; different certificate).
    if (%s ||
        host === "github.io" || dnsDomainIs(host, ".github.io")) {
        return "PROXY 127.0.0.1:%%d; DIRECT";
    }
    return "DIRECT";
}
""" % _PAC_HOSTS_JS


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

    # ---- 建连总时限(2026-10-26, 判据见上面 _CONNECT_DEADLINE 的说明) ----
    def _dl_start(self, budget=None):
        """给这次建连定一个总时限, 之后每一手都先看还剩几秒。"""
        self._dl = time.time() + (budget or _CONNECT_DEADLINE)

    def _dl_left(self):
        """还剩多少秒。没设过预算(老调用、单元桩)就当不限, 行为跟改前一模一样。"""
        dl = getattr(self, '_dl', 0.0)
        return 999.0 if not dl else (dl - time.time())

    def _dl_note(self, left, what, label):
        if _fast_log_ok('dl:' + (label or ''), 15.0):
            log('%s 建连只剩 %.1f 秒预算, 不够再%s —— 本次到点放弃, '
                '浏览器可以直接重试(后台还在找通道)' % (label or '代理', left, what))

    def _connect_race(self, ips, port, timeout=2.5, max_race=4, key='', label=''):
        """带闸门、带总时限的抢连。真正的并发握手在 _connect_race_batch 里。

        两件事(2026-10-26):
          1) 同一个池同时只放一条请求做整批抢连。抢不到名额的不追加 SYN,
             先等占用者的结论(最多 _RACE_WAIT 秒, 且不超过自己的预算), 等到
             就复用那条刚验活的通道; 等不到就只单独轻试名单里第一个 IP。
          2) 单次握手超时按剩余预算裁剪, 绝不让"4 秒抢连 + 10 秒兜底"叠成
             十几秒 —— 实测过最长 19.4 秒才回一句连不上。
        """
        left = self._dl_left()
        if left <= 0.3:
            self._dl_note(left, '抢连', label)
            return None, None
        timeout = max(0.6, min(timeout, left - 0.2))
        if not key:
            return self._connect_race_batch(ips, port, timeout=timeout,
                                            max_race=max_race)
        if _race_take(key):
            try:
                return self._connect_race_batch(ips, port, timeout=timeout,
                                                max_race=max_race)
            finally:
                _race_release(key)
        # ---- 名额被别人占着: 不再放第二批 SYN ----
        cand = [x for x in ips if x][:max_race]
        if not cand:
            return None, None
        wait = min(_RACE_WAIT, max(0.0, self._dl_left() - 1.0))
        t_end = time.time() + wait
        while time.time() < t_end:
            lg = _LAST_GOOD.get(key)
            if lg:
                try:
                    s = socket.create_connection((lg, port), timeout=1.2)
                except OSError:
                    _fail_note(lg)
                    _LAST_GOOD[key] = ''
                    break        # 它给的那条也不通, 别再等, 走自己轻试
                _note_route(key, lg, [])
                _fail_clear(lg)
                _ip_born(lg)
                _sys_fail_reset(key)
                if _fast_log_ok('shared:' + key, 20.0):
                    log('%s 复用了同时在跑的抢连结论 %s(没再放第二批握手)'
                        % (label or key, lg))
                return s, lg
            if _race_gate_left(key) <= 0:
                break            # 占用者已经收手(失败了), 不等了
            time.sleep(_RACE_WAIT_SLICE)
        one = cand[0]
        try:
            s = socket.create_connection((one, port),
                                         timeout=min(1.2, max(0.5, self._dl_left() - 0.2)))
        except OSError:
            return None, None
        _note_route(key, one, [])
        _LAST_GOOD[key] = one
        _fail_clear(one)
        _ip_born(one)
        _sys_fail_reset(key)
        return s, one

    def _connect_race_batch(self, ips, port, timeout=2.5, max_race=4):
        # 【2026-10-11 修·并发抢连(Happy Eyeballs)】
        # 原来是**串行**试候选: 撞上一个死 IP 就要干等它超时(3s)才换下一个,
        # 前面有几个死 IP 就是几倍超时 —— 实测 github 要 8.15 秒才返回 200。
        # 现在同时对前 N 个候选发起 TCP 连接, 谁先成功就用谁, 其余立刻关掉:
        # 死 IP 自己超时即可, 不再阻塞别人; 活的那个 200ms 就回来了。
        # (2026-10-26 起这层的超时与并发由外层 _connect_race 按预算/闸门裁好
        #  再传进来, 这一层本身只管握手, 所以单元桩可以直接压它。)
        ips = [x for x in ips if x][:max_race]
        if not ips:
            return None, None
        if len(ips) == 1:
            try:
                return socket.create_connection((ips[0], port), timeout=timeout), ips[0]
            except OSError:
                return None, None
        st = {'sock': None, 'ip': None, 'closed': False}
        lock = threading.Lock()
        done = threading.Event()

        def _try(ip):
            try:
                s = socket.create_connection((ip, port), timeout=timeout)
            except OSError:
                return
            with lock:
                # 已经有人赢了、或主线程已经放弃 —— 立刻关掉, 别留着占连接
                if st['closed'] or st['sock'] is not None:
                    try:
                        s.close()
                    except Exception:
                        pass
                    return
                st['sock'] = s
                st['ip'] = ip
            done.set()

        for ip in ips:
            threading.Thread(target=_try, args=(ip,), daemon=True).start()
        done.wait(timeout + 0.5)
        with lock:
            st['closed'] = True
            if st['sock'] is not None:
                return st['sock'], st['ip']
        return None, None

    # 2026-10-11 记录(别再走回头路): 这里曾试过"并发做 TCP+TLS 探测、验到 TLS 层
    # 再把 IP 交给浏览器"(_race_pick)。实测**反而更慢** —— 4.5~14.7 秒, raw 还出现
    # "候选 IP 全军覆没"。原因是国际链路上并发做 TLS 握手会互相挤占带宽,
    # 探测本身成了负担。已移除, 改为纯 TCP 并发抢连(_connect_race),
    # TLS 握手仍交给浏览器自己做。

    # ---- 系统解析结果(直连)参与竞速 ------------------------------------------
    # 【2026-10-11 修·别只在自己人里比】
    # 以前候选只来自"上次成功 / 手填 / 热备 / 体检名次", 系统解析只在**全军覆没**
    # 时才当退路。实测打脸: 线路恢复后直连 1.25s, 池子挑出来的却要 4.7s ——
    # 池子只在自己圈子里排名, 压根不知道外面那条路其实更快。
    # 现在把系统解析结果也放进抢连名单, 跟候选池一起并发抢连, 谁先握手成功用谁。
    # DNS 被污染也不怕: 解析出来的 IP 连不上就在抢连里被淘汰, 不会拖慢其他人。
    _SYS_DNS = {}          # host -> (ts, [ip, ...])
    _SYS_DNS_TTL = 60.0    # 缓存 60 秒: 运营商解析会变, 缓存太久会失真

    @staticmethod
    def _sys_ips(host, limit=2, force=False):
        """系统 DNS 解析结果 —— 即"不走狐径时浏览器本来会连的那个 IP"。"""
        now = time.time()
        if not force:
            hit = ProxyHandler._SYS_DNS.get(host)
            if hit and now - hit[0] < ProxyHandler._SYS_DNS_TTL:
                return hit[1]
        v4, v6 = [], []
        try:
            for fam, _t, _p, _c, addr in socket.getaddrinfo(
                    host, 443, proto=socket.IPPROTO_TCP):
                ip = addr[0]
                if not ip:
                    continue
                (v4 if fam == socket.AF_INET else v6).append(ip)
        except Exception:
            pass
        # IPv4 优先: 本机 IPv6 出网不一定通, 让它占满名额会挤掉真能用的 v4
        ips = []
        for ip in v4 + v6:
            if ip not in ips:
                ips.append(ip)
            if len(ips) >= limit:
                break
        ProxyHandler._SYS_DNS[host] = (now, ips)
        return ips

    def _connect_pool(self, host, port, pool, key, label, prefer=''):
        # 候选顺序: 上次真正连通成功的 IP > 手填 IP > 体检名次(按失败次数降权)。
        # 体检名次会过期(两次体检之间路由悄悄挂掉), 所以只当兜底排在后面。
        cand = []
        cur = _LAST_GOOD.get(key) or ''

        # 【2026-10-11 修·在锁死之前下手】
        # 一直复用同一个"上一把成功"的 IP 是舒服的, 但它会**用完寿命就突然死掉**,
        # 死的那一下要等一轮超时才换得过来(实测 8~16 秒, 体感=打不开)。
        # 这里按台账算寿命: 用到 80% 就**趁它还活着主动让位**给热备池里的新鲜 IP。
        # 换是零成本的 —— 反正都是同域名同端口, 浏览器完全感知不到。
        if cur and _ip_expiring(cur):
            # 【2026-10-25 二修·没有替补就别主动让位】
            # 原来只要"用过 80% 寿命"就无条件把 cur 清掉, 可热备池经常是空的
            # (本机 21:20 日志: 20.26.156.215 已撑 52 秒但暂时没有新鲜热备,
            #  下次转发重新抢连)。清掉之后下一次请求要重新发现通道, 常常先吃
            # 4~10 秒全灭 —— 用户体感就是"刚才还能打开, 现在又慢"。
            # 现在只有热备里真有没过期的替补才换; 没有就继续用这个还活着的,
            # 真死了由下面 2 秒试连/抢连自然淘汰。
            _alt = [x for x in _hot_get(key) if not _ip_expiring(x)]
            if _alt:
                avg = _avg_life()
                log('预防性换 IP: %s 已撑 %d 秒(这类 IP 平均撑 %d 秒), 趁它还通着先让位'
                    % (cur, int(_ip_age(cur)), int(avg)))
                cur = ''

        # 系统解析(直连)想进名单, 得先拿出"真能传数据"的证据 ——
        # 抢连比的是 TCP 握手快慢, 而 20.205.243.166 握手只要 0.12s(全场最快)、
        # 页面却 25 秒下不完, 系统偏偏最爱解析到它。第一版让它直接进名单, 它靠
        # 握手快赢下竞速, 实测当场吃到一个 30 秒超时, 把真能传数据的 IP 挤掉了。
        # 现在只有后台真下过一段、证明传得动的直连 IP 才有资格参与, 没验过的不赌
        # (池子全灭时还有下面原有的系统兜底)。
        sys_ips = []
        _cap = _cap_of(host, _SYS_CAP)
        if (_cap and _fail_rank(_cap['ip']) == 0
                and _cap['ip'] in self._sys_ips(host)):
            sys_ips = [_cap['ip']]

        for x in (cur, prefer) + tuple(sys_ips):
            if x and x not in cand:
                cand.append(x)
        # 热备池里的 IP 是 20 秒内刚验过的(体检名次可能已经过期 5 分钟)
        # 【2026-10-25 四修·热备别把抢连名单占满】
        # 原来热备 8 个全塞在候选最前面, 而抢连/轻探只看 cand[:6] ——
        # 热备里只要死得多一点, 池子里明明有活的也轮不上, 当场"候选全军覆没"。
        # 现在热备只先放 2 个(够快), 剩下让给池内名次, 多出来的热备排到后面。
        _hot = [x for x in _hot_get(key) if x not in cand]
        for x in _hot[:2]:
            cand.append(x)
        rest = [x for x in pool.candidates()[:24] if x not in cand]
        # 【2026-10-26 三点整改·②】排序把两本账一起算: _fail_rank 是"握手/建连失败",
        # _stall_rank 是"连上了但正文搬不动/半途断流"。老写法只看前者, 于是那种
        # "TCP 0.1 秒赢下抢连、正文一个字节不来"的 IP 永远欠不到账, 每轮都抢赢、
        # 每次都把浏览器吊在半路(本机实测 229KB / 278KB 断流那两发就是它)。
        rest.sort(key=lambda ip: _fail_rank(ip) + _stall_rank(ip))   # 两本账都往后靠
        # 摊到不同网段后再并发抢连: 一段全死还有别的段顶上
        cand += _pick_spread(rest, per_group=2, limit=6)
        for x in _hot[2:]:
            cand.append(x)
        # 【2026-10-25 四修·池子被失败清空时，从全表直接补人】
        # 每条全灭都会把 cand[:6] 从池子里 drop 掉。浏览器一开页就是十几条并发,
        # 碰上线路抽风, 一两轮就能把 22 个"可用"全清光 —— 而重新体检要等 5 分钟。
        # 本机 21:56 就是这样: 日志一路"候选 IP 全军覆没", 可同一秒手动按 IP 测
        # 20.27.177.113 / 20.199.39.232 / 20.200.245.247 全是 200, 1.2~2.1 秒。
        # 候选少于 8 个时从全表按网段补齐, 让轻探/抢连始终有真人可试, 不再等体检。
        # 【2026-10-25 四修补】只数"池外新血": 热备哪怕挂着 8 个, 也可能全是死的,
        # 池子被清空时 len(cand) 照样够 8, 原来就漏补了。现在按非热备候选计数。
        _hset = set(_hot)
        if len([x for x in cand if x not in _hset]) < 8:
            try:
                _full = (candidate_list() if key == 'github'
                         else CANDIDATE_IPS_RAW_ALL if key == 'raw'
                         else CANDIDATE_IPS_PAGES_ALL)
            except Exception:
                _full = []
            for _x in _pick_spread([x for x in _full if x not in cand],
                                   per_group=2, limit=12):
                cand.append(_x)
        # 同样把"寿命将尽"的从候选里剔掉 —— 否则刚让它让位、转头又从热备/名次里
        # 把它捡回来, 预防就白做了。全都要过期时才不挑食(总得有个能连的)。
        young = [x for x in cand if not _ip_expiring(x)]
        if young:
            # 【2026-10-25 二修·在用通道兜底】寿命将尽的都剔掉之后, 如果当前在用的
            # 那个 IP 被剔掉了, 但它其实还连着, 就把它留在最前面 —— 抢连/轻探都只看
            # 名单前几个, 放队尾等于没放。否则一旦"年轻"的候选恰好全是死的(常见:
            # 刚换过 IP, 新名次还没实测), 抢连里连一个能用的都没有, 白白走一遍全灭
            # 再退回系统解析。它真死了会在下面 2 秒/4 秒里被淘汰, 不会占着位子。
            if cur and cur in cand and cur not in young:
                young.insert(0, cur)
            cand = young

        # 【2026-10-24 新增·改法② 快速失败】
        # 这一池子有没有"近期真答过话"的证据? 判据跟面板上"实测可用"完全一致:
        #   · 近 _FRESH_WINDOW 秒里跑通过一次 HTTP(tier='http'), 或
        #   · 吞吐台账还新鲜(_kbps_of 自带 TTL 判定)
        # 两条都没有 = 31 个 IP 全是"证书还握得上、页面一次没跑通"的旧名次,
        # 这时候按老规矩并发 6 个、每个等 4 秒, 纯属拿用户的浏览器陪葬。
        # 改成只轻探 2 个、每个 2 秒, 不通马上退回系统解析。
        # 只对**跑 HTTP 的池子**生效: raw / Pages 按设计只验证书(它们的 GET /
        # 必然 400/404, 拿不到 tier='http'), 拿这条尺子量它们会把好 IP 误杀。
        fast = False
        if pool.checks_http:
            _now = time.time()
            _strong = [x for x in cand
                       if pool.tier_of(x)[0] == 'http'
                       and _now - pool.tier_of(x)[1] <= _FRESH_WINDOW]
            # 【2026-10-25 三修·"有台账"不等于"有快的"】
            # 原来只要任意一个候选有吞吐记录就不进 fast, 可今晚实测池内台账是
            # 22~43 KB/s —— 远低于 _KBPS_DIRECT_MIN(60), 根本不足以让它直连,
            # 于是又回到"按握手抢连", 挑中握手快、正文不来的 IP, 用户就是打不开。
            # 现在只有真有 ≥60 KB/s 的证据才算"有米下锅"; 否则照样轻探一轮,
            # 用 GET / 的 2xx/3xx 找出此刻真能吐页面的那一个。
            if not _strong and not any((_kbps_of(x) or 0) >= _KBPS_DIRECT_MIN
                                       for x in cand):
                fast = True
                if _fast_log_ok(key):
                    log('%s 候选池近 %d 秒没有一个实测成过、吞吐台账也全过期 —— '
                        '本次只做 2 秒轻探, 随即退回系统解析' %
                        (label, int(_FRESH_WINDOW)))

        _tried = set()      # 这次请求已经试过的 IP, 防止同一个死 IP 连撞两回

        # 【2026-10-11 三修·台账里实测最快的直接放行, 不进抢连】
        # 抢连比的是 **TCP 握手快慢**, 而"握手快 ≠ 传得动" —— 前两版都栽在这:
        #   1) 直连放进抢连名单, 结果握手快的坏 IP 赢了, 当场吃 30 秒超时;
        #   2) 改成"直连 vs 池"用吞吐对决, 可池子赢下对决后, **池内几十个 IP 之间
        #      仍按握手抢连** —— 实测后台判池内有 194 KB/s, 端到端却走了 10.87 秒。
        # 现在每个验过的 IP 都有一笔实测吞吐(热备量过、直连/池首选也量过),
        # 谁最快就直连谁, 握手速度不再参与裁决。
        # 余量: 跨到直连那条路要快 25%(换路径代价大、防两边抖动来回切),
        # 池内只需领先 15%。赌输的代价可控 —— 超时 2.5 秒就回落抢连。
        best, second = _kbps_pick(cand)
        if best and best[1] >= _KBPS_DIRECT_MIN:
            need = _SYS_WIN_RATIO if best[0] in sys_ips else _KBPS_WIN_RATIO
            if second is None or best[1] >= second[1] * need:
                _tried.add(best[0])
                try:
                    # 超时压到 2.0 秒: 证据新鲜时连接通常 <0.5 秒就回来,
                    # 超过 2 秒基本可以断定"台账已过期", 早撤早回落抢连。
                    _s = socket.create_connection((best[0], port), timeout=2.0)
                    _note_route(key, best[0], sys_ips)
                    _LAST_GOOD[key] = best[0]
                    _fail_clear(best[0])
                    _ip_born(best[0])
                    _sys_fail_reset(key)
                    log('按实测吞吐直连 %s: %d KB/s, 次快 %s'
                        % (best[0], best[1],
                           ('%d KB/s' % second[1]) if second else '无'))
                    return _s, best[0]
                except OSError:
                    _fail_note(best[0])
                    _hot_drop(key, best[0])
                    _kbps_forget(best[0])   # 赌输了就忘掉它, 下次别再赔一轮超时

        # 【2026-10-24 新增·改法③ 后台判直连赢就立刻走直连】
        # 原来只有"直连 IP 在吞吐台账里还新鲜且够快"时才会走直连, 可台账一旦被
        # _kbps_forget 作废(赌输一次)或过了 TTL, 而 _SYS_CAP 的对比结论还新鲜,
        # 下一次请求就**还挂在过期的候选池上抢连** —— 用户反馈包里"吞吐对比…选直连"
        # 之后仍然满屏"候选 IP 全军覆没", 就是这个脱节。
        # 现在对比说直连明显快, 就先拿 2 秒试一把直连; 试不上再按原逻辑抢连。
        if not fast and _sys_wins(host):
            _sc = _cap_of(host, _SYS_CAP) or {}
            _sip = _sc.get('ip') or ''
            if _sip and _sip not in _tried and _fail_rank(_sip) == 0:
                _tried.add(_sip)
                try:
                    _s2 = socket.create_connection((_sip, port), timeout=2.0)
                    _note_route(key, _sip, [_sip])
                    _LAST_GOOD[key] = _sip
                    _fail_clear(_sip)
                    _ip_born(_sip)
                    _sys_fail_reset(key)
                    log('吞吐对比判直连更快(直连 %d KB/s vs 池 %d KB/s): '
                        '本次先走直连 %s' % (
                            _sc.get('kbps', 0),
                            (_cap_of(host, _POOL_CAP) or {}).get('kbps', 0), _sip))
                    return _s2, _sip
                except OSError:
                    _fail_note(_sip)
                    _kbps_forget(_sip)

        # 【2026-10-25 四修·先试"刚验过能吐页面"的那条通道, 失败立刻换轻探】
        # 抢连只比 TCP 握手快慢。今晚实测 11 个"体检可用"的 IP, 只有 4 个真能把整页跑完
        # (20.200.245.247 0.86s / 20.27.177.113 1.56s / 48.204.201.5 2.13s /
        #  20.199.39.232 2.41s), 其余 6 个握手都通、正文一个字节不来。握手快的死 IP
        # 一抢就赢, 浏览器停在"正在打开…"——这就是用户说的"还是打不开"。
        # 只要 90 秒内有真答过 2xx/3xx 的证据, 就先给它 1.2 秒直接连; 通了就复用。
        # 【2026-10-25 再补】试不通时不要接着按握手抢连(那是又一轮抽奖), 直接把 fast
        # 置真, 走下面的 GET / 轻探重新找一条此刻真能吐页面的; 两条路都走完才退回系统。
        if not fast:
            _trust, _trust_ts = '', 0.0
            if cur and cur not in _tried and not _bad_edge(cur):
                _t, _tt = pool.tier_of(cur)
                if _t == 'http' and time.time() - _tt <= _FRESH_WINDOW:
                    _trust, _trust_ts = cur, _tt
            if not _trust:
                for _x in cand:
                    if _x in _tried or _bad_edge(_x):
                        continue
                    _t, _tt = pool.tier_of(_x)
                    if (_t == 'http' and time.time() - _tt <= _FRESH_WINDOW
                            and _tt > _trust_ts):
                        _trust, _trust_ts = _x, _tt
            if _trust:
                _tried.add(_trust)
                try:
                    _s6 = socket.create_connection((_trust, port), timeout=1.2)
                except OSError:
                    _fail_note(_trust)
                    _hot_drop(key, _trust)
                    _kbps_forget(_trust)
                    cand = [x for x in cand if x != _trust]
                    fast = True
                else:
                    _note_route(key, _trust, sys_ips)
                    _LAST_GOOD[key] = _trust
                    _fail_clear(_trust)
                    _ip_born(_trust)
                    _sys_fail_reset(key)
                    if _fast_log_ok('trust:' + key):
                        log('%s 复用刚验过的通道 %s(证据 %d 秒前), 跳过握手抢连'
                            % (label, _trust, int(time.time() - _trust_ts)))
                    return _s6, _trust

        # 【2026-10-24 新增·fast 时先"实测"再转发】
        # fast 意味着这一池子近 90 秒没有任何一条 HTTP 证据、吞吐台账也全过期。
        # 老做法是直接拿 2 个 IP 做 TCP 抢连 —— 可 TCP 通了不代表页面通：
        # 今天满屏的 400 就是这么来的（隧道加密，转发层看不见里面那个 400，日志还一切正常）。
        # 现在先拿体检同一把尺子问一发 GET /（并发 3 个、TCP 1.5 秒 + HTTP 2 秒封顶），
        # 谁真答 2xx/3xx 就用谁；一个都没答话，才按老路做 2 秒轻抢连、再退回系统解析。
        if fast and pool.checks_http:
            # 【2026-10-25 加宽 3→6·按本机日志改】fast 只会落在"闲了一阵之后的第一条请求"上,
            # 而那一条正是用户亲手点开页面的那一下, 亏不得。本机 foxpath.log 今天的记录:
            #   18:34:41 轻探实测 20.200.245.247 回 2xx(267ms)  → 秒开
            #   19:33:53 轻探实测 20.250.119.67  回 2xx(568ms)  → 秒开
            #   19:11 / 19:14 / 19:17 / 19:36 四条 3 个都没答话 → 直接掉到
            #           "候选 IP 全军覆没, 本次退回系统解析"
            # 而系统解析那一位在同一份日志里是"直连 20.205.243.166(28 KB/s)"或"连不上",
            # 也就是掉下去的这几条大概率就是用户说的"又打不开"。同一时刻体检报的是
            # 可用 22~29/50 —— 池子里明明有活的, 只问 3 个等于抽奖。
            # 6 是这套代码里反复验证过的"覆盖多网段又不自拥塞"的上限(下面抢连 max_race=6、
            # _prescan 批次的成本红线都按 6 收的), 并发仍然只这一批、单个仍然 1.5 秒封顶,
            # 所以最坏耗时没有变大, 只是把命中率从 3 个候选抬到 6 个。
            _try = [x for x in cand if x not in _tried and not _bad_edge(x)][:6]
            # 【2026-10-24 二修·改法④b】同一轮 HTTP 实测里**也问一句系统解析的 IP**。
            # 为什么现在才加：今天先试的是"fast 时先拿 2 秒 TCP 连一把直连"，A/B 一跑
            # 就露馅了(见 logs/UI整改-20261024/挑线路实测-20261024.txt)——
            # 22:16 那半小时里直连 IP 是"握手通、正文死"，对照组 8/8 个 200 中位 1.35s，
            # 而 TCP 优先插队的版本 3/8 条 4 秒没吐一个字节，反而更糟。
            # 2026-10-11 记过的老坑是同一个：20.205.243.166 握手 0.12s 全场最快、
            # 页面却 25 秒下不完。所以**不能拿 TCP 握手当证据**，只能拿 HTTP 应答当证据。
            # 现在把它拉进本来就在并发跑的实测里(不多花一秒)，并且**排在这轮结果的最后**：
            # 池子有人答话就还是池子的(它有寿命/吞吐台账)，只有池子全不答话而直连答了 2xx/3xx，
            # 才走这条"刚被证实真能吐页面"的路 —— 省掉后面 2 秒 TCP 抢连和 3~10 秒兜底等待。
            _sys_now = self._sys_ips(host) or []
            for _x in _sys_now[:1]:
                if _x and _x not in _try and _fail_rank(_x) == 0:
                    _try.append(_x)
            # 【2026-10-26 补·轻探也要看预算】一轮轻探最坏 1.5+2.0 秒。剩余预算
            # 连一轮都跑不完就别起跑(注意顺序: 时间不够时不去占 _prescan 的闸门,
            # 免得把坑占住又跑不完, 让别人干等)。
            if _try and self._dl_left() >= 3.6 and _prescan_take():
                # 【2026-10-25 四修·一轮问不到就再问一批】
                # 21:59 冷启动实测: 池里 18/50 "可用", 轻探 6 个只有 1 个答话,
                # 那个 185.199.x 还在转发途中死掉 —— 于是连吃两分钟"全军覆没",
                # 而同一分钟手动按 IP 测, 20.29.134.23 / 20.27.177.113 都是 200。
                # 6 个样本对这条时好时坏的线路来说太小, 一轮问不到并不代表池子空了。
                # 现在第一轮没人答话就换**没问过**的下一批再问一次(仍然并发、仍然封顶),
                # 并把第二轮的超时放宽到 2.2 秒 —— 这条线上 TTFB 1.9~2.4 秒的好 IP 不少。
                _probed = set()
                _cert = []
                try:
                    _batch = _try
                    for _rnd, _tmo, _hto in ((0, 1.5, 2.0), (1, 2.2, 2.6)):
                        if not _batch:
                            break
                        # 【2026-10-26 补·到点就不问第二轮】一轮最坏要 _tmo+_hto 秒,
                        # 预算不够就到此为止 —— 第一轮已经并发问过 6 个, 再撒一批
                        # 只是把这条请求拖过用户的耐心(装机实测叠到过 19.4 秒)。
                        if _rnd and self._dl_left() < _tmo + _hto:
                            self._dl_note(self._dl_left(), '再问第二轮轻探', label)
                            break
                        _probed.update(_batch)
                        with ThreadPoolExecutor(max_workers=len(_batch)) as _ex:
                            _pr = dict(zip(_batch, _ex.map(
                                lambda x, _t=_tmo, _h=_hto: pool._probe(
                                    x, timeout=_t, http_timeout=_h),
                                _batch)))
                        _cert = sorted([(m[0], x) for x, m in _pr.items()
                                        if m and m[1] == 'http'])
                        if _cert:
                            break
                        if _rnd == 0:
                            _batch = [x for x in cand if x not in _probed
                                      and not _bad_edge(x)][:6]
                finally:
                    _prescan_release()      # 探针批次一结束就交还闸门
                _tried.update(_probed)
                # 池内 IP 优先, 直连垫底(同一把尺子答了话才有资格排进来)
                _cert.sort(key=lambda t: (1 if t[1] in _sys_now else 0, t[0]))
                for _ms, _ip in _cert:
                    try:
                        _s4 = socket.create_connection((_ip, port), timeout=2.0)
                    except OSError:
                        _fail_note(_ip)
                        continue
                    _note_route(key, _ip, _sys_now)
                    _LAST_GOOD[key] = _ip
                    _fail_clear(_ip)
                    _ip_born(_ip)
                    _sys_fail_reset(key)
                    log('%s 轻探实测: %s 的 GET / 回到 2xx/3xx(%dms，%s)，本次用它转发'
                        % (label, _ip, _ms,
                           '系统解析' if _ip in _sys_now else '候选池'))
                    return _s4, _ip
                # 问下来一个都不答话: 回 4xx 的那些已经被 _probe 就地拉黑，
                # 别再让它们参与下面的抢连(它们握手最快，一抢就赢，赢了就是 400)。
                cand = [x for x in cand if not _bad_edge(x)] or cand
                # 【2026-10-25 四修·问过没答话的别挡路】它们 TCP 是通的,
                # 抢连比的就是握手, 让它们留在前 6 个里 = 必然挑中一个打不开的。
                # 没试过的排前面, 抢连才有意义。
                cand = ([x for x in cand if x not in _probed]
                        + [x for x in cand if x in _probed])
            elif (pool.checks_http and not _LAST_GOOD.get(key)
                  and _PRESCAN_BUSY[0]):
                # 【2026-10-25 四修·别让同一个页面的其它连接盲抢】
                # 浏览器开一个页就是十几条并发隧道, 而轻探是全局单闸门: 只有抢到闸门
                # 的那一条能拿到"实测答话"的结论, 其余全按 TCP 握手抢连 —— 抢中的
                # 偏偏是握手快、正文不来的那种。这里改为**等它的结论**(最多 3 秒),
                # 结论一出就复用; 轻探结束还没结论再照旧抢连。
                # 【2026-10-26 补】这一等也受建连总时限约束(留 1.2 秒给自己轻试一手)。
                _wait_until = min(time.time() + 3.0,
                                  time.time() + max(0.0, self._dl_left() - 1.2))
                while time.time() < _wait_until:
                    time.sleep(0.1)
                    _lg = _LAST_GOOD.get(key)
                    if _lg:
                        try:
                            _s5 = socket.create_connection((_lg, port), timeout=1.5)
                        except OSError:
                            _LAST_GOOD[key] = ''
                            _fail_note(_lg)
                            continue
                        _note_route(key, _lg, sys_ips)
                        _fail_clear(_lg)
                        _ip_born(_lg)
                        _sys_fail_reset(key)
                        if _fast_log_ok('wait:' + key):
                            log('%s 等到了同时在跑的轻探结论 %s, 复用它' % (label, _lg))
                        return _s5, _lg
                    if not _PRESCAN_BUSY[0]:
                        break

        # 一批并发抢连(6 个): 谁先通就用谁。
        # 不做"分批重试" —— 每多一批就多叠加一轮超时, 实测分批版出现过 16 秒尖峰。
        # 并发数**不是越多越好**: 试过 14 个, 国际链路上这些连接会互相挤占带宽,
        # 结果每个都变慢(实测退化到 7~10 秒); 6 个兼顾"覆盖多网段"与"不自拥塞"。
        # timeout 4 秒: 并发抢连的返回时间取决于"最快成功的那个", 不是这个上限,
        # 所以放宽它是零成本的, 高丢包时给 TCP 重传留够时间。
        # 但"没有任何实测证据"时(fast)反过来 —— 此时更可能全灭, 等越久亏越多,
        # 所以轻探 2 个、2 秒封顶。
        sock, ip = self._connect_race(cand, port,
                                      timeout=2.0 if fast else 4.0,
                                      max_race=2 if fast else 6,
                                      key=key, label=label)
        if (sock is None and fast and not _LAST_GOOD.get(key) and len(cand) > 6
                and self._dl_left() > 1.8):
            # 【2026-10-25 四修·整段被掐时别只抽两个】
            # 22:17 实测: 44 个官方 IP 里 TCP:443 只有 3 个还通(其余 SYN 直接丢,
            # ping 却 0% 丢包), 而轻探那 12 个恰好全在死的里面 —— 于是"全军覆没"。
            # fast + 手里一个可用通道都没有, 说明刚才那一轮证据全废了; 这时候
            # 再"抽 2 个碰运气"命中率太低。改成广撒网: 前 16 个并发握一次手,
            # 1.5 秒封顶, 谁先通就用谁(和上面同一套抢连, 只是把网撒宽)。
            # 【2026-10-26 补】这一手要 1.5 秒, 预算不够就别撒 —— 宁可到点放弃,
            # 也不要为了多一次机会把请求拖进"用户已经关了标签"的那一段。
            sock, ip = self._connect_race(cand, port, timeout=1.5, max_race=16,
                                          key=key, label=label)
        if sock is not None:
            _note_route(key, ip, sys_ips)
            _LAST_GOOD[key] = ip
            _fail_clear(ip)
            _ip_born(ip)          # 寿命台账: 这个 IP 第一次被证实可用
            _sys_fail_reset(key)
            return sock, ip
        for dead in cand[:6]:
            pool.drop(dead)
            _fail_note(dead)
            _ip_died(dead)        # 结掉这一生, 记进"能撑多久"的样本
            _hot_drop(key, dead)  # 热备里也剔掉, 下轮补新的

        _LAST_GOOD[key] = ''
        # 整批都撞死了 —— 热备池多半也过期了, 立刻补一批新的待命。
        # 【2026-10-25 收口·别自己挤自己】原来**每一条**失败的转发都各开一个补充线程:
        # 本机日志 19:47:27~19:47:30 三秒里 raw 连吃 7 条"全军覆没", 于是 7 个线程
        # 各带并发 4 的探针同时上路(28 个探测), 而那会儿链路正在拥塞 —— 补充本身
        # 变成新的负担, 越拥塞越补不上(和 _measure_hot / _prescan 记过的是同一个坑)。
        # 现在同一池 30 秒内只补一次; 后来的请求照旧往下走系统解析兜底, 一秒都不多等。
        # 判据用时间戳, 跟 trigger_selfheal 的 60 秒闸门同一个写法。
        _rnow = time.time()
        if _rnow - _HOT_REFILL_TS.get(key, 0.0) >= _HOT_REFILL_COOLDOWN:
            _HOT_REFILL_TS[key] = _rnow
            threading.Thread(target=lambda: hot_refresh(key, pool), daemon=True).start()
        log('%s 候选 IP 全军覆没, 本次退回系统解析' % label)
        trigger_selfheal()
        # 【2026-10-26 三点整改·① 到点之前先在池里再转两轮, 别立刻撒手】
        # 现场就是今天下午 16:42 那 6 发里的 5 个 502: 那会儿后台正在全池重测,
        # 16:43:54 就报出"可用 6/50", 而 13.5 秒成的那一条**再等半秒就轮到刚验活的
        # 通道** —— 老写法在这里直接清掉 _LAST_GOOD, 转身把剩下的预算押到那条已经
        # 实测必死的直连上, 等完回一句 502。用户"多点一下刷新就通了"其实是后台
        # 补上了人, 只是这条请求没等。
        # 现在: 预算还剩 _CONNECT_RETRY_MIN_LEFT 秒以上就最多再转 _CONNECT_RETRY_ROUNDS
        # 轮, 每轮先等 _CONNECT_RETRY_BACKOFF 秒让 hot_refresh/自愈把新鲜结论写进来。
        # 并发仍然只有 _connect_race 那一批(6 个、1.5 秒封顶), 而且有抢连闸门:
        # 同一个页面的其余 CONNECT 不追加 SYN, 只复用结论 —— 不会把拥塞放大。
        for _rnd in range(_CONNECT_RETRY_ROUNDS):
            if self._dl_left() < _CONNECT_RETRY_MIN_LEFT:
                break
            time.sleep(min(_CONNECT_RETRY_BACKOFF,
                           max(0.0, self._dl_left() - 1.2)))
            _lg = _LAST_GOOD.get(key)
            if _lg:
                try:
                    _sr = socket.create_connection((_lg, port),
                                                   timeout=min(1.5, max(0.5, self._dl_left() - 0.2)))
                except OSError:
                    _fail_note(_lg)
                    _LAST_GOOD[key] = ''
                else:
                    _note_route(key, _lg, sys_ips)
                    _fail_clear(_lg)
                    _ip_born(_lg)
                    _sys_fail_reset(key)
                    log('%s 全灭后第 %d 轮: 后台补员结论已到, 复用 %s'
                        % (label, _rnd + 1, _lg))
                    return _sr, _lg
            _c2 = [x for x in (list(_hot_get(key)) + cand + list(pool.candidates()))
                   if x and x not in _tried and not _bad_edge(x)]
            if not _c2:
                _c2 = [x for x in (list(_hot_get(key)) + cand) if x and x not in _tried]
            if not _c2:
                break
            sock, ip = self._connect_race(_c2, port, timeout=1.5, max_race=6,
                                          key=key, label=label)
            if sock is not None:
                _note_route(key, ip, sys_ips)
                _LAST_GOOD[key] = ip
                _fail_clear(ip)
                _ip_born(ip)
                _sys_fail_reset(key)
                log('%s 全灭后第 %d 轮抢到 %s, 本次用它转发' % (label, _rnd + 1, ip))
                return sock, ip
            for dead in _c2[:6]:
                _fail_note(dead)
                _hot_drop(key, dead)
        # 连续全灭过就把兜底的等待压到 3 秒(见 _sys_fail_budget 的说明),
        # 单条请求最坏从 ~14 秒降到 ~5 秒, 浏览器不至于整站卡死。
        _budget = _sys_fail_budget(key)
        # 【2026-10-26 三点整改·① 另一半: 不去等那条实测已经死了的直连】
        # 后台每 60 秒**绕开狐径**直连 github.com 探一次(_DIRECT_OK), 今天下午它给
        # 的就是"不通"(我同一时刻手工复现: 直连 443 12 秒超时)。老写法却把剩下的
        # 预算全押在这条路上 —— 探针 1.5 秒 + 兜底 3~10 秒, 等完仍是一句 502,
        # 而同样这几秒够候选池再转一轮(上面的轮转就是干这个的)。
        # 所以: 直连刚探过且不通 → 这一注不押, 干脆失败, 让浏览器立刻重试;
        #       还没探过 / 探到过 / 探测结果过期 → 保持老行为, 留一条
        #       "和没装本程序一样"的退路(这条退路本来就不该被我们主动阉掉)。
        if _direct_is_dead(key):
            _n0 = _sys_fail_bump(key)
            log('%s 候选池 %d 轮全灭, 直连实测也不通(%d 秒前刚探过) —— 这次不押直连, '
                '时间留给后台补员, 浏览器刷新即可(最近 %d 秒内第 %d 次全灭)'
                % (label, _CONNECT_RETRY_ROUNDS + 1,
                   int(time.time() - (_DIRECT_OK[1] or 0.0)),
                   int(_SYS_FAIL_WINDOW), _n0))
            return None, None
        # 【2026-10-26 修·账要按时间窗记】装机版 12:35~12:38 四分钟里这一句印了
        # 6 次"兜底等了 10.0 秒, 连续第 1 次全灭": 链路是**时好时坏**, 中间任何一条
        # 请求复用通道成功都会把老账本清零, 于是下一次撞死又从头等满 10 秒。
        # 现在 _SYS_FAIL 记的是时间戳(一次成功只抹最旧两笔), 60 秒内还有账就一直是
        # 3 秒; 下面这句再把预算剪到这次建连的剩余时间里 —— 到点就不陪它等。
        if self._dl_left() <= 0.3:
            self._dl_note(self._dl_left(), '兜底等系统解析', label)
            return None, None
        _tmo = max(0.5, min(_budget, self._dl_left() - 0.2))
        if _tmo < _budget:
            self._dl_note(self._dl_left(), '等满兜底的 %d 秒' % int(_budget), label)
        # 【2026-10-24 三修·改法④c】退回系统解析之前, 最后拿实测问一句。
        # 起因是装机版 22:37:00 那一条日志 + 同一秒的一次实测:
        #   "候选 IP 全军覆没, 本次退回系统解析" → curl 拿到 **400 + 1440 字节**,
        #   正文是 GitHub 的 "Bad request" 假前门页 —— 用户看到的"外国仓库打不开"就是这个。
        # 老做法这里是**闭眼放行**: 系统解析到谁就连谁, 而 Azure 前门里有一批节点
        # 证书里有 github.com、TCP/TLS 全通, 页面却必定回 400(2026-10-24 实测过 8/8 次 400
        # 的 20.200.245.244、20.205.243.161)。转发是加密隧道, 里面那个 400 我们看不见,
        # 于是日志一路绿灯、用户满屏打不开。
        # 现在先问一发 GET /(体检同一把尺子):
        #   · 答 2xx/3xx —— 用它转发, 这一下从"必定 400"变成"能开";
        #   · 答 4xx/5xx —— _probe 已经就地把它实测拉黑 15 分钟, 这次就不给它转发
        #     (宁可让这一条请求干脆失败, 也不把必定回 400 的前门交给浏览器);
        #   · 不答话 —— 没证据也没反证, 保持老行为交给系统解析赌一把。
        # 两个闸门, 免得在最该快的时候添堵:
        #   fast(近 90 秒没有任何 HTTP 证据)时**不问** —— 上面 ④b 刚刚用同一把尺子
        #   问过同一个 IP, 再问一遍只是白加 2 秒;
        #   连续全灭(_budget 已被压到 3 秒)时也不问 —— 那正是整站在抽风的时候,
        #   保平的"别卡死"比这一发的运气重要。
        _sys_all = [x for x in (self._sys_ips(host) or []) if x]
        if (pool.checks_http and not fast and _sys_all
                and all(_bad_edge(x) for x in _sys_all)):
            # 【2026-10-24 三修·把那段 15 分钟的洞堵上】上面"实测拉黑 15 分钟"原来
            # 只让**第一条**请求拒得掉: _sys_now 是从"没被拉黑的系统 IP"里挑的, 一拉黑
            # _sys_now 就空了、整段被跳过, 底下那句 create_connection((host, port))
            # 又闭眼连回同一个必定回 400 的前门。装机版日志就是这么写的 ——
            # 「退回前实测」0 条, 同期「候选 IP 全军覆没, 本次退回系统解析」100 条,
            # 用户看到的仍是那页 GitHub "Bad request"(也就是"外国仓库打不开")。
            # 现在: 系统解析到的**每一个** IP 都在实测拉黑期内 → 不探针、不连接、直接拒。
            # 这一句不花任何额外时间(连那 1.5 秒探针都省), 只把"必定 400"换成一次干脆的失败。
            log('%s 退回前实测: 系统解析到的 %s 全在实测拉黑期内(假前门)，'
                '本次不给它转发，下次重新抢连' % (label, '、'.join(_sys_all[:2])))
            return None, None
        # 【2026-10-26 补·这发探针也要看预算】探针最多 1.5 秒, 但只剩 2 秒时不再问:
        # 问完就没时间兜底了, 反而两头落空。够宽裕才问, 且超时按剩余裁剪。
        if (pool.checks_http and not fast and _budget >= _SYS_FAIL_FULL_TIMEOUT
                and self._dl_left() >= 2.0):
            _p_tmo = max(0.6, min(1.5, self._dl_left() - 0.8))
            _sys_now = [x for x in _sys_all if not _bad_edge(x)]
            _p_ip = _sys_now[0] if _sys_now else ''
            if _p_ip:
                _pm = None
                try:
                    _pm = pool._probe(_p_ip, timeout=_p_tmo)
                except Exception:
                    _pm = None
                if _pm and _pm[1] == 'http':
                    try:
                        _s5 = socket.create_connection(
                            (_p_ip, port),
                            timeout=max(0.5, min(2.0, self._dl_left())))
                    except OSError:
                        _fail_note(_p_ip)
                    else:
                        _note_route(key, _p_ip, _sys_now)
                        _LAST_GOOD[key] = _p_ip
                        _fail_clear(_p_ip)
                        _ip_born(_p_ip)
                        _sys_fail_reset(key)
                        log('%s 退回前实测: 系统解析 %s 的 GET / 回到 2xx/3xx(%dms)，'
                            '本次用它转发' % (label, _p_ip, _pm[0]))
                        return _s5, _p_ip
                elif _bad_edge(_p_ip):
                    log('%s 退回前实测: 系统解析 %s 回 4xx/5xx(假前门)，'
                        '本次不给它转发，下次重新抢连' % (label, _p_ip))
                    return None, None
        try:
            _s3 = socket.create_connection((host, port), timeout=_tmo)
            _sys_fail_reset(key)
            return _s3, None
        except OSError as e:
            _n = _sys_fail_bump(key)
            log('连接 %s 失败: %s（兜底等了 %.1f 秒, 最近 %d 秒内第 %d 次全灭）' %
                (host, e, _tmo, int(_SYS_FAIL_WINDOW), _n))
            return None, None

    def _connect(self, host, port):
        # 【2026-10-26 新增·建连总时限】一次建连从进来到"放弃"最多花
        # _CONNECT_DEADLINE 秒。下面所有贵的手(抢连/广撒网/两轮轻探/兜底)
        # 都先看剩余预算, 不够就不做 —— 失败还是失败, 但不再拖到十几二十秒。
        # 【2026-10-26 三点整改·①】这个"多久"不再是死数: 按最近真实转发的账调
        # (见 _web_dl_budget)。当天下午实测到"成功的那几发本来就要 6~13 秒",
        # 还按 8 秒一刀切, 等于把"再等两秒就通"的请求主动判死、回一句 502。
        self._dl_start(_web_dl_budget(_pool_key_for(host)))
        # 【2026-10-10 修 声明不符】先卡域名：本代理只转发 GitHub 相关域名。
        # 对外写的是「只接管 GitHub 相关域名、不转发他人流量」，
        # 原来这里的兜底对任何 host 都建隧道，与声明冲突（docs/SECURITY.md 自己也列了这条）。
        # 现在拒绝并记一行日志 —— 不静默，出问题能从日志看出来是谁在借用。
        if not is_github_related_host(host):
            log('拒绝转发非 GitHub 域名: %s:%s（本代理只接管 GitHub 相关域名）' % (host, port))
            return None, None
        if is_raw_host(host):
            # raw 文件 / 发布附件：走 185.199.108.0/22 那段专属池。
            return self._connect_pool(host, port, HEALTH_RAW, 'raw', 'raw')
        if is_pages_host(host):
            # GitHub Pages: 证书是 *.github.io, 走按 github.io 体检过的那一池。
            return self._connect_pool(host, port, HEALTH_PAGES, 'pages', 'github.io')
        if is_github_host(host):
            if not _MANUAL_IP[0]:
                _MANUAL_IP[0] = load_manual_ip()
            return self._connect_pool(host, port, HEALTH, 'github', 'github.com',
                                      prefer=_MANUAL_IP[0] or '')
        try:
            return socket.create_connection((host, port), timeout=10), None
        except OSError as e:
            log('连接 %s 失败: %s' % (host, e))
            return None, None

    def _tunnel(self, target):
        host, _, p = target.partition(':')
        port = int(p or 443)
        self._read_headers()
        _key = _pool_key_for(host)
        _t0 = time.time()
        up, used = self._connect(host, port)
        _conn_ms = (time.time() - _t0) * 1000.0
        if up is None:
            self._send(502, b'Bad Gateway')
            # 【2026-10-26 三点整改·③】建连就没成 = 用户体感"打不开", 记进网页台账。
            _web_record(_key, WEB_REFUSED, _conn_ms, 0)
            trigger_selfheal()
            return
        # 【2026-10-24】面板"本次会话"那一格：PAC 命中走候选池 / 退回系统解析各算一次。
        # 只统计**转发成功**的连接，失败的不算命中。
        hit_count(bool(used))
        try:
            self.wfile.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
            self.wfile.flush()
        except Exception:
            up.close()
            return
        if used:
            log_conn('%s -> %s' % (host, used))
        out = self._relay(up)
        # 【2026-10-26 三点整改·②③】这条隧道到底有没有把页面搬回来, 是网页台账
        # 唯一的原材料 —— 只有真实转发知道答案, 体检不知道(体检只看 GET / 答不答)。
        # 耗时按"建连 + 首字节"算: 浏览器等的就是这一段, 隧道后面挂多久是.keep-alive
        # 的事, 混进来会把中位数拉到几百秒那种没意义的数上去。
        _web_record(_key, out['kind'], _conn_ms + out['first_ms'], out['bytes_up'])
        if out['kind'] == WEB_STALL and used:
            # 断流记**另一本账**: 握手是成功的, _FAIL_CNT 一分钱不欠, 所以必须在这里
            # 单独记账才降得动它的排序。满 _STALL_DROP_POOL 次才请出池子 —— 它是
            # 时好时坏, 不像假前门那样必定骗人, 一棒子打死会把仅有的候选清光。
            # 反过来也不因为"这次成了"就把账清零: 2026-10-26 已经吃过"一成功就清零"
            # 的亏(见 _SYS_FAIL 的修法), 时好时坏的链路只让账自己按窗口过期。
            _n = _stall_note(used, out['bytes_up'])
            log('%s 断流: %s 这次搬了 %d 字节就停了(窗口内第 %d 次), 排序已降权%s'
                % (host, used, out['bytes_up'], _n,
                   '' if _n < _STALL_DROP_POOL else ', 请出候选池'))
            if _n >= _STALL_DROP_POOL:
                HEALTH.drop(used)
                _hot_drop(_key, used)
                trigger_selfheal()
        if out['kind'] == WEB_BADGW and used:
            log('上游返回 4xx/5xx, 剔除假活 IP %s 并触发自愈' % used)
            HEALTH.drop(used)
            trigger_selfheal()

    def _relay(self, up):
        conn = self.connection
        pair = [conn, up]
        up_err = False
        stalled = False
        _first_up = True
        bytes_up = 0
        first_ms = 0.0
        _t_relay = time.time()
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
                    stalled = True
                    break
                if not r:
                    # 双方都静默满一个空闲上限才收摊, 而且写进日志 ——
                    # 不再像以前那样不声不响地把流掐掉。
                    log('转发空闲超过 %d 秒, 关闭这条连接(对端可能已放弃)' % RELAY_IDLE_TIMEOUT)
                    stalled = True
                    break
                stop = False
                for s in r:
                    try:
                        data = s.recv(65536)
                    except TimeoutError:
                        # 3.10 起 socket.timeout 就是 TimeoutError
                        log('转发等待数据超过 %d 秒, 关闭这条连接' % RELAY_IDLE_TIMEOUT)
                        stalled = s is up or bytes_up > 0
                        stop = True
                        break
                    except OSError:
                        stalled = s is up or bytes_up > 0
                        stop = True
                        break
                    # 【2026-10-11 修·嗅探上游首段】上游 IP 若"证书对但被限流/封禁",
                    # 会返回 HTTP 4xx/5xx(典型 400): 这种假活 IP 之前 TCP/TLS 都通,
                    # 代理以为成功转发, 实则用户拿到错误页。首段若是 4xx/5xx 即判死。
                    # 【2026-10-26 修·判状态位判错了】原来写的是 `code[2:3] in b'45'`
                    # —— 那是状态码的**第三位**(404 的 4、504 的 4), 于是典型的
                    # 400 / 500 / 503 全都漏网(本函数注释里点名的"典型 400"恰好是
                    # 一个都不判)。状态码的类别看**第一位**, 现在按第一位判。
                    # (说明: 走 CONNECT 的隧道里是 TLS 密文, 这段本来就只 cleartext
                    #  代理时才会命中, 修它是为了让 badgw 这一档的口径与注释一致。)
                    if _first_up and s is up and data[:5] == b'HTTP/' and len(data) >= 12:
                        code = data[9:12]
                        if code[:2].isdigit() and code[:1] in (b'4', b'5'):
                            up_err = True
                            stop = True
                            break
                    if s is up and data:
                        if _first_up:
                            # 【2026-10-26 三点整改·③】首字节多久来 —— 浏览器"转圈"
                            # 的那一段就是这个数, 网页台账的耗时按它算(不含 keep-alive)。
                            first_ms = (time.time() - _t_relay) * 1000.0
                        _first_up = False
                        bytes_up += len(data)
                    elif s is up:
                        _first_up = False
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
            up_err = True
        finally:
            for s in pair:
                try:
                    s.close()
                except Exception:
                    pass
        # 【2026-10-26 三点整改·②③】这条隧道的结局 —— 网页台账和断流账都从这里取。
        #   badgw  上游回 4xx/5xx(假前门)
        #   ok     搬过正文且不是我们自己等到超时/被断
        #   stall  **其余全部**: 一个字节都没来(握手通、正文死的典型样子),
        #          或搬了一半被超时/OSError 掐断(本机实测 229KB / 278KB 那两发)
        # 为什么"没搬成数据"也算 stall 而不算 refused: 建连是成功的, 失败发生在
        # 正文阶段 —— 这正是"体检可用 6/50、网页却打不开"那段时间的真实形状。
        if up_err:
            kind = WEB_BADGW
        elif bytes_up > 0 and not stalled:
            kind = WEB_OK
        else:
            kind = WEB_STALL
        return {'kind': kind, 'bytes_up': bytes_up, 'first_ms': first_ms,
                'stalled': stalled, 'up_err': up_err}


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
        # 【2026-10-11 修复】Windows 下 PAC 要生效必须 ProxyEnable=1; 本程序之前
        # 只写了 AutoConfigURL 没开总闸, 导致"启用了加速"浏览器/系统却仍不读 PAC
        # —— 表现就是打开加速后 github 依然打不开。这里补开总闸; disable_proxy /
        # 退出时会在下面按备份把 ProxyEnable 还原回原值, 不会残留。
        reg_set(REG_INTERNET, 'ProxyEnable', 1, 4)
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
        # 【2026-10-10 修·还原会覆盖用户设置】有备份、但**当前系统代理已经不是狐径设的**
        # —— 说明中间被别的东西改过(用户自己改的、公司策略下发的、别的工具设的)。
        # 这时候按备份还原 = 把人家刚设好的东西覆盖成"狐径启用之前的那个旧值"，
        # 而且那份新设置**原文再也找不回**；面板还会回一句"已停用, 系统代理已还原"，
        # 用户根本不知道自己的设置被动了。
        # 与下面"没有备份"那一支同一个口径：**不是我们设的，就一个字节都不动**。
        if saved is not None and not proxy_on():
            log('有还原备份, 但当前系统代理不是狐径所设 —— 保持原样, 不覆盖')
            return False, ('当前系统代理不是狐径所设（中途可能被别的程序或策略改过）—— '
                           '已保持原样，没有做任何修改')
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
        # 【2026-10-10 修·撤掉用完的备份】还原成功后把那份快照删掉 —— 它已经用完了。
        # 留着就是隐患：盘上永远躺着一份**过期快照**，下次"停用并还原"若在异常路径上
        # 用到它，就会拿旧值覆盖用户此刻的设置(上面那道闸门也拦得住，但不如根本不留)。
        # 删掉是安全的：此刻注册表里就是用户的原值，备份已无用处；
        # 用户再点"启用加速"时 enable_proxy 会重新备份一份。
        try:
            if os.path.exists(BACKUP_FILE):
                os.remove(BACKUP_FILE)
                log('还原备份已用完, 已撤掉: %s' % BACKUP_FILE)
        except OSError as e:
            log('还原备份撤掉失败(不影响本次还原结果): %s' % e)
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


# ---------------------------------------------------- 开机态自愈（2026-10-26 巡检固化）
#
# 现场（本机 2026-10-26 早上实测）：重启把 FoxPath 连同 atexit 一起带走，注册表里留着
#   AutoConfigURL=http://127.0.0.1:8788/pac、ProxyEnable=1，而 8787/8788 一个都没人听。
#   浏览器还在用缓存的 PAC，于是 github 连到死端口、其它站点正常 —— 用户看到的就是
#   "github 打不开"，而程序里一行日志都没有（v1.2.2 的还原只挂在 atexit 上）。
# 再加一条：这台机器上「开机自启」从来没打开过（HKCU\Run 里没有 GitHubDirectFix），
#   所以每次重启都会重新踩这个坑。
def _write_run_mark():
    """盖戳：记下"此刻有一个实例在跑，退出时会负责还原"。"""
    try:
        with open(RUN_MARK_FILE, 'w', encoding='utf-8') as f:
            json.dump({'pid': os.getpid(), 'app': str(APP_VERSION),
                       'ts': time.time(), 'pac': _pac_url()}, f, ensure_ascii=False)
    except Exception as e:
        log('写运行戳失败(不影响加速本身): %s' % e)


def _take_run_mark():
    """读走并删掉上一次的戳；没有戳说明上次是正常退出（或第一次跑）。"""
    try:
        if not os.path.exists(RUN_MARK_FILE):
            return None
        with open(RUN_MARK_FILE, encoding='utf-8') as f:
            d = json.load(f)
        try:
            os.remove(RUN_MARK_FILE)
        except Exception:
            pass
        return d if isinstance(d, dict) else None
    except Exception:
        try:
            os.remove(RUN_MARK_FILE)
        except Exception:
            pass
        return None


def startup_proxy(keep_off):
    """本次启动对系统代理该做什么 —— 静默/常规两种模式共用一份口径（以前是两段复制粘贴）。"""
    if keep_off:
        log('按升级前的状态: 没有开启加速')
        return
    if not proxy_on():
        enable_proxy()
        return
    # PAC 已经指向本程序 = 上次开着加速时进程没走到还原
    if _BOOT_DIRTY[0]:
        p = _BOOT_DIRTY[0]
        log('!! 上次进程没有正常退出（被结束任务/断电/重启都是这样）—— 现场: pid=%s 版本=%s 时间=%s；'
            '系统里留着指向 %s 的 PAC，本次启动已直接接管，不重复写注册表'
            % (p.get('pid'), p.get('app'),
               time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.get('ts') or 0)), _pac_url()))
    # 总闸可能被安全软件/策略关回 0：PAC 地址还指着我们，proxy_on() 为真，
    # 老代码就不会再动 ProxyEnable —— 表现同样是"加速看着开着，实际一点没生效"。
    cur = reg_get(REG_INTERNET, 'ProxyEnable')
    if str(cur) != '1':
        reg_set(REG_INTERNET, 'ProxyEnable', 1, 4)
        notify_proxy_change()
        log('已补开系统代理总闸 ProxyEnable=1（原来是 %s：PAC 指向本程序但总闸是关的，'
            '多半被安全软件或组策略改回去了）' % ('(未设置)' if cur is None else cur))
    if _load_backup() is None:
        log('注意: 系统代理已指向本程序, 但没有还原备份 —— 退出时会直接清除该 PAC')


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
# 做法: 升级源 version.json 先过 **Ed25519 验签** -> 下载到 <exe>.new -> 校验 sha256 ->
#       交给一个独立小助手 (先让旧程序自己退出并还原代理 -> 覆盖 -> 再启动新的)。
#       验签不过、没有 .sig、sha256 不符 —— 一律拒绝并保留旧版本, 绝不"先替换再校验"。
# 不需要管理员权限: D:\Program Files 的 ACL 允许普通用户写(实测过)。
# 升级源: 仓库里的 version.json, GitCode raw 优先、GitHub 兜底;
#         测试时可在数据目录放一个 update_url.txt 指到本地文件。
UPDATE_URLS = (
    # 2026-10-23: 按用户要求去掉 Gitee 兜底（老仓库地址一律不出现）；只留 GitCode + GitHub。
    # GitCode 没有 Gitee 那种 raw 直链，用它的 API raw：/raw/version.json?ref=main
    'https://gitcode.com/api/v5/repos/kele551/FoxPath/raw/version.json?ref=main',
    'https://raw.githubusercontent.com/kele551/FoxPath/main/version.json',
)

# 【2026-10-16 升级通道加固】内置的 Ed25519 **公钥**（离线生成，公开无妨、本来就要随程序分发）。
# 升级源 version.json 必须带一份同目录的 `version.json.sig`（128 个十六进制字符 = 64 字节签名），
# 用这把公钥验过才认；验不过 / 没签名 / 签名格式不对，一律**拒绝这条候选**（详见 _verify_update_sig）。
# 没有私钥就签不出合法签名，所以即便 Gitee / GitHub 账号被盗、有人推了恶意 version.json + 恶意 exe，
# 客户端也不会装。私钥只在维护者机器上、绝不入库（见 docs/SECURITY.md）。
# 能力边界（别夸大）：这挡的是"升级源被篡改"；挡不住维护者机器上的私钥本身被偷，
# 也不等于 Windows 代码签名证书。
UPDATE_PUBKEY = 'a29ea38e6313de486303f6ce0703adc5c7f28fbda9d444523c40d33982ec6082'
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
#   ⓪ 升级源必须过 **Ed25519 验签**（2026-10-16 加；见 UPDATE_PUBKEY / _verify_update_sig）,
#      验不过/没签名一律拒绝并保留旧版本 —— 这是"升级源被篡改"的唯一防线;
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


def _consume_update_result_file():
    """【2026-10-11·用户要求"只出现一次"】本会话首次把升级结果行展示给面板后,
    删掉落盘记录(update-result.json), 只留内存。这样:
      升级结束那次会话 → 看得到这一行;
      程序重启后再开面板 → 读不到记录、不再显示。
    既满足"升级结束出现一次", 又满足"用户再次打开时不出现"。
    """
    try:
        if os.path.exists(UPDATE_RESULT_FILE):
            os.remove(UPDATE_RESULT_FILE)
    except Exception:
        pass


def last_result_text():
    """面板「更新」卡片里那一行: 上次升级结果(成功/失败 + 时间 + 一句怎么办)。

    【2026-10-11·用户要求"只出现一次"】调用即视为"已展示过一次", 顺手清掉落盘记录
    (见 _consume_update_result_file), 只留内存供本次会话继续回看; 重启后不再出现。
    """
    d = _LAST_RESULT[0]
    if not d:
        return ''
    _consume_update_result_file()
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
    info = read_update_info(use_cache=False, stale_fallback=True)
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


def _read_text_from(u, timeout=20):
    """读一个升级源地址的**原始字节**（http(s) 或本地文件）。返回 (bytes, None) 或 (None, 原因)。

    返回 bytes 而不是 str 是必须的：Ed25519 签名是对 `version.json` 的**原始字节**做的，
    解析成字符串再编码回去（换行、BOM、编码任何一个环节变了）就验不过了。
    """
    if u.startswith(('http://', 'https://')):
        req = urllib.request.Request(u, headers={'User-Agent': 'FoxPath'})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(), None
    with open(u, 'rb') as f:
        return f.read(), None


def _sig_url_of(u):
    """签名文件与 version.json **同目录同名**：<...>/version.json -> <...>/version.json.sig。

    线上就是这么放的（`…/raw/main/version.json.sig`；GitCode 是 `…/raw/version.json?ref=main`）；
    本地路径（update_url.txt 指到文件，演练用）同样按"名字后面加 .sig"找。
    2026-10-17: 升级源现在可能带查询串（GitCode 的 ?ref=main），`.sig` 要插在 `?` 之前，
    不能直接拼在末尾。
    """
    if '?' in u:
        p, q = u.split('?', 1)
        return p + '.sig?' + q
    return u + '.sig'


def _verify_update_sig(u, raw):
    """用内置公钥验签升级源。返回 (ok, 原因)。

    fail-closed 的四条：
      · 内置的 _ed25519.py 没加载起来        -> 拒绝（宁可不让升级，也绝不放行没验签的更新）；
      · 拿不到同目录的 .sig（404/网络/文件没了）-> 拒绝；
      · .sig 不是 128 个十六进制字符          -> 拒绝（格式不对一律拒绝，不"猜"）；
      · checkvalid 不过                       -> 拒绝（内容被改过，或签名不是这把私钥做的）。
    """
    if not UPDATE_SIG_AVAILABLE:
        return False, '验签模块缺失(_ed25519.py)'
    try:
        pub = bytes.fromhex(UPDATE_PUBKEY)
    except Exception:
        return False, '内置公钥不是合法的十六进制'
    sig_u = _sig_url_of(u)
    try:
        sig_raw, _ = _read_text_from(sig_u, timeout=20)
    except Exception as e:
        return False, '拿不到签名(%s)' % type(e).__name__
    try:
        txt = sig_raw.decode('utf-8', 'replace').strip()
    except Exception:
        return False, '签名文件不是文本'
    if not re.fullmatch(r'[0-9a-fA-F]{128}', txt):
        # 注意措辞：长度对但不是十六进制也走这里（"128 个字符"与"128 个十六进制字符"是两回事）
        return False, '签名格式不对(应为 128 个十六进制字符, 实际 %d 个字符)' % len(txt)
    try:
        if _ed25519.checkvalid(bytes.fromhex(txt), raw, pub):
            return True, ''
    except Exception as e:
        return False, '验签出错(%s)' % type(e).__name__
    return False, '签名不匹配'


# 候选全都不行时留给调用方的一句人话（面板/气泡用），原因原文进日志。
SIG_FAIL_MSG = '更新源校验未通过，已保留当前版本'
# 最近一次"读升级源"失败的原文原因（如"签名不匹配"/"拿不到签名(HTTPError)"）。
# 【为什么要分两栏】"校验未通过"和"连不上源"要给用户**不一样**的话：
# 前者是我们主动拒绝（源被改过 / 签名缺失），后者才是网络问题 —— 混在一起会让人白折腾网络。
_LAST_READ_WHY = ['']       # 本次联网失败的原文原因
_LAST_READ_SIG = [False]    # 原因属不属于"验签这条线"（True 才提示"校验未通过"）


def _update_cache_read():
    """读升级缓存；**只认验过签的那一份**，其余当没缓存。

    【2026-10-16】缓存里存的是"验过签的升级信息"，所以缓存命中就等于这次也验过签。
    但要是缓存是**老版本**（还不认识签名这件事）写下的，就只能当它不可信、重新联网验
    一遍 —— 否则"删掉 update.json / 读一份旧缓存"就成了跳过验签的后门。
    """
    try:
        with open(UPDATE_CACHE, encoding='utf-8') as f:
            c = json.load(f)
    except Exception:
        return None
    if not c.get('_sig_ok'):
        log('升级缓存不是验签得来的（可能是旧版写的），忽略它、重新联网验签')
        return None
    return c


def read_update_info(use_cache=True, stale_fallback=False):
    """读升级信息; use_cache=True 时 6 小时内不重复联网。

    【2026-10-12 修·手动检查吃了 6 小时缓存】以前面板「检查更新」也走默认缓存:
    旧版实例(或上一轮自动检查)写进 update.json 的结果, 6 小时内用户怎么点都不碰
    网络 —— 新版发布后老用户最长 6 小时毫无感知; 刚升级完的实例更惨, 读到的还是
    升级前那份旧缓存, 面板直接误报"本地版本比线上新"。手动检查必须联网;
    stale_fallback: 联网全失败时回读缓存并标 _stale —— 宁可明说"显示的是上次结果",
    也不静默把过期结论当现状。

    【2026-10-16 升级通道加固】每个候选都要 **Ed25519 验签通过**才采用：
    version.json 与它同目录的 version.json.sig 一起取，先验签、后解析 ——
    绝不存在"先替换再验签"的顺序（这里连 exe 都还没碰）。
    """
    if use_cache:
        c = _update_cache_read()
        if c and time.time() - float(c.get('_checked', 0)) < 6 * 3600:
            return c
    urls = list(UPDATE_URLS)
    try:
        if os.path.isfile(UPDATE_URL_TXT):
            with open(UPDATE_URL_TXT, encoding='utf-8') as f:
                u = f.read().strip()
            if u:
                urls = [u]
    except Exception:
        pass
    # 每个候选都要求「取得到 + Ed25519 验签通过」才采用；验不过就换下一个（见 _verify_update_sig）。
    # 全部不行就把离用户最近的那条原因留给面板与日志 —— 不再只有一句"连不上升级源"。
    last_why = ''
    last_is_sig = False          # 这条原因是不是"验签这条线"上的（决定面板给哪句话）
    for u in urls:
        try:
            raw_b, _ = _read_text_from(u)
        except Exception as e:
            last_why, last_is_sig = '读不到升级源(%s)' % type(e).__name__, False
            log('升级检查失败(%s): %s' % (u, e))
            continue
        ok, why = _verify_update_sig(u, raw_b)
        if not ok:
            # ★ 验签不过 = 这条候选作废：**绝不解析、绝不采用、更不会去动 exe**。
            last_why, last_is_sig = why, True
            log('升级源校验未通过(%s): %s —— 已拒绝这条候选，继续试下一个' % (u, why))
            continue
        try:
            info = json.loads(raw_b.decode('utf-8', 'replace'))
            if not info.get('version'):
                last_why, last_is_sig = '升级源里没有版本号', True
                continue
            info['_checked'] = time.time()
            info['_source'] = u
            info['_sig_ok'] = True      # 标记"这份结果是验过签的"（缓存里也留着，便于排查）
            _LAST_READ_WHY[0], _LAST_READ_SIG[0] = '', False
            try:
                with open(UPDATE_CACHE, 'w', encoding='utf-8') as f:
                    json.dump(info, f, ensure_ascii=False)
            except Exception:
                pass
            return info
        except Exception as e:
            last_why, last_is_sig = '升级源不是合法 JSON(%s)' % type(e).__name__, True
            log('升级检查失败(%s): %s' % (u, e))
            continue
    if last_why:
        _LAST_READ_WHY[0], _LAST_READ_SIG[0] = last_why, last_is_sig
        log('升级检查: 所有候选取不到或验签不通过 —— %s' % last_why)
    if stale_fallback:
        # 联网全挂: 回读缓存, 但打上 _stale 标记, 由调用方在面板上明说。
        # 缓存本身必须是**验过签的那一份**（_update_cache_read 会把没验签的挡掉）——
        # 回退只是"显示上次结果"，不是"放松验签"。
        c = _update_cache_read()
        if c:
            c['_stale'] = True
            return c
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
    # 用户明确按下"检查更新" = 必须联网(2026-10-12 修): 不许被 6 小时缓存挡过去
    info = read_update_info(use_cache=False, stale_fallback=False)
    if not info:
        # 2026-10-16：区分"连不上"和"验签不过"——后者要给用户一句明确的话
        # （更新源校验未通过，已保留当前版本），别让人以为是自己网络的问题。
        _why = (_LAST_READ_WHY[0] or '').strip()
        if _why and _LAST_READ_SIG[0]:
            _update_set(phase='failed', error='sig',
                        msg='%s（%s）' % (SIG_FAIL_MSG, _why))
        else:
            _update_set(phase='failed', error='net', msg='连不上升级源(或还没发布升级信息)')
        return _update_get()
    node = update_exe_node(info) or {}
    remote = str(info.get('version') or '')
    # ★ 结论只按版本号语义下(2026-10-09 线上事故): 只有**远程严格大于本地**才是
    # 「发现新版本」。面板拿 relation / newer 两个字段渲染, 不再自己比字符串。
    rel, newer, msg = ver_verdict(remote, APP_VERSION)
    if info.get('_stale'):
        msg = msg + '（联网失败，显示的是上次检查的结果）'
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

    sha256 是**升级包本身**的完整性凭证(下载有没有坏、是不是同一份); 它和 exe 放在
    同一个升级源里, 所以光有它挡不住"源被整体替换"—— 那道闸是升级源的 Ed25519 验签
    (_verify_update_sig, 2026-10-16 加), 两道都过才采用。
    升级源里没有 sha256 时必须拒绝 —— 不能像以前那样"want 为空就放行", 那会让漏写或
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
    # 【2026-10-16 纵深防御】只认**验过签**的升级信息：read_update_info 只会把验签通过的
    # 结果写进缓存，这里再认一次 _sig_ok —— 万一以后有人加了新入口、或塞进一份老版本写的
    # 缓存，也不会拿着没验签的 version.json 去换 exe（fail-closed，宁可让用户重点一次）。
    if not (info or {}).get('_sig_ok'):
        why = SIG_FAIL_MSG + '（升级信息未经验签，请重新点一次「检查更新」）'
        _update_set(phase='failed', error='sig', msg=why)
        log('升级: 拒绝执行 —— 手上的升级信息没有通过 Ed25519 验签')
        report_update_result(False, auto=auto, from_ver=APP_VERSION, why='sig')
        return
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
    # 【2026-10-12 新增 · 下载多源回退】以前只认 exe.url 单源: Gitee 偶发抽风/限速(451)
    # 时升级链直接断死, 用户只能"手动去发行页下载"。现在按 **url + mirrors[]** 依次试,
    # 只认 https(与升级源同一口径); 首个成功即采用, 全失败时把"试过哪几家"写清楚 ——
    # 不再一句"下载失败"让人猜。mirrors 对老版本无害: 1.0.x 只读 url, 多出来的字段忽略。
    urls = [str(node.get('url') or '')] + [str(u) for u in (node.get('mirrors') or [])]
    # 生产只认 https；**例外**：本机回环 http（127.0.0.1 / localhost）放行 —— 仅供
    # 发版前升级演练用（演练在本地起 http 服务当"升级源"），回环地址拿不到也被远程攻击者利用不了。
    urls = [u for u in urls
            if u.lower().startswith('https://')
            or u.lower().startswith('http://127.0.0.1')
            or u.lower().startswith('http://localhost')]
    sha, err, tried = '', '', []
    for idx, u in enumerate(urls):
        sha, err = _download_to(new, u, int(node.get('size') or 0))
        if sha:
            if idx > 0:
                log('升级: 主源之后第 %d 个镜像源成功: %s' % (idx, u.split('//', 1)[1].split('/')[0]))
            break
        tried.append(u.split('//', 1)[1].split('/')[0])
        log('升级: 下载源 %s 失败(%s), 换下一个' % (tried[-1], err))
    if not sha:
        if not urls:
            err = '升级源里没有可用的 https 下载地址'
        elif len(tried) > 1:
            err = '%s(共试 %d 个源: %s)' % (err, len(tried), ', '.join(tried))
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
<html lang="zh-CN" data-theme="dark">
<head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>狐径 FoxPath __VERSION__</title>
<style>
/* ══════════════════════════════════════════════════════════════════════════
   设计令牌 —— 与《UI 整改方案》同一套（石墨灰 + 狐径橙），只改变量、不写字面量
   ══════════════════════════════════════════════════════════════════════════ */
:root{
  --font:"Microsoft YaHei UI","Microsoft YaHei","PingFang SC","Segoe UI",system-ui,sans-serif;
  --mono:"Cascadia Mono",Consolas,"Courier New",monospace;
  --bg:#171a20; --bg-1:#1c2027; --card:#20252d; --card-2:#262d37;
  --line:#303844; --line-2:#3e4856;
  --txt:#e7ebf1; --txt-2:#a3aebe; --txt-3:#76818f;
  --ok:#3ecf8e; --warn:#f0b429; --danger:#f2555a; --info:#4f8cff;
  --accent:#f0883e; --accent-ink:#241103;
  --fs-title:20px; --fs-h:14px; --fs-body:13px; --fs-meta:12px; --fs-micro:11px;
  --r-card:10px; --r-btn:8px; --r-pill:999px;
  --shadow-1:0 1px 0 rgba(0,0,0,.18); --shadow-2:0 14px 40px rgba(0,0,0,.45);
  /* 浏览器原生那部分（滚动条/表单控件/日期弹层）也一起跟主题，不然暗色页面配亮色滚动条。
     2026-10-24 四款一起补这一行。 */
  color-scheme:dark;
}
[data-theme="light"]{
  --bg:#f3f5f9; --bg-1:#e9edf4; --card:#ffffff; --card-2:#f7f9fc;
  --line:#e2e7ef; --line-2:#d3dae5;
  --txt:#17202b; --txt-2:#5b6675; --txt-3:#8a96a5;
  --ok:#12a150; --warn:#a86f00; --danger:#d13438; --info:#1a5fd0;
  --accent:#c2620f; --accent-ink:#fff;
  --shadow-1:0 1px 0 rgba(16,30,54,.04); --shadow-2:0 18px 40px rgba(20,34,60,.14);
  color-scheme:light;
}

*{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--txt)}
body{font:var(--fs-body)/1.55 var(--font);-webkit-font-smoothing:antialiased;
  background-image:radial-gradient(120% 60% at 50% -10%,rgba(240,136,62,.07),transparent 60%)}
[data-theme="light"] body{background-image:none}
button,input{font:inherit;color:inherit}
button{cursor:pointer;background:none;border:0}
h1,h2,h3,p{margin:0}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:6px}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-thumb{background:var(--line-2);border-radius:8px;border:2px solid var(--bg)}
::-webkit-scrollbar-track{background:transparent}
.wrap{max-width:1180px;margin:0 auto;padding:18px 20px 40px}

/* ── 顶栏 ───────────────────────────────────────────────────────────── */
.top{display:flex;align-items:center;gap:14px;padding:2px 2px 16px}
.logo{width:38px;height:38px;border-radius:11px;flex:none;display:grid;place-items:center;
  background:var(--accent);color:var(--accent-ink);font-weight:700;font-size:17px;
  box-shadow:var(--shadow-1)}
.top h1{font-size:var(--fs-title);font-weight:650;letter-spacing:.2px;display:flex;
  align-items:center;gap:8px;flex-wrap:wrap}
.ver{font:600 var(--fs-micro)/1 var(--mono);color:var(--txt-2);background:var(--card-2);
  border:1px solid var(--line);border-radius:var(--r-pill);padding:4px 8px;letter-spacing:.02em}
.top p{color:var(--txt-3);font-size:var(--fs-micro);margin-top:3px}
.top-r{margin-left:auto;display:flex;align-items:center;gap:8px}

/* ── 通用组件 ───────────────────────────────────────────────────────── */
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r-card);
  padding:16px 18px;box-shadow:var(--shadow-1);margin-bottom:14px}
.card.tight{padding:14px 16px}
.card-h{display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap}
.card-h h2{font-size:var(--fs-h);font-weight:600}
.card-h .hint{color:var(--txt-2);font-size:var(--fs-micro)}
.card-h .right{margin-left:auto;display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.muted{color:var(--txt-3)}
.xs{font-size:var(--fs-micro)}
.mono{font-family:var(--mono)}
.num{font-variant-numeric:tabular-nums}
.t-lg{font-size:17px;font-weight:650;line-height:1.35}
.msg{display:block;font-size:var(--fs-micro);color:var(--ok);min-height:15px;margin-top:6px}
.msg.bad{color:var(--danger)}

.pill{display:inline-flex;align-items:center;gap:6px;height:24px;padding:0 10px;
  border-radius:var(--r-pill);border:1px solid var(--line);font-size:var(--fs-micro);
  color:var(--txt-2);white-space:nowrap;background:var(--card-2)}
.pill i{width:6px;height:6px;border-radius:50%;background:var(--txt-3);flex:none}
.pill.ok i{background:var(--ok);box-shadow:0 0 0 3px rgba(62,207,142,.18)}
.pill.warn i{background:var(--warn);box-shadow:0 0 0 3px rgba(240,180,41,.18)}
.pill.bad i{background:var(--danger);box-shadow:0 0 0 3px rgba(242,85,90,.18)}
.pill.on{color:var(--accent);border-color:rgba(240,136,62,.45);background:rgba(240,136,62,.12)}

.btn{height:30px;padding:0 12px;border-radius:var(--r-btn);border:1px solid var(--line);
  background:var(--card-2);color:var(--txt);font-size:var(--fs-meta);
  display:inline-flex;align-items:center;gap:7px;white-space:nowrap;
  transition:border-color .15s,background .15s,color .15s,opacity .15s}
.btn:hover{border-color:var(--line-2);background:var(--card)}
.btn.primary{background:var(--accent);border-color:transparent;color:var(--accent-ink);font-weight:600}
.btn.primary:hover{filter:brightness(1.07)}
.btn.ghost{background:transparent;border-color:transparent;color:var(--txt-2)}
.btn.ghost:hover{color:var(--txt);background:var(--card-2)}
.btn.danger{color:var(--danger);border-color:rgba(242,85,90,.38);background:transparent}
.btn.danger:hover{background:rgba(242,85,90,.12)}
.btn.sm{height:26px;padding:0 9px;font-size:var(--fs-micro)}
.btn:disabled{opacity:.45;cursor:default}
.icon-btn{width:30px;height:30px;border-radius:var(--r-btn);border:1px solid var(--line);
  background:var(--card-2);color:var(--txt-2);display:grid;place-items:center;font-size:14px;
  transition:border-color .15s,color .15s}
.icon-btn:hover{color:var(--txt);border-color:var(--line-2)}

.chip{height:26px;padding:0 11px;border-radius:var(--r-pill);border:1px solid var(--line);
  background:transparent;color:var(--txt-2);font-size:var(--fs-meta);
  display:inline-flex;align-items:center;gap:6px;transition:all .15s}
.chip:hover{color:var(--txt);border-color:var(--line-2)}
.chip.on{background:rgba(240,136,62,.14);border-color:rgba(240,136,62,.45);
  color:var(--accent);font-weight:600}
[data-theme="light"] .chip.on{background:rgba(194,98,15,.12)}
kbd{font:500 10px/1 var(--mono);color:var(--txt-3);border:1px solid var(--line-2);
  border-radius:5px;padding:3px 5px;background:var(--card)}

/* 开关 */
.sw{width:36px;height:20px;border-radius:var(--r-pill);background:var(--line-2);position:relative;
  flex:none;transition:background .18s}
.sw:after{content:"";position:absolute;top:2px;left:2px;width:16px;height:16px;border-radius:50%;
  background:#fff;transition:transform .18s;box-shadow:0 1px 2px rgba(0,0,0,.35)}
.sw.on{background:var(--accent)}
.sw.on:after{transform:translateX(16px)}
.sw.big{width:56px;height:30px;border-radius:var(--r-pill)}
.sw.big:after{width:26px;height:26px}
.sw.big.on:after{transform:translateX(26px)}
.sw[disabled]{opacity:.5;cursor:default}

/* hero */
.hero{display:flex;align-items:center;gap:18px;flex-wrap:wrap;margin-bottom:10px}
.hero-mid{flex:1;min-width:230px}
.hero-mid .sub{color:var(--txt-3);font-size:var(--fs-micro);margin-top:2px}
.hero-right{display:flex;align-items:center;gap:22px;flex-wrap:wrap}
.kv .k{color:var(--txt-2);font-size:var(--fs-micro);letter-spacing:.02em}
.kv .v{font-size:15px;font-weight:600;margin-top:2px;font-variant-numeric:tabular-nums}
.kv .v small{font-size:var(--fs-micro);font-weight:400;color:var(--txt-3);margin-left:2px}
.kv .v.mono{font-family:var(--mono);font-size:14px;font-weight:500}
.btns{display:flex;gap:8px}

/* 状态说明行（原来那几条提示，现在放在 hero 下面一行一条） */
.tips{margin:0 2px 14px;display:flex;flex-direction:column;gap:4px}
.tips>div{font-size:var(--fs-micro);color:var(--txt-2)}
/* 线路状态移进日志卡后：红字区分，空的自动收起 */
.logtips{margin:0 0 10px;gap:5px}
.logtips>div{font-size:var(--fs-micro);line-height:1.6;color:var(--danger)}
.logtips>div:empty{display:none}

/* 数字卡 */
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:14px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:var(--r-card);
  padding:13px 15px;box-shadow:var(--shadow-1)}
.stat .k{color:var(--txt-2);font-size:var(--fs-micro);letter-spacing:.04em;text-transform:uppercase}
.stat .v{font-size:24px;font-weight:650;line-height:1.25;margin-top:5px;font-variant-numeric:tabular-nums}
.stat .v small{font-size:var(--fs-meta);font-weight:500;color:var(--txt-3);margin-left:3px}
.stat .d{font-size:var(--fs-micro);color:var(--txt-2);margin-top:3px}
.stat .d.up{color:var(--ok)} .stat .d.down{color:var(--danger)}

/* 两栏 */
.cols{display:block}
.col{min-width:0}
.col>*:last-child{margin-bottom:0}

/* 表格 */
.tbl{width:100%;border-collapse:collapse;font-size:var(--fs-meta)}
.tbl th{text-align:left;font-weight:500;font-size:var(--fs-micro);letter-spacing:.05em;
  text-transform:uppercase;color:var(--txt-2);padding:0 8px 8px;border-bottom:1px solid var(--line);
  white-space:nowrap}
.tbl th.sortable{cursor:pointer;user-select:none}
.tbl th.sortable:hover{color:var(--txt-2)}
.tbl th .arw{display:inline-block;width:9px;color:var(--accent);font-size:9px}
.tbl td{padding:9px 8px;border-bottom:1px solid var(--line);vertical-align:middle}
.tbl tbody tr:hover td{background:var(--card-2)}
.tbl tbody tr:last-child td{border-bottom:0}
.tbl th.r,.tbl td.r{text-align:right}
.copy{opacity:0;transition:opacity .15s;color:var(--txt-3);font-size:var(--fs-micro);padding:2px 4px}
tr:hover .copy{opacity:1}
.copy:hover{color:var(--accent)}
.table-foot{display:flex;align-items:center;gap:10px;margin-top:10px;font-size:var(--fs-micro);
  color:var(--txt-2);flex-wrap:wrap}
.empty{padding:14px 4px;font-size:var(--fs-meta);color:var(--txt-3);line-height:1.7}

/* 句子式设置行（线路体检 / 设置项） */
.set{display:flex;align-items:center;gap:12px;padding:10px 0;border-top:1px solid var(--line)}
.set:first-of-type{border-top:0}
.set .txt{flex:1;min-width:0}
.set .txt b{display:block;font-size:var(--fs-body);font-weight:550;word-break:break-all}
.set .txt span{display:block;color:var(--txt-3);font-size:var(--fs-micro);margin-top:2px}
.set .ctl{flex:none}

/* 图例 */
.legend{display:flex;align-items:center;gap:14px;margin-top:8px;font-size:var(--fs-micro);
  color:var(--txt-2);flex-wrap:wrap}
.legend i{display:inline-block;width:8px;height:8px;border-radius:2px;margin-right:5px}
#chart{width:100%;height:152px;display:block}

/* 日志 */
details.logwrap{margin:0}
details.logwrap>summary{cursor:pointer;font-size:var(--fs-meta);color:var(--txt-2);
  list-style:none;display:flex;align-items:center;gap:6px}
details.logwrap>summary::-webkit-details-marker{display:none}
details.logwrap>summary:before{content:"▸";color:var(--txt-3);transition:transform .15s}
details.logwrap[open]>summary:before{transform:rotate(90deg)}
.log{font:12px/1.7 var(--mono);color:var(--txt-2);background:var(--bg-1);
  border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin-top:10px;
  height:190px;overflow:auto;white-space:pre-wrap;word-break:break-all}
.lognote{color:var(--txt-3);font-size:var(--fs-micro);margin-left:auto}

/* 升级卡 */
.upd-row{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.upd-ver{font:600 15px/1.5 var(--mono);color:var(--txt)}
.upd-track{font:600 15px/1.5 var(--mono);color:var(--line-2);white-space:pre}
.upd-bar{height:8px;background:var(--line);border-radius:6px;overflow:hidden;margin-top:10px}
.upd-bar>i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--accent),var(--warn));
  transition:width .25s ease}
.upd-note{color:var(--txt-2);font-size:var(--fs-micro);margin-top:6px}
.upd-banner{margin-top:8px;padding:8px 10px;border-radius:6px;background:rgba(240,180,41,.12);
  border:1px solid rgba(240,180,41,.35);color:var(--txt);font-size:var(--fs-meta)}
.upd-ok{color:var(--ok);font-weight:600}
.upd-err{color:var(--danger);font-weight:600}
.field{display:flex;gap:8px}
.input{flex:1;min-width:0;height:30px;padding:0 10px;border-radius:var(--r-btn);
  border:1px solid var(--line);background:var(--bg-1);color:var(--txt);font-size:var(--fs-meta)}
.input:focus{border-color:var(--accent)}
.input::placeholder{color:var(--txt-3)}

.foot{display:flex;align-items:center;gap:10px;justify-content:center;margin-top:18px;
  font-size:var(--fs-micro);color:var(--txt-3);flex-wrap:wrap}
.foot a{color:var(--txt-3)}
.foot a:hover{color:var(--accent)}

/* Toast */
.toast{position:fixed;left:50%;bottom:24px;transform:translate(-50%,14px);opacity:0;
  pointer-events:none;background:var(--card);border:1px solid var(--line-2);
  box-shadow:var(--shadow-2);border-radius:9px;padding:9px 14px;font-size:var(--fs-meta);
  display:flex;align-items:center;gap:10px;transition:opacity .18s,transform .18s;z-index:40;
  max-width:min(560px,92vw)}
.toast.on{opacity:1;transform:translate(-50%,0)}
.toast b{color:var(--accent);font-weight:600}

@media (max-width:1000px){
  .cols{grid-template-columns:minmax(0,1fr)}
  .stats{grid-template-columns:repeat(2,minmax(0,1fr))}
  .hero-right{gap:14px}
}
@media (max-width:640px){
  .wrap{padding:14px 12px 30px}
  .stats{grid-template-columns:minmax(0,1fr)}
  .top{align-items:flex-start}
}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style>
</head>
<body data-app="fox">
<div class="wrap">

  <header class="top">
    <div class="logo">狐</div>
    <div style="min-width:0">
      <h1>狐径 FoxPath <span class="ver">v__VERSION__</span></h1>
      <p>本机代理接管 GitHub 流量 · 只影响 GitHub 相关域名 · 不装证书、不改 hosts、零管理员</p>
    </div>
    <div class="top-r">
      <span class="pill" id="hdrPill"><i></i><span id="hdrPillText">读取中…</span></span>
      <button class="icon-btn" id="btnTheme" title="切换明暗（也可以按 T）">☾</button>
    </div>
  </header>

  <!-- ① hero：大开关 + 状态句 + 出口 IP + 延迟 + 两个按钮 -->
  <section class="card hero">
    <button class="sw big" id="btnPower" role="switch" aria-checked="false"
            title="启用 / 停用（会改本机系统代理）"></button>
    <div class="hero-mid">
      <div class="t-lg" id="state">读取中…</div>
      <div class="sub" id="stateSub">系统代理接管 · 只影响 GitHub 相关域名 · 不装证书、不改 hosts</div>
      <span class="msg" id="actMsg"></span>
    </div>
    <div class="hero-right">
      <div class="kv"><div class="k">出口 IP</div><div class="v mono" id="ip">检测中…</div></div>
      <div class="kv"><div class="k">延迟</div><div class="v" id="ms">— <small>ms</small></div></div>
      <div class="btns">
        <button class="btn" id="btnTest">立即重测</button>
        <button class="btn danger" id="btnDisable">停用并还原</button>
      </div>
    </div>
  </section>

  <!-- 线路状态那几句话已移入「日志」卡（2026-10-24 用户要求：红字别堆在首页），空了自动隐藏 -->

  <!-- ② 4 个数字卡 -->
  <section class="stats">
    <!-- 【2026-10-26 三点整改·③】第一张卡从"体检可用 IP 数"换成"网页实测"：
         最近 3 分钟浏览器真实请求的结局。老口径"可用 31/50"讲的是握手，用户问的是
         "仓库能不能打开"，本机实测两个口径可以同时对立，所以把握手数降成明细。 -->
    <div class="stat"><div class="k">网页实测</div>
      <div class="v" id="stWeb">—</div>
      <div class="d" id="stWebD">最近 3 分钟真实请求，不是体检</div></div>
    <div class="stat"><div class="k">接管域名</div>
      <div class="v" id="stHosts">— <small>个</small></div>
      <div class="d" id="stHostsD">含 *.github.io</div></div>
    <div class="stat"><div class="k">上次体检</div>
      <div class="v" id="stCheck">— <small>前</small></div>
      <div class="d" id="stCheckD">还没体检过</div></div>
    <div class="stat"><div class="k">本次会话</div>
      <div class="v" id="stHits">0 <small>次</small></div>
      <div class="d" id="stHitsD">PAC 命中 0 · 直连 0</div></div>
  </section>

  <div class="cols">
    <div class="col">
      <!-- ③ 延迟曲线（canvas 手绘，没有图表库） -->
      <section class="card">
        <div class="card-h">
          <h2>延迟走势</h2>
          <span class="hint" id="histHint">每次体检一个点（5 分钟）</span>
          <div class="right">
            <button class="chip on" id="range3">3 小时</button>
            <button class="chip" id="range24">24 小时</button>
            <a class="btn ghost sm" id="btnCsv" href="/api/history.csv?hours=3" download>导出 CSV</a>
          </div>
        </div>
        <canvas id="chart" width="760" height="152" aria-label="延迟走势图"></canvas>
        <div class="legend">
          <span><i style="background:var(--accent)"></i>出口 IP 延迟</span>
          <span><i style="background:var(--danger)"></i>这一轮全灭</span>
          <span style="margin-left:auto" id="histSummary">还没有采样</span>
        </div>
      </section>

      <!-- ④ IP 表：可排序 / 行内复制 / 复制全部 -->
      <section class="card">
        <div class="card-h">
          <h2>当前可用 IP</h2>
          <span class="pill ok"><i></i><span id="sortPill">按延迟排序</span></span>
          <div class="right">
            <button class="chip" id="onlyGood" title="把丢包抽样 100% 的行先收起来">隐藏 100% 丢包</button>
            <button class="btn ghost sm" id="btnCopyAll">复制全部</button>
            <button class="btn ghost sm" id="btnRetest2">重新体检</button>
          </div>
        </div>
        <table class="tbl">
          <thead id="ipHead"><tr>
            <th class="sortable" data-sort="ip">IP<span class="arw"></span></th>
            <th class="sortable r" data-sort="ms">延迟<span class="arw"></span></th>
            <th class="sortable r" data-sort="loss">丢包<span class="arw"></span></th>
            <th class="sortable r" data-sort="fails">失败<span class="arw"></span></th>
            <!-- 【2026-10-24 新增列】这个 IP 的证据强度: 真跑过请求 / 只验过证书 / 已出窗 -->
            <th class="r">证据</th>
            <th class="r"></th>
          </tr></thead>
          <tbody id="ips"></tbody>
        </table>
        <div class="table-foot">
          <span id="ipsCount">读取中…</span>
          <span class="muted">丢包＝本机 3 次 TCP 握手失败率（不是 ICMP 丢包）；失败＝连续转发失败次数，成功即清零</span>
        </div>
      </section>


  <!-- ⑨ 版本与升级：老功能一个都没少 -->
  <section class="card" id="updCard">
    <div class="card-h">
      <h2>版本与升级</h2>
      <span class="hint" id="updMsg">默认自动升级: 启动后发现有新版本会自动下好、校验、换上新版（不弹确认框）</span>
    </div>
    <div class="upd-row">
      <span class="muted xs">版本</span>
      <span class="upd-ver" id="uvLocal">__VERSION__</span>
      <span class="upd-track" id="uvArrow">   =====>   </span>
      <span class="upd-ver" id="uvRemote">—</span>
      <button class="btn primary" id="btnUpdCheck">检查更新</button>
      <button class="btn primary" id="btnUpdGo" style="display:none">立即升级</button>
      <span style="flex:1"></span>
      <span class="set" style="border:0;padding:0;gap:10px">
        <span class="txt" style="display:flex;align-items:center;gap:8px">
          <b style="font-size:var(--fs-meta);font-weight:500">自动升级</b>
          <button class="sw" id="autoUpd" role="switch" aria-checked="false" title="自动升级"></button>
        </span>
      </span>
      <span class="set" style="border:0;padding:0;gap:10px">
        <span class="txt" style="display:flex;align-items:center;gap:8px">
          <b style="font-size:var(--fs-meta);font-weight:500">升级结果气泡</b>
          <button class="sw" id="notifyBubble" role="switch" aria-checked="false" title="升级结果气泡"></button>
        </span>
      </span>
    </div>
    <div class="upd-bar" id="updBarWrap" style="display:none"><i id="updBar"></i></div>
    <div class="upd-banner" id="updBanner" style="display:none"></div>
    <div class="upd-note upd-ok" id="updAuto"></div>
    <div class="upd-note" id="updLast"></div>
    <div class="upd-note" id="updDetail"></div>
  </section>


    </div>

    <div class="col">
      <!-- ⑤ 线路体检：每域名一行状态 -->
      <section class="card">
        <div class="card-h">
          <h2>线路体检</h2>
          <span class="pill" id="ipv6Pill"><i></i><span id="ipv6Text">IPv6 检测中</span></span>
        </div>
        <div id="lines"><div class="empty">读取中…</div></div>
        <div class="field" style="margin-top:12px;gap:8px">
          <button class="btn" id="btnDiagCopy" style="flex:1;justify-content:center">复制诊断信息</button>
          <button class="btn primary" id="btnReport" style="flex:1;justify-content:center">一键反馈包</button>
        </div>
        <span class="msg" id="diagMsg"></span>
        <div class="field" style="margin-top:10px">
          <button class="btn ghost sm" id="btnDiagRe">刷新体检信息</button>
        </div>
        <details class="logwrap" style="margin-top:10px">
          <summary>诊断原文（复制用，点开看）</summary>
          <div class="upd-note" style="word-break:break-all;white-space:pre-wrap" id="diag">读取中…</div>
        </details>
      </section>

      <!-- ⑥ 手动指定 IP -->
      <section class="card">
        <div class="card-h">
          <h2>手动指定 IP</h2>
          <span class="hint">自动探测一个都不通时用</span>
        </div>
        <div class="field">
          <input class="input mono" id="ipInput" placeholder="例如 20.205.243.166" spellcheck="false">
          <button class="btn primary" id="btnIpSave">保存并重测</button>
        </div>
        <div class="field" style="margin-top:8px">
          <button class="btn ghost sm" id="btnIpClear">清除手动 IP</button>
          <span class="msg" id="ipMsg" style="margin:0;align-self:center"></span>
        </div>
        <p class="muted xs" style="margin-top:8px">只影响本机 PAC 这一份名单，随时可清除。</p>
      </section>

      <!-- ⑦ 更多设置 -->
      <section class="card">
        <div class="card-h"><h2>更多</h2><span class="hint">按 <kbd>/</kbd> 跳到手动 IP，<kbd>Esc</kbd> 取消</span></div>
        <div class="set">
          <div class="txt"><b>开机自启</b><span>登录后静默驻留托盘，不弹窗</span></div>
          <div class="ctl"><button class="sw" id="auto" role="switch" aria-checked="false" title="开机自启"></button></div>
        </div>
        <div class="set">
          <div class="txt"><b>立即测速</b><span>真下载一段 GitHub 首页，量出经狐径 / 直连各自的速度</span></div>
          <div class="ctl"><button class="btn sm" id="btnSpeed">开始测速</button></div>
        </div>
        <div class="set">
          <div class="txt"><b>退出并还原</b><span>退出前把系统代理恢复成原来的样子</span></div>
          <div class="ctl"><button class="btn danger sm" id="btnQuit">退出</button></div>
        </div>
        <span class="msg" id="speedMsg"></span>
      </section>

      <!-- ⑧ 日志：默认折叠 -->
      <section class="card tight">
        <details class="logwrap">
          <summary>日志（实时，最近 200 行）</summary>
          <div class="tips logtips">
            <div id="lifeBar"></div>
            <div id="directTip"></div>
            <div id="speedTip"></div>
            <div id="routeTip"></div>
            <div id="chanTip"></div>
          </div>
          <pre class="log" id="log"></pre>
        </details>
      </section>


    </div>
  </div>

  <div class="foot">
    <span>狐径 FoxPath · 作者 __AUTHOR__</span>
    <span>·</span>
    <a href="https://__HOMEPAGE__" target="_blank" rel="noopener">__HOMEPAGE__</a>
    <span>·</span>
    <span>所有请求只在本机；本页没有任何外部资源</span>
  </div>
</div>

<div class="toast" id="toast"><span id="toastText"></span></div>

<script>
/* ══════════════════════════════════════════════════════════════════════════
   狐径面板脚本（全部原生 JS，零依赖、零外部请求）
   ① 主题 ② 小工具 ③ 状态渲染 ④ 曲线 ⑤ IP 表排序 ⑥ 升级 ⑦ 键盘
   ══════════════════════════════════════════════════════════════════════════ */
function $(id){return document.getElementById(id);}
function api(u){return fetch(u,{cache:'no-store'}).then(function(r){return r.json();});}
function act(u){return fetch(u,{method:'POST'}).then(function(r){return r.json();});}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}

/* ── Toast（底部居中，3 秒）──────────────────────────────────────────── */
var _toastTimer=null;
function toast(txt,ms){
  var t=$('toast'); if(!t)return;
  $('toastText').textContent=txt||'';
  t.className='toast on';
  clearTimeout(_toastTimer);
  _toastTimer=setTimeout(function(){t.className='toast';},ms||3000);
}

/* ── 复制（先试剪贴板 API，不行再退回旧的 execCommand）──────────────── */
function fallbackCopy(t){
  var ta=document.createElement('textarea');
  ta.value=t; ta.style.position='fixed'; ta.style.top='-1000px'; ta.style.left='-1000px';
  document.body.appendChild(ta); ta.select();
  var ok=false;
  try{ok=document.execCommand('copy');}catch(e){ok=false;}
  document.body.removeChild(ta);
  return ok;
}
function copyText(t,okMsg){
  if(!t){toast('没有东西可复制');return;}
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(t).then(function(){toast(okMsg||'已复制');})
      .catch(function(){toast(fallbackCopy(t)?(okMsg||'已复制'):'复制失败，请手动选中复制');});
  }else{
    toast(fallbackCopy(t)?(okMsg||'已复制'):'复制失败，请手动选中复制');
  }
}

/* ── 主题：默认跟随系统，手动切换会记住（localStorage）────────────────
   【2026-10-24 修 主题两个键打架】右下角「外观」面板存的是 ui-theme-mode（auto|light|dark），
   顶栏那个旧按钮存的是 foxpath.theme（dark|light）。两边各写各的，旧键会被面板忽略，
   手动切过的观感刷新就没了。现在：读的时候新键优先（auto=跟随系统），写的时候两个键一起写。 */
var THEME_KEY='foxpath.theme';
var AP_KEY='ui-theme-mode';
function themeMode(){
  try{
    var m=localStorage.getItem(AP_KEY), old=localStorage.getItem(THEME_KEY);
    /* 只有旧键（顶栏 ☾/☀ 切过主题）的人，在这里一次性搬到新键：
       页尾「外观」面板只认 ui-theme-mode，不搬的话它会把旧键的选择当没有、按系统重来一遍。 */
    if(!m && (old==='dark'||old==='light')){ localStorage.setItem(AP_KEY, old); return old; }
    return m||old||'auto';
  }catch(e){ return 'auto'; }
}
function sysTheme(){
  try{ return window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches?'light':'dark'; }
  catch(e){ return 'dark'; }
}
function applyTheme(t,remember){
  t=(t==='light')?'light':'dark';
  document.documentElement.setAttribute('data-theme',t);
  var b=$('btnTheme');
  if(b){b.textContent=(t==='light')?'☀':'☾';
    b.title='当前 '+(t==='light'?'亮色':'暗色')+'，点按或按 T 切换';}
  if(remember){try{localStorage.setItem(THEME_KEY,t);localStorage.setItem(AP_KEY,t);}catch(e){}}
  drawChart();
}
function initTheme(){
  var forced=null;
  try{forced=new URLSearchParams(location.search).get('theme');}catch(e){}
  var m=themeMode();
  var eff=forced||(m==='light'||m==='dark'?m:sysTheme());
  applyTheme(eff,false);
}

/* ── 线路状态那几条提示（沿用原来的判断，只换了放的位置）────────────── */
function _say(id,txt,ms,err){
  var e=$(id); if(!e)return;
  e.textContent=txt||'';
  e.className='msg'+(err?' bad':'');
  clearTimeout(e._t);
  if(txt){e._t=setTimeout(function(){e.textContent='';e.className='msg';},ms||2500);}
}

var ST={};            // 最近一次 /api/status
var HIST={hours:3,points:[],summary:{}};
var SORT={key:'ms',dir:1};
var ONLY_GOOD=false;
var SORT_LABEL={ip:'IP',ms:'延迟',loss:'丢包',fails:'失败'};

function paintStatus(d){
  ST=d;
  /* hero */
  var on=!!d.enabled;
  var pw=$('btnPower');
  pw.className='sw big'+(on?' on':'');
  pw.setAttribute('aria-checked',on?'true':'false');
  pw.title=on?'已开启加速——点一下停用并还原系统代理':'未开启——点一下启用加速（会改本机系统代理）';
  $('state').textContent=on?'加速已开启':'未启用加速';
  $('stateSub').textContent=on
    ?'系统代理已接管 · 只影响 GitHub 相关域名 · 不装证书、不改 hosts'
    :'系统代理没有被接管 · 点左边开关才会真正生效';
  $('hdrPill').className='pill '+(on?'ok':'');
  $('hdrPillText').textContent=on?'加速中':'未启用';
  $('ip').textContent=d.ip||'暂无可用 IP';
  $('ms').innerHTML=(d.ms==null)?'— <small>ms</small>':(d.ms+' <small>ms</small>');

  /* 数字卡 —— 【2026-10-26 三点整改·③】第一张卡 = 网页实测(真实转发), 体检可用数
     降为明细。理由写在 logs 里那份现场: "可用 6/50"的同一分钟, 6 发里 5 发 502。 */
  var okN=(d.good_n==null)?0:d.good_n, allN=d.total_n;
  /* 【2026-10-24 改口径】大数字原本这里是"实测成过"的个数 —— 近 90 秒真发过一次请求
     并拿到 2xx/3xx 的 IP。因为 good_n(证书验过就算)和它能差到 31 vs 1。 */
  var strongN=(d.good_strong_n==null)?okN:d.good_strong_n;
  var tn=d.tier_n||{};
  var w=(d.web||{}).github||{};
  var wcls=(w.code==='good')?'d up':((w.code==='down'||w.code==='flaky'||w.code==='slow')?'d down':'d');
  var wv=$('stWeb'), wd=$('stWebD');
  if(!wv||!wd){/* 老面板模板没这两格就什么都不画, 别让 JS 抛异常把后面整段带崩 */}
  else{
    wv.textContent=w.text||'还没实测';
    var delta='';
    var pts=HIST.points||[];
    if(pts.length>=2){
      var a=pts[pts.length-1].ok, b=pts[pts.length-2].ok;
      if(a!=null&&b!=null){var dv=a-b;delta=' · 比上一轮 '+(dv>0?'+':(dv<0?'':'±'))+dv;}
    }
    wd.className=wcls;
    wd.textContent=(w.detail||'最近 3 分钟没有真实网页请求')
      +' · 体检可用 '+strongN+'/'+(allN==null?'—':allN)
      +'('+(tn.tls||0)+' 个仅验证书)'+delta;
    if(strongN===0&&okN>0){
      wd.className='d down';
      wd.textContent='池里 '+okN+' 个都没近期答过话 · '+esc(w.text||'')+'，只能靠兜底';
    }
  }

  var hosts=(d.pac_hosts||[]).length+1;   // +1 = *.github.io 这一组
  $('stHosts').innerHTML=(hosts||'—')+' <small>个</small>';
  $('stHostsD').textContent='codeload 已接管 · gist 暂未接管';

  var age=d.health_age;
  if(age==null){$('stCheck').innerHTML='— <small>前</small>';$('stCheckD').textContent='还没体检过';}
  else{
    var unit='秒',val=age;
    if(age>=60){val=Math.round(age/60);unit='分钟前';}
    if(age>=3600){val=Math.round(age/3600);unit='小时前';}
    $('stCheck').innerHTML=val+' <small>'+(unit==='秒'?'秒前':unit)+'</small>';
    $('stCheckD').textContent=d.last?('上次 '+d.last+' 完成'):'每 5 分钟自动一次';
  }

  var h=d.hits||{};
  $('stHits').innerHTML=(h.total||0)+' <small>次</small>';
  $('stHitsD').textContent='PAC 命中 '+(h.pool||0)+' · 直连 '+(h.sys||0);

  /* 线路状态提示（原逻辑照搬） */
  var lb=$('lifeBar');
  if(d.life&&d.cur_ip){
    var src=d.life_n?('本机实测 '+d.life_n+' 个样本'):'经验值(攒够样本后自动校准)';
    var left=d.cur_left;
    var tail=(left===null||left===undefined)
      ?'寿命未知(该 IP 已失效, 下次访问会换新的)'
      :('已撑 '+d.cur_age+' 秒, 约 '+Math.max(0,left)+' 秒后自动提前换掉(不等它锁死)');
    lb.textContent='IP 寿命基准 '+d.life+' 秒('+src+') · 当前 '+d.cur_ip
      +' · '+tail+' · 热备 '+(d.hot||0)+' 个待命';
    lb.style.color=(left!==null&&left!==undefined&&left<30)?'var(--danger)':'';
  }else{lb.textContent='';}

  var dt=$('directTip');
  if(d.direct===false){
    dt.textContent='当前这台机器直连 github 主站也不通（不是狐径的问题，换 IP 也打不开）。'
      +'狐径会在线路恢复时自动生效；急用可开手机热点。';
    dt.style.color='var(--danger)';
  }else if(d.direct===true){
    dt.textContent='直连 github 正常，狐径会挑更快的 IP 走。';
    dt.style.color='var(--ok)';
  }else{dt.textContent='';dt.style.color='';}

  var stEl=$('speedTip');
  var sp=d.speed||{};
  function rd(v){
    if(!v||!v.ts)return null;
    if(!v.ok)return {bad:true,txt:v.err||'不通',t:v.total||0};
    return {bad:false,kb:Math.round((v.bytes||0)/1024),t:v.total,kbps:v.kbps,ttfb:v.ttfb,ts:v.ts};
  }
  var P=rd(sp.proxy),D=rd(sp.direct);
  if(sp.busy){
    stEl.textContent='正在测速…(真下载一段 github 首页, 最多 40 秒)';
    stEl.style.color='';
  }else if(!P&&!D){
    stEl.textContent='';stEl.style.color='';
  }else{
    function one(v){
      if(v.bad)return v.t?('超时(等了 '+v.t+'s 零字节)'):('失败('+v.txt+')');
      return v.kb+'KB/'+v.t+'s ≈ '+v.kbps+' KB/s';
    }
    var txt='';
    var age2=Math.round(Date.now()/1000-((P?P.ts:D.ts)||0));
    txt+='线路实测('+age2+'秒前)：经狐径 '+(P?one(P):'未测')+' · 直连 '+(D?one(D):'未测');
    var verdict='',color='';
    if(P&&!P.bad&&D&&!D.bad){
      if(P.kbps<50&&D.kbps<50){
        verdict=' —— 两条路都堵着，是这条宽带到 GitHub 的链路在拥塞，换 IP 也救不了，只能等它缓过来';
        color='var(--danger)';
      }else if(P.kbps>=200){verdict=' —— 通畅';color='var(--ok)';}
      else if(P.kbps>=50){verdict=' —— 偏慢，能开但会转圈';color='var(--warn)';}
      else{verdict=' —— 经狐径也很慢';color='var(--danger)';}
      if(D.kbps>0&&P.kbps>D.kbps*1.5){
        verdict+='（狐径比直连快 '+(P.kbps/D.kbps).toFixed(1)+' 倍，加速是生效的）';
      }
    }else if(P&&P.bad&&D&&D.bad){
      verdict=' —— 两边都连不上，等线路恢复';color='var(--danger)';
    }
    stEl.textContent=txt+verdict;
    stEl.style.color=color;
  }

  var rtEl=$('routeTip');
  var rt=(d.route||{}).github||(d.route||{}).raw||(d.route||{}).pages||null;
  var cp=d.cap||{};
  function kbps(o){return (o&&o.ok)?(o.kbps+' KB/s'):'传不动';}
  if(rt&&rt.ip){
    var rage=Math.round(Date.now()/1000-(rt.ts||0));
    var why='';
    if(cp.sys&&cp.pool){
      why=' —— 后台实测：直连 '+kbps(cp.sys)+' vs 候选池 '+kbps(cp.pool)
        +(cp.sys_wins?'，直连更快所以放行':'，池子更快所以走池');
    }
    rtEl.textContent='上一次转发走了：'+(rt.src==='sys'
      ?('系统解析(直连) '+rt.ip):('候选池 '+rt.ip))+why+'（'+rage+' 秒前）';
    rtEl.style.color='';
  }else{rtEl.textContent='';}

  paintChan(d);

  /* 开关 / 升级相关 */
  setSw('auto',!!d.autostart);
  setSw('autoUpd',d.autoupd!==false);
  setSw('notifyBubble',d.notify!==false);
  $('updAuto').textContent=d.upgraded||'';
  var lr=$('updLast');
  lr.textContent=d.lastres||'';
  lr.className='upd-note '+(d.lastres?(d.lastok?'upd-ok':'upd-err'):'');
  var nb=$('updBanner');
  if(d.newver){
    nb.style.display='block';
    nb.innerHTML=d.autoupd
      ?('发现新版本 <b>v'+esc(d.newver)+'</b> —— 已按设置自动升级（不弹确认框, 校验不过会保留旧版）。')
      :('发现新版本 <b>v'+esc(d.newver)+'</b> —— 自动升级已关闭, 点上面的「检查更新」再点「立即升级」。');
  }else{nb.style.display='none';}

  /* 日志 / IPv6 / 体检 */
  var logEl=$('log');
  var txt=(d.logs||[]).join('\\n');
  if(logEl.textContent!==txt){logEl.textContent=txt;logEl.scrollTop=logEl.scrollHeight;}
  var v6=$('ipv6Pill');
  v6.className='pill '+(d.ipv6?'ok':'warn');
  $('ipv6Text').textContent=d.ipv6?'IPv6 可用':'IPv6 暂不可用';

  paintLines(d);
  paintIps();
}

function setSw(id,on){
  var el=$(id); if(!el)return;
  el.className='sw'+(on?' on':'');
  el.setAttribute('aria-checked',on?'true':'false');
}

/* ── 每 10 分钟的"跑得通通道"重匹配 ────────────────────────────────────
   数据来自后台 channel_loop()：它是真下载一遍(主站)／真复验一遍(raw、Pages)之后
   的结果，跟「可用 22/50」那种"证书对就算活着"的口径不是一回事，所以单独一行。
   本轮一个都没跑通时要点破：那多半是链路在拥塞，换 IP 救不了，别让人误以为程序坏了。 */
function paintChan(d){
  var el=$('chanTip'); if(!el) return;
  var ch=d.chan||{}, order=[['github','主站'],['raw','raw'],['pages','Pages']];
  var parts=[], worst=99;
  for(var i=0;i<order.length;i++){
    var c=ch[order[i][0]];
    if(!c||!c.ts) continue;
    /* 本轮还在实测中(pass 仍是初值 0)时别说"一个都没跑通"—— 那是扫描途中的假象 */
    if(c.running){parts.push(order[i][1]+'：本轮 '+(c.sampled||0)+' 个正在实测…'); continue;}
    var age=Math.round(Date.now()/1000-c.ts);
    var isGh=order[i][0]==='github';
    var t=order[i][1]+'：测'+(c.sampled||0)+' 通'+(c.pass||0)
      +(c.weak?(' 偏慢'+c.weak):'')
      +' · 最佳 '+(c.ip_best||'无')
      +(isGh&&c.kbps_best?('（'+c.kbps_best+' KB/s）'):'')
      +' · 在用 '+(c.in_use||'无')
      +(c.swapped?'（刚换岗）':'')
      +(c.note?('（'+c.note+'）'):'')
      +' · '+(age<90?(age+'秒前'):Math.round(age/60)+'分钟前');
    if(isGh){worst=Math.min(worst,(c.pass||0));}
    parts.push(t);
  }
  if(!parts.length){el.textContent='';el.style.color='';return;}
  var every=Math.round((d.chan_interval||600)/60);
  var tail=(worst===0)
    ?' —— 主站本轮没有一个跑得通：这是这条宽带到 GitHub 的链路在拥塞，换 IP 也救不了，等它缓过来'
    :'';
  el.textContent='通道重匹配（每 '+every+' 分钟）：'+parts.join(' ｜ ')+tail;
  el.style.color=(worst===0)?'var(--danger)':'';
}

/* ── 线路体检那 4 行 ─────────────────────────────────────────────────── */
function paintLines(d){
  var box=$('lines'); var rows=d.lines||[];
  if(!rows.length){box.innerHTML='<div class="empty">还没有体检数据，点「立即重测」跑一轮。</div>';return;}
  box.innerHTML=rows.map(function(r){
    var cls=r.status==='ok'?'ok':(r.status==='warn'?'warn':(r.status==='bad'?'bad':''));
    var label=r.status==='ok'?'通':(r.status==='warn'?'慢':(r.status==='bad'?'不通':'直连'));
    var sub;
    if(r.status==='off'){sub=r.note||'未接管（保持直连）';}
    else{
      /* 【2026-10-26 三点整改·③】这一行的主语换成"网页实测"，握手可用数退到后面。
         顺序很重要：用户先看能不能打开，再看凭什么。没实测样本时照旧只报体检。 */
      var ww=r.web||{};
      sub=(ww.n?(ww.text+'（'+ww.detail+'） '):'')+'体检可用 '+r.n+'/'+r.total;
      if(r.fastest!=null){sub+=' · 最快 '+r.fastest+'ms';}
      if(r.status==='bad'&&!ww.n){sub+=' · 本轮全部超时';}
    }
    return '<div class="set"><div class="txt"><b>'+esc(r.host)+'</b><span>'+esc(sub)+'</span></div>'
      +'<span class="ctl"><span class="pill '+cls+'"><i></i>'+label+'</span></span></div>';
  }).join('');
}

/* ── IP 表：排序 / 筛选 / 复制 ────────────────────────────────────────── */
function ipRows(){
  var d=ST||{};
  var rows=(d.ips_detail||[]).slice();
  if(!rows.length&&d.good){
    rows=d.good.map(function(x){return {ip:x[0],ms:x[1]};});
  }
  if(ONLY_GOOD){rows=rows.filter(function(r){return r.loss!==100;});}
  rows.sort(function(a,b){
    var k=SORT.key,x=a[k],y=b[k];
    if(k==='ip'){return (x>y?1:(x<y?-1:0))*SORT.dir;}
    var nx=(x===null||x===undefined)?1e9:x, ny=(y===null||y===undefined)?1e9:y;
    if(nx===ny){return (a.ms||0)-(b.ms||0);}
    return (nx-ny)*SORT.dir;
  });
  return rows;
}
function paintSort(){
  var ths=document.querySelectorAll('#ipHead th[data-sort]');
  for(var i=0;i<ths.length;i++){
    var k=ths[i].getAttribute('data-sort');
    var arw=ths[i].querySelector('.arw');
    if(arw){arw.textContent=(SORT.key===k)?(SORT.dir>0?'▲':'▼'):'';}
  }
  $('sortPill').textContent='按「'+(SORT_LABEL[SORT.key]||'延迟')+'」'+(SORT.dir>0?'升序':'降序');
}
function paintIps(){
  var rows=ipRows(), tb=$('ips');
  if(!rows.length){
    tb.innerHTML='<tr><td colspan="6"><div class="empty">还没有可用 IP —— 可能正在体检，'
      +'或者这条线当前连不上（点「重新体检」再试一次）。</div></td></tr>';
  }else{
    tb.innerHTML=rows.map(function(r){
      var loss=(r.loss===null||r.loss===undefined)
        ?'<span class="muted">—</span>'
        :('<span style="color:'+(r.loss>0?'var(--warn)':'inherit')+'">'+r.loss+'%</span>');
      var fails=(r.fails===null||r.fails===undefined)?'<span class="muted">—</span>'
        :(r.fails>0?('<span style="color:var(--danger)">'+r.fails+'</span>'):'0');
      var delay=(r.ms==null)?'<span class="muted">—</span>':(r.ms+' <small class="muted">ms</small>');
      /* 证据列: 'http' = 近 90 秒真发过一次请求并拿到 2xx/3xx(能打开页面的口径);
         'tls' = 只有证书验过; null/缺字段 = 证据已出窗或这轮没验。 */
      var tier=(r.tier==='http')
        ?'<span style="color:var(--ok)">跑通过</span>'
        :(r.tier==='tls'
          ?'<span style="color:var(--warn)">仅证书</span>'
          :'<span class="muted">已出窗</span>');
      return '<tr><td class="mono">'+esc(r.ip)+'</td>'
        +'<td class="r num">'+delay+'</td>'
        +'<td class="r num">'+loss+'</td>'
        +'<td class="r num">'+fails+'</td>'
        +'<td class="r">'+tier+'</td>'
        +'<td class="r"><button class="copy" data-ip="'+esc(r.ip)+'">复制</button></td></tr>';
    }).join('');
  }
  var n=rows.length, total=(ST.good_n||n);
  var fw=ST.fresh_window||90;
  $('ipsCount').textContent=n
    ?('显示 '+n+' 个 / 共 '+total+' 个活着'+(total>n?'（表格只列前 10 个）':'')
      +' · 其中近 '+fw+' 秒跑通过 '+(ST.good_strong_n==null?'?':ST.good_strong_n)+' 个')
    :'';
  paintSort();
}

/* ── 延迟曲线（canvas 手绘）─────────────────────────────────────────── */
function cssVar(name,fallback){
  try{
    var v=getComputedStyle(document.documentElement).getPropertyValue(name);
    return (v&&v.trim())||fallback;
  }catch(e){return fallback;}
}
function hexA(hex,a){
  var h=(hex||'').trim();
  var m=/^#([0-9a-fA-F]{6})$/.exec(h);
  if(!m){return h;}
  var n=parseInt(m[1],16);
  return 'rgba('+((n>>16)&255)+','+((n>>8)&255)+','+(n&255)+','+a+')';
}
function drawChart(){
  var c=$('chart');
  if(!c||!c.getContext)return;
  var cssW=c.clientWidth||600, cssH=152;
  var dpr=Math.min(2,window.devicePixelRatio||1);
  if(c.width!==Math.round(cssW*dpr)||c.height!==Math.round(cssH*dpr)){
    c.width=Math.round(cssW*dpr); c.height=Math.round(cssH*dpr);
  }
  var g=c.getContext('2d');
  g.setTransform(dpr,0,0,dpr,0,0);
  g.clearRect(0,0,cssW,cssH);
  var accent=cssVar('--accent','#f0883e'),
      danger=cssVar('--danger','#f2555a'),
      line=cssVar('--line','#303844'),
      txt3=cssVar('--txt-2','#a3aebe');
  var pad={l:34,r:14,t:12,b:18};
  var W=Math.max(10,cssW-pad.l-pad.r), H=Math.max(10,cssH-pad.t-pad.b);
  g.lineWidth=1; g.strokeStyle=line;
  for(var i=0;i<=3;i++){
    var y=Math.round(pad.t+H*i/3)+.5;
    g.beginPath(); g.moveTo(pad.l,y); g.lineTo(pad.l+W,y); g.stroke();
  }
  var pts=HIST.points||[];
  if(!pts.length){
    g.fillStyle=txt3;
    g.font='12px "Microsoft YaHei UI",system-ui,sans-serif';
    g.textAlign='center'; g.textBaseline='middle';
    g.fillText('还没有采样：每次体检（5 分钟）会写下一个点',pad.l+W/2,pad.t+H/2);
    return;
  }
  var ts0=pts[0].ts, ts1=pts[pts.length-1].ts;
  if(ts1<=ts0){ts1=ts0+1;}
  var lats=[];
  pts.forEach(function(p){if(p.latency!=null){lats.push(p.latency);}});
  var lo=lats.length?Math.min.apply(null,lats):0,
      hi=lats.length?Math.max.apply(null,lats):1;
  if(hi-lo<80){var mid=(hi+lo)/2; lo=Math.max(0,mid-40); hi=mid+40;}
  function X(t){return pad.l+W*(t-ts0)/(ts1-ts0);}
  function Y(v){return pad.t+H-H*(v-lo)/(hi-lo);}

  var grad=g.createLinearGradient(0,pad.t,0,pad.t+H);
  grad.addColorStop(0,hexA(accent,.28));
  grad.addColorStop(1,hexA(accent,0));

  var segs=[],seg=[];
  pts.forEach(function(p){
    if(p.latency!=null){seg.push(p);}
    else{if(seg.length){segs.push(seg);seg=[];}}
  });
  if(seg.length){segs.push(seg);}

  segs.forEach(function(s){
    if(s.length>1){
      g.beginPath();
      s.forEach(function(p,i){var x=X(p.ts),y=Y(p.latency);i?g.lineTo(x,y):g.moveTo(x,y);});
      g.lineTo(X(s[s.length-1].ts),pad.t+H);
      g.lineTo(X(s[0].ts),pad.t+H);
      g.closePath(); g.fillStyle=grad; g.fill();
    }
    g.beginPath();
    s.forEach(function(p,i){var x=X(p.ts),y=Y(p.latency);i?g.lineTo(x,y):g.moveTo(x,y);});
    g.strokeStyle=accent; g.lineWidth=2; g.lineJoin='round'; g.lineCap='round'; g.stroke();
    if(s.length===1){
      g.beginPath(); g.arc(X(s[0].ts),Y(s[0].latency),2.6,0,Math.PI*2);
      g.fillStyle=accent; g.fill();
    }
    var last=s[s.length-1];
    g.beginPath(); g.arc(X(last.ts),Y(last.latency),3.4,0,Math.PI*2);
    g.fillStyle=accent; g.fill();
    g.beginPath(); g.arc(X(last.ts),Y(last.latency),7,0,Math.PI*2);
    g.strokeStyle=hexA(accent,.35); g.lineWidth=3; g.stroke();
  });
  pts.forEach(function(p){
    if(p.latency==null){
      g.beginPath(); g.arc(X(p.ts),pad.t+H-1,3,0,Math.PI*2);
      g.fillStyle=danger; g.fill();
    }
  });
  g.font='10px Consolas,monospace'; g.fillStyle=txt3;
  g.textAlign='left'; g.textBaseline='middle';
  g.fillText(hi+'ms',2,pad.t+6);
  g.fillText(lo+'ms',2,pad.t+H-4);
  g.textAlign='right';
  g.fillText(histTime(ts0),pad.l+W,pad.t+H+9);
}

function histTime(ts){
  try{
    var d=new Date(ts*1000);
    return ('0'+d.getHours()).slice(-2)+':'+('0'+d.getMinutes()).slice(-2);
  }catch(e){return '';}
}
function paintHist(){
  var s=HIST.summary||{};
  if(!s.n){$('histSummary').textContent='还没有采样（每次体检一个点，5 分钟）';return;}
  var txt='最低 '+s.min+'ms · 最高 '+s.max+'ms · 中位 '+s.median+'ms';
  if(s.down){txt+=' · 全灭 '+s.down+' 轮';}
  $('histSummary').textContent=txt;
  var hint=$('histHint');
  hint.textContent=(HIST.hours===24?'最近 24 小时':'最近 3 小时')+' · 每 5 分钟一个点';
}
function loadHistory(hours){
  if(hours){HIST.hours=hours;}
  api('/api/history?hours='+HIST.hours).then(function(d){
    HIST.points=d.points||[];
    HIST.summary=d.summary||{};
    paintHist(); drawChart(); paintStatus(ST);
    var a=$('btnCsv'); if(a){a.href='/api/history.csv?hours='+HIST.hours;}
    $('range3').className='chip'+(HIST.hours===3?' on':'');
    $('range24').className='chip'+(HIST.hours===24?' on':'');
  }).catch(function(){});
}

/* ── 动作按钮 ───────────────────────────────────────────────────────── */
function doAct(u,msgId){
  act(u).then(function(r){
    if(r&&r.ok===false){_say(msgId||'actMsg',(r.msg||'操作没有成功'),12000,true);}
    else{_say(msgId||'actMsg',(r&&r.msg)||'已完成',4000,false);}
    refresh(true);
  }).catch(function(){_say(msgId||'actMsg','面板没有响应, 操作结果未知',12000,true);refresh(true);});
}
function refresh(withHistory){
  api('/api/status').then(function(d){
    paintStatus(d);
    if(withHistory){loadHistory();}
  }).catch(function(){});
}

function copyDiag(){
  api('/api/diag').then(function(d){
    copyText((d&&d.diag)||'','诊断信息已复制，直接粘贴发给作者就行');
  }).catch(function(){
    var t=$('diag')?$('diag').textContent:'';
    copyText(t,'诊断信息已复制');
  });
}

/* ── 升级卡（沿用原来的动画与状态机）────────────────────────────────── */
(function(){
  var U={bar:$('updBar'),wrap:$('updBarWrap'),msg:$('updMsg'),
    remote:$('uvRemote'),arrow:$('uvArrow'),go:$('btnUpdGo'),
    local:$('uvLocal'),detail:$('updDetail'),anim:null,timer:null};
  if(!U.msg)return;
  function spin(on){
    if(U.anim){clearInterval(U.anim);U.anim=null;}
    if(!on){U.arrow.textContent='   =====>   ';return;}
    var fr=['o--------->','=o-------->','==o------->','===o------>','====o----->',
      '=====o---->','======o--->','=======o-->','========o->','=========>'];
    var i=0;
    U.anim=setInterval(function(){U.arrow.textContent='   '+fr[i%fr.length]+'   ';i++;},85);
  }
  function kb(n){return Math.round((n||0)/1024)+' KB';}
  function paint(v){
    U.remote.textContent=v.remote?('v'+v.remote):'—';
    var busy=(v.phase==='downloading'||v.phase==='verifying'||v.phase==='applying');
    spin(v.phase==='checking');
    if(v.phase==='downloading'){
      U.wrap.style.display='block';
      U.bar.style.width=(v.pct||0)+'%';
      U.msg.className='hint';
      U.msg.textContent=(v.auto?'正在自动下载新版本（已按设置自动升级）  ':'正在下载新版本  ')
        +kb(v.got)+(v.total?(' / '+kb(v.total)+'   '+(v.pct||0)+'%'):'');
      U.go.style.display='none';
    }else if(v.phase==='verifying'||v.phase==='applying'){
      U.wrap.style.display='block'; U.bar.style.width='100%';
      U.msg.innerHTML='<span class="upd-ok">'+esc(v.msg||'')+'</span>';
      U.go.style.display='none';
    }else if(v.phase==='failed'){
      U.wrap.style.display='block';
      U.msg.innerHTML='<span class="upd-err">升级没有完成：'+esc(v.msg||'')+'</span>';
    }else if(v.newer){
      U.msg.innerHTML='<span class="upd-ok">发现新版本 v'+esc(v.remote)+'</span>'+(v.notes?('  '+esc(v.notes)):'');
      U.go.style.display=''; U.go.disabled=false;
      U.wrap.style.display='none'; U.bar.style.width='0';
    }else if(v.relation==='older'){
      U.msg.innerHTML='<span class="upd-err">本地版本比线上新（预发布/开发版本），线上暂未发布</span>'
        +'<span class="muted">　本地 v'+esc(v.local||'')+' · 线上 v'+esc(v.remote||'')+'</span>';
      U.go.style.display=''; U.go.disabled=true;
      U.go.title='本地版本比线上新，不能升级（要退回旧版本请用手动方式）';
      U.wrap.style.display='none'; U.bar.style.width='0';
    }else{
      U.msg.className='hint';
      U.msg.textContent=v.msg||'还没检查过线上版本，点「检查更新」看一眼';
      U.go.style.display='none';
    }
    if(U.detail){
      var bits=[];
      if(v.local){bits.push('本地 v'+v.local);}
      if(v.remote){bits.push('线上 v'+v.remote);}
      if(v.phase){bits.push('阶段 '+v.phase);}
      if(v.pct!=null&&busy){bits.push((v.pct||0)+'%');}
      U.detail.textContent=bits.join(' · ');
    }
    var b=(v.phase!=='idle'&&v.phase!=='failed');
    if(b&&!U.timer){U.timer=setInterval(tick,400);}
    if(!b&&U.timer){clearInterval(U.timer);U.timer=null;}
  }
  function tick(){api('/api/update/status').then(paint).catch(function(){});}
  $('btnUpdCheck').onclick=function(){
    U.msg.className='hint';
    U.msg.textContent='正在检查升级源…'; spin(true);
    act('/api/update/check').then(tick).catch(function(){tick();});
  };
  $('btnUpdGo').onclick=function(){
    if(U.go.disabled){return;}
    U.go.style.display='none'; U.wrap.style.display='block'; U.bar.style.width='0';
    act('/api/update/start').then(function(r){
      if(r&&r.ok===false){
        U.wrap.style.display='none';
        _say('updMsg',r.msg||'这次不能升级',12000,true);
      }
      tick();
    }).catch(function(){
      U.wrap.style.display='none';
      _say('updMsg','面板没有响应, 升级结果未知',12000,true); tick();
    });
  };
  tick();
  setInterval(tick,15000);
})();

/* ── 事件绑定 ───────────────────────────────────────────────────────── */
$('btnTheme').onclick=function(){
  var cur=document.documentElement.getAttribute('data-theme');
  applyTheme(cur==='light'?'dark':'light',true);
};
$('btnPower').onclick=function(){
  var on=!!(ST&&ST.enabled);
  if(on){
    if(!confirm('停用后 GitHub 会恢复原来的连接方式，确定停用？')){return;}
    doAct('/api/disable','actMsg');
  }else{
    doAct('/api/enable','actMsg');
  }
};
$('btnDisable').onclick=function(){
  if(!confirm('停用后 GitHub 会恢复原来的连接方式，确定停用？')){return;}
  doAct('/api/disable','actMsg');
};
$('btnTest').onclick=function(){
  var b=this; b.disabled=true; _say('actMsg','正在重测（约 10~30 秒）…',30000,false);
  act('/api/retest').then(function(){
    b.disabled=false;
    setTimeout(function(){refresh(true);},6000);
    setTimeout(function(){refresh(true);},16000);
    setTimeout(function(){refresh(true);},28000);
  }).catch(function(){b.disabled=false;_say('actMsg','面板没有响应',12000,true);});
};
$('btnRetest2').onclick=function(){$('btnTest').click();};
$('btnSpeed').onclick=function(){
  var b=this; b.disabled=true; $('speedMsg').textContent='测速中…';
  act('/api/speedtest').then(function(r){
    $('speedMsg').textContent=(r&&r.msg)||'';
    b.disabled=false;
    setTimeout(function(){refresh();},800);
    setTimeout(function(){refresh();},8000);
    setTimeout(function(){refresh();},20000);
  }).catch(function(){b.disabled=false;$('speedMsg').textContent='面板没有响应';});
};
$('auto').onclick=function(){
  var on=this.getAttribute('aria-checked')!=='true';
  setSw('auto',on);
  act('/api/autostart?on='+(on?1:0)).then(function(){refresh();}).catch(function(){refresh();});
};
$('autoUpd').onclick=function(){
  var on=this.getAttribute('aria-checked')!=='true';
  setSw('autoUpd',on);
  act('/api/autoupdate?on='+(on?1:0)).then(function(r){
    _say('updMsg',(r&&r.msg)||'已保存',6000,false); refresh();
  }).catch(function(){_say('updMsg','设置没有保存成功',8000,true);refresh();});
};
$('notifyBubble').onclick=function(){
  var on=this.getAttribute('aria-checked')!=='true';
  setSw('notifyBubble',on);
  act('/api/notifybubble?on='+(on?1:0)).then(function(r){
    _say('updMsg',(r&&r.msg)||'已保存',6000,false); refresh();
  }).catch(function(){_say('updMsg','设置没有保存成功',8000,true);refresh();});
};
$('btnQuit').onclick=function(){
  if(!confirm('退出后 GitHub 将恢复原有连接方式，确定退出？')){return;}
  act('/api/quit').then(function(){
    clearInterval(_refreshTimer); clearInterval(_histTimer); clearInterval(_diagTimer);
    $('state').textContent='已安全退出，可关闭此页';
    _say('actMsg','狐径已退出，系统代理已还原',30000,false);
  }).catch(function(){
    $('state').textContent='已退出（面板无响应，可关闭此页）';
  });
};
$('btnIpSave').onclick=function(){
  var v=$('ipInput').value.trim();
  if(!v){_say('ipMsg','先填一个 IP',6000,true);return;}
  act('/api/set-ip?ip='+encodeURIComponent(v)).then(function(r){
    if(r&&r.ok===false){_say('ipMsg',(r.msg||'这个地址不能用'),12000,true);return;}
    _say('ipMsg',(r&&r.msg)||'已保存，正在重测…',8000,false);
    loadDiag(); refresh(true);
  }).catch(function(){_say('ipMsg','面板没有响应, 结果未知',12000,true);});
};
$('btnIpClear').onclick=function(){
  act('/api/set-ip?ip=').then(function(r){
    _say('ipMsg',(r&&r.msg)||'已清除',6000,false); loadDiag(); refresh(true);
  }).catch(function(){_say('ipMsg','面板没有响应',8000,true);});
};
$('ipInput').addEventListener('keydown',function(e){
  if(e.key==='Enter'){$('btnIpSave').click();}
});
$('btnDiagCopy').onclick=copyDiag;
$('btnDiagRe').onclick=function(){loadDiag();refresh(true);};
$('btnReport').onclick=function(){
  var b=this; b.disabled=true;
  api('/api/report').then(function(d){
    copyText((d&&d.text)||'','反馈包已复制（版本+系统+可用 IP+日志尾部 50 行），直接粘给作者');
    b.disabled=false;
  }).catch(function(){
    b.disabled=false; toast('面板没有响应，稍后再点');
  });
};
$('btnCopyAll').onclick=function(){
  var rows=ipRows();
  if(!rows.length){toast('还没有可用 IP 可复制');return;}
  copyText(rows.map(function(r){return r.ip;}).join('\\n'),'已复制 '+rows.length+' 个 IP');
};
$('onlyGood').onclick=function(){
  ONLY_GOOD=!ONLY_GOOD;
  this.className='chip'+(ONLY_GOOD?' on':'');
  paintIps();
};
$('ips').addEventListener('click',function(e){
  var b=e.target.closest?e.target.closest('button.copy'):null;
  if(!b){return;}
  var ip=b.getAttribute('data-ip');
  copyText(ip,'已复制 '+ip);
});
$('ipHead').addEventListener('click',function(e){
  var th=e.target.closest?e.target.closest('th[data-sort]'):null;
  if(!th){return;}
  var k=th.getAttribute('data-sort');
  if(SORT.key===k){SORT.dir=-SORT.dir;}else{SORT.key=k;SORT.dir=1;}
  paintIps();
});
$('range3').onclick=function(){loadHistory(3);};
$('range24').onclick=function(){loadHistory(24);};

/* 键盘：/ 跳到手动 IP，Esc 取消焦点/收起提示，T 切主题 */
document.addEventListener('keydown',function(e){
  var tag=(e.target&&e.target.tagName)||'';
  var typing=(tag==='INPUT'||tag==='TEXTAREA'||tag==='SELECT'||(e.target&&e.target.isContentEditable));
  if(e.key==='/'&&!typing&&!e.ctrlKey&&!e.metaKey&&!e.altKey){
    e.preventDefault();
    var el=$('ipInput');
    if(el){el.focus();el.select&&el.select();}
    return;
  }
  if(e.key==='Escape'){
    if(document.activeElement&&document.activeElement.blur){document.activeElement.blur();}
    $('toast').className='toast';
    return;
  }
  if((e.key==='t'||e.key==='T')&&!typing&&!e.ctrlKey&&!e.metaKey&&!e.altKey){
    var cur=document.documentElement.getAttribute('data-theme');
    applyTheme(cur==='light'?'dark':'light',true);
  }
});

/* ── 轮询 ───────────────────────────────────────────────────────────── */
var _refreshTimer=setInterval(function(){refresh();},3000);
var _histTimer=setInterval(function(){loadHistory();},60000);
var _diagTimer=null;
function loadDiag(){
  api('/api/diag').then(function(d){
    $('diag').textContent=(d&&d.diag)||'读取失败';
  }).catch(function(){});
}
_diagTimer=setInterval(loadDiag,30000);

initTheme();
paintSort();
refresh(true);
loadDiag();
setTimeout(function(){drawChart();},60);
window.addEventListener('resize',function(){drawChart();});
</script>
<!-- ===== 外观：主题三档 + 主色（2026-10-24 四款统一组件） ===== -->
<style>
#apFab{z-index:70;width:30px;height:30px;border-radius:50%;flex:none;margin-left:6px;border:1px solid var(--line);background:transparent;color:var(--txt-2);display:grid;place-items:center;cursor:pointer;font-size:13px;padding:0}
#apFab:hover{color:var(--accent);border-color:var(--accent)}
#apPop{position:fixed;z-index:71;width:250px;background:var(--card);border:1px solid var(--line-2);
  border-radius:12px;box-shadow:0 14px 40px rgba(0,0,0,.45);padding:12px;display:none}
#apPop.on{display:block}
.ap-row{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.ap-lab{font-size:11px;color:var(--txt-3);width:30px;flex:none}
.ap-seg{display:flex;gap:4px;flex:1}
.ap-seg button{flex:1;height:26px;border-radius:7px;border:1px solid var(--line);background:transparent;
  color:var(--txt-2);font-size:11px;cursor:pointer;padding:0}
.ap-seg button.on{background:color-mix(in srgb,var(--accent) 15%,transparent);border-color:var(--accent);color:var(--accent);font-weight:600}
.ap-sw{display:flex;gap:8px;flex:1}
.ap-sw button{width:20px;height:20px;border-radius:50%;border:2px solid transparent;cursor:pointer;padding:0;flex:none}
.ap-sw button.on{border-color:var(--txt)}
.ap-hint{font-size:10px;color:var(--txt-3);line-height:1.5;margin-top:9px}
#btnTheme,#themeBtn{display:none!important}
html[data-accent="blue"]{--accent:#4f8cff;--accent-ink:#04122e}
html[data-accent="green"]{--accent:#3ecf8e;--accent-ink:#062016}
html[data-accent="violet"]{--accent:#a78bfa;--accent-ink:#1a1030}
html[data-accent="amber"]{--accent:#f0b429;--accent-ink:#221603}
html[data-theme="light"][data-accent="blue"]{--accent:#1a5fd0;--accent-ink:#fff}
html[data-theme="light"][data-accent="green"]{--accent:#0f9d58;--accent-ink:#fff}
html[data-theme="light"][data-accent="violet"]{--accent:#6d28d9;--accent-ink:#fff}
html[data-theme="light"][data-accent="amber"]{--accent:#a86f00;--accent-ink:#fff}
html[data-accent]{--accent-soft:color-mix(in srgb,var(--accent) 14%,transparent);--accent-line:color-mix(in srgb,var(--accent) 45%,transparent)}
</style>
<button id="apFab" title="外观：主题与主色" aria-label="外观">◐</button>
<div id="apPop" role="dialog" aria-label="外观设置">
  <div class="ap-row"><span class="ap-lab">主题</span><div class="ap-seg" id="apMode">
    <button type="button" data-m="auto">跟随系统</button><button type="button" data-m="light">亮色</button><button type="button" data-m="dark">暗色</button>
  </div></div>
  <div class="ap-row"><span class="ap-lab">主色</span><div class="ap-sw" id="apAcc">
    <button type="button" data-a="default" title="品牌色"></button><button type="button" data-a="blue" title="蓝" style="background:#4f8cff"></button><button type="button" data-a="green" title="绿" style="background:#3ecf8e"></button><button type="button" data-a="violet" title="紫" style="background:#a78bfa"></button><button type="button" data-a="amber" title="琥珀" style="background:#f0b429"></button>
  </div></div>
  <div class="ap-hint">「跟随系统」随 Windows 亮/暗模式自动切换；选择记在本机，重开仍在。</div>
</div>
<script>
(function(){
  var R=document.documentElement, K='ui-theme-mode', A='ui-accent';
  var media=window.matchMedia?window.matchMedia('(prefers-color-scheme: light)'):null;
  var brand=(getComputedStyle(R).getPropertyValue('--accent')||'').trim()||'#888';
  function mode(){ try{return localStorage.getItem(K)||'auto'}catch(e){return 'auto'} }
  function acc(){ try{return localStorage.getItem(A)||'default'}catch(e){return 'default'} }
  function apply(){
    var m=mode();
    var dark = m==='dark' || (m==='auto' && !(media&&media.matches));
    R.setAttribute('data-theme', dark?'dark':'light');
    var a=acc();
    if(a==='default'){ R.removeAttribute('data-accent'); } else { R.setAttribute('data-accent',a); }
    sync(m,a);
  }
  function sync(m,a){
    var mb=document.querySelectorAll('#apMode button');
    for(var i=0;i<mb.length;i++) mb[i].classList.toggle('on', mb[i].getAttribute('data-m')===m);
    var ab=document.querySelectorAll('#apAcc button');
    for(var j=0;j<ab.length;j++) ab[j].classList.toggle('on', ab[j].getAttribute('data-a')===a);
    var fab=document.getElementById('apFab');
    if(fab) fab.textContent = R.getAttribute('data-theme')==='dark' ? '◐' : '◑';
  }
  function setMode(m){ try{localStorage.setItem(K,m)}catch(e){} apply(); }
  function setAcc(a){ try{localStorage.setItem(A,a)}catch(e){} apply(); }
  var fab=document.getElementById('apFab'), pop=document.getElementById('apPop');
  var holder=document.querySelector('.top-r')||document.querySelector('.hbar')||document.querySelector('header');
  if(holder && fab){ holder.appendChild(fab); if(holder.tagName==='HEADER'){ fab.style.position='fixed'; fab.style.top='10px'; fab.style.right='12px'; } }
  if(fab) fab.addEventListener('click',function(e){ e.stopPropagation();
    if(!pop.classList.contains('on')){ var r=fab.getBoundingClientRect();
      pop.style.right='12px'; pop.style.left='auto'; pop.style.top=(r.bottom+8)+'px'; }
    pop.classList.toggle('on'); });
  document.addEventListener('click',function(e){ if(pop && !pop.contains(e.target) && e.target!==fab) pop.classList.remove('on'); });
  document.addEventListener('keydown',function(e){
    if(e.key==='Escape'){ pop && pop.classList.remove('on'); }
    if((e.key==='t'||e.key==='T') && !/^(INPUT|TEXTAREA|SELECT)$/.test((e.target.tagName||''))){
      e.stopImmediatePropagation(); e.preventDefault();
      setMode(R.getAttribute('data-theme')==='dark'?'light':'dark');
    }
  }, true);
  document.getElementById('apMode').addEventListener('click',function(e){
    var b=e.target.closest?e.target.closest('button'):null; if(!b) return; setMode(b.getAttribute('data-m'));
  });
  document.getElementById('apAcc').addEventListener('click',function(e){
    var b=e.target.closest?e.target.closest('button'):null; if(!b) return; setAcc(b.getAttribute('data-a'));
  });
  var d=document.querySelector('#apAcc button[data-a="default"]'); if(d) d.style.background=brand;
  if(media && media.addEventListener) media.addEventListener('change',function(){ if(mode()==='auto') apply(); });
  else if(media && media.addListener) media.addListener(function(){ if(mode()==='auto') apply(); });
  var forced=null; try{ forced=new URLSearchParams(location.search).get('theme'); }catch(e){}
  if(forced==='light'||forced==='dark'){ R.setAttribute('data-theme',forced); sync(mode(),acc()); } else { apply(); }
  window.__uiTheme={mode:mode,accent:acc,setMode:setMode,setAccent:setAcc};
})();
</script>
</body></html>
"""


PANEL_PAGE = (PANEL_HTML.replace('__VERSION__', APP_VERSION)
              .replace('__AUTHOR__', AUTHOR).replace('__HOMEPAGE__', HOMEPAGE))


class PanelHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype='text/html; charset=utf-8', extra=None):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        # 审查 M-6: 没有 nosniff 时, 浏览器可能把 text/plain 的接口回话当脚本嗅探执行
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Length', str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
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
        query = self.path.split('?')[1] if '?' in self.path else ''
        if path == '/pac':
            self._send(200, (PAC_TEMPLATE % PROXY_PORT).encode('ascii'),
                       'application/x-ns-proxy-autoconfig')
        elif path in ('/', '/ui'):
            self._send(200, PANEL_PAGE.encode('utf-8'))
        elif path == '/api/history':
            # 【2026-10-24 新增】延迟曲线的数据源: 最近 N 小时（默认 3，最多 7 天）
            hours = _query_int(query, 'hours', 3, 1, HISTORY_KEEP_DAYS * 24)
            pts = history_points(hours)
            self._send(200, json.dumps({
                'ok': True, 'hours': hours, 'step': HISTORY_STEP,
                'generated': int(time.time()), 'points': pts,
                'summary': history_summary(pts),
            }, ensure_ascii=False).encode('utf-8'),
                'application/json; charset=utf-8')
        elif path == '/api/history.csv':
            # 【2026-10-24 新增】同一份采样导出 CSV（面板「导出 CSV」按钮用它）
            hours = _query_int(query, 'hours', 3, 1, HISTORY_KEEP_DAYS * 24)
            pts = history_points(hours)
            rows = ['time,epoch,ip,latency_ms,ok_count,total,raw_ok,pages_ok']
            for p in pts:
                rows.append(','.join((
                    time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.get('ts') or 0)),
                    str(int(p.get('ts') or 0)),
                    str(p.get('ip') or ''),
                    '' if p.get('latency') is None else str(int(p['latency'])),
                    str(p.get('ok') if p.get('ok') is not None else ''),
                    str(p.get('total') if p.get('total') is not None else ''),
                    str(p.get('raw_ok') if p.get('raw_ok') is not None else ''),
                    str(p.get('pages_ok') if p.get('pages_ok') is not None else ''),
                )))
            self._send(200, ('\r\n'.join(rows) + '\r\n').encode('utf-8'),
                       'text/csv; charset=utf-8',
                       {'Content-Disposition': 'attachment; filename="foxpath-history-%dh.csv"'
                                               % hours})
        elif path == '/api/report':
            # 【2026-10-24 新增】一键反馈包：只回一段文本，面板负责复制到剪贴板。
            # 不写共享文件、不上传（与「复制诊断信息」同一条隐私口径）。
            self._send(200, json.dumps({'ok': True, 'text': feedback_text()},
                                       ensure_ascii=False).encode('utf-8'),
                       'application/json; charset=utf-8')
        elif path == '/api/status':
            good, ts = HEALTH.snapshot()
            raw_good, _ = HEALTH_RAW.snapshot()
            pages_good, _ = HEALTH_PAGES.snapshot()
            _cur_ip = _LAST_GOOD.get('github') or (good[0][0] if good else '')
            # 寿命未知要如实给 null: 转成 0 的话面板会显示"约 0 秒后换", 语义正好相反
            _cur_left = _ip_remaining(_cur_ip)
            data = {
                'ip': good[0][0] if good else None,
                'ms': good[0][1] if good else None,
                'good': good[:10],
                'enabled': proxy_on(),
                'autostart': autostart_on(),
                # 本次启动是不是"接上次的残留"起来的（上次没走还原）。面板暂时只在
                # 日志里说明，这个字段留给以后的一键反馈/体检用。
                'dirty_boot': bool(_BOOT_DIRTY[0]),
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
                # 【2026-10-11】IP 寿命台账: 面板能直接看出"这类 IP 平均能撑多久"、
                # 当前这个撑了多久、还剩多久, 以及有几个热备待命。
                'life': int(_avg_life()),
                'life_n': _life_samples(),
                # 显示**真正在用的那个** IP 的寿命(不是体检第一名):
                # 转发送出去的是 _LAST_GOOD, 它的年龄才是"会不会马上锁死"的那个数
                'cur_ip': _cur_ip,
                'cur_age': int(_ip_age(_cur_ip)),
                'cur_left': None if _cur_left is None else int(_cur_left),
                'hot': len(_hot_get('github')),
                # 线路体检: 绕开狐径直连 github 通不通(None = 还没探过)
                'direct': _DIRECT_OK[0],
                'direct_age': int(time.time() - _DIRECT_OK[1]) if _DIRECT_OK[1] else None,
                # 【2026-10-26 三点整改·③】网页实测: 最近 3 分钟**真实转发**的结局。
                # 这格才是"用户能不能打开"的答案 —— "可用 6/50"是体检数出来的握手
                # 能通的 IP 数, 本机 2026-10-26 实测两者可以同时对立(可用 6 个、
                # 6 发 5 个 502)。面板首页第一张卡以后显示它, IP 数退成明细。
                'web': {k: _web_status(k) for k in ('github', 'raw', 'pages')},
                'stall_ips': len([ip for ip in _STALL if _stall_rank(ip) > 0]),
                # 线路测速(2026-10-11): "连得上"和"打得开"是两回事, 把真实下载速度
                # 也回给面板 —— 走狐径 / 直连各一份, 用户一眼能分出是谁在拖后腿。
                'speed': {'proxy': dict(_SPEED.get('proxy') or {}),
                          'direct': dict(_SPEED.get('direct') or {}),
                          'busy': bool(_SPEED_BUSY[0])},
                # 【2026-10-11】最近一次转发是"池子挑的 IP"赢还是"系统解析(直连)"赢。
                # 不看这个数字就不知道加速到底有没有在干活: 一直 pool = 池子总比直连快;
                # 老显示 sys 则说明池子选出来的不如外面那条路, 得回头查候选池。
                'route': {k: dict(v) for k, v in _ROUTE.items()},
                'cap': {'sys': dict(_cap_of('github.com', _SYS_CAP) or {}),
                        'pool': dict(_cap_of('github.com', _POOL_CAP) or {}),
                        'sys_wins': _sys_wins('github.com'),
                        'hot': sorted([{'ip': i, 'kbps': k} for i, k in
                                       ((x, _kbps_of(x)) for x in _hot_get('github'))
                                       if k], key=lambda d: -d['kbps'])},
                # 【2026-10-24 新增】每 10 分钟一轮的"跑得通通道"重匹配结果。
                # 这是**新字段**, 老调用方(read status['cap'] 那批)不受影响。
                'chan': {k: _chan_public(v) for k, v in _CHAN.items()},
                'chan_interval': int(_CHAN_INTERVAL),
                'chan_min_kbps': _CHAN_MIN_KBPS,
                # ── 【2026-10-24 UI 整改】仪表盘专用：全是**新增字段**，
                #    上面那些老字段(ip/ms/good/life/cur_*/direct/speed/route/cap)
                #    一个都没动，老调用方不受影响。
                'good_n': len(good),
                # 【2026-10-24 新增】"可用"拆成两个口径, 面板与反馈包都用这两个数:
                #   good_strong_n —— 近 _FRESH_WINDOW 秒真发过一次请求并拿到 2xx/3xx
                #   tier_n        —— 当前池子里两类证据各多少个
                # 老字段 good/good_n 的含义一个没变, 只是再多给一层真相。
                'good_strong_n': len(HEALTH.strong()),
                'fresh_window': int(_FRESH_WINDOW),
                'tier_n': HEALTH.tier_counts(),
                'total_n': len([x for x in candidate_list() if ':' not in x]),
                'raw_n': len(raw_good), 'raw_total': len(CANDIDATE_IPS_RAW_ALL),
                'pages_n': len(pages_good),
                'pages_total': len(CANDIDATE_IPS_PAGES_ALL),
                'health_ts': ts,
                'health_age': int(time.time() - ts) if ts else None,
                'ipv6': bool(local_has_ipv6()),
                'hits': hits_snapshot(),
                'pac_hosts': list(PAC_HOSTS),
                'lines': lines_status(),
                'ips_detail': ips_detail(good),
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
            # 【2026-10-24】重测完把这一轮结果落进 history.jsonl（手动重测也是一次体检），
            # 顺便抽一轮丢包样本 —— 以前这里是三行 lambda，现在包成函数好挂这两个新动作。
            def _retest_job():
                good = HEALTH.refresh(candidate_list())
                raw_good = HEALTH_RAW.refresh(CANDIDATE_IPS_RAW_ALL)
                pages_good = HEALTH_PAGES.refresh(CANDIDATE_IPS_PAGES_ALL)
                history_append(good, raw_good, pages_good)
                loss_probe_async(good)
            threading.Thread(target=_retest_job, daemon=True).start()
            log('手动重测已触发(含 raw 与 github.io 池)')
        elif path == '/api/speedtest':
            # 面板「立即测速」(2026-10-11): 后台跑, 不卡页面; 已在测就直接告诉它等着
            started = speed_probe_async()
            resp = {'ok': True, 'msg': '正在测速…(约 10~40 秒后刷新)'
                    if started else '上一次还没测完, 稍等几秒再刷新'}
            if started:
                log('手动测速已触发')
        elif path == '/api/quit':
            log('收到退出指令, 正在还原系统代理')
            disable_proxy()
            # 先回执再延迟杀进程, 让面板收到 200 后停轮询并显示"已退出", 不再卡"正在退出"
            self._send(200, json.dumps({'ok': True, 'msg': '已退出'}).encode('utf-8'),
                      'application/json; charset=utf-8')
            threading.Thread(target=safe_quit, daemon=True).start()
            return
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
            # 【2026-10-24 修·回执丢了】这里原来只把 ok/msg 赋给局部变量、**没写进 resp**，
            # 于是接口永远回 {"ok":true,"msg":""}：面板收到的是"已保存"，而实际上
            # 非法地址/私网地址被 save_manual_ip 拒了(审查 M-14 原本就要求把原因给人看)。
            # 返回结构没变(还是 ok/msg)，只是把真实结果如实回给面板。
            resp = {'ok': ok, 'msg': msg}
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


# 【2026-10-11 修·连接级自愈】"IP 锁死"根因: Health 池每 5 分钟体检一次,
# 两次体检之间候选 IP 过期/被限流(返回 4xx)却仍锁在池里, 代理反复试死 IP →
# 用户只能重启才重置。这里在**转发实际失败**时立刻触发一次全池重测(含 HTTP 预检,
# 能把"TCP 通但 HTTP 4xx"的假活 IP 判死剔除), 带 60 秒冷却, 不等 5 分钟、不用用户重启。
_RETEST_COOLDOWN_TS = [0.0]
_RETEST_LOCK = threading.Lock()
# 【2026-10-26 新增·自愈要给浏览器让路】
# 装机版日志: 12:35:05 / 12:36:25 / 12:37:30 各来一次"连接级自愈: 立即全池重测",
# 每一次都是 50(github) + raw + github.io 三个池同时全量重探 —— 而那一刻链路正
# 在抽风, 用户的浏览器就卡在同一个页面上转圈。重测本身成了新的负担(跟 _prescan、
# hot_refresh 记过的是同一个坑), 而且链路整体不通时连着两轮重测都捞不回人。
# 现在按"上一轮真捞回几个"退让: 一个都没捞回就把间隔翻倍(60 → 120 → 240 → 封顶
# 600 秒), 捞回 3 个以上立刻回到 60 秒。后台 health_loop 那 5 分钟一轮的照旧跑,
# 面板上「立即重测」也照旧随时能按, 所以最坏只是"自愈慢一点", 不会失能。
_RETEST_BACKOFF = [60.0]
_RETEST_BACKOFF_MAX = 600.0
_RETEST_REVIVE_MIN = 3      # 一轮重测至少捞回这么多才算"链路又活了"


def _selfheal_job():
    good = HEALTH.refresh(candidate_list())
    raw_good = HEALTH_RAW.refresh(CANDIDATE_IPS_RAW_ALL)
    pages_good = HEALTH_PAGES.refresh(CANDIDATE_IPS_PAGES_ALL)
    n = [len(good or []), len(raw_good or []), len(pages_good or [])]
    with _RETEST_LOCK:
        if max(n) >= _RETEST_REVIVE_MIN:
            _RETEST_BACKOFF[0] = 60.0
        else:
            _RETEST_BACKOFF[0] = min(_RETEST_BACKOFF_MAX, _RETEST_BACKOFF[0] * 2)
        gap = _RETEST_BACKOFF[0]
    log('连接级自愈完成: github/raw/pages 各捞回 %d/%d/%d 个, 下轮自愈间隔改为 %d 秒'
        % (n[0], n[1], n[2], int(gap)))


def trigger_selfheal():
    now = time.time()
    with _RETEST_LOCK:
        gap = _RETEST_BACKOFF[0]
        if now - _RETEST_COOLDOWN_TS[0] < gap:
            return
        _RETEST_COOLDOWN_TS[0] = now
    log('连接级自愈: 转发连续失败, 立即全池重测(不等5分钟)')
    threading.Thread(target=_selfheal_job, daemon=True).start()


def health_loop():
    while True:
        # 官方 IP 表每 6 小时同步一次; 可用数量少于 3 个也顺手同步一次,
        # 免得 GitHub 换了地址我们还抱着旧表。
        need_meta = (time.time() - _last_meta_ok[0]) > 6 * 3600
        good = HEALTH.refresh(candidate_list())
        good_raw = HEALTH_RAW.refresh(CANDIDATE_IPS_RAW_ALL)
        # GitHub Pages 与 raw/附件同一段 IP, 但证书记的是 *.github.io —— 单独体检
        good_pages = HEALTH_PAGES.refresh(CANDIDATE_IPS_PAGES_ALL)
        # 【2026-10-24】每轮体检都落一行到 history.jsonl（面板延迟曲线的数据源;
        # 手动重测那次在 /api/retest 里也落）。丢包抽样只在体检后抽一轮，纯展示用。
        history_append(good, good_raw, good_pages)
        loss_probe_async(good)
        if need_meta or len(good) < 3:
            # 【2026-10-24 修】同步这件事**绝不能把体检线程带死**: 上面那条 /32 的
            # TypeError 就是这么发生的(它落在 try 之外)。同步失败只是"表旧一点",
            # 体检线程死了才是"从此不再挑线路"。
            try:
                fetch_official_ips()
            except Exception as e:
                log('官方 IP 表同步异常: %s（继续用现有表, 体检不中断）' % e)
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
            avg = _avg_life()
            # 寿命台账(用户问的就是"多久会被锁死"): 有样本就把平均寿命一并报出来,
            # 没有就说明还处在观察期、暂时不做预防性轮换。
            _n = _life_samples()
            life_txt = (' | IP 寿命基准 %d 秒(%s), 热备 %d 个' % (
                int(avg), ('%d 个实测样本' % _n) if _n else '冷启动经验值',
                len(_hot_get('github'))))
            log('体检: 可用 %d/%d 已运行%d分钟 -> %s%s' % (
                len(good), len(CANDIDATES), up_min,
                ', '.join('%s(%dms)' % (i, m) for i, m in good[:3]), life_txt))
        else:
            # 【2026-10-10 修·自愈只跑第一步】这里原来是
            #     elif good_raw or good_pages:  只写一行日志
            #     else:                         good = recover()
            # 于是"github.com 这一池全灭、而 raw/pages 还活着"这种**最典型的半坏状态**
            # 永远走不进 recover() —— 也就是说 README 承诺的自愈三步
            # （重拉官方表 → 问系统 DNS → 放宽超时到 6 秒重测）在这种状态下**根本不生效**，
            # 用户看到的只是"面板说一个都不通"，程序自己不会去救。
            # 现在：只看 github.com 这一池是不是空的；raw/pages 的体检结果
            # 降级成"顺带记一行参考信息"，不再决定要不要自愈。
            if good_raw or good_pages:
                log('raw/pages 体检: 可用 %d/%d 与 %d/%d -> %s'
                    % (len(good_raw), len(CANDIDATE_IPS_RAW_ALL),
                       len(good_pages), len(CANDIDATE_IPS_PAGES_ALL),
                       ', '.join('%s(%dms)' % (i, m) for i, m in (good_raw or good_pages)[:2])))
            good = recover()
            if good:
                log('自愈成功(已运行%d分钟): 可用 %d 个, 最快 %s(%dms)'
                    % (up_min, len(good), good[0][0], good[0][1]))

        time.sleep(CHECK_INTERVAL)


# ── 常驻系统托盘(右键菜单: 显示控制面板 / 退出并还原)──────────────────────
# 用户 2026-10-11 要求: 托盘图标常驻(不是只弹面板), 右键就能干净退出,
# 不用每次进任务管理器手动结束进程。独立 daemon 线程跑消息循环, 不阻塞主线程。
_TRAY_HWND = [None]
_TRAY_CB = 0x8001                       # WM_APP + 1, 托盘回调消息
_MENU_SHOW, _MENU_QUIT = 1, 2

def _tray_delete_icon(hwnd):
    """从通知区摘掉托盘图标(进程退出前清干净, 不留僵尸图标)。"""
    try:
        s = ctypes.WinDLL('shell32', use_last_error=True)
        nid = _NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(_NOTIFYICONDATAW)
        nid.hWnd = hwnd
        nid.uID = 1
        s.Shell_NotifyIconW(_NIM_DELETE, ctypes.byref(nid))
    except Exception:
        pass

def safe_quit():
    """统一的干净退出: 还原系统代理 + 撤运行戳 -> 摘托盘图标 -> 终止进程。

    【2026-10-26 修】这里原来自己写了一遍 disable_proxy(), 然后 os._exit(0) ——
    **os._exit 不走 atexit**, 所以刚加的"撤运行戳"那步(on_exit 里)在干净退出时
    从来没被执行过: 明明是按面板的「退出并还原」或 /api/quit 正常退的,
    下次启动照样 dirty_boot=true、照样打「上次进程没有正常退出」—— 等于新功能
    天天在说谎, 真出事时没人当回事。改成直接复用 on_exit(), 还原代理与撤戳一次做完,
    两条退出路径(托盘/接口)口径也不会再分叉。
    """
    try:
        on_exit()
    except Exception as e:
        log('退出前还原异常: %s' % e)
    hwnd = _TRAY_HWND[0]
    if hwnd:
        _tray_delete_icon(hwnd)
    os._exit(0)

def _tray_thread():
    if os.name != 'nt':
        return
    try:
        user32 = ctypes.WinDLL('user32', use_last_error=True)
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        shell32 = ctypes.WinDLL('shell32', use_last_error=True)
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
        user32.DestroyWindow.argtypes = [wintypes.HWND]
        user32.PostQuitMessage.argtypes = [ctypes.c_int]
        user32.GetMessageW.restype = ctypes.c_ssize_t
        user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND,
                                       wintypes.UINT, wintypes.UINT]
        user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
        user32.DispatchMessageW.restype = ctypes.c_ssize_t
        user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
        user32.SetForegroundWindow.argtypes = [wintypes.HWND]
        user32.GetCursorPos.restype = wintypes.BOOL
        user32.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
        user32.TrackPopupMenu.restype = ctypes.c_uint
        user32.TrackPopupMenu.argtypes = [wintypes.HMENU, ctypes.c_uint,
                                          ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                          wintypes.HWND, ctypes.c_void_p]
        user32.CreatePopupMenu.restype = wintypes.HMENU
        user32.CreatePopupMenu.argtypes = []
        user32.AppendMenuW.restype = wintypes.BOOL
        user32.AppendMenuW.argtypes = [wintypes.HMENU, ctypes.c_uint,
                                       ctypes.c_ulonglong, wintypes.LPCWSTR]
        user32.DestroyMenu.argtypes = [wintypes.HMENU]
        user32.PostMessageW.restype = wintypes.BOOL
        user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT,
                                        wintypes.WPARAM, wintypes.LPARAM]
        kernel32.GetModuleHandleW.restype = wintypes.HMODULE
        kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        shell32.Shell_NotifyIconW.restype = wintypes.BOOL
        shell32.Shell_NotifyIconW.argtypes = [ctypes.c_uint,
                                              ctypes.POINTER(_NOTIFYICONDATAW)]
        shell32.ExtractIconExW.restype = ctypes.c_uint
        shell32.ExtractIconExW.argtypes = [wintypes.LPCWSTR, ctypes.c_int,
                                           ctypes.POINTER(wintypes.HANDLE),
                                           ctypes.POINTER(wintypes.HANDLE),
                                           ctypes.c_uint]
        user32.DestroyIcon.restype = wintypes.BOOL
        user32.DestroyIcon.argtypes = [wintypes.HANDLE]

        WM_RBUTTONUP = 0x0205
        WM_LBUTTONUP = 0x0202
        WM_LBUTTONDBLCLK = 0x0203
        WM_NULL = 0x0000
        NIF_MESSAGE = 0x01
        TPM_RIGHTBUTTON = 0x0002
        TPM_RETURNCMD = 0x0100
        MF_STRING = 0x0000

        hinst = kernel32.GetModuleHandleW(None)
        cls = 'FoxPathTray_%d' % os.getpid()

        @ctypes.WINFUNCTYPE(ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT,
                            wintypes.WPARAM, wintypes.LPARAM)
        def wndproc(hwnd, msg, wp, lp):
            if msg == _TRAY_CB:
                evt = lp & 0xFFFF
                if evt == WM_RBUTTONUP:
                    hmenu = user32.CreatePopupMenu()
                    user32.AppendMenuW(hmenu, MF_STRING, _MENU_SHOW, '显示控制面板')
                    user32.AppendMenuW(hmenu, MF_STRING, _MENU_QUIT, '退出并还原')
                    # 微软要求: TrackPopupMenu 前先 SetForegroundWindow,
                    # 之后发一个 WM_NULL, 否则菜单点一次后不消失。
                    user32.SetForegroundWindow(hwnd)
                    pt = wintypes.POINT()
                    user32.GetCursorPos(ctypes.byref(pt))
                    cmd = user32.TrackPopupMenu(hmenu,
                                                TPM_RIGHTBUTTON | TPM_RETURNCMD,
                                                pt.x, pt.y, 0, hwnd, None)
                    user32.DestroyMenu(hmenu)
                    user32.PostMessageW(hwnd, WM_NULL, 0, 0)
                    if cmd == _MENU_SHOW:
                        try:
                            webbrowser.open('http://127.0.0.1:%d/ui' % PANEL_PORT)
                        except Exception:
                            pass
                    elif cmd == _MENU_QUIT:
                        safe_quit()
                elif evt in (WM_LBUTTONUP, WM_LBUTTONDBLCLK):
                    try:
                        webbrowser.open('http://127.0.0.1:%d/ui' % PANEL_PORT)
                    except Exception:
                        pass
            elif msg == 0x0010:        # WM_CLOSE
                user32.DestroyWindow(hwnd)
            elif msg == 0x0002:        # WM_DESTROY
                user32.PostQuitMessage(0)
            return user32.DefWindowProcW(hwnd, msg, wp, lp)

        wc = _WNDCLASSEXW()
        wc.cbSize = ctypes.sizeof(_WNDCLASSEXW)
        wc.lpfnWndProc = ctypes.cast(wndproc, ctypes.c_void_p)
        wc.hInstance = hinst
        wc.lpszClassName = cls
        if not user32.RegisterClassExW(ctypes.byref(wc)):
            log('托盘: 注册窗口类失败')
            return
        try:
            hicon_large = wintypes.HANDLE()
            hicon_small = wintypes.HANDLE()
            _extracted = False
            hwnd = user32.CreateWindowExW(0, cls, APP_NAME, 0, 0, 0, 0, 0,
                                          None, None, hinst, None)
            if not hwnd:
                log('托盘: 创建窗口失败')
                return
            _TRAY_HWND[0] = hwnd
            nid = _NOTIFYICONDATAW()
            nid.cbSize = ctypes.sizeof(_NOTIFYICONDATAW)
            nid.hWnd = hwnd
            nid.uID = 1
            nid.uFlags = NIF_MESSAGE | _NIF_ICON | _NIF_TIP
            nid.uCallbackMessage = _TRAY_CB
            # 托盘图标用 exe 自带原生图标(和文件图标一致), 不再用系统蓝色"i"
            try:
                n_ext = shell32.ExtractIconExW(
                    sys.executable, 0,
                    ctypes.byref(hicon_large), ctypes.byref(hicon_small), 1)
                if n_ext and int(hicon_small.value or 0):
                    nid.hIcon = hicon_small
                    _extracted = True
                elif n_ext and int(hicon_large.value or 0):
                    nid.hIcon = hicon_large
                    _extracted = True
                else:
                    nid.hIcon = user32.LoadIconW(None, ctypes.c_wchar_p(_IDI_INFORMATION))
            except Exception:
                nid.hIcon = user32.LoadIconW(None, ctypes.c_wchar_p(_IDI_INFORMATION))
            if _extracted:
                log('托盘图标取 exe 原生图标')
            nid.szTip = APP_NAME
            if not shell32.Shell_NotifyIconW(_NIM_ADD, ctypes.byref(nid)):
                log('托盘: 添加图标失败')
                return
            log('托盘图标已就绪(右键可退出, 左键打开面板)')
            msg = wintypes.MSG()
            while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
        finally:
            if _extracted:
                try:
                    if int(hicon_small.value or 0):
                        user32.DestroyIcon(hicon_small)
                    if int(hicon_large.value or 0):
                        user32.DestroyIcon(hicon_large)
                except Exception:
                    pass
            try:
                _tray_delete_icon(hwnd)
            except Exception:
                pass
            try:
                user32.DestroyWindow(hwnd)
            except Exception:
                pass
            try:
                user32.UnregisterClassW(cls, hinst)
            except Exception:
                pass
    except Exception as e:
        log('托盘线程异常: %s' % e)

def tray_serve():
    """启动常驻托盘(daemon 线程)。"""
    t = threading.Thread(target=_tray_thread, daemon=True)
    t.start()
    return t

def on_exit():
    """程序退出时, 如果我们正在管理系统代理, 把它还原成之前的样子。"""
    try:
        if proxy_on():
            log('程序退出, 还原系统代理')
            disable_proxy()
    except Exception:
        pass
    # 撤掉"我在跑"的戳 —— 走到这里说明还原流程真的执行过了。
    # 没走到（被结束任务/断电/重启）时戳会留在盘上，下次启动据此说明残留的来历。
    try:
        os.remove(RUN_MARK_FILE)
    except Exception:
        pass


def _enable_dpi_aware():
    """高分屏声明 DPI 感知: 否则 Windows 把窗口/菜单按 100% 画好再整块放大,
    文字发虚起毛刺。对齐热点新闻的做法(SetProcessDPIAware)。
    必须在创建任何窗口前调用 —— 放在 main 最开头。"""
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def main():
    _enable_dpi_aware()               # 高分屏清晰: 必须在任何窗口创建前
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

    # 单实例过了才动这个戳：第二次双击（走上面 return 的那条路）不能把在跑实例的戳吃掉。
    _BOOT_DIRTY[0] = _take_run_mark()

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
    tray_serve()                       # 常驻托盘(右键退出 / 左键开面板), 两种模式都挂
    fetch_official_ips()
    threading.Thread(target=health_loop, daemon=True).start()
    # 热备池守护: 20 秒补一次"刚验过、随时能顶上"的 IP, 让预防性换 IP 有米下锅
    threading.Thread(target=hot_loop, daemon=True).start()
    # 线路体检: 60 秒探一次"不走狐径时 github 通不通", 好如实告诉用户是谁的问题
    threading.Thread(target=direct_probe_loop, daemon=True).start()
    # 线路测速: 每 150 秒真下载一段首页, 量"经狐径/直连"各自的下载速度
    # (握手成功≠打得开: 实测握手 0.1 秒、数据却要 20 秒, 面板必须显示这一层)
    threading.Thread(target=speed_probe_loop, daemon=True).start()
    # DNS 预热: 提前备好常用域名的系统解析结果, 让"直连"在竞速里不输在起跑线
    threading.Thread(target=dns_warm_loop, daemon=True).start()
    # 直连能力体检: 只有"真能传数据"的直连 IP 才给竞速资格, 免得握手快的坏 IP 抢到
    threading.Thread(target=sys_cap_loop, daemon=True).start()
    # 【2026-10-24 新增·每 10 分钟重匹配"跑得通的通道"】
    # 上面几轮各管一层(体检排名 / 热备复验 / 直连切边), 没有一处会普查"这一批 IP 谁真传得动"。
    # 这一轮补的就是那一层, 并且会在证据变差时**主动换岗**, 不等用户先挨一次超时。
    # 先缓 15 秒再起: 让体检/热备把候选名单先立起来, 免得第一轮普查空手而归。
    threading.Thread(target=lambda: (time.sleep(15), channel_loop()),
                     daemon=True).start()

    # 【2026-10-11 修·启动预体检改为后台异步】消除"启动后头几分钟候选池为空/过期"全灭窗口,
    # 但必须放在 start_proxy/tray_serve 之后、用后台线程跑 —— 否则会阻塞代理/托盘起来,
    # 用户双击后要等十几秒才出图标、github 才走代理(体感"启动慢/打不开")。
    # 即便预体检还没完, 代理已开, 连接级自愈(selfheal)会在撞全灭时立即重测兜底。
    def _precheck():
        try:
            HEALTH.refresh(candidate_list())
            HEALTH_RAW.refresh(CANDIDATE_IPS_RAW_ALL)
            HEALTH_PAGES.refresh(CANDIDATE_IPS_PAGES_ALL)
            log('启动预体检完成(后台)')
            # 候选池刚填满 —— 这是补热备的最佳时机(不等 hot_loop 的下一轮 20 秒),
            # 否则启动后头 20 秒里转发只能靠体检名次, 预防性换 IP 没米下锅。
            hot_refresh('github', HEALTH)
            hot_refresh('raw', HEALTH_RAW)
            hot_refresh('pages', HEALTH_PAGES)
            log('热备池就绪: github %d 个 / raw %d 个 / pages %d 个' % (
                len(_hot_get('github')), len(_hot_get('raw')), len(_hot_get('pages'))))
        except Exception as e:
            log('启动预体检失败(将交由 health_loop 稍后补): %s' % e)
    threading.Thread(target=_precheck, daemon=True).start()

    _write_run_mark()                  # 代理与面板都已就位，从这里起"我在跑"这件事有人负责收尾

    if '--silent' in args:
        # 静默模式(开机自启用)以前**没有**注册退出还原 —— 这正是"程序关了,
        # PAC 却留在注册表里"的根因。现在两种模式都注册。
        atexit.register(on_exit)
        startup_proxy(keep_off)
        log('静默模式, 每 5 分钟自动体检')
        while True:
            time.sleep(60)
    else:
        atexit.register(on_exit)
        startup_proxy(keep_off)
        if _AUTO_UPGRADED[0]:
            # 原来开着的面板页每 3 秒轮询一次, 新实例起来后它会自己接上 ——
            # 不再重复开一个浏览器窗口, 免得打断用户。
            log('这次是升级后自动重启: 原来开着的面板标签页会自己接上, 不再重复打开浏览器')
        else:
            # 【2026-10-11 再改·启动彻底安静】上一版把浏览器窗口换成了右下角气泡,
            # 用户照样嫌烦 —— 他要的是"双击完什么也别冒出来"。
            # 现在: 冷启动只驻托盘、不弹窗、不弹气泡, 一行都不往屏幕上送。
            # 要看面板: 左键托盘图标(或第二次双击 exe)。
            log('启动静默: 已常驻托盘(左键开面板, 右键退出并还原); 不弹窗也不弹气泡')
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
