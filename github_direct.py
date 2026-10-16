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
APP_VERSION = '1.1.1'
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


def _cap_test(host, ip, window=2.5, max_bytes=262144, min_ok=8192, deadline=8.0):
    """测某个 IP 到底能不能真的把数据传下来, 而不是只握得上。

    【2026-10-11 再修·测持续吞吐, 别测"凑够字节的时间"】
    上一版是"读满 32KB 就停", 日志里恒定显示 37KB。问题在于这测的是
    **达到阈值所花的时间**(含 TLS 后的首字节等待), 不是稳态速度, 会系统性
    **低估**快 IP: 同一个 20.205.243.166, 体检测出 48 KB/s, 实际跑 161 KB/s。
    低估直连 = 永远轮不到它上位。
    现在改成**固定读满 window 秒**, 到点或读够上限才收, 得到的是真实吞吐。
    """
    try:
        raw = socket.create_connection((ip, 443), timeout=6.0)
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
                ('直连' if _sys_wins(host) else '候选池')))
        except Exception as e:
            log('吞吐对比异常: %s' % e)
        time.sleep(60)


def _cap_of(host, tbl):
    """取一份还新鲜的体检证据; 过期或无效返回 None。"""
    r = tbl.get(host)
    if not r or not r.get('ok') or not r.get('ip'):
        return None
    if time.time() - (r.get('ts') or 0) >= _SYS_CAP_TTL:
        return None
    return r


def _sys_wins(host):
    """直连是不是**明显**快过候选池 —— 是就让它上位。

    必须留余量(_SYS_WIN_RATIO): 两边速度本来就在抖, 谁高一点就切谁会导致
    来回横跳, 反而更不稳定。要快出一截才值得换。
    """
    s, p = _cap_of(host, _SYS_CAP), _cap_of(host, _POOL_CAP)
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
                    _LAST_GOOD[key] = ''
                    log('空闲期换岗: %s 已撑 %d 秒但暂时没有新鲜热备, 下次转发重新抢连'
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
            return _lat
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
        good = sorted([(i, m) for i, m in res if m is not None], key=lambda x: x[1])
        with self._lock:
            # 【2026-10-11 修·别让一次糟糕的体检清空候选池】
            # 高丢包时一轮探测会把大半 IP 判成超时(实测: 49 个只测出 4 个可用),
            # 候选池骤减就没得挑了。上一轮**证实可用**的先留着压在后面兜底 ——
            # 真死了也没关系: 转发有失败降权 + 并发抢连, 死 IP 会被自然跳过。
            if self._good and len(good) < len(self._good) // 2:
                have = {i for i, _ in good}
                good = good + [(i, m) for i, m in self._good if i not in have]
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
    // avatars./camo.githubusercontent.com also go through the local proxy now.
    // They are in the SAME 185.199.108.0/22 range as raw/objects and serve the
    // same *.githubusercontent.com certificate, so the raw pool fits them.
    // Measured on this machine (2026-10-11): one 282KB avatar took 5.7-14.2s
    // DIRECT but 1.1-4.7s through the proxy. githubassets stays DIRECT: it is a
    // different domain with a different certificate and is already fast (0.27s).
    // github.io and *.github.io (GitHub Pages) also go through the local proxy.
    // They share the 185.199.108.0/22 pool with raw/objects, but the proxy checks
    // them against the *.github.io certificate, NOT the githubusercontent one.
    if (host === "github.com" || host === "www.github.com" ||
        host === "raw.githubusercontent.com" ||
        host === "objects.githubusercontent.com" ||
        host === "avatars.githubusercontent.com" ||
        host === "camo.githubusercontent.com" ||
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

    def _connect_race(self, ips, port, timeout=2.5, max_race=4):
        # 【2026-10-11 修·并发抢连(Happy Eyeballs)】
        # 原来是**串行**试候选: 撞上一个死 IP 就要干等它超时(3s)才换下一个,
        # 前面有几个死 IP 就是几倍超时 —— 实测 github 要 8.15 秒才返回 200。
        # 现在同时对前 N 个候选发起 TCP 连接, 谁先成功就用谁, 其余立刻关掉:
        # 死 IP 自己超时即可, 不再阻塞别人; 活的那个 200ms 就回来了。
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
        for x in _hot_get(key):
            if x not in cand:
                cand.append(x)
        rest = [x for x in pool.candidates()[:24] if x not in cand]
        rest.sort(key=lambda ip: _fail_rank(ip))   # 连着失败的往后靠
        # 摊到不同网段后再并发抢连: 一段全死还有别的段顶上
        cand += _pick_spread(rest, per_group=2, limit=6)
        # 同样把"寿命将尽"的从候选里剔掉 —— 否则刚让它让位、转头又从热备/名次里
        # 把它捡回来, 预防就白做了。全都要过期时才不挑食(总得有个能连的)。
        young = [x for x in cand if not _ip_expiring(x)]
        if young:
            cand = young

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
                try:
                    # 超时压到 2.0 秒: 证据新鲜时连接通常 <0.5 秒就回来,
                    # 超过 2 秒基本可以断定"台账已过期", 早撤早回落抢连。
                    _s = socket.create_connection((best[0], port), timeout=2.0)
                    _note_route(key, best[0], sys_ips)
                    _LAST_GOOD[key] = best[0]
                    _fail_clear(best[0])
                    _ip_born(best[0])
                    log('按实测吞吐直连 %s: %d KB/s, 次快 %s'
                        % (best[0], best[1],
                           ('%d KB/s' % second[1]) if second else '无'))
                    return _s, best[0]
                except OSError:
                    _fail_note(best[0])
                    _hot_drop(key, best[0])
                    _kbps_forget(best[0])   # 赌输了就忘掉它, 下次别再赔一轮超时

        # 一批并发抢连(6 个): 谁先通就用谁。
        # 不做"分批重试" —— 每多一批就多叠加一轮超时, 实测分批版出现过 16 秒尖峰。
        # 并发数**不是越多越好**: 试过 14 个, 国际链路上这些连接会互相挤占带宽,
        # 结果每个都变慢(实测退化到 7~10 秒); 6 个兼顾"覆盖多网段"与"不自拥塞"。
        # timeout 4 秒: 并发抢连的返回时间取决于"最快成功的那个", 不是这个上限,
        # 所以放宽它是零成本的, 高丢包时给 TCP 重传留够时间。
        sock, ip = self._connect_race(cand, port, timeout=4.0, max_race=6)
        if sock is not None:
            _note_route(key, ip, sys_ips)
            _LAST_GOOD[key] = ip
            _fail_clear(ip)
            _ip_born(ip)          # 寿命台账: 这个 IP 第一次被证实可用
            return sock, ip
        for dead in cand[:6]:
            pool.drop(dead)
            _fail_note(dead)
            _ip_died(dead)        # 结掉这一生, 记进"能撑多久"的样本
            _hot_drop(key, dead)  # 热备里也剔掉, 下轮补新的

        _LAST_GOOD[key] = ''
        # 整批都撞死了 —— 热备池多半也过期了, 立刻补一批新的待命
        threading.Thread(target=lambda: hot_refresh(key, pool), daemon=True).start()
        log('%s 候选 IP 全军覆没, 本次退回系统解析' % label)
        trigger_selfheal()
        try:
            return socket.create_connection((host, port), timeout=10), None
        except OSError as e:
            log('连接 %s 失败: %s' % (host, e))
            return None, None

    def _connect(self, host, port):
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
        up, used = self._connect(host, port)
        if up is None:
            self._send(502, b'Bad Gateway')
            trigger_selfheal()
            return
        try:
            self.wfile.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
            self.wfile.flush()
        except Exception:
            up.close()
            return
        if used:
            log_conn('%s -> %s' % (host, used))
        up_err = self._relay(up)
        if up_err and used:
            log('上游返回 4xx/5xx, 剔除假活 IP %s 并触发自愈' % used)
            HEALTH.drop(used)
            trigger_selfheal()

    def _relay(self, up):
        conn = self.connection
        pair = [conn, up]
        up_err = False
        _first_up = True
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
                    # 【2026-10-11 修·嗅探上游首段】上游 IP 若"证书对但被限流/封禁",
                    # 会返回 HTTP 4xx/5xx(典型 400): 这种假活 IP 之前 TCP/TLS 都通,
                    # 代理以为成功转发, 实则用户拿到错误页。首段若是 4xx/5xx 即判死。
                    if _first_up and s is up and data[:5] == b'HTTP/' and len(data) >= 12:
                        code = data[9:12]
                        if code[:2].isdigit() and code[2:3] in b'45':
                            up_err = True
                            stop = True
                            break
                    if s is up:
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
        return up_err


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
# 升级源: 仓库里的 version.json, Gitee raw 优先、GitHub 兜底;
#         测试时可在数据目录放一个 update_url.txt 指到本地文件。
UPDATE_URLS = (
    'https://gitee.com/kele551/FoxPath/raw/main/version.json',
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

    线上就是这么放的（`…/raw/main/version.json.sig`）；本地路径（update_url.txt 指到文件，
    演练用）同样按"名字后面加 .sig"找。
    """
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
    urls = [u for u in urls if u.lower().startswith('https://')]
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
    <button id="btnSpeed">立即测速</button>
    <label><input type="checkbox" id="auto"> 开机自启</label>
    <button class="danger" id="btnQuit">退出并还原</button>
    <span id="actMsg" style="font-size:13px;color:#16a34a"></span>
  </div>
  <div class="row" id="lifeBar" style="margin-top:8px;font-size:13px;color:#64748b"></div>
  <div class="row" id="directTip" style="margin-top:6px;font-size:13px"></div>
  <div class="row" id="speedTip" style="margin-top:6px;font-size:13px;color:#64748b"></div>
  <div class="row" id="routeTip" style="margin-top:6px;font-size:13px;color:#64748b"></div>
  <div class="row" id="speedMsg" style="font-size:13px;color:#64748b"></div>
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
    // IP 寿命台账: 直接回答"多久会被锁死、还剩多久、有没有备胎"(2026-10-11)
    const lb = document.getElementById('lifeBar');
    if (d.life && d.cur_ip) {
      const src = d.life_n ? ('本机实测 ' + d.life_n + ' 个样本') : '经验值(攒够样本后自动校准)';
      const left = d.cur_left;
      // cur_left 为 null = 这个 IP 已失效或还没建立寿命记录, 不能显示成"还能撑 X 秒"
      const tail = (left === null || left === undefined)
        ? '寿命未知(该 IP 已失效, 下次访问会换新的)'
        : ('已撑 ' + d.cur_age + ' 秒, 约 ' + Math.max(0, left) + ' 秒后自动提前换掉(不等它锁死)');
      lb.textContent = 'IP 寿命基准 ' + d.life + ' 秒(' + src + ') · 当前 ' + d.cur_ip
        + ' · ' + tail + ' · 热备 ' + (d.hot || 0) + ' 个待命';
      lb.style.color = (left !== null && left !== undefined && left < 30) ? '#dc2626' : '#64748b';
    } else { lb.textContent = ''; }
    // 线路体检: 明说"是线路不通还是狐径没干活", 别让用户猜(2026-10-11 用户反复报打不开)
    const dt = document.getElementById('directTip');
    if (d.direct === false) {
      dt.textContent = '当前这台机器直连 github 主站也不通（不是狐径的问题，换 IP 也打不开）。'
        + '狐径会在线路恢复时自动生效；急用可开手机热点，或先用 Gitee。';
      dt.style.color = '#dc2626';
    } else if (d.direct === true) {
      dt.textContent = '直连 github 正常，狐径会挑更快的 IP 走。';
      dt.style.color = '#16a34a';
    } else { dt.textContent = ''; }
    // 线路测速(2026-10-11): 光看"通不通"会误判 —— 实测里握手 0.1 秒就成功、
    // 数据却要 20 秒才下完, 浏览器表现就是"打不开"。这里把真实下载速度摆出来,
    // 走狐径和直连各一份, 谁在拖后腿一眼看清。
    const stEl = document.getElementById('speedTip');
    const sp = d.speed || {};
    const rd = function(v){
      if (!v || !v.ts) return null;
      // 一个字节都没等到时别写"不通": 那是超时(连接其实建起来了), 写清楚
      if (!v.ok) return {bad: true, txt: v.err || '不通', t: v.total || 0};
      return {bad: false, kb: Math.round((v.bytes||0)/1024), t: v.total,
              kbps: v.kbps, ttfb: v.ttfb, ts: v.ts};
    };
    const P = rd(sp.proxy), D = rd(sp.direct);
    if (sp.busy) {
      stEl.textContent = '正在测速…(真下载一段 github 首页, 最多 40 秒)';
      stEl.style.color = '#64748b';
    } else if (!P && !D) {
      stEl.textContent = '';
    } else {
      const one = function(v){
        if (v.bad) return v.t ? ('超时(等了 ' + v.t + 's 零字节)') : ('失败(' + v.txt + ')');
        return v.kb + 'KB/' + v.t + 's ≈ ' + v.kbps + ' KB/s';
      };
      let txt = '';
      const age = Math.round(Date.now()/1000 - (P ? P.ts : D.ts));
      txt += '线路实测(' + age + '秒前)：经狐径 ' + (P ? one(P) : '未测')
           + ' · 直连 ' + (D ? one(D) : '未测');
      let verdict = '';
      let color = '#64748b';
      if (P && !P.bad && D && !D.bad) {
        if (P.kbps < 50 && D.kbps < 50) {
          verdict = ' —— 两条路都堵着，是这条宽带到 GitHub 的链路在拥塞，换 IP 也救不了，只能等它缓过来';
          color = '#dc2626';
        } else if (P.kbps >= 200) {
          verdict = ' —— 通畅';
          color = '#16a34a';
        } else if (P.kbps >= 50) {
          verdict = ' —— 偏慢，能开但会转圈';
          color = '#b45309';
        } else {
          verdict = ' —— 经狐径也很慢';
          color = '#dc2626';
        }
        if (D.kbps > 0 && P.kbps > D.kbps * 1.5) {
          verdict += '（狐径比直连快 ' + (P.kbps / D.kbps).toFixed(1) + ' 倍，加速是生效的）';
        }
      } else if (P && P.bad && D && D.bad) {
        verdict = ' —— 两边都连不上，等线路恢复';
        color = '#dc2626';
      }
      stEl.textContent = txt + verdict;
      stEl.style.color = color;
    }
    // 路由来源(2026-10-11): 最近一次转发到底走了谁 —— 候选池挑的 IP, 还是系统
    // 解析出来的那个(也就是"直连"), 以及后台用同一把尺子量出来的两边吞吐。
    // 一直显示池子 = 池子确实更快; 老显示直连 = 池子选得不如外面那条路。
    const rtEl = document.getElementById('routeTip');
    const rt = (d.route || {}).github || (d.route || {}).raw
             || (d.route || {}).pages || null;
    const cp = d.cap || {};
    const kbps = function(o){ return (o && o.ok) ? (o.kbps + ' KB/s') : '传不动'; };
    if (rt && rt.ip) {
      const rage = Math.round(Date.now()/1000 - (rt.ts || 0));
      let why = '';
      if (cp.sys && cp.pool) {
        why = ' —— 后台实测：直连 ' + kbps(cp.sys) + ' vs 候选池 ' + kbps(cp.pool)
            + (cp.sys_wins ? '，直连更快所以放行' : '，池子更快所以走池');
      }
      rtEl.textContent = '上一次转发走了：' + (rt.src === 'sys'
          ? ('系统解析(直连) ' + rt.ip) : ('候选池 ' + rt.ip)) + why
        + '（' + rage + ' 秒前）';
      rtEl.style.color = '#64748b';
    } else { rtEl.textContent = ''; }
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
// 「立即测速」(2026-10-11): 真下载一段 github 首页量速度, 后台跑完自己刷新
document.getElementById('btnSpeed').onclick = ()=>{
  const b = document.getElementById('btnSpeed'), m = document.getElementById('speedMsg');
  b.disabled = true; m.textContent = '测速中…';
  act('/api/speedtest').then(r=>{
    m.textContent = r.msg || '';
    b.disabled = false;
    setTimeout(refresh, 500); setTimeout(refresh, 8000); setTimeout(refresh, 20000);
  });
};
document.getElementById('auto').onchange = (e)=>
  act('/api/autostart?on='+(e.target.checked?1:0)).then(refresh);
document.getElementById('btnQuit').onclick = ()=>{
  if(confirm('退出后 GitHub 将恢复原有连接方式，确定退出？')){
    act('/api/quit').then(()=>{
      clearInterval(_refreshTimer); clearInterval(_diagTimer);
      document.getElementById('state').textContent='已安全退出，可关闭此页';
      _say('actMsg','狐径已退出，系统代理已还原', 6000, false);
    }).catch(()=>{
      document.getElementById('state').textContent='已退出（面板无响应，可关闭此页）';
    });
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
loadDiag(); var _diagTimer = setInterval(loadDiag,10000);
refresh(); var _refreshTimer = setInterval(refresh,3000);
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
            _cur_ip = _LAST_GOOD.get('github') or (good[0][0] if good else '')
            # 寿命未知要如实给 null: 转成 0 的话面板会显示"约 0 秒后换", 语义正好相反
            _cur_left = _ip_remaining(_cur_ip)
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
                                              HEALTH_RAW.refresh(CANDIDATE_IPS_RAW_ALL),
                                              HEALTH_PAGES.refresh(CANDIDATE_IPS_PAGES_ALL)),
                             daemon=True).start()
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
def trigger_selfheal():
    now = time.time()
    if now - _RETEST_COOLDOWN_TS[0] < 60:
        return
    _RETEST_COOLDOWN_TS[0] = now
    log('连接级自愈: 转发连续失败, 立即全池重测(不等5分钟)')
    threading.Thread(target=lambda: (
        HEALTH.refresh(candidate_list()),
        HEALTH_RAW.refresh(CANDIDATE_IPS_RAW_ALL),
        HEALTH_PAGES.refresh(CANDIDATE_IPS_PAGES_ALL),
    ), daemon=True).start()


def health_loop():
    while True:
        # 官方 IP 表每 6 小时同步一次; 可用数量少于 3 个也顺手同步一次,
        # 免得 GitHub 换了地址我们还抱着旧表。
        need_meta = (time.time() - _last_meta_ok[0]) > 6 * 3600
        good = HEALTH.refresh(candidate_list())
        good_raw = HEALTH_RAW.refresh(CANDIDATE_IPS_RAW_ALL)
        # GitHub Pages 与 raw/附件同一段 IP, 但证书记的是 *.github.io —— 单独体检
        good_pages = HEALTH_PAGES.refresh(CANDIDATE_IPS_PAGES_ALL)
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
    """统一的干净退出: 还原系统代理 -> 摘托盘图标 -> 终止进程。"""
    try:
        if proxy_on():
            log('程序退出, 还原系统代理')
            disable_proxy()
    except Exception:
        pass
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
