# -*- coding: utf-8 -*-
# 作者: 海风（kele551）
"""狐径 2026-10-26：链路抽风时"别把用户吊死"的三件事 —— 全灭记账、建连总时限、
抢连闸门、自愈退让。全部用假时钟 + 假 socket，一秒真实网络都不碰，也不绑端口。

现场（本机 foxpath.log 装机版 v1.2.2，12:04~12:38）：
  · "连接 github.com 失败: timed out（兜底等了 10.0 秒, 连续第 1 次全灭）"
    四分钟里印了 6 次，次次都是"第 1 次"、次次都等满 10 秒 —— 因为这条线是
    **时好时坏**：中间只要有一条请求"复用刚验过的通道"成功，老账本就被清零，
    下一条撞死的又从头等 10 秒。
  · AB 对照脚本量到一条打不开的请求端到端 **19.4 秒**才回一句连不上
    （抢连 4s + 广撒网 16 个 1.5s + 两轮轻探 + 兜底 10s 层层叠加）。
  · 浏览器开一个 GitHub 页面并发十几条 CONNECT，池子没新鲜证据时每条各自
    对 6 个（全灭后 16 个）IP 发握手 —— 一次页面 90~250 个并发 SYN，全砸在
    正拥塞的国际链路上，探测自己成了负担（_prescan / hot_refresh 记过同一个坑）。
  · 12:35:05 / 12:36:25 / 12:37:30 各触发一次"连接级自愈: 立即全池重测"，
    每轮 50+IP×3 池，正好和用户抢带宽。

用法：
    python tests\\test_fast_fail.py
"""
import ast
import os
import threading
import types
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SRC = os.path.join(REPO, 'github_direct.py')

WANT_FUNCS = {'_sys_fail_recent', '_sys_fail_bump', '_sys_fail_reset',
              '_sys_fail_budget', '_race_take', '_race_release',
              '_race_gate_left', '_fast_log_ok'}
WANT_METHODS = {'_dl_start', '_dl_left', '_dl_note',
                '_connect_race', '_connect_race_batch'}
WANT_CONSTS = {'_SYS_FAIL', '_SYS_FAIL_LOCK', '_SYS_FAIL_WINDOW', '_SYS_FAIL_HOLD',
               '_SYS_FAIL_SHORT_TIMEOUT', '_SYS_FAIL_FULL_TIMEOUT',
               '_RACE_LOCK', '_RACE_BUSY', '_RACE_STALE', '_RACE_WAIT',
               '_RACE_WAIT_SLICE', '_CONNECT_DEADLINE', '_FAST_LOG',
               '_FAST_LOG_LOCK', '_RETEST_COOLDOWN_TS', '_RETEST_LOCK',
               '_RETEST_BACKOFF', '_RETEST_BACKOFF_MAX', '_RETEST_REVIVE_MIN'}

FAILS = []


def check(name, got, want):
    if got == want:
        print('[ok] %s' % name)
    else:
        print('[!!] %s  得到=%r 应为=%r' % (name, got, want))
        FAILS.append(name)


class FakeTime(object):
    """假时钟：只有 sleep 会让时间走，测试里等多少就是多少，不占真实一秒。"""

    def __init__(self, t=100000.0):
        self.t = t

    def time(self):
        return self.t

    def sleep(self, s):
        self.t += s


class FakeSocketMod(object):
    """假 socket：create_connection 一律按名单记账，可指定哪些 IP 必死。"""

    def __init__(self, dead=()):
        self.calls = []
        self.dead = set(dead)

    def create_connection(self, addr, timeout=None):
        ip = addr[0]
        self.calls.append((ip, timeout))
        if ip in self.dead:
            raise OSError('假死: %s' % ip)
        return {'ip': ip, 'timeout': timeout}

    def close(self):        # _connect_race_batch 收尾会关多余的 socket
        pass


def load(stub_env):
    """把要测的定义从 7000 行里摘出来单独 exec（import 整份会绑 8787/8788 端口）。"""
    tree = ast.parse(open(SRC, encoding='utf-8').read())
    ns = dict(stub_env)
    got = set()

    def feed(node):
        if isinstance(node, ast.FunctionDef) and not node.decorator_list:
            if node.name in WANT_FUNCS or node.name in WANT_METHODS:
                exec(compile(ast.Module(body=[node], type_ignores=[]), SRC, 'exec'), ns)
                got.add(node.name)
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name) \
                and node.targets[0].id in WANT_CONSTS:
            exec(compile(ast.Module(body=[node], type_ignores=[]), SRC, 'exec'), ns)
            got.add(node.targets[0].id)

    for node in tree.body:
        feed(node)
        if isinstance(node, ast.ClassDef) and node.name == 'ProxyHandler':
            for sub in node.body:
                feed(sub)
    miss = (WANT_FUNCS | WANT_METHODS | WANT_CONSTS) - got
    check('该摘的定义都摘到了（缺: %s）' % sorted(miss), len(miss), 0)
    return ns


def new_ns(clock=None, dead=()):
    clock = clock or FakeTime()
    sock = FakeSocketMod(dead=dead)
    env = {
        'time': clock, 'socket': sock, 'threading': threading,
        'log': lambda m: None,
        '_LOGS': [], '_LAST_GOOD': {},
        '_note_route': lambda key, ip, sys_ips: None,
        '_fail_clear': lambda ip: None, '_fail_note': lambda ip: None,
        '_ip_born': lambda ip: None, '_ip_died': lambda ip: None,
        '_hot_drop': lambda key, ip: None,
    }
    env['log'] = lambda m: env['_LOGS'].append(m)
    ns = load(env)
    ns['_CLOCK'] = clock
    ns['_SOCKMOD'] = sock
    return ns


def self_obj(ns):
    """造一个只带这次要用的方法的假 handler（等价于 ProxyHandler 实例的建连部分）。"""
    o = types.SimpleNamespace()
    for name in WANT_METHODS:
        setattr(o, name, types.MethodType(ns[name], o))
    return o


def main():
    FULL = 10.0
    SHORT = 3.0

    print('---- 1) 全灭记账：时好时坏的链路不能"一成功就清零"')
    ns = new_ns()
    clock = ns['_CLOCK']
    check('没账时预算 = %.1f 秒' % FULL, ns['_sys_fail_budget']('github'), FULL)
    check('记第一笔全灭返回第 1 笔', ns['_sys_fail_bump']('github'), 1)
    check('一笔全灭之后预算压到 %.1f 秒' % SHORT, ns['_sys_fail_budget']('github'), SHORT)
    # 这就是今天真踩到的那条：12:37:35 别的一条请求复用通道成功, 把账清了,
    # 12:37:42 撞死的那条又从头等满 10 秒
    ns['_sys_fail_reset']('github')
    check('刚全灭就连通一次 —— 这笔账仍然算数(%.1f 秒)' % SHORT,
          ns['_sys_fail_budget']('github'), SHORT)
    check('窗口内还剩几笔', ns['_sys_fail_recent']('github'), 1)
    ns['_sys_fail_bump']('github')
    ns['_sys_fail_bump']('github')
    check('连着记到第 3 笔', ns['_sys_fail_recent']('github'), 3)
    clock.t += ns['_SYS_FAIL_HOLD'] + 1
    ns['_sys_fail_reset']('github')
    check('过了 %d 秒保期再连通 → 陈账作废, 恢复 %.1f 秒'
          % (ns['_SYS_FAIL_HOLD'], FULL), ns['_sys_fail_budget']('github'), FULL)
    check('作废之后账本真的空了', ns['_sys_fail_recent']('github'), 0)
    ns['_sys_fail_bump']('github')
    clock.t += ns['_SYS_FAIL_WINDOW'] + 1
    check('账过了 %d 秒窗口自己作废(没人清它也白)' % ns['_SYS_FAIL_WINDOW'],
          ns['_sys_fail_recent']('github'), 0)
    check('过期之后预算回到 %.1f 秒' % FULL, ns['_sys_fail_budget']('github'), FULL)
    ns['_sys_fail_bump']('raw')
    check('github 的账不牵连 raw 的账', ns['_sys_fail_recent']('github'), 0)
    check('记账互斥锁在（多线程并发请求不能把账记乱）',
          isinstance(ns['_SYS_FAIL_LOCK'], type(threading.Lock())), True)

    print('---- 2) 抢连闸门：同一个池同时只放一条请求做整批握手')
    ns = new_ns()
    check('空闸门时没人占', ns['_race_gate_left']('github'), 0.0)
    check('第一个请求拿到名额', ns['_race_take']('github'), True)
    check('第二个请求被拒（不许再放第二批 SYN）', ns['_race_take']('github'), False)
    check('被占时能报出还要多久', ns['_race_gate_left']('github') > 0, True)
    check('别的池不受影响', ns['_race_take']('raw'), True)
    ns['_race_release']('github')
    check('交还名额后别人能进', ns['_race_take']('github'), True)
    # 占用者万一挂了（线程被杀），闸门必须能自己解开，不能永久卡死转发
    ns['_CLOCK'].t += ns['_RACE_STALE'] + 1
    check('占用超过 %.0f 秒视为已失效，闸门自己解开' % ns['_RACE_STALE'],
          ns['_race_take']('raw'), True)
    ns['_race_release']('github')
    ns['_race_release']('raw')

    print('---- 3) _connect_race：闸门 + 总时限真的作用在握手名单上')
    # a. 闸门空闲、全死 → 整批抢连照跑（6 个），不偷工
    ns = new_ns(dead=tuple('1.1.1.%d' % i for i in range(1, 7)))
    h = self_obj(ns)
    h._dl_start()
    ips = ['1.1.1.%d' % i for i in range(1, 7)]
    # timeout 给 0.4 而不是 4.0：_connect_race_batch 里的 done.wait() 用的是真秒,
    # 这里只想验"名单没被偷工", 不想让单测真等 4.5 秒。超时裁剪另有 f) 一组。
    sock, ip = h._connect_race(ips, 443, timeout=0.4, max_race=6,
                               key='github', label='github.com')
    check('闸门空闲：六个候选都试了', [c[0] for c in ns['_SOCKMOD'].calls], ips)
    check('全死时如实返回 None', (sock, ip), (None, None))
    check('抢连结束一定交还闸门', ns['_race_gate_left']('github'), 0.0)

    # b. 闸门被占 + 有"刚验过的通道" → 复用，一条新 SYN 都不发
    ns = new_ns()
    h = self_obj(ns)
    h._dl_start()
    ns['_race_take']('github')
    ns['_LAST_GOOD']['github'] = '9.9.9.9'
    sock, ip = h._connect_race(['1.1.1.1', '1.1.1.2', '1.1.1.3', '1.1.1.4',
                                '1.1.1.5', '1.1.1.6'], 443, timeout=4.0,
                               max_race=6, key='github', label='github.com')
    check('闸门被占时只连那一条已验活的通道', [c[0] for c in ns['_SOCKMOD'].calls],
          ['9.9.9.9'])
    check('复用到手就转发', ip, '9.9.9.9')
    check('复用成功也记一行日志（用户查得出为什么快）',
          any('复用了同时在跑的抢连结论' in m for m in ns['_LOGS']), True)
    ns['_race_release']('github')
    check('复用这一手没把别人的闸门占住', ns['_race_gate_left']('github'), 0.0)

    # c. 闸门被占 + 手里没通道 → 只轻试名单第一个，不再撒网
    ns = new_ns()
    h = self_obj(ns)
    h._dl_start()
    ns['_race_take']('github')
    sock, ip = h._connect_race(['2.2.2.1', '2.2.2.2', '2.2.2.3', '2.2.2.4',
                                '2.2.2.5', '2.2.2.6'], 443, timeout=4.0,
                               max_race=6, key='github', label='github.com')
    check('等不到结论时最多再放 1 个握手', [c[0] for c in ns['_SOCKMOD'].calls],
          ['2.2.2.1'])
    check('轻试成功就用它', ip, '2.2.2.1')
    ns['_race_release']('github')

    # d. 已验活的那条其实挂了 → 不许干等，撤账后回到自己轻试一手
    ns = new_ns(dead=('9.9.9.9',))
    h = self_obj(ns)
    h._dl_start()
    ns['_race_take']('github')
    ns['_LAST_GOOD']['github'] = '9.9.9.9'
    sock, ip = h._connect_race(['3.3.3.1', '3.3.3.2', '3.3.3.3'], 443, timeout=4.0,
                               max_race=6, key='github', label='github.com')
    check('先试已验活的、不通立刻改试名单第一个',
          [c[0] for c in ns['_SOCKMOD'].calls], ['9.9.9.9', '3.3.3.1'])
    check('改试成功照样转发', ip, '3.3.3.1')
    ns['_race_release']('github')

    # e. 预算到点 → 一个握手都不发，直接放弃
    ns = new_ns()
    h = self_obj(ns)
    h._dl = ns['_CLOCK'].t - 1.0        # 早就超了
    sock, ip = h._connect_race(['4.4.4.1', '4.4.4.2'], 443, timeout=4.0,
                               max_race=6, key='github', label='github.com')
    check('到点放弃：零握手', ns['_SOCKMOD'].calls, [])
    check('到点放弃：返回 None', (sock, ip), (None, None))
    check('到点要说人话（日志里看得见是被预算拦的）',
          any('建连只剩' in m for m in ns['_LOGS']), True)

    # f. 单次握手超时按剩余预算裁剪，绝不让它等满 4 秒
    ns = new_ns(dead=tuple('5.5.5.%d' % i for i in range(1, 7)))
    h = self_obj(ns)
    h._dl = ns['_CLOCK'].t + 1.0
    h._connect_race(['5.5.5.%d' % i for i in range(1, 7)], 443, timeout=4.0,
                    max_race=6, key='github', label='github.com')
    to = [c[1] for c in ns['_SOCKMOD'].calls]
    check('超时从 4.0 剪到剩余(0.6~0.8 秒之间)', all(0.6 <= x <= 0.8 for x in to), True)
    check('剪完仍然真的并发跑完整批', len(to), 6)

    print('---- 4) 自愈退让：捞不回人就不要每分钟全池重测一次')
    ns = new_ns()
    clock = ns['_CLOCK']
    check('初始间隔 60 秒', ns['_RETEST_BACKOFF'][0], 60.0)
    # 直接跑作业本体，不开线程：三池都报 0 个 → 间隔翻倍
    pools = types.SimpleNamespace(
        HEALTH=types.SimpleNamespace(refresh=lambda lst: []),
        HEALTH_RAW=types.SimpleNamespace(refresh=lambda lst: []),
        HEALTH_PAGES=types.SimpleNamespace(refresh=lambda lst: []),
        candidate_list=lambda: ['x'], CANDIDATE_IPS_RAW_ALL=['y'],
        CANDIDATE_IPS_PAGES_ALL=['z'])
    # 轻量探活(_light_retest)要走的两个入口: snapshot 给一份 10 个的主榜,
    # _probe 按 pools._live 控制"前几次调用答话"。这样才能真的测到
    # "前排够数就不动全池"这条新规矩, 而不是靠 NameError 兜过去假装通过。
    pools.HEALTH.snapshot = lambda: (
        [('9.9.9.%d' % i, 100 + i) for i in range(1, 11)], 0.0)
    pools._live = [9]
    pools._probed = []

    def _probe_light(ip, timeout=3.0):
        pools._probed.append(ip)
        return (120, 'http') if len(pools._probed) <= pools._live[0] else None

    pools.HEALTH._probe = _probe_light
    job = make_job(ns, clock, pools, threading)
    job()
    check('一轮空手 → 120 秒', ns['_RETEST_BACKOFF'][0], 120.0)
    job()
    check('两轮空手 → 240 秒', ns['_RETEST_BACKOFF'][0], 240.0)
    pools.HEALTH.refresh = lambda lst: ['a', 'b', 'c', 'd', 'e']
    job()
    check('捞回 5 个 → 立刻回到 60 秒', ns['_RETEST_BACKOFF'][0], 60.0)
    for _ in range(6):
        pools.HEALTH.refresh = lambda lst: []
        job()
    check('封顶 %d 秒，不会无限退让' % ns['_RETEST_BACKOFF_MAX'],
          ns['_RETEST_BACKOFF'][0], ns['_RETEST_BACKOFF_MAX'])
    # 间隔真的起作用了吗：把 ts 摆在 90 秒前，间隔 240 时不该再触发
    trig, fired = make_trigger(ns, clock, pools, threading)
    ns['_RETEST_BACKOFF'][0] = 240.0
    ns['_RETEST_COOLDOWN_TS'][0] = clock.t - 90.0
    fired.clear()
    trig()
    check('抽风期内隔 90 秒不再重测（按退让后的间隔）', fired, [])
    # 【2026-10-30 改】这句原本断言"超过间隔就该再试一轮"。加了轻量探活之后,
    # "再试"分成了两级: 先只敲前排那几个, 够数就收工, 只有当它们也不答话了才动全池。
    # 改它的依据不是想象 —— 本机 foxpath.log 22:04~22:15 实测: 体检每 316 秒一轮,
    # 之后几乎必然紧跟一次全池重测, 而这些重测每次照样捞回 27~29 个(链路好得很),
    # 代价却是面板连着 12 次轮询有 5 次 RemoteDisconnected。
    ns['_RETEST_COOLDOWN_TS'][0] = clock.t - 300.0
    pools._probed = []
    pools._live = [9]                      # 前排答话得很痛快
    trig()
    check('超过间隔但前排够数 → 只做轻量探活，不动全池', len(fired), 0)
    check('轻量探活只摸前 6 个，没惊动整榜', len(pools._probed), 6)

    # 前排真的不答话了，才该请出全池重测
    ns['_RETEST_BACKOFF'][0] = 60.0
    ns['_RETEST_COOLDOWN_TS'][0] = clock.t - 300.0
    pools._probed = []
    pools._live = [0]                      # 前排全哑
    trig()
    check('前排全不答话 → 真的开工全池重测', len(fired), 1)

    # 轻量探活自己出岔子，不许变成"从此不自愈"（fail-safe）
    ns['_RETEST_COOLDOWN_TS'][0] = clock.t - 300.0
    pools.HEALTH.snapshot = lambda: (_ for _ in ()).throw(RuntimeError('boom'))
    fired.clear()
    trig()
    check('轻量探活自身异常 → 降级为全池重测（不许失能）', len(fired), 1)
    pools.HEALTH.snapshot = lambda: (
        [('9.9.9.%d' % i, 100 + i) for i in range(1, 11)], 0.0)

    # 【2026-10-30 补】上面几档假连接池都是"三个池同进同退", 于是 max(n) 和 n[0]
    # 判据结果一模一样 —— bug 就藏在这段盲区里。本机 foxpath.log 的真实形态恰恰
    # 相反: 整份日志 106 轮自愈、"下轮间隔"全是 60 秒, 翻倍退让一次都没走过, 因为
    # github 主池被掐到 0 个的时候, raw / pages 各自才 8 个 IP 却照常捞回 4 个,
    # 老判据 max(n)=4 >= 3 就把闸门拽回 60 秒 —— 链路堵死时每分钟照样全池重探 50 个。
    ns['_RETEST_BACKOFF'][0] = 60.0
    pools.HEALTH.refresh = lambda lst: []            # 主池全灭
    pools.HEALTH_RAW.refresh = lambda lst: ['r'] * 4  # 小池照样捞回
    pools.HEALTH_PAGES.refresh = lambda lst: ['p'] * 4
    job()
    check('主池全灭、仅 raw/pages 各捞回 4 个 → 照样翻倍退让(不许被小池拽回 60 秒)',
          ns['_RETEST_BACKOFF'][0], 120.0)
    # 反过来: 主池一活就该立刻回到 60 秒(退让不能变成"放弃治疗")
    pools.HEALTH.refresh = lambda lst: ['a', 'b', 'c']
    job()
    check('主池捞回 3 个 → 立刻回到 60 秒', ns['_RETEST_BACKOFF'][0], 60.0)

    print('---- 5) 源码级不变量（改回去要立刻发现）')
    src = open(SRC, encoding='utf-8').read()
    body = src[src.index('    def _connect(self, host, port):'):]
    body = body[:body.index('    def _tunnel(self, target):')]
    lines = [l.strip() for l in body.strip().splitlines()]
    dl_at = next((i for i, l in enumerate(lines) if l.startswith('self._dl_start')), 99)
    host_at = next((i for i, l in enumerate(lines)
                    if 'is_github_related_host' in l), 99)
    check('总时限在域名判定之前就设好（后面每一手都看得到预算）',
          dl_at < host_at, True)
    # 原来这里数死"2 处"。2026-10-26 三点整改·① 在全灭之后又加了"预算内再转两轮",
    # 手数会变而**规矩不变**: 任何一处抢连都不许绕过闸门裸放 SYN。
    _races = src.count('self._connect_race(')
    check('每一处抢连都带了 key/label（闸门才生效）',
          (_races, src.count('key=key, label=label')), (_races, _races))
    check('兜底用的是剪过的 _tmo，不是原样 _budget',
          '_s3 = socket.create_connection((host, port), timeout=_tmo)' in src, True)
    check('广撒网 16 个之前先看预算',
          'and self._dl_left() > 1.8' in src, True)
    check('轻探的时间判据排在占闸门之前（不许占坑又跑不完）',
          'if _try and self._dl_left() >= 3.6 and _prescan_take():' in src, True)
    check('旧的清零式常量已经不再被引用', '_SHORT_BUDGET_GAP' in src, False)
    check('总时限是 %d 秒量级（浏览器等得起）' % ns['_CONNECT_DEADLINE'],
          2.0 <= ns['_CONNECT_DEADLINE'] <= 12.0, True)
    check('整份源码语法过', compile_ok(), True)

    print('\n%s  失败 %d 条' % ('全部通过' if not FAILS else '有失败', len(FAILS)))
    return 0 if not FAILS else 1


def make_job(ns, clock, pools, real_threading):
    """把 _selfheal_job 摘出来跑（不开线程），三池用假对象。"""
    tree = ast.parse(open(SRC, encoding='utf-8').read())
    env = dict(ns)
    env.update({'HEALTH': pools.HEALTH, 'HEALTH_RAW': pools.HEALTH_RAW,
                'HEALTH_PAGES': pools.HEALTH_PAGES,
                'candidate_list': pools.candidate_list,
                'CANDIDATE_IPS_RAW_ALL': pools.CANDIDATE_IPS_RAW_ALL,
                'CANDIDATE_IPS_PAGES_ALL': pools.CANDIDATE_IPS_PAGES_ALL,
                'threading': real_threading})
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == '_selfheal_job':
            exec(compile(ast.Module(body=[node], type_ignores=[]), SRC, 'exec'), env)
            return env['_selfheal_job']
    FAILS.append('摘不到 _selfheal_job')
    return lambda: None


def make_trigger(ns, clock, pools, real_threading):
    """摘 trigger_selfheal，用假 Thread 记录它到底有没有真的开工。"""
    tree = ast.parse(open(SRC, encoding='utf-8').read())
    fired = []

    class FakeThread(object):
        def __init__(self, target=None, args=(), daemon=None):
            self.target = target

        def start(self):
            fired.append(self.target)

    env = dict(ns)
    env.update({'HEALTH': pools.HEALTH, 'HEALTH_RAW': pools.HEALTH_RAW,
                'HEALTH_PAGES': pools.HEALTH_PAGES,
                'candidate_list': pools.candidate_list,
                'CANDIDATE_IPS_RAW_ALL': pools.CANDIDATE_IPS_RAW_ALL,
                'CANDIDATE_IPS_PAGES_ALL': pools.CANDIDATE_IPS_PAGES_ALL,
                # trigger_selfheal 只是把作业丢进线程，假 Thread 不会真跑它，
                # 给个占位名字就行(不占的话 exec 出来的函数体取不到 _selfheal_job 会炸)。
                '_selfheal_job': lambda: None,
                'threading': types.SimpleNamespace(Thread=FakeThread),
                # 轻量探活必须走真身: 早先漏掉它时 _light_retest 会 NameError,
                # 被 trigger_selfheal 的 except 兜成"照样全池重测" —— 测试看着全绿,
                # 其实一条都没验到新逻辑(#300 那句断言当时就是这么"假装通过"的)。
                '_bad_edge': lambda ip: False,
                'ThreadPoolExecutor': ThreadPoolExecutor})
    _bodies = [n for n in tree.body
               if isinstance(n, ast.FunctionDef)
               and n.name in ('trigger_selfheal', '_light_retest')]
    exec(compile(ast.Module(body=_bodies, type_ignores=[]), SRC, 'exec'), env)
    return env['trigger_selfheal'], fired


def compile_ok():
    try:
        compile(open(SRC, encoding='utf-8').read(), SRC, 'exec')
        return True
    except SyntaxError:
        return False


if __name__ == '__main__':
    raise SystemExit(main())
