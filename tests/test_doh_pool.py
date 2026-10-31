# -*- coding: utf-8 -*-
# 作者: 海风（kele551）
"""狐径「DoH 干净解析补池」的单测 —— 全离线：假 urllib、假 DNS 回包，
一秒真实网络都不碰，也不 import github_direct.py（一 import 就绑 8787/8788）。
照 tests/test_ip_sources.py 的办法用 ast 只摘需要的常量与函数单独 exec。

为什么要有这份测试（2026-10-30 参考 FastGithub 的加密 DNS 思路之后新增）：
  · 官方段表拉不到、系统 DNS 又在骗人（本机历史上给过 2001::1 / 78.16.49.15 这种
    污染地址）时，DoH 是唯一还能拿到真地址的路。
  · 这条路上有两个坑只能靠测试钉住：
      ① 查询必须**绕开本机代理**（ProxyHandler({})）—— 请求绕回狐径、而狐径在等
        这份结果，就是自己等自己，症状是整个自愈卡住；
      ② DoH 说什么都不算证据，拿回来的地址一律要过体检才算进池，
        否则一次 DNS 欺骗就能把假地址喂进候选池。

覆盖：
  1) 构造 opener 时带的是空代理表（防死锁那条硬约束）
  2) 只认 A/AAAA，CNAME 之类的记录一律不收
  3) 回环/内网/链路本地/组播这类地址不收（复用手动 IP 那套校验）
  4) 第一台答话就不问第二台；第一台挂了换第二台；全挂返回 [] 且不抛
  5) 冷却闸门：两分钟内第二次调用一次请求都不发
  6) 只有体检通过的地址才并进 CANDIDATES；一个都没过时池子不变
  7) 地址已在池里 → 不去重复体检，结论如实说"没问到新地址"
  8) 体检函数本身抛异常也不能把补池带崩
  9) 面板/反馈包读到的那一笔账(_DOH_LAST)与结论一致
  10) 服务器名单里不许有实测不答话的那台

样例地址的坑（第一次跑就踩了，写下来免得下次再踩）：
  测试里的"干净公网地址"不能写成 198.51.100.x / 203.0.113.x / 2001:db8:: 这类
  文档保留段 —— Python 的 ipaddress 把它们也算 is_private，会被 _manual_ip_reject
  当成内网地址挡掉，于是所有用例都变成"什么都没查到"，看着像功能坏了。这里统一
  用 140.82.x.x（GitHub 真实在用的段）和 2606:50c0::（GitHub Pages 的 v6）。

用法：
    python tests\\test_doh_pool.py
"""
import ast
import ipaddress
import json
import os
import sys
import threading
import types
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SRC = os.path.join(REPO, "github_direct.py")      # 跟着仓库走，换台机器也能跑

WANT_CONSTS = ['DOH_SERVERS', 'DOH_TIMEOUT', 'DOH_COOLDOWN', 'DOH_MIN_GOOD',
               'DOH_MAX_IPS', '_DOH_TS', '_DOH_LOCK', '_DOH_SOURCE', '_DOH_LAST']
WANT_FUNCS = ['_manual_ip_reject', '_doh_opener', 'doh_lookup', 'doh_refresh_pools',
              'doh_status']

FAILS = []

ALI = 'https://dns.alidns.com/resolve'
TD = 'https://doh.pub/resolve'


def check(name, got, want):
    if got == want:
        print('[ok] %s' % name)
    else:
        print('[X ] %s  得到=%r 应为=%r' % (name, got, want))
        FAILS.append(name)


class FakeTime(object):
    def __init__(self, now=1700000000.0):
        self.now = now

    def time(self):
        return self.now

    def sleep(self, s):
        pass


class FakeUrllib(object):
    """假 urllib：routes = {查询 url: 回包 bytes | Exception}；顺手记下代理处理的设置。"""

    def __init__(self, routes, world):
        self.routes = routes
        self.world = world
        self.request = types.SimpleNamespace(
            Request=self._Request, urlopen=self._urlopen,
            build_opener=self._build_opener, ProxyHandler=self._ProxyHandler)
        self.parse = urllib.parse

    def _Request(self, url, headers=None):
        return types.SimpleNamespace(full_url=url, headers=headers or {})

    def _urlopen(self, req, timeout=None):
        return self._resp(req.full_url)

    def _ProxyHandler(self, proxies):
        self.world.proxy_maps.append(dict(proxies if proxies is not None else {'__None__': 1}))
        return ('proxy-handler', dict(proxies if proxies is not None else {'__None__': 1}))

    def _build_opener(self, *handlers):
        self.world.built += 1
        self.world.handlers.append(handlers)
        return types.SimpleNamespace(open=self._open)

    def _open(self, req, timeout=None):
        return self._resp(req.full_url)

    def _resp(self, url):
        r = self.routes.get(url, ConnectionError('没登记这条 url'))
        if isinstance(r, Exception):
            raise r
        class Resp(object):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return r
        return Resp()


class FakePool(object):
    """假候选池：只有 alive 里登记过的地址才算体检通过。"""

    def __init__(self, existing=(), alive=()):
        self.existing = list(existing)
        self.alive = set(alive)
        self.calls = []
        self.raise_on = False

    def candidates(self):
        return list(self.existing)

    def refresh(self, ips, timeout=None):
        self.calls.append(list(ips))
        if self.raise_on:
            raise RuntimeError('体检自己炸了')
        return [(ip, 12) for ip in ips if ip in self.alive]


def q(server, host, itype):
    return '%s?name=%s&type=%s' % (server, host, itype)


def ans(*rows):
    return json.dumps({'Status': 0, 'Answer': [dict(r) for r in rows]}).encode()


def main():
    # ── 1) 必须绕开本机代理（防自己等自己）──────────────────────────────
    world = types.SimpleNamespace(built=0, handlers=[], proxy_maps=[])
    routes = {q(ALI, 'github.com', 'A'): ans({'type': 1, 'data': '140.82.112.10.'})}
    ns = load(routes, world)
    got = ns['doh_lookup']('github.com', 'A')
    check('查到地址', got, ['140.82.112.10'])
    check('建过 opener', world.built, 1)
    check('用的是空代理表(绕开本机代理)', world.proxy_maps, [{}])
    check('空代理表是以 handler 形式装进去的',
          [type(h).__name__ if not isinstance(h, tuple) else h[0]
           for hs in world.handlers for h in hs], ['proxy-handler'])

    # ── 2/3) 只认 A/AAAA、脏地址一律不收 ────────────────────────────────
    routes = {q(ALI, 'github.com', 'A'): ans(
        {'type': 5, 'data': 'cname.evil.test.'},          # CNAME 不收
        {'type': 1, 'data': '127.0.0.1'},                 # 回环不收
        {'type': 1, 'data': '192.168.1.7'},               # 内网不收
        {'type': 1, 'data': '169.254.1.1'},               # 链路本地不收
        {'type': 1, 'data': '224.0.0.5'},                 # 组播不收
        {'type': 1, 'data': '0.0.0.0'},                   # 未指定不收
        {'type': 1, 'data': '140.82.112.11'},             # 干净地址收
        {'type': 1, 'data': '140.82.112.11'})}            # 重复不加成两条
    ns = load(routes, types.SimpleNamespace(built=0, handlers=[], proxy_maps=[]))
    check('脏地址全挡、干净地址留下', ns['doh_lookup']('github.com', 'A'),
          ['140.82.112.11'])

    routes = {q(ALI, 'github.com', 'AAAA'): ans({'type': 28, 'data': '2606:50c0:8002::5'},
                                                 {'type': 28, 'data': 'fe80::1'})}
    ns = load(routes, types.SimpleNamespace(built=0, handlers=[], proxy_maps=[]))
    check('AAAA 收、链路本地 v6 不收', ns['doh_lookup']('github.com', 'AAAA'),
          ['2606:50c0:8002::5'])

    # ── 4) 换源与全挂 ──────────────────────────────────────────────────
    routes = {q(ALI, 'github.com', 'A'): ConnectionError('alidns 不通'),
              q(TD, 'github.com', 'A'): ans({'type': 1, 'data': '140.82.113.20'})}
    ns = load(routes, types.SimpleNamespace(built=0, handlers=[], proxy_maps=[]))
    check('第一台挂了换第二台', ns['doh_lookup']('github.com', 'A'), ['140.82.113.20'])
    check('记下真正答话的那台', ns['_DOH_SOURCE'][0], 'doh.pub')
    routes = {q(ALI, 'github.com', 'A'): ConnectionError('不通'),
              q(TD, 'github.com', 'A'): ConnectionError('也不通')}
    ns = load(routes, types.SimpleNamespace(built=0, handlers=[], proxy_maps=[]))
    check('两台都挂时返回空表不抛异常', ns['doh_lookup']('github.com', 'A'), [])
    routes = {q(ALI, 'github.com', 'A'): b'{"Answer": "not-a-list"}'}
    ns = load(routes, types.SimpleNamespace(built=0, handlers=[], proxy_maps=[]))
    check('回包形状不对也不抛', ns['doh_lookup']('github.com', 'A'), [])
    routes = {q(ALI, 'github.com', 'A'): ans({'type': 1, 'data': '140.82.113.30'}),
              q(TD, 'github.com', 'A'): ans({'type': 1, 'data': '140.82.113.31'})}
    ns = load(routes, types.SimpleNamespace(built=0, handlers=[], proxy_maps=[]))
    check('第一台答了就不问第二台', ns['doh_lookup']('github.com', 'A'), ['140.82.113.30'])
    check('名单里不含实测不答话的 google', 'dns.google' in ' '.join(ns['DOH_SERVERS']), False)

    # ── 5) 冷却闸门 ────────────────────────────────────────────────────
    clock = FakeTime()
    routes = {q(ALI, 'github.com', 'A'): ans({'type': 1, 'data': '140.82.114.40'}),
              q(ALI, 'raw.githubusercontent.com', 'A'): ans({'type': 1, 'data': '140.82.114.41'})}
    ns = load(routes, types.SimpleNamespace(built=0, handlers=[], proxy_maps=[]), clock=clock)
    gh, raw = ns['HEALTH'], ns['HEALTH_RAW']
    msg = ns['doh_refresh_pools']('(测试)')
    check('补池结论(新增 2 个)', msg, 'DoH(dns.alidns.com) 补池: 新增 2 个实测通过的地址')
    check('两个池各体检一次', (len(gh.calls), len(raw.calls)), (1, 1))
    clock.now += 30.0                                  # 30 秒后又想问
    before = len(gh.calls)
    check('冷却期内第二次什么都不做', ns['doh_refresh_pools'](), '')
    check('冷却期内一次网络都不碰', len(gh.calls), before)
    clock.now += 200.0
    cand_before = list(ns['CANDIDATES'])
    calls_before = len(gh.calls)
    check('过了冷却就能再问', ns['doh_refresh_pools'](),
          'DoH(dns.alidns.com) 补池: 新增 2 个实测通过的地址')
    check('过了冷却确实又发了请求', len(gh.calls), calls_before + 1)
    check('重复地址不会把候选池撑大', ns['CANDIDATES'], cand_before)

    # ── 6) 只有体检通过的才进池 ─────────────────────────────────────────
    routes = {q(ALI, 'github.com', 'A'): ans({'type': 1, 'data': '140.82.115.50'},
                                             {'type': 1, 'data': '140.82.115.51'}),
              q(ALI, 'github.com', 'AAAA'): ans(),
              q(ALI, 'raw.githubusercontent.com', 'A'): ans(),
              q(ALI, 'raw.githubusercontent.com', 'AAAA'): ans()}
    ns = load(routes, types.SimpleNamespace(built=0, handlers=[], proxy_maps=[]),
              clock=FakeTime(), alive=['140.82.115.50'])
    pool = ns['HEALTH']
    base = list(ns['CANDIDATES'])
    msg = ns['doh_refresh_pools']('(池子见底)')
    check('通过的地址才进池', ns['CANDIDATES'], base + ['140.82.115.50'])
    check('结论里如实报新增 1 个', msg, 'DoH(dns.alidns.com) 补池: 新增 1 个实测通过的地址')
    check('送去体检的是两个新地址', sorted(pool.calls[-1]),
          ['140.82.115.50', '140.82.115.51'])

    # ── 7) 一个都没通过 / 地址本来就在池里 ──────────────────────────────
    ns2 = load(routes, types.SimpleNamespace(built=0, handlers=[], proxy_maps=[]),
               clock=FakeTime(5000.0), alive=[])
    check('都没通过时的结论', ns2['doh_refresh_pools'](),
          'DoH(dns.alidns.com) 给了 2 个地址, 实测一个都没通过')
    check('没通过就不动池子', ns2['CANDIDATES'], ['140.82.112.3'])
    ns3 = load(routes, types.SimpleNamespace(built=0, handlers=[], proxy_maps=[]),
               clock=FakeTime(5000.0), alive=['140.82.115.50'],
               existing=['140.82.115.50', '140.82.115.51'])
    check('地址已在池里时不去重复体检', ns3['doh_refresh_pools'](),
          'DoH 没问到新地址(两台都没答话, 或地址已在池里)')
    check('已在池里时不体检', ns3['HEALTH'].calls, [])

    # ── 8) 体检函数炸了也不能带崩补池 ──────────────────────────────────
    ns4 = load(routes, types.SimpleNamespace(built=0, handlers=[], proxy_maps=[]),
               clock=FakeTime(5000.0), alive=['140.82.115.50'])
    ns4['HEALTH'].raise_on = True
    check('体检抛异常时老实返回结论', ns4['doh_refresh_pools'](),
          'DoH(dns.alidns.com) 给了 2 个地址, 实测一个都没通过')
    check('体检炸了不污染池子', ns4['CANDIDATES'], ['140.82.112.3'])
    check('炸的那次写进日志了',
          any('DoH 地址体检出错' in m for m in ns4['logs']), True)

    # ── 9) 面板那一笔账 ────────────────────────────────────────────────
    st = ns4['doh_status']()
    check('面板读得到上次结论', st['text'],
          'DoH(dns.alidns.com) 给了 2 个地址, 实测一个都没通过')
    check('面板读到新增个数', st['added'], 0)
    check('面板知道问过几次服务器', st['servers'], [ALI, TD])

    print('')
    if FAILS:
        print('失败 %d 条: %s' % (len(FAILS), ', '.join(FAILS)))
        return 1
    print('全部通过')
    return 0


def load(routes, world, clock=None, alive=('140.82.112.10', '140.82.112.11',
                                          '140.82.114.40', '140.82.114.41',
                                          '140.82.115.50'),
         existing=('140.82.112.3',)):
    """把需要的常量与函数摘进一个干净命名空间，DoH 就在这个假环境里跑。"""
    tree = ast.parse(open(SRC, encoding='utf-8').read())
    ns = {
        'urllib': FakeUrllib(routes, world),
        'json': json, 'ipaddress': ipaddress, 'threading': threading,
        'time': clock or FakeTime(),
        'logs': [],
        'CANDIDATES': ['140.82.112.3'],
        'HEALTH': FakePool(existing, alive),
        'HEALTH_RAW': FakePool([], alive),
    }
    ns['log'] = lambda m, *a, **k: ns['logs'].append(m)
    got_f = 0
    for node in tree.body:
        if isinstance(node, ast.Assign):
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if any(n in WANT_CONSTS for n in names):
                try:
                    exec(compile(ast.Module(body=[node], type_ignores=[]), SRC, 'exec'), ns)
                except Exception as e:
                    check('常量 %s 能否求值' % names, '异常:%s' % type(e).__name__, '正常')
        elif (isinstance(node, ast.FunctionDef) and node.name in WANT_FUNCS
              and not node.decorator_list):
            exec(compile(ast.Module(body=[node], type_ignores=[]), SRC, 'exec'), ns)
            got_f += 1
    check('摘到的函数个数', got_f, len(WANT_FUNCS))
    return ns


if __name__ == '__main__':
    sys.exit(main())
