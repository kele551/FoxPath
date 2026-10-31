# -*- coding: utf-8 -*-
# 作者: 海风（kele551）
"""滚动岗哨（_patrol_once）的行为测试：补上"体检周期 300 秒 > IP 寿命 250 秒"造成的新鲜度空档。
全部假时钟 + 假连接池，一秒真实网络都不碰，也不绑端口。

岗哨要解决的问题（本机 foxpath.log + 源码实测参数）：
  · 体检 5 分钟一轮全扫 50 个，新鲜窗口 _FRESH_WINDOW 只有 90 秒，而单个 IP
    实际寿命 148~250 秒 —— 每个周期有约七成时间，池子里的"可用"标记是过期的。
  · 用户这时刷新，代理会把已经死掉的 IP 判成"最快"，第一个请求必然踩雷。
    岗哨不替代体检，只在间隙里反复把**当前最可能要用的那几个**重新验一遍。

必须钉死的三条性质（改坏了要立刻发现）：
  ① 名额只给池子前 _PATROL_TOP 个 —— 摊到 50 个上等于一个都探不过来；
  ② 前排里**最久没验过的**先探 —— 否则会在同一个 IP 上反复刷，其余照样过期；
  ③ 探不回来**绝不判死**（不 drop）—— 一次糟糕的探测清空前排是更早吃过的亏，
     它只该随窗口自己过期掉下去。

用法：
    python tests\\test_patrol.py
"""
import ast
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SRC = os.path.join(REPO, 'github_direct.py')

WANT_FUNCS = {'_patrol_once'}
WANT_CONSTS = {'_PATROL_BATCH', '_PATROL_TOP', '_FRESH_WINDOW'}

FAILS = []


def check(name, got, want):
    if got == want:
        print('[ok] %s' % name)
    else:
        print('[!!] %s  得到=%r 应为=%r' % (name, got, want))
        FAILS.append(name)


class FakeClock(object):
    def __init__(self, t=300000.0):
        self.t = t

    def time(self):
        return self.t


class FakeHealth(object):
    """假连接池：按 (延迟, 陈旧程度) 造前排，记录岗哨探了谁、各次结果如何。"""

    def __init__(self, clock, good, tier, results=None):
        self._good = list(good)          # [(ip, ms)] 已按延迟排好序（转发挑人的顺序）
        self._tier = dict(tier)          # ip -> (层级, 验出时刻)
        self.clock = clock
        self.results = results or {}     # ip -> 'http'/'tls' 表示能探回来; 缺省=探不回来
        self.probed = []

    def snapshot(self):
        return list(self._good), 0.0

    def tier_of(self, ip):
        return self._tier.get(ip) or (None, 0.0)

    def drop(self, ip):
        self._good = [(i, m) for i, m in self._good if i != ip]

    def _probe(self, ip):
        """照抄真 _probe 的关键副作用：探回来就地刷新证据时刻，探不回来什么都不动。"""
        self.probed.append(ip)
        tier = self.results.get(ip)
        if tier is None:
            return None
        self._tier[ip] = (tier, self.clock.t)
        return (120, tier)


def load(health, clock, bad_edges=(), now=None):
    """按白名单把符号从源码里摘出来，装进一个带假依赖的命名空间。"""
    tree = ast.parse(open(SRC, encoding='utf-8').read())
    picked = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in WANT_FUNCS:
            picked.append(node)
        elif isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id in WANT_CONSTS:
                    picked.append(node)
    ns = {
        'HEALTH': health,
        'time': clock,
        'log': lambda *a, **k: None,
        '_bad_edge': lambda ip: ip in bad_edges,
    }
    mod = ast.Module(body=picked, type_ignores=[])
    exec(compile(mod, SRC, 'exec'), ns)
    return ns


def build_scenario(clock):
    """12 个 IP：前 8 名里第 3、第 7 位最陈旧；第 9~12 名故意做得更陈旧，
    用来验证岗哨不会把名额浪费在池子后排上。"""
    good = [('10.0.0.%d' % i, 100 + i * 10) for i in range(1, 13)]
    tier = {}
    for i in range(1, 13):
        ip = '10.0.0.%d' % i
        age = {3: 400.0, 7: 300.0}.get(i)          # 前排里最陈旧的两个
        if age is None:
            age = 500.0 + i                         # 后排更陈旧，但不该被照顾
        tier[ip] = ('http', clock.t - min(age, 500.0) - i)
    tier['10.0.0.3'] = ('http', clock.t - 400.0)
    tier['10.0.0.7'] = ('http', clock.t - 300.0)
    # 其余前排都很新鲜
    for i in (1, 2, 4, 5, 6, 8):
        tier['10.0.0.%d' % i] = ('http', clock.t - 10.0 * i)
    return good, tier


def expected_batch(health, good, clock, top_n, batch_n, skip=()):
    """期望清单由场景推导，绝不写死具体 IP ——
    岗哨的规矩是"前排里最陈旧的优先"，要验的是这条规矩本身。
    早先写死 IP 的版本在 _PATROL_TOP 从 8 放宽到 14 时立刻失效，
    而那时候代码行为其实完全正确。"""
    pool = [t for t in good[:top_n] if t[0] not in skip]
    pool.sort(key=lambda kv: clock.t - (health.tier_of(kv[0])[1] or 0.0),
              reverse=True)
    return [ip for ip, _ms in pool[:batch_n]]


def main():
    print('---- 1) 名额只给前排，而且最陈旧的先探')
    clock = FakeClock()
    good, tier = build_scenario(clock)
    health = FakeHealth(clock, good, tier)
    ns = load(health, clock)
    top_n = ns['_PATROL_TOP']
    batch_n = ns['_PATROL_BATCH']
    exp = expected_batch(health, good, clock, top_n, batch_n)
    batch = ns['_patrol_once']()
    check('一轮只探 %d 个' % batch_n, len(batch), batch_n)
    check('探的全在前 %d 名里' % top_n,
          all(ip in [i for i, _ in good[:top_n]] for ip in batch), True)
    check('挑的正是前排里最陈旧的几个', health.probed, exp)
    check('池尾再陈旧也不占用名额',
          [i for i in health.probed if i not in [x for x, _ in good[:top_n]]], [])

    print('---- 2) 探回来 → 证据时刻刷新（岗哨的核心价值）')
    health2 = FakeHealth(clock, good, dict(tier),
                         results={ip: 'http' for ip in exp})
    ns2 = load(health2, clock)
    target = exp[0]
    before = health2.tier_of(target)[1]
    ns2['_patrol_once']()
    after = health2.tier_of(target)[1]
    check('探活后 tier 时间戳前进到当下', (after > before, after), (True, clock.t))
    fresh = clock.t - after <= ns2['_FRESH_WINDOW']
    check('于是它重新进入 90 秒新鲜窗口', fresh, True)

    print('---- 3) 探不回来也不许判死（2026-10-11 的教训）')
    health3 = FakeHealth(clock, good, dict(tier), results={})   # 全部探不通
    ns3 = load(health3, clock)
    exp3 = expected_batch(health3, good, clock, top_n, batch_n)
    old3 = {ip: health3.tier_of(ip)[1] for ip in exp3}
    ns3['_patrol_once']()
    survivors = [i for i, _ in health3.snapshot()[0]]
    check('一轮全探不通也不清退任何一个 IP',
          all(ip in survivors for ip in exp3), True)
    check('池子规模不变', len(survivors), len(good))
    check('证据时刻也没被篡改',
          [health3.tier_of(ip)[1] for ip in exp3], [old3[ip] for ip in exp3])

    print('---- 4) 被实测拉黑的假边缘不许占岗哨名额')
    banked = exp[0]
    health4 = FakeHealth(clock, good, dict(tier), results={banked: 'http'})
    ns4 = load(health4, clock, bad_edges=(banked,))
    batch4 = ns4['_patrol_once']()
    check('拉黑对象不被选中', banked in batch4, False)
    check('名额让给了没被拉黑的下一个',
          batch4, expected_batch(health4, good, clock, top_n, batch_n, skip=(banked,)))

    print('---- 5) 名额算得过来账（前排轮一圈必须小于新鲜窗口）')
    ns5 = load(health, clock)
    top_n = ns5['_PATROL_TOP']
    batch_n = ns5['_PATROL_BATCH']
    interval = None
    tree = ast.parse(open(SRC, encoding='utf-8').read())
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == '_PATROL_INTERVAL':
                    interval = ast.literal_eval(node.value)
    round_trip = (top_n / float(batch_n)) * interval
    check('_PATROL_INTERVAL 已定义', interval is not None, True)
    check('前排斥一圈 %.0f 秒 < 新鲜窗口 %.0f 秒，无空档'
          % (round_trip, ns5['_FRESH_WINDOW']),
          round_trip < ns5['_FRESH_WINDOW'], True)

    print('---- 6) 源码级不变量（改回去要立刻发现）')
    src = open(SRC, encoding='utf-8').read()
    check('岗哨线程真的被拉起来了',
          'threading.Thread(target=_patrol_loop' in src, True)
    check('岗哨是常驻循环不是一次性跑完', '_patrol_loop' in src and 'while True' in src, True)
    check('整份源码语法过', compile_ok(), True)

    print()
    if FAILS:
        print('>>> 有失败: %d 项 -> %s' % (len(FAILS), '; '.join(FAILS)))
        return 1
    print('>>> 全部通过  失败 0 条')
    return 0


def compile_ok():
    try:
        compile(open(SRC, encoding='utf-8').read(), SRC, 'exec')
        return True
    except SyntaxError:
        return False


if __name__ == '__main__':
    sys.exit(main())
