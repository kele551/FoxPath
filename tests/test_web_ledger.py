# -*- coding: utf-8 -*-
# 作者: 海风（kele551）
"""狐径 2026-10-26「三点整改」的判据：网页级实测台账、断流分账、预算自适应、空池轮转。
全部假时钟 + 假 socket，一秒真实网络都不碰，也不绑端口。

现场（本机 foxpath.log + 同一时刻手工实测，2026-10-26 16:22~16:44）：
  · 16:42 面板"可用 6/50"，同一分钟手工 curl 走 127.0.0.1:8787 打
    github.com/kele551/hotnews：6 发里 **5 发 CONNECT 直接 502**，剩下 1 发 13.5 秒
    才回首字节。强制全池重测之后变 5 发 3 中（3.4s / 4.2s / 9.7s），另外 2 发是
    **收到 229KB / 278KB 之后断流**。
  · 同一时刻**绕开狐径**的直连 443 实测 12 秒超时（curl code=000）。老写法却在池子
    全灭后把剩下的预算全押在这条已死的路上（探针 1.5 秒 + 兜底 3~10 秒），等完回一句
    502 —— 而 13.5 秒那一条"再等半秒就轮到后台刚验活的通道"。
  · 那种"TCP 0.1 秒赢下抢连、正文一个字节不来 / 下一半死掉"的 IP，在 _FAIL_CNT 里
    一分钱不欠（握手确实成功了），于是每轮都抢赢、每次都把浏览器吊在半路。

三条整改各自要钉住的东西：
  ① _web_dl_budget / 全灭后再转两轮 / _direct_is_dead —— 不许把预算交给已死的直连，
     也不许在"成功本来就要 13 秒"的时候还按 8 秒一刀切。
  ② _stall_note / _stall_rank + _relay 的结局判定 —— 断流单独一本账，只降权、
     满两次才请出池子（时好时坏，一棒子打死会把仅有的候选清光）。
  ③ _web_verdict / _web_status —— 面板第一格从此读真实转发，"可用 N/M"降成明细。

用法：
    python tests\\test_web_ledger.py
"""
import ast
import os
import threading
import types

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SRC = os.path.join(REPO, 'github_direct.py')

WANT_FUNCS = {'_web_record', '_web_rows', '_web_median_ms', '_web_counts',
              '_web_verdict', '_web_status', '_web_dl_budget', '_direct_is_dead',
              '_stall_note', '_stall_rank', '_stall_bytes', '_stall_clear',
              '_pool_key_for'}
WANT_METHODS = {'_relay'}
WANT_CONSTS = {'WEB_OK', 'WEB_STALL', 'WEB_REFUSED', 'WEB_BADGW',
               '_WEB_LEDGER', '_WEB_LOCK', '_WEB_WINDOW', '_WEB_MAX',
               '_WEB_MIN_SAMPLES',
               '_STALL', '_STALL_LOCK', '_STALL_WINDOW', '_STALL_MIN_BYTES',
               '_STALL_DEMOTE_RANK', '_STALL_DROP_POOL',
               '_CONNECT_DEADLINE', '_CONNECT_DEADLINE_MAX',
               '_CONNECT_RETRY_ROUNDS', '_CONNECT_RETRY_MIN_LEFT',
               '_CONNECT_RETRY_BACKOFF', '_DIRECT_PROBE_FRESH', '_DIRECT_OK'}

FAILS = []


def check(name, got, want):
    if got == want:
        print('[ok] %s' % name)
    else:
        print('[!!] %s  得到=%r 应为=%r' % (name, got, want))
        FAILS.append(name)


class FakeTime(object):
    def __init__(self, t=200000.0):
        self.t = t

    def time(self):
        return self.t

    def sleep(self, s):
        self.t += s


class FakeSelect(object):
    """select.select 按脚本站位：'up'/'conn' = 那边可读，'timeout' = 空转超时，
    'exc' = 异常集非空。pair 固定是 [conn, up]（与 _relay 里同一写法）。"""

    def __init__(self, script=None):
        self.script = list(script or [])
        self.calls = 0

    def select(self, rlist, _w, _x, _timeout):
        self.calls += 1
        item = self.script.pop(0) if self.script else 'timeout'
        if item == 'timeout':
            return [], [], []
        if item == 'exc':
            return [], [], list(rlist)
        # 异常集必须是**空列表**而不是 [False, False] —— 后者在 `if e:` 里是真,
        # 每次循环都当成"有异常"直接收摊, 一个字节都读不到。
        if item == 'up':
            return [rlist[1]], [], []
        if item == 'conn':
            return [rlist[0]], [], []
        raise AssertionError('假 select 脚本里没这一手: %r' % item)


class FakeEnd(object):
    """隧道一端的假 socket：按脚本吐字节，吐完回空串(= 对端正常收尾)。"""

    def __init__(self, chunks=(), name='up'):
        self.chunks = list(chunks)
        self.name = name
        self.sent = []
        self.closed = False

    def settimeout(self, _t):
        pass

    def recv(self, _n):
        if not self.chunks:
            return b''
        return self.chunks.pop(0)

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True


def load(stub_env):
    """把要测的定义从 7700 行里摘出来单独 exec（import 整份会绑 8787/8788 端口）。"""
    tree = ast.parse(open(SRC, encoding='utf-8').read())
    ns = dict(stub_env)
    got = set()

    def feed(node):
        if isinstance(node, ast.FunctionDef) and not node.decorator_list:
            if node.name in WANT_FUNCS or node.name in WANT_METHODS:
                exec(compile(ast.Module(body=[node], type_ignores=[]), SRC, 'exec'), ns)
                got.add(node.name)
        elif isinstance(node, ast.Assign) and len(node.targets) == 1:
            tgt = node.targets[0]
            if isinstance(tgt, ast.Name) and tgt.id in WANT_CONSTS:
                exec(compile(ast.Module(body=[node], type_ignores=[]), SRC, 'exec'), ns)
                got.add(tgt.id)
            elif isinstance(tgt, ast.Tuple):
                # WEB_OK, WEB_STALL, WEB_REFUSED, WEB_BADGW = 'ok', ... 这种一行多常量
                names = {e.id for e in tgt.elts if isinstance(e, ast.Name)} & WANT_CONSTS
                if names:
                    exec(compile(ast.Module(body=[node], type_ignores=[]), SRC, 'exec'), ns)
                    got.update(names)

    for node in tree.body:
        feed(node)
        if isinstance(node, ast.ClassDef) and node.name == 'ProxyHandler':
            for sub in node.body:
                feed(sub)
    miss = (WANT_FUNCS | WANT_METHODS | WANT_CONSTS) - got
    check('该摘的定义都摘到了（缺: %s）' % sorted(miss), len(miss), 0)
    return ns


def new_ns():
    clock = FakeTime()
    logs = []
    env = {
        'time': clock, 'log': lambda m: logs.append(m),
        'threading': threading,
        'select': FakeSelect(),
        'socket': types.SimpleNamespace(),
        'RELAY_IDLE_TIMEOUT': 600,
    }
    ns = load(env)
    ns['_CLOCK'] = clock
    ns['_LOGS'] = logs
    # 每个用例都从干净的账本开始（模块级 dict 会被上一步的 exec 建在 ns 里）
    ns['_WEB_LEDGER'].clear()
    ns['_STALL'].clear()
    return ns


def relay_ns(script, up_chunks=(), conn_chunks=()):
    """造一个只带 _relay 的假 handler + 假两端 socket，跑一次转发拿结局。

    假时钟每 recv 一次走 0.1 秒，让 first_ms 有非零值可断言；脚本走完之后
    FakeSelect 一律回"空转超时"，也就是真实链路里那种"对端不再吐字节"。
    """
    ns = new_ns()
    ns['select'] = FakeSelect(script)
    clock = ns['_CLOCK']
    up = FakeEnd(up_chunks, name='up')
    conn = FakeEnd(conn_chunks, name='conn')
    for end in (up, conn):
        real = end.recv

        def _step(*a, _e=end, _r=real):
            clock.t += 0.1
            return _r(*a)
        end.recv = _step
    o = types.SimpleNamespace()
    o.connection = conn
    o.wfile = None
    o._relay = types.MethodType(ns['_relay'], o)
    out = o._relay(up)
    return ns, out, up, conn


def main():
    print('---- 1) ③ 网页台账：真实转发的四种结局，各自算成一句人话')
    ns = new_ns()
    clock, rec = ns['_CLOCK'], ns['_web_record']
    check('没样本时不下结论', ns['_web_verdict']('github')[:2],
          ('unknown', '还没实测'))
    rec('github', ns['WEB_OK'], 1200.0, 250000)
    rec('github', ns['WEB_OK'], 900.0, 180000)
    check('少于 %d 次只说"样本还少"，不抢答"能开"' % ns['_WEB_MIN_SAMPLES'],
          ns['_web_verdict']('github')[0], 'few')
    for _ in range(8):
        rec('github', ns['WEB_OK'], 4000.0, 300000)
    check('10 次全成 → 能打开', ns['_web_verdict']('github')[0], 'good')
    ns['_WEB_LEDGER'].clear()
    for _ in range(6):
        rec('github', ns['WEB_OK'], 3000.0, 1000)
    for _ in range(2):
        rec('github', ns['WEB_STALL'], 8000.0, 229000)
    for _ in range(2):
        rec('github', ns['WEB_REFUSED'], 8000.0, 0)
    code, text, detail = ns['_web_verdict']('github')
    check('成 6 / 共 10（60%）→ 能打开但常断流', (code, text), ('slow', '能打开，但常断流'))
    check('明细把三种失败各多少都写出来',
          all(x in detail for x in ('断流 2', '连不上 2')), True)
    # 2026-10-26 装机实测踩到的：6 成 3 败、败的全是握手失败，面板却写"常断流"——
    # 断流和连不上是两回事，措辞必须跟着账走。
    ns['_WEB_LEDGER'].clear()
    for _ in range(6):
        rec('github', ns['WEB_OK'], 1000.0, 100)
    for _ in range(4):
        rec('github', ns['WEB_REFUSED'], 8000.0, 0)
    check('一次都没断流、失败全在握手 → 说"常连不上"而不是"常断流"',
          ns['_web_verdict']('github')[:2], ('slow', '能打开，但常连不上'))
    ns['_WEB_LEDGER'].clear()
    for _ in range(3):
        rec('github', ns['WEB_OK'], 1000.0, 1)
    for _ in range(7):
        rec('github', ns['WEB_REFUSED'], 8000.0, 0)
    check('成 3 / 共 10（30%）→ 时通时断', ns['_web_verdict']('github')[0], 'flaky')
    ns['_WEB_LEDGER'].clear()
    for _ in range(5):
        rec('github', ns['WEB_BADGW'], 500.0, 1440)
    check('一次都没成 → 打不开', ns['_web_verdict']('github')[:2], ('down', '打不开'))

    print('---- 2) 台账本身的边界：过窗口的账要自己过期，不许越攒越多')
    ns = new_ns()
    clock, rec = ns['_CLOCK'], ns['_web_record']
    base = clock.t
    for i in range(ns['_WEB_MAX'] + 10):
        clock.t = base + i            # 每条隔 1 秒，都在窗口内
        rec('github', ns['WEB_OK'], 1000.0, 10)
    check('只保留最近 %d 条' % ns['_WEB_MAX'], len(ns['_web_rows']('github')),
          ns['_WEB_MAX'])
    clock.t = base + 300              # 跳出 180 秒窗口(最老一条是 base+10, 已 290 秒)
    check('3 分钟之前的账全部过期，不参与判定', len(ns['_web_rows']('github')), 0)
    check('三个池各记各的：raw 的账不会污染 github',
          (rec('raw', ns['WEB_OK'], 100.0, 1), ns['_web_counts']('github')[0]),
          (True, 0))

    print('---- 3) ① 建连预算：跟着实测走，别在"成功本来就要 13 秒"时按 8 秒切')
    ns = new_ns()
    rec, clock = ns['_web_record'], ns['_CLOCK']
    check('没账 = 老规矩 %.1f 秒' % ns['_CONNECT_DEADLINE'],
          ns['_web_dl_budget']('github'), ns['_CONNECT_DEADLINE'])
    for _ in range(5):
        rec('github', ns['WEB_OK'], 7000.0, 1000)
    check('最近成功中位 7 秒 → 给两倍余量 14 秒',
          ns['_web_dl_budget']('github'), 14.0)
    ns['_WEB_LEDGER'].clear()
    for _ in range(5):
        rec('github', ns['WEB_OK'], 12000.0, 1000)
    check('中位 12 秒也只到上限 %.1f 秒（浏览器不能无限吊着）'
          % ns['_CONNECT_DEADLINE_MAX'], ns['_web_dl_budget']('github'),
          ns['_CONNECT_DEADLINE_MAX'])
    ns['_WEB_LEDGER'].clear()
    for _ in range(2):
        rec('github', ns['WEB_OK'], 15000.0, 1000)
    for _ in range(8):
        rec('github', ns['WEB_REFUSED'], 8000.0, 0)
    check('全灭期(8/10 失败)不把预算抬到 20 秒 —— 那正是拥塞，等越久亏越多',
          ns['_web_dl_budget']('github'), ns['_CONNECT_DEADLINE'])

    print('---- 4) ① 另一半：直连实测已经死了，就不许再把预算押给它')
    ns = new_ns()
    clock = ns['_CLOCK']
    ns['_DIRECT_OK'][0] = False
    ns['_DIRECT_OK'][1] = clock.t - 30
    check('刚探过(30 秒前)且不通 → 判死，不押这一注', ns['_direct_is_dead']('github'), True)
    ns['_DIRECT_OK'][1] = clock.t - 600
    check('探测结果过期(10 分钟前) = 不知道 → 保持老行为去赌一把',
          ns['_direct_is_dead']('github'), False)
    ns['_DIRECT_OK'][0] = True
    ns['_DIRECT_OK'][1] = clock.t - 5
    check('直连通着当然不判死', ns['_direct_is_dead']('github'), False)
    ns['_DIRECT_OK'][0] = None
    check('还没探过也不判死（别拿"没证据"当"有反证"）', ns['_direct_is_dead']('github'), False)

    print('---- 5) ② 断流分账：握手没失败也要降权，满两次才请出池子')
    ns = new_ns()
    clock, note, rank = ns['_CLOCK'], ns['_stall_note'], ns['_stall_rank']
    check('没账时 rank = 0', rank('1.2.3.4'), 0)
    check('第一次断流（半途死，229KB）', note('1.2.3.4', 229000), 1)
    check('rank 记到 1 → 排序就该降权', rank('1.2.3.4'), 1)
    check('第二次断流（正文压根没来）', note('1.2.3.4', 0), 2)
    check('够 _STALL_DROP_POOL 次 → 该请出池子',
          rank('1.2.3.4') >= ns['_STALL_DROP_POOL'], True)
    check('最近一次搬了多少字节（0 = 正文没来）', ns['_stall_bytes']('1.2.3.4'), 0)
    clock.t += ns['_STALL_WINDOW'] + 1
    check('过了 %d 秒窗口账自己过期，不搞"永久拉黑"' % int(ns['_STALL_WINDOW']),
          rank('1.2.3.4'), 0)
    note('9.9.9.9', 100)
    ns['_stall_clear']('9.9.9.9')
    check('_stall_clear 能把账抹掉（只留给手工/重测用）', rank('9.9.9.9'), 0)

    print('---- 6) ②③ _relay 的结局判定：这一层是网页台账唯一的原材料')
    # 正常搬完一页，最后由浏览器那头收尾（读到空 = 对端正常 FIN，不算断流）
    ns, out, up, conn = relay_ns(['up', 'conn'], (b'x' * 50000,))
    check('搬过正文且不是我们等超时 → ok', out['kind'], ns['WEB_OK'])
    check('bytes_up 按真实转出的字节累加', out['bytes_up'], 50000)
    check('first_ms > 0（耗时=建连+首字节，不含 keep-alive 挂着的部分）',
          out['first_ms'] > 0, True)
    check('转出去的字节确实交给了浏览器', len(conn.sent) > 0, True)
    # 连上了、一个字节都不来（"握手通、正文死"那种假活 IP）
    ns, out, up, conn = relay_ns([], ())
    check('一个字节都没搬动 → 记断流，不记 ok', out['kind'], ns['WEB_STALL'])
    check('select 空转超时算 stalled', out['stalled'], True)
    # 搬了一半死掉 —— 本机实测的 229KB / 278KB 那两发就是这个形状
    ns, out, up, conn = relay_ns(['up', 'timeout'], (b'y' * 229000,))
    check('半途断流 → 记断流（而且知道搬了 229000 字节）',
          (out['kind'], out['bytes_up'], out['stalled']),
          (ns['WEB_STALL'], 229000, True))
    # 假前门：上游第一串就是 cleartext 的 4xx / 5xx
    ns, out, up, conn = relay_ns(['up'], (b'HTTP/1.1 400 Bad Request\r\n\r\n' + b'z' * 1400,))
    check('上游回 400 → badgw（2026-10-26 修：以前判的是第三位，400 全漏）',
          out['kind'], ns['WEB_BADGW'])
    check('badgw 也带 up_err 供老逻辑剔除', out['up_err'], True)
    ns, out, up, conn = relay_ns(['up'], (b'HTTP/1.1 503 Slow Down\r\n\r\n' + b'z' * 900,))
    check('上游回 503 → 一样判 badgw', out['kind'], ns['WEB_BADGW'])
    # 浏览器那头先断开（对端 FIN），上游什么都没搬 —— 也是"没打开"
    ns, out, up, conn = relay_ns(['conn'], ())
    check('浏览器断开而正文从未搬动 → 仍记断流（不给假绿灯）', out['kind'], ns['WEB_STALL'])

    print('---- 7) 源码级不变量（改回去要立刻发现）')
    src = open(SRC, encoding='utf-8').read()
    body = src[src.index('    def _connect_pool(self, host, port, pool, key,'):]
    body = body[:body.index('    def _connect(self, host, port):')]
    check('全灭之后先在池里再转几轮，而不是立刻撒手',
          'for _rnd in range(_CONNECT_RETRY_ROUNDS):' in body, True)
    check('轮转里每一手都先看预算（不许拖过用户的耐心）',
          'if self._dl_left() < _CONNECT_RETRY_MIN_LEFT:' in body, True)
    check('轮转之后才轮到"押不押直连"的判断',
          body.index('for _rnd in range(_CONNECT_RETRY_ROUNDS):')
          < body.index('if _direct_is_dead(key):'), True)
    check('押直连那道闸排在真正的兜底连接之前',
          body.index('if _direct_is_dead(key):')
          < body.index('_s3 = socket.create_connection((host, port), timeout=_tmo)'), True)
    check('建连时限改为按实测调（不再写死 _CONNECT_DEADLINE）',
          'self._dl_start(_web_dl_budget(_pool_key_for(host)))' in src, True)
    check('候选排序把两本账一起算（断流 IP 也降权）',
          'rest.sort(key=lambda ip: _fail_rank(ip) + _stall_rank(ip))' in src, True)
    check('_relay 的结局进了网页台账',
          "_web_record(_key, out['kind'], _conn_ms + out['first_ms'], out['bytes_up'])" in src,
          True)
    check('建连失败(502)也进台账 —— 否则"打不开"这一档永远没样本',
          "_web_record(_key, WEB_REFUSED, _conn_ms, 0)" in src, True)
    check('断流不再白记：会请出池子并触发自愈',
          "_hot_drop(_key, used)" in src and "if _n >= _STALL_DROP_POOL:" in src, True)
    check('/api/status 把网页实测端出去了', "'web': {k: _web_status(k)" in src, True)
    check('面板第一格读的是网页实测，不是可用 IP 数',
          'id="stWeb"' in src and src.index('id="stWeb"') < src.index('id="stHosts"'), True)
    check('体检可用数降成明细（面板上还在，但不再是主语）',
          "体检可用 '+strongN" in src, True)
    check('旧的第一格 id=stIp 已经不再留在模板里（JS 找不到会抛异常）',
          'id="stIp"' in src, False)
    check('整份源码语法过', compile_ok(), True)

    print('\n%s  失败 %d 条' % ('全部通过' if not FAILS else '有失败', len(FAILS)))
    return 0 if not FAILS else 1


def compile_ok():
    try:
        compile(open(SRC, encoding='utf-8').read(), SRC, 'exec')
        return True
    except SyntaxError:
        return False


if __name__ == '__main__':
    import sys
    sys.exit(main())
