# -*- coding: utf-8 -*-
# 作者: 海风（kele551）
"""狐径「代理端口自动顺延」的单测 —— 全离线：假 socket、假 server，
一个真实端口都不碰、也不 import github_direct.py（一 import 就绑 8787/8788）。
照 tests/test_boot_state.py 的办法用 ast 只摘需要的常量与函数单独 exec。

为什么要有这份测试（2026-10-30 参考 FastGithub 的端口策略之后新增）：
  · 以前 8787 被别的程序占着就直接弹错误框退出 —— 对用户等于"这软件不能和别的东西共存"。
  · 顺延最容易写错的两件事都在这里卡着：
      ① Windows 的 SO_REUSEADDR 允许 bind 到**别人正在听**的端口而不报错，
        所以必须先连一把（_port_is_live）再谈绑定，否则"看着起来了"其实端口是别人的；
      ② 顺延之后 PAC、git 接管、running.json、面板、反馈包都要跟着改口，
        漏一个就是"加速看着开着、一个字节都没转发"。

覆盖：
  1) 首选端口空闲 → 就用 8787，proxy_port() 写定
  2) 8787 上有东西在听 → 顺延到下一个候选，且**不是靠 bind 报错**发现的
  3) 前几个都有人听 → 依次往后走
  4) bind 真失败（端口被系统保留那段占了）→ 也照样顺延
  5) 全都占着 → 返回 (None, 最后一个错)，且不许把 _PROXY_PORT 写成错的端口
  6) PAC 模板里没有写死的 8787（端口是传进去的），面板/注册表口径都走 proxy_port()

用法：
    python tests\\test_proxy_port_fallback.py
"""
import ast
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SRC = os.path.join(REPO, "github_direct.py")      # 跟着仓库走，换台机器也能跑

WANT_CONSTS = ['PROXY_PORT', 'PANEL_PORT', 'PROXY_PORT_ALTS',
               'PROXY_HOSTS', 'PROXY_HOSTS_RAW', 'GITHUB_IO_SUFFIX',
               'PAC_HOSTS', '_PAC_HOSTS_JS', 'PAC_TEMPLATE']
WANT_FUNCS = ['proxy_port', '_port_is_live', '_bind_proxy_server']

FAILS = []


def check(name, got, want):
    if got == want:
        print('[ok] %s' % name)
    else:
        print('[X ] %s  得到=%r 应为=%r' % (name, got, want))
        FAILS.append(name)


class World(object):
    """假的本机：busy = 已经有别人在听的端口；refuse = bind 会被拒的端口。"""

    def __init__(self, busy=(), refuse=()):
        self.busy = set(busy)
        self.refuse = set(refuse)
        self.bound = []
        self.connects = []

    def make_socket(self, *a, **k):
        return FakeSock(self)

    def make_server(self, addr, handler):
        port = addr[1]
        if port in self.refuse:
            raise OSError(10048, 'bind 被拒(系统保留段)')
        self.bound.append(port)
        return types.SimpleNamespace(serve_forever=lambda: None,
                                     shutdown=lambda: None)


class FakeSock(object):
    def __init__(self, world):
        self.world = world

    def settimeout(self, t):
        pass

    def connect_ex(self, addr):
        port = addr[1]
        self.world.connects.append(port)
        return 0 if port in self.world.busy else 10053

    def close(self):
        pass


def load(world, start_port=8787):
    tree = ast.parse(open(SRC, encoding='utf-8').read())
    ns = {
        'socket': types.SimpleNamespace(socket=world.make_socket,
                                        AF_INET=2, SOCK_STREAM=1,
                                        error=OSError),
        'ProxyServer': world.make_server,
        'ProxyHandler': object,
        'threading': __import__('threading'),
        '_PROXY_PORT': [start_port],
        'logs': [],
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


def main():
    # ── 1) 首选端口空闲 ──────────────────────────────────────────────────
    w = World()
    ns = load(w)
    srv, port = ns['_bind_proxy_server']()
    check('空闲时用首选端口', port, 8787)
    check('确实绑定了', w.bound, [8787])
    check('proxy_port 写定', ns['proxy_port'](), 8787)
    check('先探过端口再绑', w.connects[:1], [8787])

    # ── 2) 8787 上有东西在听 → 顺延（靠 connect 发现，不靠 bind 报错）──────
    w = World(busy=[8787])
    ns = load(w)
    srv, port = ns['_bind_proxy_server']()
    check('被占就顺延到下一个候选', port, 8789)
    check('只绑了一个端口', w.bound, [8789])
    check('proxy_port 跟着改口', ns['proxy_port'](), 8789)
    check('发现占用用的是连一把', 8787 in w.connects, True)

    # ── 3) 前三个都有人听 ────────────────────────────────────────────────
    w = World(busy=[8787, 8789, 8797])
    ns = load(w)
    srv, port = ns['_bind_proxy_server']()
    check('依次往后走', port, 8897)
    check('绑定的就是它', w.bound, [8897])

    # ── 4) bind 真失败（系统保留段）──────────────────────────────────────
    w = World(refuse=[8787])
    ns = load(w)
    srv, port = ns['_bind_proxy_server']()
    check('bind 被拒也顺延', port, 8789)
    check('没绑上第一次', w.bound, [8789])

    # ── 5) 全占着：不许把 _PROXY_PORT 写坏 ───────────────────────────────
    allp = [8787, 8789, 8797, 8897, 18787, 28787]
    w = World(busy=allp)
    ns = load(w, start_port=8787)
    srv, err = ns['_bind_proxy_server']()
    check('全占用时返回没有 server', srv, None)
    check('最后一个错是端口占用', isinstance(err, OSError), True)
    check('一个端口都没绑', w.bound, [])
    check('proxy_port 不许被写坏', ns['proxy_port'](), 8787)

    w = World(busy=[8787], refuse=[8789, 8797, 8897, 18787, 28787])
    ns = load(w)
    srv, err = ns['_bind_proxy_server']()
    check('占用+bind 失败混合时也老实返回 None', srv, None)

    # ── 6) 端口口径只有一个：proxy_port()，没有写死的 8787 ───────────────
    w = World(busy=[8787])
    ns = load(w)
    ns['_bind_proxy_server']()
    pac = ns['PAC_TEMPLATE'] % ns['proxy_port']()
    check('PAC 里写的是顺延后的端口', '127.0.0.1:8789' in pac, True)
    check('PAC 里不许有写死的 8787', '127.0.0.1:8787' in pac, False)
    src = open(SRC, encoding='utf-8').read()
    for name in ('PAC_TEMPLATE % PROXY_PORT', "'http://127.0.0.1:8787'",
                 '"http://127.0.0.1:8787"'):
        check('源码里不残留写死端口: %s' % name, name in src, False)
    check('PAC 模板本身是纯 ASCII', isinstance(pac.encode('ascii'), bytes), True)

    print('')
    if FAILS:
        print('失败 %d 条: %s' % (len(FAILS), ', '.join(FAILS)))
        return 1
    print('全部通过')
    return 0


if __name__ == '__main__':
    sys.exit(main())
