# -*- coding: utf-8 -*-
# 作者: 海风（kele551）
"""狐径 2026-10-26 接管清单与官方 IP 表回落的单测 —— 全离线：假 urlopen，一秒真实网络都不碰，
也不 import 整个 github_direct.py（一 import 就绑 8787/8788，会牵连正在用的实例），
照 tests/test_boot_state.py 的办法用 ast 只摘需要的常量与函数单独 exec。

为什么要有这份测试（都是当天实测撞出来的）：
  · 传发布附件用的 uploads.github.com 以前**不在** PROXY_HOSTS 里，浏览器一律直连 ——
    于是"页面能开、传附件却撞运气"。v1.2.3 发版当天取自己刚上传的附件字节都费劲，
    最后只能改走 api.github.com 的 assets 口。
  · fetch_official_ips 的注释一直写着"三个源"，代码里其实只有两个；而那两个
    （api.github.com 与 raw.githubusercontent.com）走的是**同一条国际链路**：
    第一个断了，第二个多半一起断 —— 国内线路的用户等于没有兜底，
    表现就是"同步成功却一个 IP 都不通"以外另一种：始终只有内置那十几个旧地址。

覆盖：
  1) uploads.github.com 进了 PROXY_HOSTS，因此自动进 PAC 与面板"接管域名"计数
  2) api.github.com / gist.github.com 仍然**不在**清单里（候选池全是 web 段，拿它连 api 是错的）
  3) uploads.github.com 归 github.com 那一池（is_github_host 认、is_raw_host 不认）
  4) 官方 IP 表的源顺序 = 官方 → GitCode → GitHub raw；且清单里不许出现已停更的老仓库地址
  5) api.github.com 挂 → 从 GitCode 取到地址，_META_SOURCE 记成 GitCode
  6) GitCode 返回 200 但解析不出地址 → 继续往下一个源（审查 M-2 那条判据不许退回去）
  7) 三个源全挂 → 退回内置表，且不许谎报"已同步官方 IP 表"

用法：
    python tests\\test_ip_sources.py
"""
import ast
import ipaddress
import json
import os
import types

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SRC = os.path.join(REPO, "github_direct.py")      # 跟着仓库走，换台机器也能跑

WANT_CONSTS = ['PROXY_HOSTS', 'PROXY_HOSTS_RAW', 'GITHUB_IO_SUFFIX',
               'PAC_HOSTS', '_PAC_HOSTS_JS', 'PAC_TEMPLATE']
WANT_FUNCS = ['is_raw_host', 'is_github_host', 'is_pages_host', '_valid_ip', 'fetch_official_ips']

FAILS = []


def check(name, got, want):
    if got == want:
        print('[ok] %s' % name)
    else:
        print('[X ] %s  得到=%r 应为=%r' % (name, got, want))
        FAILS.append(name)


class FakeTime(object):
    def time(self):
        return 1700000000.0

    def sleep(self, s):
        pass


def make_urllib(routes):
    """假网络：routes = {url: bytes | Exception}。没登记的就当连接被掐。"""

    class Resp(object):
        def __init__(self, blob):
            self._blob = blob

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return self._blob

    def urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, 'full_url') else req
        r = routes.get(url, ConnectionError('没登记这条 url'))
        if isinstance(r, Exception):
            raise r
        return Resp(r)

    def Request(url, headers=None):
        return types.SimpleNamespace(full_url=url, headers=headers or {})

    return types.SimpleNamespace(
        request=types.SimpleNamespace(Request=Request, urlopen=urlopen))


def load(routes, meta_source=None):
    """把需要的常量与函数摘进一个干净命名空间，fetch_official_ips 就在这个假环境里跑。"""
    tree = ast.parse(open(SRC, encoding='utf-8').read())
    ns = {
        'urllib': make_urllib(routes),
        'json': json,
        'ipaddress': ipaddress,
        'time': FakeTime(),
        'logs': [],
        'log': (lambda m, *a, **k: ns['logs'].append(m)),
        'CANDIDATE_IPS': ['140.82.112.3', '20.205.243.166'],      # 内置表（离线固定两份小样）
        'CANDIDATE_IPS_V6': [],
        'CANDIDATES': ['140.82.112.3', '20.205.243.166'],
        '_META_SOURCE': meta_source if meta_source is not None else [''],
        '_last_meta_ok': [0.0],
    }
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


API_META = 'https://api.github.com/meta'
GITCODE = 'https://gitcode.com/api/v5/repos/kele551/FoxPath/raw/meta.json?ref=main'
GH_RAW = 'https://raw.githubusercontent.com/kele551/FoxPath/main/meta.json'

GOOD = json.dumps({'ips': ['203.0.113.10'], 'web': ['198.51.100.0/24'], 'web6': ['2001:db8::1'],
                   'note': '测试用的假地址（TEST-NET）'}).encode()
EMPTY = json.dumps({'ips': [], 'web': [], 'web6': []}).encode()


def source_urls():
    """从 fetch_official_ips 的函数体里把 urls 元组摘出来（不跑它，也就一秒网络都不碰）。"""
    tree = ast.parse(open(SRC, encoding='utf-8').read())
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == 'fetch_official_ips':
            for sub in ast.walk(node):
                if isinstance(sub, ast.Assign) and \
                        any(isinstance(t, ast.Name) and t.id == 'urls' for t in sub.targets):
                    return [e.value for e in sub.value.elts if isinstance(e, ast.Constant)]
    return []


def main():
    ns = load({API_META: GOOD, GITCODE: GOOD, GH_RAW: GOOD})

    # 1) uploads.github.com 进清单，并且一路传到 PAC
    check('PROXY_HOSTS 里有 uploads.github.com',
          'uploads.github.com' in ns['PROXY_HOSTS'], True)
    check('PAC_HOSTS 里有 uploads.github.com',
          'uploads.github.com' in ns['PAC_HOSTS'], True)
    check('PAC 脚本里判定到了 uploads.github.com',
          'host === "uploads.github.com"' in ns['_PAC_HOSTS_JS'], True)

    # 2) 老陷阱：api / gist 不许被收进来（候选池全是 web 段）
    for h in ('api.github.com', 'gist.github.com'):
        check('%s 不在接管清单里' % h, h in ns['PAC_HOSTS'], False)

    # 3) 归池正确：uploads 走 github.com 池，不是 raw 池
    check('is_github_host(uploads.github.com)', ns['is_github_host']('uploads.github.com'), True)
    check('is_raw_host(uploads.github.com)', ns['is_raw_host']('uploads.github.com'), False)
    check('is_github_host 认大小写与端口',
          ns['is_github_host']('Uploads.GitHub.com:443'), True)

    # 4) 官方 IP 表的源顺序与地址卫生（按 ast 取 urls 元组，注释怎么改都不影响判据）
    urls = source_urls()
    check('fetch_official_ips 的源顺序', urls, [API_META, GITCODE, GH_RAW])
    # 关键字拆开拼：不然"禁止清单"自己会被扫成命中
    dead = 'gitee' + '.com/kele551'
    check('三个源里没有已停更的老仓库地址', any(dead in u for u in urls), False)

    # 5) api.github.com 挂掉 → GitCode 顶上，记账口径跟着换
    ns = load({API_META: OSError(10060, 'timed out'), GITCODE: GOOD, GH_RAW: GOOD})
    out = ns['fetch_official_ips']()
    check('GitCode 的 ips 进了候选', '203.0.113.10' in out, True)
    check('GitCode 的 web 段也展开进了候选', '198.51.100.1' in out, True)
    check('同步源记成 GitCode', ns['_META_SOURCE'][0], 'GitCode')
    check('日志里说的就是 GitCode',
          any('已同步官方 IP 表(GitCode)' in l for l in ns['logs']), True)

    # 6) GitCode 返回 200 但解析不出地址 → 继续下一个源（不许就此宣布成功）
    ns = load({API_META: OSError(10060, 'timed out'), GITCODE: EMPTY, GH_RAW: GOOD})
    out = ns['fetch_official_ips']()
    check('空表会换下一个源', ns['_META_SOURCE'][0], 'GitHub')
    check('空表当场要说清', any('返回成功但没有 IP' in l for l in ns['logs']), True)

    # 7) 三个源全挂 → 内置表，且不许谎报
    ns = load({API_META: OSError(10060, 'timed out'),
               GITCODE: ConnectionError('断了'), GH_RAW: OSError(10060, 'timed out')})
    out = ns['fetch_official_ips']()
    check('全挂时仍有内置候选', out[:2], ['140.82.112.3', '20.205.243.166'])
    check('全挂时不写"已同步"', ns['_META_SOURCE'][0], '')
    check('全挂时日志是失败口径', any('同步官方 IP 表失败' in l for l in ns['logs']), True)

    print('\n%s' % ('全部通过' if not FAILS else '失败 %d 项: %s' % (len(FAILS), FAILS)))
    return 1 if FAILS else 0


if __name__ == '__main__':
    raise SystemExit(main())
