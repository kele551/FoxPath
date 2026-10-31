# -*- coding: utf-8 -*-
# 作者: 海风（kele551）
"""狐径「本机 git 接管」的单测 —— 全离线：假 git、零真实网络，
而且**绝不碰真实的 ~/.gitconfig**（所有 git 调用都被命名空间里的桩接走了）。
照 tests/test_ip_sources.py 的办法用 ast 只摘需要的常量与函数单独 exec，
不 import github_direct.py（一 import 就绑 8787/8788，会牵连正在用的实例）。

为什么要有这份测试（2026-10-30 参考 FastGithub 之后新增这段功能）：
  · 接管写的是用户机器上的真配置。写坏了、还原漏了，症状就是"狐径一关 git 就断" ——
    这种账不能靠人肉点一遍面板来保证。
  · 本机 2026-10-30 现场：狐径没在跑，而 gitconfig 里五条 http.https://…/.proxy
    还钉在 127.0.0.1:8787（手工设的、没人负责还原）。
  · 端口顺延（同一轮新加的功能）会把"我们的地址"变成 8789 —— 判据必须跟着
    端口集合走，不然残留永远清不掉，还会把一个死端口当"原值"写回去。

覆盖：
  1) 空配置接管：五条键都指过来，备份里原值都记成 None
  2) 幂等：连着接管两次，第二次一条 --replace-all 都不发，也不把自己记成原值
  3) 别人设的代理（本机其它端口 / 外部主机）一律不覆盖、不写备份；混合场景只接管空的
  4) 手工留下的"我们的旧端口"残留：接管后原值记 None，还原是 unset 而不是写回死端口
  5) 还原成功：五条键清空、备份撤掉（全部写回成功才撤）
  6) 还原失败：没做成的那几条留在备份里等下次再试，不许把原值丢了
  7) --restore 无备份：清掉指向狐径端口的残留，别人的代理一条不动
  8) 本机没有 git：明确说明，什么都不写
  9) _is_our_proxy_url / our_proxy_ports 的判据表
  10) 面板那一行的各种口径
  11) 30 秒缓存：轮询不重复起子进程；接管/还原后强制作废
  12) 关开关会顺手还原
  13) 备份文件坏了（非 JSON / 结构不对）也不能把接管带崩
  14) 名单外、值却是"为狐径设的"那几条（api.github.com / gist.github.com / gitlab）：
      值判据接管、还原一起清、--restore 也清；别人的代理与非 GitHub 域一条都不动
  15) 上一轮被强杀留下的键（值=现在的端口、备份丢了）：认领进备份、不重复写、还原清掉

用法：
    python tests\\test_git_takeover.py
"""
import ast
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import types
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SRC = os.path.join(REPO, "github_direct.py")      # 跟着仓库走，换台机器也能跑

WANT_CONSTS = ['PROXY_PORT', 'PROXY_PORT_ALTS', 'GIT_TAKEOVER_DEFAULT',
               'GIT_PROXY_HOSTS', 'GIT_KEY_TMPL', 'GIT_BACKUP_FILE',
               'GIT_FAMILY_SUFFIXES', 'GIT_KEY_REGEXP', 'GIT_KEY_RE',
               '_GIT_LOCK', '_GIT_NOTE', '_GIT_LINE_CACHE', '_GIT_LINE_TTL']
WANT_FUNCS = ['_git_note', 'git_last_note', 'git_takeover_on', 'set_git_takeover',
              'git_target_url', 'our_proxy_ports', '_is_our_proxy_url',
              '_git_key_values', '_git_managed_keys', '_github_family',
              '_git_residue_keys', '_git_backup_read', '_git_backup_write',
              '_git_backup_drop', '_remember_git_backup', '_claim_git_key',
              'git_takeover',
              'git_release', 'git_status_line', 'git_status_line_cached',
              'proxy_port']

FAILS = []
TMPS = []


def check(name, got, want):
    if got == want:
        print('[ok] %s' % name)
    else:
        print('[X ] %s  得到=%r 应为=%r' % (name, got, want))
        FAILS.append(name)


class FakeGit(object):
    """假 git：把 `git --no-pager config --global …` 模拟成一个小字典。

    真实实现里 rc!=0 就是"这条键没设过"，`--unset-all` 对不存在的键返回 5 ——
    这两条语义桩里必须照做，否则测试通过、线上却是另一种行为。
    """

    def __init__(self, cfg=None, have=True, fail=()):
        self.cfg = dict(cfg or {})
        self.have = have
        self.fail = set(fail)          # {('--unset-all', 键), ...}
        self.get_err = None            # 设成 (rc, 输出) 就模拟"git 答不上来"
        self.calls = []

    def run(self, args, timeout=8.0):
        args = list(args)
        self.calls.append(args)
        if not self.have:
            return None, ''            # 真实现：PATH 里找不到 git 就返回 (None, '')
        op, key = args[0], args[1]
        if (op, key) in self.fail:
            return 1, '桩里这条被设成失败'
        if op == '--get':
            if self.get_err:
                return self.get_err
            v = self.cfg.get(key)
            return (0, v) if v else (1, '')
        if op == '--replace-all':
            self.cfg[key] = args[2]
            return 0, ''
        if op == '--get-regexp':
            # 真 git 的口径：命中 0 条、命中 1 条、什么都没有都是 rc=1（上面实测过）。
            # 输出是"键 值"一行一条，键按写进去的原样打印。
            pat = re.compile(key)
            rows = ['%s %s' % (k, v) for k, v in self.cfg.items()
                    if pat.match(k) and v]
            return (0, '\n'.join(rows)) if rows else (1, '')
        if op == '--unset-all':
            if key not in self.cfg:
                return 5, ''
            del self.cfg[key]
            return 0, ''
        raise AssertionError('没想到的 git 调用: %r' % (args,))

    def writes(self):
        return [c for c in self.calls if c[0] not in ('--get', '--get-regexp')]

    def resets(self):
        self.calls = []


def load(git, port=8787, settings=None):
    """把需要的常量与函数摘进一个干净命名空间，接管/还原就在这个假环境里跑。"""
    tree = ast.parse(open(SRC, encoding='utf-8').read())
    tmp = tempfile.mkdtemp(prefix='foxpath-git-test-')
    TMPS.append(tmp)
    ns = {
        'os': os, 'json': json, 'time': time, 'threading': threading, 're': re,
        'urllib': types.SimpleNamespace(parse=urllib.parse),
        'DATA_DIR': tmp,
        'SETTINGS': dict(settings if settings is not None else {'git_takeover': True}),
        'SETTINGS_LOCK': threading.Lock(),
        'save_settings': (lambda: True),
        'logs': [],
        '_PROXY_PORT': [port],          # 本次测试假装在听的端口
        '_run_git': git.run,            # ★ 全部 git 调用都走桩，不起真进程
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


def key_of(ns, host):
    return ns['GIT_KEY_TMPL'] % host


def all_keys(ns):
    return [key_of(ns, h) for h in ns['GIT_PROXY_HOSTS']]


def backup_of(ns):
    p = ns['GIT_BACKUP_FILE']
    if not os.path.exists(p):
        return None
    with open(p, encoding='utf-8') as f:
        return json.load(f)


def main():
    # ── 1) 空配置接管 ────────────────────────────────────────────────────
    g = FakeGit({})
    ns = load(g)
    keys = all_keys(ns)
    check('接管前键都是空的', g.cfg, {})
    check('接管结论', ns['git_takeover'](),
          'git 已接管 %d 条键(指向 http://127.0.0.1:8787)' % len(keys))
    check('五条键都指过来', sorted(g.cfg.values()),
          ['http://127.0.0.1:8787'] * len(keys))
    bk = backup_of(ns)
    check('备份记了几条', len(bk['keys']), len(keys))
    check('空配置的原值都记成 None', sorted(set(bk['keys'].values()), key=str), [None])
    check('备份里带上当时的端口', bk.get('port'), 8787)

    # ── 2) 幂等：第二次不许再写，也不许把自己当原值 ──────────────────────
    g.resets()
    check('第二次接管结论', ns['git_takeover'](), 'git 本来就指着本机代理, 本次没有改动')
    check('第二次一条都没写', len(g.writes()), 0)
    check('备份没有被改坏', backup_of(ns)['keys'], bk['keys'])

    # ── 3) 别人设的代理一律不覆盖 ────────────────────────────────────────
    other = {}
    for i, h in enumerate(ns['GIT_PROXY_HOSTS']):
        other[key_of(ns, h)] = ('http://127.0.0.1:%d' % (7890 + i)
                                if i % 2 == 0 else 'http://proxy.corp:8080')
    g = FakeGit(dict(other))
    ns = load(g)
    check('全被别人设着时不接管', ns['git_takeover'](),
          '没有接管: git 里这几条键是别的东西设的代理, 狐径不覆盖')
    check('五条都保持原样', g.cfg, other)
    check('不覆盖时不写备份', backup_of(ns), None)
    check('五条一条都没写过', len(g.writes()), 0)

    # ── 3c) 读不出 git 配置（超时/被锁）时宁可不干 ───────────────────────
    g = FakeGit({key_of(ns, 'github.com'): 'http://127.0.0.1:7890'})
    g.get_err = (-1, 'TimeoutExpired: git 卡住了')
    ns = load(g)
    why = '读不到 git 配置(rc=-1 TimeoutExpired: git 卡住了) —— 这一轮不动 git'
    check('读不出配置时不接管', ns['git_takeover'](), why)
    check('读不出时一条都不写', len(g.writes()), 0)
    check('读不出时不建备份', backup_of(ns), None)
    check('读不出时那行状态', ns['git_status_line'](), why)
    check('读不出时缓存那行也是同一句', ns['git_status_line_cached'](), why)

    # ── 3b) 混合：一条别人的 + 四条空的 ─────────────────────────────────
    g = FakeGit({key_of(ns, 'github.com'): 'http://127.0.0.1:7890'})
    ns = load(g)
    check('混合场景接管剩下 4 条', ns['git_takeover'](),
          'git 已接管 4 条键(指向 http://127.0.0.1:8787)')
    check('别人的那条没动', g.cfg[key_of(ns, 'github.com')], 'http://127.0.0.1:7890')
    check('混合场景备份不含别人的键', key_of(ns, 'github.com') in backup_of(ns)['keys'], False)
    check('混合场景还原', ns['git_release'](), 'git 配置已还原 4 条')
    check('还原后只剩别人那条', g.cfg, {key_of(ns, 'github.com'): 'http://127.0.0.1:7890'})

    # ── 4) 手工留下的旧端口残留（顺延后的世界）──────────────────────────
    g = FakeGit({key_of(ns, h): 'http://127.0.0.1:8787'
                 for h in ('github.com', 'raw.githubusercontent.com')})
    ns = load(g, port=8789)                       # 本次实际听 8789
    check('git_target_url 跟着端口走', ns['git_target_url'](), 'http://127.0.0.1:8789')
    check('残留也接管(五条全指过来)', ns['git_takeover'](),
          'git 已接管 5 条键(指向 http://127.0.0.1:8789)')
    check('两条残留也带回现在的端口',
          [g.cfg[key_of(ns, h)] for h in ('github.com', 'raw.githubusercontent.com')],
          ['http://127.0.0.1:8789'] * 2)
    check('死端口不当成原值存', set(backup_of(ns)['keys'].values()), {None})
    check('还原是清空而不是写回死端口', ns['git_release'](), 'git 配置已还原 5 条')
    check('cfg 里已无残留', g.cfg, {})

    # ── 5+6) 还原：成功就撤备份，失败就把原值留着 ───────────────────────
    g = FakeGit({}, fail=[('--unset-all', key_of(ns, 'uploads.github.com'))])
    ns = load(g)
    ns['git_takeover']()
    check('接管后确有 5 条', len(g.cfg), 5)
    check('有一条还原失败时的话', ns['git_release'](),
          'git 已还原 4 条, 另有 1 条没做成(原值仍留着, 下次退出或 --restore 再试)')
    check('没做成的那条留在备份里', list(backup_of(ns)['keys'].keys()),
          [key_of(ns, 'uploads.github.com')])
    check('钉着的键还在 git 里', g.cfg[key_of(ns, 'uploads.github.com')],
          'http://127.0.0.1:8787')
    g.fail.clear()
    check('下一次退出把它补还原掉', ns['git_release'](), 'git 配置已还原 1 条')
    check('全还原成才撤备份', backup_of(ns), None)
    check('git 里彻底干净', g.cfg, {})

    # ── 7) --restore 无备份：只清我们端口的残留 ──────────────────────────
    g = FakeGit({key_of(ns, 'github.com'): 'http://127.0.0.1:8787',
                 key_of(ns, 'codeload.github.com'): 'http://127.0.0.1:28787',
                 key_of(ns, 'raw.githubusercontent.com'): 'http://127.0.0.1:7890'})
    ns = load(g, port=8789)                       # 新实例：没有备份文件
    check('平时的还原不动任何东西', ns['git_release'](), '')
    check('平时的还原不碰外部端口残留', g.cfg[key_of(ns, 'github.com')],
          'http://127.0.0.1:8787')
    check('--restore 清掉两条残留', ns['git_release'](clean_orphan=True),
          '--restore: 顺手清掉 2 条指向本程序的 git 残留键')
    check('顺延前的 8787 也算我们的', g.cfg.get(key_of(ns, 'github.com')), None)
    check('别人的 7890 一条不动', g.cfg.get(key_of(ns, 'raw.githubusercontent.com')),
          'http://127.0.0.1:7890')
    check('--restore 第二次没有残留可清', ns['git_release'](clean_orphan=True),
          '--restore: git 配置里没有本程序留下的残留')

    # ── 8) 本机没有 git ──────────────────────────────────────────────────
    g = FakeGit({}, have=False)
    ns = load(g)
    check('没有 git 时明说', ns['git_takeover'](), '本机 PATH 里没有 git, 没有接管')
    check('没有 git 也不写备份', backup_of(ns), None)
    check('没有 git 时还原无事可做', ns['git_release'](), '')
    check('没有 git 那行状态', ns['git_status_line'](), '本机没找到 git —— 没有接管')

    # ── 9) 判据表 ───────────────────────────────────────────────────────
    ns = load(FakeGit({}), port=8789)
    for v, want in (('http://127.0.0.1:8789', True), ('http://127.0.0.1:8787', True),
                    ('http://127.0.0.1:28787', True), ('http://localhost:8787', True),
                    ('http://127.0.0.1:7890', False), ('http://proxy.corp:8080', False),
                    ('', False), ('not a url', False), ('http://127.0.0.1', False)):
        check('_is_our_proxy_url(%r)' % v, ns['_is_our_proxy_url'](v), want)
    check('端口集合含首选与全部备选', sorted(ns['our_proxy_ports']()),
          [8787, 8789, 8797, 8897, 18787, 28787])

    # ── 10) 面板那一行 ──────────────────────────────────────────────────
    g = FakeGit({})
    ns = load(g)
    check('接管前那行', ns['git_status_line'](), 'git 未接管(这几条键现在都是空的)')
    ns['git_takeover']()
    check('接管后那行', ns['git_status_line'](),
          'git 已全部接管(5/5 指向 http://127.0.0.1:8787)')
    check('最近一次结论也留着', ns['git_last_note'](),
          'git 已接管 5 条键(指向 http://127.0.0.1:8787)')
    g.cfg[key_of(ns, 'github.com')] = 'http://127.0.0.1:7890'
    check('部分接管那行', ns['git_status_line'](),
          'git 部分接管(4/5 指向 http://127.0.0.1:8787, 另有 1 条是别的代理)')
    g.cfg = {k: 'http://127.0.0.1:8787' for k in all_keys(ns)}
    ns['_PROXY_PORT'][0] = 8789
    check('指着旧端口那行', ns['git_status_line'](),
          'git 指着狐径的旧端口(5 条) —— 点「启用加速」会带回现在的端口')
    ns['_PROXY_PORT'][0] = 8787
    g.cfg = {}
    ns['SETTINGS']['git_takeover'] = False
    check('开关关闭那行', ns['git_status_line'](), 'git 接管已关闭(设置里可打开)')

    # ── 11) 30 秒缓存：面板轮询不许反复起子进程 ─────────────────────────
    ns['SETTINGS']['git_takeover'] = True
    g.resets()
    line1 = ns['git_status_line_cached']()
    line2 = ns['git_status_line_cached']()
    line3 = ns['git_status_line_cached']()
    check('缓存命中时行内容一致', (line1, line2, line3), (line1,) * 3)
    check('三次读只起 6 个子进程(5 条键 + 1 次 --get-regexp)', len(g.calls), 6)
    ns['_GIT_LINE_CACHE'][1] = time.time() - 31.0        # 假装过了 31 秒
    ns['git_status_line_cached']()
    check('过期后重新现读', len(g.calls), 12)
    ns['git_takeover']()
    n = len(g.calls)
    check('接管后读到的是新状态', ns['git_status_line_cached'](),
          'git 已全部接管(5/5 指向 http://127.0.0.1:8787)')
    check('接管确实让缓存作废了', len(g.calls) > n, True)

    # ── 12) 关开关会顺手还原 ────────────────────────────────────────────
    ok, msg = ns['set_git_takeover'](False)
    check('关开关返回 ok', ok, True)
    check('关开关的话', msg, '已关闭 git 接管')
    check('关开关把键还原干净', g.cfg, {})
    check('关开关撤掉备份', backup_of(ns), None)
    check('设置里落的是 False', ns['SETTINGS']['git_takeover'], False)
    check('关开关后那行', ns['git_status_line'](), 'git 接管已关闭(设置里可打开)')
    check('再打开的话', ns['set_git_takeover'](True)[1],
          '已开启 git 接管: 下次启用加速会把本机 git 的 GitHub 流量一起指过来')
    check('光打开不写 git(等启用加速)', g.cfg, {})

    # ── 13) 备份文件坏了也不能崩 ────────────────────────────────────────
    with open(ns['GIT_BACKUP_FILE'], 'w', encoding='utf-8') as f:
        f.write('{ 这不是 json')
    check('坏备份读成 None', ns['_git_backup_read'](), None)
    check('坏备份下接管照常', ns['git_takeover'](),
          'git 已接管 5 条键(指向 http://127.0.0.1:8787)')
    with open(ns['GIT_BACKUP_FILE'], 'w', encoding='utf-8') as f:
        json.dump({'keys': '不是 dict'}, f)
    check('结构不对也读成 None', ns['_git_backup_read'](), None)
    check('结构不对时还原不装样子', ns['git_release'](), '')

    # ── 14) 名单外、但值是"为狐径设的"那几条（api.github.com / gist.github.com）──
    # 本机 2026-10-30 真机实测抓出来的洞：这两条是用户手工设的，值钉在 127.0.0.1:8787。
    # 老写法只在名单内动手 → 端口一顺延它们就指着别的东西，程序一删它们就指着死端口，
    # 而现在这套会把它们带上、还原时一起清掉（判据是**值**，不是域名名单）。
    APIK = 'http.https://api.github.com/.proxy'
    GISTK = 'http.https://gist.github.com/.proxy'
    GITLABK = 'http.https://gitlab.com/.proxy'
    g = FakeGit({key_of(ns, 'github.com'): 'http://127.0.0.1:8789',
                 APIK: 'http://127.0.0.1:8787',
                 GISTK: 'http://127.0.0.1:7890',
                 GITLABK: 'http://127.0.0.1:8787'})
    ns = load(g, port=8789)
    check('_git_residue_keys 只认 GitHub 一家且值是狐径端口的',
          ns['_git_residue_keys'](), {APIK: 'http://127.0.0.1:8787'})
    check('名单外的手工键也一起指过来(4 条空的 + 1 条手工的)', ns['git_takeover'](),
          'git 已接管 5 条键(指向 http://127.0.0.1:8789)，含 1 条手工设的'
          '，另认领 1 条本来就指着本机的')
    check('手工设的那条带回现在的端口', g.cfg[APIK], 'http://127.0.0.1:8789')
    check('别人的 7890 不覆盖', g.cfg[GISTK], 'http://127.0.0.1:7890')
    check('gitlab 那条一个字节不动', g.cfg[GITLABK], 'http://127.0.0.1:8787')
    check('手工那条也进了备份(原值 None)', backup_of(ns)['keys'][APIK], None)
    check('本来就指着我们的那条也被认领(不留成没人负责的键)',
          backup_of(ns)['keys'][key_of(ns, 'github.com')], None)
    check('那行状态如实说明带了几条', ns['git_status_line'](),
          'git 已全部接管(5/5 指向 http://127.0.0.1:8789)，另带 1 条手工设的')
    check('还原把手工那条与认领那条一起清掉', ns['git_release'](), 'git 配置已还原 6 条')
    check('还原后只剩别人设的两条', g.cfg, {GISTK: 'http://127.0.0.1:7890',
                                       GITLABK: 'http://127.0.0.1:8787'})
    check('撤掉了备份', backup_of(ns), None)
    # 端口顺延后还没接管的那一段：面板要如实说"有几条指着老端口"，别让人以为一切正常
    g = FakeGit({APIK: 'http://127.0.0.1:8787'})
    ns = load(g, port=8789)
    check('顺延后未接管时那行会点数', ns['git_status_line'](),
          'git 指着狐径的旧端口(1 条) —— 点「启用加速」会带回现在的端口')
    # --restore 自救时也要能把手工键清掉（这是它存在的唯一理由）
    check('--restore 把手工键一起清', ns['git_release'](clean_orphan=True),
          '--restore: 顺手清掉 1 条指向本程序的 git 残留键')
    check('--restore 后 cfg 干净', g.cfg, {})
    # --get-regexp 一条都没命中(rc=1)时不许凭空多出几条手工键
    g = FakeGit({APIK: 'http://127.0.0.1:8787'})
    ns = load(g, port=8789)
    ns['_run_git'] = (lambda args, timeout=8.0: (0, '') if args[0] == '--get'
                      else (1, '') if args[0] == '--get-regexp' else (0, ''))
    check('--get-regexp 空表时不接管任何手工键', ns['_git_residue_keys'](), {})

    # ── 15) 上一轮被强杀留下的键（值就是现在的端口、备份却没了）────────────
    # 这条正是"跳过 = 没人负责还原"的那个洞：程序退出后 git 继续钉在死端口上。
    g = FakeGit({k: 'http://127.0.0.1:8787' for k in all_keys(ns)})
    ns = load(g, port=8787)
    check('认领话术', ns['git_takeover'](),
          'git 本来就指着本机代理, 另认领 5 条(停用并还原时会一起清掉)')
    check('认领不产生任何 git 写入', len(g.writes()), 0)
    check('认领都进了备份', len(backup_of(ns)['keys']), 5)
    g.resets()
    check('第二次什么都不做', ns['git_takeover'](), 'git 本来就指着本机代理, 本次没有改动')
    check('第二次不重复记账', len(backup_of(ns)['keys']), 5)
    check('停用还原把这五条都清掉', ns['git_release'](), 'git 配置已还原 5 条')
    check('还原后 git 干净', g.cfg, {})
    check('还原后撤备份', backup_of(ns), None)

    # ── 16) 本机装机的真实形状：一部分要写、一部分本来就指着我们 ──────────
    # 2026-10-30 装机首启实测：源配置里 github/raw/objects/api/gist 已经是 8787，
    # 只有 codeload/uploads 空着 —— 结论若只报"接管 2 条"，用户数了数 git 里有 7 条
    # 会以为没管全。认领数必须一起报。
    seeded = {k: 'http://127.0.0.1:8787' for k in all_keys(ns)}
    del seeded[key_of(ns, 'codeload.github.com')]
    del seeded[key_of(ns, 'uploads.github.com')]
    seeded[APIK] = 'http://127.0.0.1:8787'
    g = FakeGit(dict(seeded))
    ns = load(g, port=8787)
    check('装机形状的结论把认领也报出来', ns['git_takeover'](),
          'git 已接管 2 条键(指向 http://127.0.0.1:8787)，另认领 4 条本来就指着本机的')
    check('六条全指着本机', sorted(set(g.cfg.values())), ['http://127.0.0.1:8787'])
    check('六条都进了备份(还原有人负责)', len(backup_of(ns)['keys']), 6)

    for t in TMPS:
        shutil.rmtree(t, ignore_errors=True)
    print('')
    if FAILS:
        print('失败 %d 条: %s' % (len(FAILS), ', '.join(FAILS)))
        return 1
    print('全部通过')
    return 0


if __name__ == '__main__':
    sys.exit(main())
