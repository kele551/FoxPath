# -*- coding: utf-8 -*-
# 作者: 海风（kele551）
"""狐径 2026-10-31：冷启动缓存（消除"每次发新版网页打不开"）。

根因：每次自动升级重启 exe 后，IP 候选池要从零探测约 1-2 分钟才填满，这期间系统代理
已开却几乎无可用线路，用户一访问 GitHub 就选不到好 IP —— 体感"新版打不开"。
修复：把最近一次体检结果存盘，启动先 load 旧缓存即满池，后台复测再刷新。

本测试只验证缓存的序列化与存取逻辑（export/import 往返、save/load 文件往返、
以及文件缺失 / schema 不符 / 过旧 / 损坏 JSON 四类异常都静默不崩、不动现有池）。
一秒真实网络都不碰、不绑端口、不污染真实缓存（HEALTH_CACHE 被指向临时文件）。

用法：
    python tests\\test_health_cache.py
"""
import os
import sys
import json
import time
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
import github_direct as G

fails = []


def check(name, cond):
    print(('[ok] ' if cond else '[!!] ') + name)
    if not cond:
        fails.append(name)


# 1) export/import 往返一致
h = G.Health()
h.import_state({'good': [['1.2.3.4', 120]], 'tier': {'1.2.3.4': ['http', 1000.0]}, 'last': 5.0})
st = h.export_state()
check('export 结构正确', st['good'] == [['1.2.3.4', 120]]
      and st['tier']['1.2.3.4'] == ['http', 1000.0] and st['last'] == 5.0)
h2 = G.Health(); h2.import_state(st)
check('import 回写一致', h2.export_state() == st)
h3 = G.Health(); h3.import_state('not a dict')
check('import 非dict不崩', h3.export_state()['good'] == [])

# 2) save/load 文件往返（monkeypatch 到临时文件，不污染真实缓存）
tmpd = tempfile.mkdtemp()
G.HEALTH_CACHE = os.path.join(tmpd, 'health_cache.json')
tip = G.CANDIDATES[0] if G.CANDIDATES else '140.82.113.3'   # 真实候选 IP，确保 load 不被过滤
G.HEALTH.import_state({'good': [[tip, 88]], 'tier': {tip: ['tls', 2000.0]}, 'last': 7.0})
G.save_health_cache()
check('缓存文件已写', os.path.exists(G.HEALTH_CACHE))
G.HEALTH.import_state({})
G.load_health_cache()
got = G.HEALTH.export_state()
check('load 从文件恢复', got['good'] and got['good'][0][0] == tip and got['good'][0][1] == 88)

# 3) 文件不存在：静默返回、不动现有池
os.remove(G.HEALTH_CACHE)
G.HEALTH.import_state({'good': [['1.1.1.1', 1]], 'tier': {}, 'last': 0})
G.load_health_cache()
check('文件缺失不崩且保留原池', G.HEALTH.export_state()['good'] == [['1.1.1.1', 1]])

# 4) schema 不符：忽略
with open(G.HEALTH_CACHE, 'w') as f:
    json.dump({'schema': 999, 'pools': {}}, f)
G.HEALTH.import_state({'good': [['2.2.2.2', 2]], 'tier': {}, 'last': 0})
G.load_health_cache()
check('schema不符忽略', G.HEALTH.export_state()['good'] == [['2.2.2.2', 2]])

# 5) 过旧(>24h)：忽略
with open(G.HEALTH_CACHE, 'w') as f:
    json.dump({'schema': G.HEALTH_CACHE_SCHEMA, 'saved_at': time.time() - 25 * 3600,
               'pools': {'github': {'good': [['3.3.3.3', 3]], 'tier': {}, 'last': 0}}}, f)
G.HEALTH.import_state({'good': [['4.4.4.4', 4]], 'tier': {}, 'last': 0})
G.load_health_cache()
check('过旧忽略', G.HEALTH.export_state()['good'] == [['4.4.4.4', 4]])

# 6) 损坏 JSON：忽略
with open(G.HEALTH_CACHE, 'w') as f:
    f.write('{ this is not json')
G.HEALTH.import_state({'good': [['5.5.5.5', 5]], 'tier': {}, 'last': 0})
G.load_health_cache()
check('损坏JSON忽略', G.HEALTH.export_state()['good'] == [['5.5.5.5', 5]])

print('ALL CACHE TESTS PASSED' if not fails else ('FAILURES: ' + ', '.join(fails)))
sys.exit(1 if fails else 0)
