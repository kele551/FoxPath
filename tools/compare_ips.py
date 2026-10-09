# -*- coding: utf-8 -*-
"""对比：GitHub 官方当前 IP 段 vs 狐径代码里的候选 IP 表。

用法: python tools/compare_ips.py      # 仓库里的那份
      python tools/compare_ips.py      # 工作区里的那份（projects\\狐径\\tools\\）

只用标准库（urllib），不需要装 requests —— 只有 tools/publish.py 才需要 requests。
"""
import io
import ipaddress
import json
import os
import re
import urllib.request

# 仓库根：本脚本既可能在 <仓库>\tools\ 下（随仓库入库的那份），
# 也可能在 <项目>\tools\ 下（工作区那份），两种位置都自己认出来。
_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
repo = _HERE if os.path.exists(os.path.join(_HERE, 'github_direct.py')) \
    else os.path.join(_HERE, 'repo')
print('  仓库目录:', repo)

src = io.open(os.path.join(repo, 'github_direct.py'), encoding='utf-8').read()

m = re.search(r'CANDIDATE_IPS\s*=\s*\[(.*?)\]', src, re.S)
have = re.findall(r"'(\d+\.\d+\.\d+\.\d+)'", m.group(1)) if m else []
print('  代码里的候选 IP：%d 个' % len(have))
print('   ', ', '.join(have))

print()
print('=== GitHub 官方当前公布的网段（api.github.com/meta）===')
try:
    req = urllib.request.Request('https://api.github.com/meta',
                                 headers={'User-Agent': 'FoxPath-compare-ips',
                                          'Accept': 'application/vnd.github+json'})
    with urllib.request.urlopen(req, timeout=60) as r:
        j = json.loads(r.read().decode('utf-8', 'replace'))
    for key in ('web', 'api', 'git'):
        vals = j.get(key) or []
        print('  %-4s: %s' % (key, ', '.join(vals)))
    web = j.get('web') or []
    # 我们的候选 IP 落在哪些官方网段里
    nets = []
    for c in web:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except Exception:
            pass
    inside, outside = [], []
    for ip in have:
        a = ipaddress.ip_address(ip)
        (inside if any(a in n for n in nets) else outside).append(ip)
    print()
    print('  我们的候选里，落在官方 web 段内的: %d 个' % len(inside))
    print('  不在官方 web 段内的（可能已失效/不属于 github.com）: %d 个' % len(outside))
    if outside:
        print('   ', ', '.join(outside))
    # 官方段里我们完全没覆盖的
    covered = []
    for n in nets:
        hit = any(ipaddress.ip_address(ip) in n for ip in have)
        if not hit:
            covered.append(str(n))
    if covered:
        print('  官方 web 段里我们**一个 IP 都没覆盖**的:', ', '.join(covered))
except Exception as e:
    print('  取官方表失败:', type(e).__name__, e)
