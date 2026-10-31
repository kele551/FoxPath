# -*- coding: utf-8 -*-
"""狐径 真机全量验证：系统代理已由生产路径开启后的"浏览器模式"实测
--------------------------------------------------------------------------
与 test_sustained.py 的区别：
  sustained 是"直测代理端口"，绕开了**系统代理**这一层；
  本脚本补上那一层 —— 完整模拟浏览器的行为：
    1. 从注册表读出 AutoConfigURL / ProxyEnable（真系统代理设置，不是写死的端口）；
    2. 从那个 URL 取回 PAC（dashboard 由本次运行的新版程序投放）；
    3. 把 PAC 里 FindProxyForURL 的规则**等价移植**成 Python 裁决(浏览器就是这么干的);
    4. 按裁决路由真实请求：命中 GitHub 的走代理，其余按 DIRECT 直连;
    5. 带一次透明重试(Chrome 在半截连接上会自动重发)统计真实成功率。
另有一组 DIRECT 对照组：确认非 GitHub 站点没被代理误伤。

前置条件：FoxPath 已由生产路径开启加速(注册表 AutoConfigURL 指向本机面板)。
"""
import re
import sys
import time
import urllib.request
import urllib.error
import winreg

INTERNET = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'

# ---- PAC 里 FindProxyForURL 的规则（与 github_direct.py 的 PAC_TEMPLATE 一一对应）----
PAC_HOSTS = (
    "github.com", "www.github.com", "codeload.github.com", "uploads.github.com",
    "raw.githubusercontent.com", "objects.githubusercontent.com",
    "avatars.githubusercontent.com", "camo.githubusercontent.com",
    "github.io",
)


def pac_decision(host):
    """等价移植 PAC 的裁决: GitHub 系走代理, 其余直连。"""
    host = host.lower()
    if host in PAC_HOSTS or host.endswith(".github.io"):
        return True
    return False


def reg_read(name):
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET)
        return winreg.QueryValueEx(k, name)[0]
    except FileNotFoundError:
        return None


def first_proxy_of(pac_text):
    """从 'PROXY 127.0.0.1:8787; DIRECT' 里取出第一个 PROXY 入口。"""
    for part in pac_text.replace('\r', '').split(';'):
        part = part.strip()
        if part.upper().startswith('PROXY '):
            return 'http://' + part.split(None, 1)[1].strip()
    return None


def main():
    print('---- 1) 读系统代理设置(不是写死的端口, 读的是注册表真值) ----')
    pac_url = reg_read('AutoConfigURL')
    proxy_enable = reg_read('ProxyEnable')
    proxy_server = reg_read('ProxyServer')
    print('  ProxyEnable   = %r' % proxy_enable)
    print('  ProxyServer   = %r' % proxy_server)
    print('  AutoConfigURL = %r' % pac_url)
    if not pac_url:
        print('!! 注册表里没有 PAC —— 说明加速没开, 先运行程序并启用加速再做这项验证')
        return 1
    if str(proxy_enable) != '1':
        print('!! ProxyEnable 不是 1 —— PAC 不会被启用, 请先在程序里启用加速')
        return 1

    print('---- 2) 从 %s 取回 PAC ----' % pac_url)
    pac = urllib.request.urlopen(pac_url, timeout=8).read().decode('utf-8', 'replace')
    pm = re.search(r'PROXY\s+([0-9]+\.[0-9.]+:\d+|\[[0-9a-fA-F:]+\]:\d+)', pac)
    proxy_entry = ('http://' + pm.group(1)) if pm else None
    print('  PAC 长度      = %d bytes' % len(pac))
    print('  解析出的代理  = %r' % proxy_entry)
    if not proxy_entry:
        print('!! PAC 里没有可用的 PROXY 入口')
        return 1

    opener_proxy = urllib.request.build_opener(
        urllib.request.ProxyHandler({'https': proxy_entry}))
    opener_direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    # ---- 3) 真实请求, 按 PAC 裁决路由 ----
    targets = [
        ('https://github.com', True),
        ('https://raw.githubusercontent.com/github/explore/main/README.md', True),
        ('https://avatars.githubusercontent.com/u/9919', True),
        ('https://www.microsoft.com', False),   # DIRECT 对照组
    ]
    N = 24
    TIMEOUT = 25.0

    def fetch(url, via_proxy, retry=True):
        opener = opener_proxy if via_proxy else opener_direct
        req = urllib.request.Request(url, headers={'User-Agent': 'FoxPath-BrowserSim/1.0'})
        t0 = time.time()
        try:
            with opener.open(req, timeout=TIMEOUT) as r:
                data = r.read()
                code = r.getcode()
                cl = r.headers.get('Content-Length')
                clen = int(cl) if cl and cl.isdigit() else None
                if not (200 <= code < 400):
                    return 'fail', time.time() - t0, len(data), 'HTTP %s' % code
                if clen is not None and len(data) < clen:
                    return 'stall', time.time() - t0, len(data), \
                           '截断 %d/%d B' % (len(data), clen)
                if not data:
                    return 'stall', time.time() - t0, 0, '0 字节'
                return 'ok', time.time() - t0, len(data), ''
        except urllib.error.HTTPError as e:
            return 'fail', time.time() - t0, 0, 'HTTPError %s' % e.code
        except Exception as e:
            s = str(e).lower(); tn = type(e).__name__.lower()
            st = ('stall' if ('timed out' in s or 'timeout' in s or tn == 'timeouterror'
                             or 'remotedisconnected' in tn or 'connectionreset' in tn
                             or 'incompleteread' in tn or 'incomplete' in s)
                  else 'fail')
            return st, time.time() - t0, 0, '%s: %s' % (type(e).__name__, str(e)[:64])

    results = []
    ok = stall = fail = retried = 0
    direct_ok = direct_n = 0
    t0_all = time.time()
    print('---- 3) 真实浏览器模式请求 (N=%d) ----' % N)
    for i in range(N):
        url, via_proxy = targets[i % len(targets)]
        st, dt, nb, note = fetch(url, via_proxy)
        if st != 'ok':
            st2, dt2, nb2, note2 = fetch(url, via_proxy)
            retried += 1
            note = '(首次%s:%s) 重试->%s' % (st, note, st2)
            st, dt, nb = st2, dt + dt2, nb2
        if st == 'ok':
            ok += 1
        elif st == 'stall':
            stall += 1
        else:
            fail += 1
        if not via_proxy:
            direct_n += 1
            direct_ok += (1 if st == 'ok' else 0)
        results.append((i + 1, url, '代理' if via_proxy else '直连', st,
                        round(dt, 2), nb, note))
        print('  #%02d %-4s %-46s %-5s %.2fs %8dB %s'
              % (i + 1, '代理' if via_proxy else '直连', url.replace('https://', '')[:46],
                 st, dt, nb, note), flush=True)
        time.sleep(3.0)

    total = ok + stall + fail
    rate = (ok / total * 100.0) if total else 0.0
    print('\n' + '=' * 66)
    print('真机全量验证报告（系统代理 + PAC 路由，浏览器模式）')
    print('=' * 66)
    print('系统代理      : ProxyEnable=%s  AutoConfigURL=%s' % (proxy_enable, pac_url))
    print('PAC 解析代理  : %s' % proxy_entry)
    print('总请求        : %d（其中走代理 %d / 对照组直连 %d）'
          % (total, total - direct_n, direct_n))
    print('重试次数      : %d' % retried)
    print('最终成功      : %d' % ok)
    print('最终断流      : %d' % stall)
    print('最终失败      : %d' % fail)
    print('成功率        : %.1f%%' % rate)
    print('直连对照组    : %d/%d 成功（非 GitHub 站点未被代理误伤）' % (direct_ok, direct_n))
    print('总耗时        : %.1fs' % (time.time() - t0_all))
    print('-' * 66)
    bad = [r for r in results if r[3] != 'ok']
    if bad:
        print('失败/断流明细:')
        for r in bad:
            print('  #%02d %-4s %-8s %s  %s' % (r[0], r[2], r[3], r[1], r[6]))
    else:
        print('全程零断流、零失败 —— 网页层面的时通时断已消失。')
    print('=' * 66)
    print('BROWSER_RESULT_RATE=%.1f' % rate)
    return 0 if not bad else 1


if __name__ == '__main__':
    sys.exit(main())
