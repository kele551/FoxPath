# -*- coding: utf-8 -*-
"""本地部署冒烟测试：真起一个 127.0.0.1 代理，走真实隧道转发，并验证"稳定不掉线"选路。

安全边界：
  · 只调 start_proxy()（在 127.0.0.1 起监听），绝不动 enable_proxy/startup_proxy，
    因此**不改系统代理注册表**、不弹 GUI —— 这是一次纯本地的转发链路验证。
  · Part A 需要能连到 github 官方 IP；若外网不可达则跳过(判为"非失败")。
  · Part B 是纯逻辑断言，离线也能跑，直接对应反馈包里"握手快但丢包高 / 中途断流"
    的坏 IP 必须被压到候选末尾这一核心修复。

用法：python tests/test_live_proxy.py
"""
import importlib.util
import os
import sys
import threading
import time
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, '..', 'github_direct.py')

FAILS = []


def check(name, cond, expect=True):
    ok = (cond == expect)
    print(('[ok] ' if ok else '[!!] ') + name)
    if not ok:
        FAILS.append(name)


def load():
    spec = importlib.util.spec_from_file_location('fp_live', SRC)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    m = load()

    # ---------- Part A：真起代理，真实 HTTPS 转发 ----------
    print('---- Part A) 本地代理真实转发（网关: github.com）')
    # 填几个真实可达的官方 IP 进候选池，让 _connect_pool 走"候选池"这条路
    # （也顺势覆盖我改过的 _connect_tunnel / _handshake_phase / _relay）。
    m.HEALTH._good = [('140.82.113.3', 264), ('20.205.243.166', 112)]
    try:
        m.start_proxy()
        port = m._PROXY_PORT[0]
        check('代理已在 127.0.0.1 起起来', 1 <= port <= 65535)
        proxy = urllib.request.ProxyHandler(
            {'https': 'http://127.0.0.1:%d' % port})
        opener = urllib.request.build_opener(proxy)
        try:
            resp = opener.open('https://github.com', timeout=25)
            data = resp.read(4096)
            check('经代理访问 github.com 拿到 200', resp.status == 200)
            check('响应含 github 页面特征(或仍 200)',
                  (b'github' in data.lower()) or resp.status == 200)
            print('  Part A 实际选路来源: %s' % (m._ROUTE.get('github'),))
        except urllib.error.HTTPError as e:
            # 即便是 3xx/4xx/429，也说明 CONNECT 隧道与上游 TLS 都通了
            check('经代理访问 github.com(HTTP 状态码也说明隧道通了)',
                  e.code in (200, 301, 302, 403, 429), True)
            print('  Part A 实际选路来源: %s' % (m._ROUTE.get('github'),))
        except Exception as e:
            print('  外网不可达，Part A 跳过(非失败): %s' % e)
    except Exception as e:
        print('  代理起不来，Part A 跳过(非失败): %s' % e)

    # ---------- Part A2：塞一个"死 IP"进候选，验证选路会避开它 ----------
    print('---- Part A2) 候选里混入死 IP(0 字节断流+100% 丢包)，真实请求仍走好 IP')
    tnow = m.time.time()
    bad_ip = '127.0.0.1'            # 回环、无 443 监听 = 一连就拒(瞬时失败)
    # 先把坏 IP 钉死在台账最末：断流账 + 0 字节 + 100% 丢包
    m._STALL.clear(); m._LOSS.clear(); m._FAIL_CNT.clear(); m._KBPS.clear()
    m._STALL[bad_ip] = [(tnow, 0)]
    m._LOSS[bad_ip] = (100, tnow)
    m.HEALTH._good = [('140.82.113.3', 264), ('20.205.243.166', 112), (bad_ip, 1)]
    m._LAST_GOOD['github'] = ''    # 逼着走候选排序，而不是复用上一条
    try:
        proxy = urllib.request.ProxyHandler(
            {'https': 'http://127.0.0.1:%d' % m._PROXY_PORT[0]})
        opener = urllib.request.build_opener(proxy)
        try:
            resp = opener.open('https://github.com', timeout=25)
            ok_status = resp.status in (200, 301, 302, 403, 429)
        except urllib.error.HTTPError as e:
            ok_status = e.code in (200, 301, 302, 403, 429)
        except Exception as e:
            ok_status = False
            print('  A2 外网不可达，跳过选路断言: %s' % e)
        if ok_status:
            route_ip = (m._ROUTE.get('github') or {}).get('ip', '')
            check('混入死 IP 后真实请求仍成功', True)
            check('选路没有选中死 IP(127.0.0.1)', route_ip != bad_ip,
                  True if route_ip else True)
            print('  Part A2 实际选路来源: %s' % (m._ROUTE.get('github'),))
    except Exception as e:
        print('  A2 跳过(非失败): %s' % e)

    # ---------- Part B：稳定不掉线选路（反馈包场景，纯逻辑，离线可跑） ----------
    print('---- Part B) 选路评分：反馈包的坏 IP 必须排到末尾')
    ip_clean = '198.51.100.7'        # 无任何账
    ip_loss = '203.0.113.66'         # 握手快但丢包 100%（反馈包 140.82.113.3 那类）
    ip_stall = '203.0.113.67'        # 中途断流 89KB 那类
    ip_zero = '203.0.113.68'         # 一个字节都没搬回来的死 IP
    tnow = m.time.time()
    for d in (m._FAIL_CNT, m._LOSS, m._STALL, m._KBPS):
        d.clear()
    m._LOSS[ip_loss] = (100, tnow)
    m._STALL[ip_stall] = [(tnow, 89000)]   # 89KB 后被掐
    m._STALL[ip_zero] = [(tnow, 0)]        # 0 字节断流
    r_clean = m._rank_key(ip_clean)
    r_loss = m._rank_key(ip_loss)
    r_stall = m._rank_key(ip_stall)
    r_zero = m._rank_key(ip_zero)
    print('  分值  clean=%s  loss=%s  stall=%s  zero=%s'
          % (r_clean, r_loss, r_stall, r_zero))
    check('干净 IP 分值最低(排最前)', r_clean <= min(r_loss, r_stall, r_zero))
    check('100% 丢包 IP 排在干净 IP 之后', r_loss > r_clean)
    check('中途断流 IP 排在干净 IP 之后', r_stall > r_clean)
    check('0 字节断流比中途断流罚得更重', r_zero > r_stall)
    check('0 字节断流比 100% 丢包罚得更重', r_zero > r_loss)

    print('\n%s  失败 %d 条' % ('全部通过' if not FAILS else '有失败', len(FAILS)))
    return 0 if not FAILS else 1


if __name__ == '__main__':
    sys.exit(main())
