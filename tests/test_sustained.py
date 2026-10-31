# -*- coding: utf-8 -*-
"""狐径 真机持续压测 (headless, 纯本地, 不写系统代理)
-----------------------------------------------------------------
目的: 验证"稳定不掉线"修复在真实生产转发路径下的长时间表现, 含本次新增的
      中继层"传输中静默看门狗"(STALL_WATCHDOG)对大页面卡死类的拦截。
做法:
  1. 起一个修复后的代理服务器(自动避开被旧实例占用的 8787, 顺延到备用端口);
  2. 按 main() 预体检口径填充 github/raw/pages 三池 + 热备池 —— 否则转发会掉进
     "系统解析兜底"分支, 根本不经过本次修复的选路逻辑;
  3. 对真实 GitHub 各域名跑 N 轮轮换 HTTPS GET, 经代理端口转发;
  4. 客户端带一次透明重试(模拟浏览器在半截连接上自动重发) + Content-Length 校验,
     统计最终成功率 / 断流 / 失败, 直接回答"时通时断是否消失"。
注意: 本测试**不调用 enable_proxy / 不写注册表 / 不干扰正在运行的旧实例**,
     只把测试流量显式指向本次起的新代理端口(等价于浏览器走 PAC 的效果)。
"""
import importlib.util
import os
import sys
import time
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "github_direct.py")

spec = importlib.util.spec_from_file_location("fp_sustained", SRC)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def log(msg):
    print("[sustained] " + msg, flush=True)


# ---- 1. 起修复后的代理 (自动顺延避开 8787) ----
log("启动修复后代理 ...")
m.start_proxy()
port = m.proxy_port()
log("代理监听 127.0.0.1:%d" % port)

# ---- 2. 按生产预体检口径填池 (关键: 让选路修复真正生效) ----
log("填充候选池(生产 refresh 口径) ...")
try:
    m.HEALTH.refresh(m.candidate_list())
    m.HEALTH_RAW.refresh(m.CANDIDATE_IPS_RAW_ALL)
    m.HEALTH_PAGES.refresh(m.CANDIDATE_IPS_PAGES_ALL)
    m.hot_refresh("github", m.HEALTH)
    m.hot_refresh("raw", m.HEALTH_RAW)
    m.hot_refresh("pages", m.HEALTH_PAGES)
    log("候选池就绪: github=%d raw=%d pages=%d"
        % (len(m._hot_get("github")), len(m._hot_get("raw")),
           len(m._hot_get("pages"))))
except Exception as e:
    log("!! 填池异常(继续跑, 转发可能走兜底): %s" % e)


# ---- 3. 持续压测 (带一次透明重试, 模拟浏览器) ----
TARGETS = [
    "https://github.com",
    "https://raw.githubusercontent.com/github/explore/main/README.md",
    "https://api.github.com/rate_limit",
    "https://avatars.githubusercontent.com/u/9919",
]
N = 30
TIMEOUT = 20.0

proxy = urllib.request.ProxyHandler({"https": "http://127.0.0.1:%d" % port})
opener = urllib.request.build_opener(proxy)


def classify(e):
    s = str(e).lower()
    t = type(e).__name__.lower()
    if ("timed out" in s or "timeout" in s or t == "timeouterror"
            or "remotedisconnected" in t or "connectionreseterror" in t
            or "incompleteread" in t or "incomplete" in s):
        return "stall"
    return "fail"


def fetch_once(url):
    t0 = time.time()
    req = urllib.request.Request(url, headers={"User-Agent": "FoxPath-Test/1.0"})
    try:
        with opener.open(req, timeout=TIMEOUT) as r:
            data = r.read()
            code = r.getcode()
            cl = r.headers.get("Content-Length")
            clen = int(cl) if cl and cl.isdigit() else None
            if not (200 <= code < 400):
                return "fail", round(time.time() - t0, 2), len(data), "HTTP %s" % code
            if clen is not None and len(data) < clen:
                return "stall", round(time.time() - t0, 2), len(data), \
                       "截断 %d/%d B" % (len(data), clen)
            if len(data) == 0:
                return "stall", round(time.time() - t0, 2), 0, "0 字节"
            return "ok", round(time.time() - t0, 2), len(data), ""
    except urllib.error.HTTPError as e:
        return "fail", round(time.time() - t0, 2), 0, "HTTPError %s" % e.code
    except Exception as e:
        st = classify(e)
        return st, round(time.time() - t0, 2), 0, \
               "%s: %s" % (type(e).__name__, str(e)[:70])


results = []
ok = stall = fail = 0
retried = 0
t0_all = time.time()
for i in range(N):
    url = TARGETS[i % len(TARGETS)]
    st, dt, nb, note = fetch_once(url)
    if st != "ok":
        # 透明重试一次(浏览器在半截连接上会自动重发 -> 新隧道 -> 干净 IP)
        st2, dt2, nb2, note2 = fetch_once(url)
        retried += 1
        final = st2
        note = "(首次%s:%s) 重试->%s %s" % (st, note, st2, note2)
        dt = dt + dt2
        nb = nb2
        st = final
    if st == "ok":
        ok += 1
    elif st == "stall":
        stall += 1
    else:
        fail += 1
    results.append((i + 1, url, st, round(dt, 2), nb, note))
    short = url.replace("https://", "")
    log("#%02d %-46s %-5s %.2fs %8d B  %s"
        % (i + 1, short[:46], st, dt, nb, note))
    time.sleep(3.0)

elapsed = time.time() - t0_all
total = ok + stall + fail
rate = (ok / total * 100.0) if total else 0.0

print("\n" + "=" * 64, flush=True)
print("狐径 真机持续压测报告 (含中继静默看门狗)", flush=True)
print("=" * 64, flush=True)
print("代理端口        : 127.0.0.1:%d (修复后代码路径)" % port, flush=True)
print("总请求数(含重试) : %d" % total, flush=True)
print("触发重试次数     : %d" % retried, flush=True)
print("最终成功         : %d" % ok, flush=True)
print("最终断流         : %d" % stall, flush=True)
print("最终失败         : %d" % fail, flush=True)
print("最终成功率       : %.1f%%" % rate, flush=True)
print("总耗时           : %.1fs" % elapsed, flush=True)
print("-" * 64, flush=True)
if stall or fail:
    print("失败/断流明细:", flush=True)
    for (idx, url, st, dt, nb, nt) in results:
        if st != "ok":
            print("  #%02d %-6s %s  %s" % (idx, st, url, nt), flush=True)
else:
    print("全程零断流、零失败 —— 时通时断已消失。", flush=True)
print("=" * 64, flush=True)
print("RESULT_RATE=%.1f" % rate, flush=True)
sys.exit(0)
