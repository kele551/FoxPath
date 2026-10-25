# -*- coding: utf-8 -*-
# 作者: 海风（kele551）
# 用途: 「直连 vs 候选池」判据 + 日志口径的单测（2026-10-25 待办 #64）。
#
# 为什么不 import github_direct.py：它一 import 就绑 8787/8788 端口、起后台线程，
# 和已在跑的实例撞车（用户机器上正在用的那个会被牵连）。这里用 ast 只把
# `_sys_wins` / `_cap_of` / `_cap_verdict` 三个纯判据函数和它们用的几个阈值摘出来单独 exec。
import ast
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SRC = os.path.join(REPO, "github_direct.py")

WANT_FUNCS = {"_sys_wins", "_cap_of", "_cap_fresh", "_wins_by_evidence", "_cap_verdict"}
WANT_CONSTS = {"_SYS_CAP", "_POOL_CAP", "_SYS_CAP_TTL", "_SYS_WIN_RATIO", "_SYS_MIN_KBPS"}

FAILS = []


def load_fragment():
    tree = ast.parse(open(SRC, encoding="utf-8").read())
    ns = {"time": time}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in WANT_FUNCS \
                and not node.decorator_list:
            exec(compile(ast.Module(body=[node], type_ignores=[]), SRC, "exec"), ns)
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name) \
                and node.targets[0].id in WANT_CONSTS:
            exec(compile(ast.Module(body=[node], type_ignores=[]), SRC, "exec"), ns)
    miss = (WANT_FUNCS | WANT_CONSTS) - set(ns)
    if miss:
        FAILS.append("摘取失败，缺: " + ", ".join(sorted(miss)))
    return ns


def ev(ip, kbps, age=0.0, ok=True):
    return {"ip": ip, "kbps": kbps, "ok": ok, "ts": time.time() - age,
            "bytes": kbps * 1024, "cost": 1.0}


def check(name, got, want):
    ok = got == want
    print("%s %s  得到=%r 应为=%r" % ("[ok]" if ok else "[!!]", name, got, want))
    if not ok:
        FAILS.append("%s（得到 %r）" % (name, got))


def main():
    ns = load_fragment()
    sys_wins, cap_verdict = ns["_sys_wins"], ns["_cap_verdict"]
    H = "github.com"
    FAST, MID, SLOW = 400, 100, 20
    min_k, ratio = ns["_SYS_MIN_KBPS"], ns["_SYS_WIN_RATIO"]
    print("阈值: 直连门槛 %d KB/s、要快过 %s 倍才算赢、证据 %d 秒内新鲜\n"
          % (min_k, ratio, ns["_SYS_CAP_TTL"]))

    def run(s, p, name, want):
        ns["_SYS_CAP"].clear()
        ns["_POOL_CAP"].clear()
        if s is not None:
            ns["_SYS_CAP"][H] = s
        if p is not None:
            ns["_POOL_CAP"][H] = p
        check(name, sys_wins(H), want)

    # ── 没证据的两支 ──
    run(None, None, "两边都没证据 → 不切直连", False)
    run(None, ev("1.1.1.1", FAST), "直连没证据、池子有 → 不切", False)
    run(ev("2.2.2.2", FAST), None, "直连有、池子没对手 → 可以试直连", True)

    # ── 证据有效性 ──
    run(ev("2.2.2.2", FAST, ok=False), None, "直连记录 ok=False → 当没证据", False)
    run(ev("2.2.2.2", FAST, age=ns["_SYS_CAP_TTL"] + 1), None,
        "直连证据过期（超 TTL）→ 当没证据", False)
    run(ev("2.2.2.2", FAST), ev("1.1.1.1", SLOW, age=ns["_SYS_CAP_TTL"] + 1),
        "池子证据过期 → 视作没对手，直连可试", True)

    # ── 同 IP / 门槛 / 余量 ──
    run(ev("3.3.3.3", FAST), ev("3.3.3.3", SLOW), "两边同一个 IP → 不作数", False)
    run(ev("2.2.2.2", MID), ev("1.1.1.1", SLOW), "直连够快但池子慢得多 → 切直连", True)
    # 压线方向要算对：判据是 sp >= pp*ratio，所以 pp = sp/ratio 才是临界值
    edge = int(MID / ratio)                       # 100/1.25 = 80
    run(ev("2.2.2.2", MID), ev("1.1.1.1", edge),
        "刚好压线（直连 = 池子×%s）→ 切直连" % ratio, True)
    run(ev("2.2.2.2", MID), ev("1.1.1.1", edge + 1),
        "差一点点没到余量 → 不切（防来回横跳）", False)
    run(ev("2.2.2.2", SLOW), ev("1.1.1.1", 1),
        "直连自己不到门槛（<%d KB/s）→ 不切" % min_k, False)

    print("")
    # ── 日志口径：比不出来就不能说"选 X"（判据吃的就是日志印的那两份，不再回表查）──
    check("两边都没测到 → 说'不作数'",
          cap_verdict(None, None), '两边都没测到，本轮不作数')
    check("两边都过期 → 也说'不作数'",
          cap_verdict(ev("2.2.2.2", FAST, age=ns["_SYS_CAP_TTL"] + 1),
                      ev("1.1.1.1", SLOW, age=ns["_SYS_CAP_TTL"] + 1)),
          '两边都没测到，本轮不作数')
    s, p = ev("3.3.3.3", FAST), ev("3.3.3.3", SLOW)
    check("两边是同一个 IP → 说'不作数'",
          cap_verdict(s, p), '两边是同一个 IP，本轮不作数')
    s = ev("2.2.2.2", FAST)
    check("直连有池子没 → 说'选 直连'", cap_verdict(s, None), '直连')
    check("池子明显快 → 说'选 候选池'",
          cap_verdict(ev("2.2.2.2", MID), ev("1.1.1.1", 400)), '候选池')
    check("直连没测到但池子测到了 → 说'选 候选池'（这句是真话）",
          cap_verdict(None, ev("1.1.1.1", FAST)), '候选池')

    print("")
    if FAILS:
        print("未通过 %d 项:" % len(FAILS))
        for f in FAILS:
            print("  - " + f)
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())
