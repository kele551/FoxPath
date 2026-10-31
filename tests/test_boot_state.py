# -*- coding: utf-8 -*-
# 作者: 海风（kele551）
"""狐径 2026-10-26 开机态自愈的单测：不 import 整个 github_direct.py（一 import 就绑 8787/8788，
会牵连正在用的实例），照 tests/test_sys_wins.py 的办法用 ast 只摘出三个新函数单独 exec。

覆盖：
  1) keep_off            → 只说"没开启加速"，一个注册表字节都不动
  2) PAC 不是我们的      → 走 enable_proxy()
  3) PAC 是我们的但总闸=0 → 补开 ProxyEnable=1 并通知系统（老代码这条完全不动，就是"看着开着其实没生效"）
  4) PAC 是我们的且总闸=1 → 不再重复写注册表
  5) 有残留戳            → 日志里要说清"上次没正常退出 + 现场 pid/版本/时间"
  6) 运行戳写/读往返      → 取走即删，二次取为 None
  7) 干净退出的撤戳路径   → safe_quit 必须走 on_exit（os._exit 不走 atexit，
                            自己再写一遍 disable_proxy 就会漏掉撤戳，2026-10-26 实测踩过）
"""
import ast
import json
import os
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SRC = os.path.join(REPO, "github_direct.py")      # 跟着仓库走，换台机器也能跑（同 test_sys_wins.py）
WANT = {"startup_proxy", "_write_run_mark", "_take_run_mark"}

FAILS = []


def check(name, got, want):
    if got == want:
        print("[ok] %s" % name)
    else:
        print("[X ] %s  得到=%r 应为=%r" % (name, got, want))
        FAILS.append(name)


def load(stub_env):
    tree = ast.parse(open(SRC, encoding="utf-8").read())
    ns = dict(stub_env)
    got = 0
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in WANT and not node.decorator_list:
            exec(compile(ast.Module(body=[node], type_ignores=[]), SRC, "exec"), ns)
            got += 1
    check("摘到的函数个数", got, 3)
    return ns


def run_case(env):
    """返回 (日志行, 注册表写入, enable_proxy 次数)"""
    calls = {"enable": 0, "reg_set": [], "notify": 0}
    ns = load({
        "os": env.get("os", os), "json": json, "time": time,
        "APP_VERSION": "1.2.2", "REG_INTERNET": "Soft",
        "RUN_MARK_FILE": env["mark"],
        "_BOOT_DIRTY": [env.get("dirty")],
        "proxy_on": lambda: env["proxy_on"],
        "enable_proxy": (lambda: (calls.__setitem__("enable", calls["enable"] + 1), ("ok", "已开启"))[1]),
        "reg_get": (lambda p, n: calls["reg_set"].append(("get", n)) or env["reg"].get(n)),
        "reg_set": (lambda p, n, v, t=None: calls["reg_set"].append(("set", n, v))),
        "notify_proxy_change": lambda: calls.__setitem__("notify", calls["notify"] + 1),
        "_load_backup": lambda: env.get("backup", {"AutoConfigURL": None}),
        "_pac_url": lambda: "http://127.0.0.1:8788/pac",
        "log": (lambda m, debug=False: env["logs"].append(m)),
    })
    ns["startup_proxy"](env.get("keep_off", False))
    return env["logs"], calls


def main():
    tmp = tempfile.mkdtemp(prefix="fpboot-")
    mark = os.path.join(tmp, "running.json")

    print("---- 1) keep_off：不动注册表")
    lg = []
    logs, c = run_case({"mark": mark, "proxy_on": True, "reg": {"ProxyEnable": 0}, "logs": lg, "keep_off": True})
    check("只打一行", len(logs), 1)
    check("内容是没开加速", "没有开启加速" in logs[0], True)
    check("没调 enable_proxy", c["enable"], 0)
    check("没写注册表", [x for x in c["reg_set"] if x[0] == "set"], [])

    print("---- 2) PAC 不是我们的 → 正常启用")
    lg = []
    logs, c = run_case({"mark": mark, "proxy_on": False, "reg": {}, "logs": lg})
    check("调了一次 enable_proxy", c["enable"], 1)
    check("没碰总闸(交给 enable_proxy 自己写)", [x for x in c["reg_set"] if x[0] == "set"], [])

    print("---- 3) PAC 是我们的、总闸被关成 0 → 补开")
    lg = []
    logs, c = run_case({"mark": mark, "proxy_on": True, "reg": {"ProxyEnable": 0}, "logs": lg})
    check("写了 ProxyEnable=1", ("set", "ProxyEnable", 1) in c["reg_set"], True)
    check("通知了系统一次", c["notify"], 1)
    check("日志说明原因", any("补开系统代理总闸" in x for x in logs), True)
    check("没重复 enable_proxy", c["enable"], 0)

    print("---- 3b) 总闸没设过（None）也算关，要补")
    lg = []
    logs, c = run_case({"mark": mark, "proxy_on": True, "reg": {}, "logs": lg})
    check("写了 ProxyEnable=1", ("set", "ProxyEnable", 1) in c["reg_set"], True)
    check("日志里写的是(未设置)", any("(未设置)" in x for x in logs), True)

    print("---- 4) PAC 是我们的、总闸本来就 1 → 一个字节都不动")
    lg = []
    logs, c = run_case({"mark": mark, "proxy_on": True, "reg": {"ProxyEnable": 1}, "logs": lg})
    check("没写注册表", [x for x in c["reg_set"] if x[0] == "set"], [])
    check("没通知系统", c["notify"], 0)
    check("没有多余日志", logs, [])

    print("---- 5) 带着上次残留的现场起来 → 要说清楚")
    lg = []
    logs, c = run_case({"mark": mark, "proxy_on": True, "reg": {"ProxyEnable": 1}, "logs": lg,
                        "dirty": {"pid": 4321, "app": "1.2.2", "ts": time.time() - 3600}})
    line = " / ".join(logs)
    check("说了上次没正常退出", "上次进程没有正常退出" in line, True)
    check("带上 pid", "pid=4321" in line, True)
    check("带上接管说明", "本次启动已直接接管" in line, True)

    print("---- 5b) 没有备份时仍然提示退出会直接清")
    lg = []
    logs, c = run_case({"mark": mark, "proxy_on": True, "reg": {"ProxyEnable": 1}, "logs": lg, "backup": None})
    check("有这句", any("没有还原备份" in x for x in logs), True)

    print("---- 6) 运行戳：写 -> 取走 -> 再取为空")
    ns = load({"os": os, "json": json, "time": time, "APP_VERSION": "1.2.2",
               "RUN_MARK_FILE": mark, "_pac_url": lambda: "http://127.0.0.1:8788/pac",
               "proxy_port": lambda: 8789,      # 2026-10-30 端口顺延：戳里记的是实际端口
               "log": lambda m, debug=False: None})
    check("一开始没有", ns["_take_run_mark"](), None)
    ns["_write_run_mark"]()
    d = ns["_take_run_mark"]()
    check("取回的是 dict", isinstance(d, dict), True)
    check("里面 pid 是本次", d.get("pid") == os.getpid(), True)
    check("里面记的是实际代理端口(不是写死的 8787)", d.get("port"), 8789)
    check("取过即删", os.path.exists(mark), False)
    check("再取为空", ns["_take_run_mark"](), None)

    print("---- 7) 干净退出必须撤戳：safe_quit 走 on_exit，别自己 os._exit 拍屁股")
    tree = ast.parse(open(SRC, encoding="utf-8").read())
    fns = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    sq = fns.get("safe_quit")
    check("有 safe_quit", sq is not None, True)
    names = {c.func.id for c in ast.walk(sq) if isinstance(c, ast.Call)
             and isinstance(c.func, ast.Name)} if sq else set()
    check("调了 on_exit(撤戳在那)", "on_exit" in names, True)
    dupd = [c for c in ast.walk(sq) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
            and c.func.id == "disable_proxy"]
    check("不再自己写一份 disable_proxy", len(dupd), 0)
    exits = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and ast.unparse(n).startswith("os._exit"):
            owner = next((f.name for f in tree.body if isinstance(f, ast.FunctionDef)
                          and n.lineno >= f.lineno and n.lineno <= f.end_lineno), "<模块级>")
            exits.append(owner)
    check("全文件只有 safe_quit 里一处 os._exit", exits, ["safe_quit"])
    check("os._exit 只有一处", len(exits), 1)

    print("\n%s  失败 %d 条" % ("全部通过" if not FAILS else "有失败", len(FAILS)))
    return 0 if not FAILS else 1


if __name__ == "__main__":
    raise SystemExit(main())
