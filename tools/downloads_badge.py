# -*- coding: utf-8 -*-
"""生成「真实下载数 = GitHub + GitCode」徽章数据（shields.io endpoint JSON）。

被 .github/workflows/downloads-badge.yml 每天调用一次，写入 docs/downloads.json；
README 里的下载徽章用 shields.io 的 endpoint 读它。

为什么两个加起来：国外仓（GitHub）有下载数接口；国内仓（GitCode = AtomGit）有
`download_statistics` 接口；两边都在累计真实下载，合起来才接近"总下载量"。
Gitee 不公开下载数（API/网页都没有），所以算不进来。

用法：
    python tools/downloads_badge.py --repo FoxPath --out docs/downloads.json
    python tools/downloads_badge.py --repo FoxPath --print   # 只打印，不写文件
"""
import argparse
import json
import sys
import urllib.request

UA = "Mozilla/5.0 (downloads-badge)"
TIMEOUT = 30


def _get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def github_downloads(repo):
    """GitHub 发行版附件的下载数合计。失败返回 None。"""
    try:
        rels = _get_json(
            "https://api.github.com/repos/kele551/%s/releases?per_page=100" % repo)
        return sum(int(a.get("download_count") or 0)
                   for r in rels for a in (r.get("assets") or []))
    except Exception as e:
        print("  [WARN] GitHub 下载数取不到: %s" % e, file=sys.stderr)
        return None


def gitcode_downloads(repo):
    """GitCode（=AtomGit）的 download_statistics_total。失败返回 None。"""
    try:
        d = _get_json(
            "https://gitcode.com/api/v5/repos/kele551/%s/download_statistics" % repo)
        return int(d.get("download_statistics_total") or 0)
    except Exception as e:
        print("  [WARN] GitCode 下载数取不到: %s" % e, file=sys.stderr)
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, help="仓库名，例如 FoxPath")
    ap.add_argument("--out", default="", help="写出的 JSON 路径（例如 docs/downloads.json）")
    ap.add_argument("--print", action="store_true", help="只打印，不写文件")
    a = ap.parse_args()

    gh = github_downloads(a.repo)
    gc = gitcode_downloads(a.repo)
    # 任意一边失败就按 0 算（宁可少算，也不要制造假数字），但至少一边成功才更新
    if gh is None and gc is None:
        print("两边都取不到，放弃（保持旧值）", file=sys.stderr)
        return 1
    total = (gh or 0) + (gc or 0)
    print("GitHub=%s GitCode=%s 合计=%s" % (gh, gc, total))

    if a.print or not a.out:
        return 0

    # shields.io endpoint 格式
    payload = {
        "schemaVersion": 1,
        "label": "下载",
        "message": str(total),
        "color": "blue",
    }
    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print("已写入 %s" % a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
