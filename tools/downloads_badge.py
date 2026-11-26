# -*- coding: utf-8 -*-
"""生成「真实下载数」和「浏览量」徽章数据（只统计 GitHub 主源）。

被 .github/workflows/downloads-badge.yml 每天调用一次：
  · docs/downloads.json —— 下载数（GitHub 发行版附件 download_count）
  · docs/views.json     —— 浏览量（hits.sh 的 GitHub 计数）
README 里两枚徽章都用 shields.io 的 endpoint 读它们。

2026-11-25 红线第 36 条：只发 GitHub；GitCode（=AtomGit）纯被动镜像、不挂附件，
不再并入下载数/浏览量；Gitee 老仓库早已停更。

用法：
    python tools/downloads_badge.py --repo FoxPath --out docs/downloads.json --views-out docs/views.json
    python tools/downloads_badge.py --repo FoxPath --print
"""
import argparse
import json
import re
import sys
import urllib.request

UA = "Mozilla/5.0 (badges)"
TIMEOUT = 30
OWNER = "kele551"


def _get(url, binary=False):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        b = r.read()
    return b if binary else b.decode("utf-8", "replace")


def _get_json(url):
    return json.loads(_get(url))


def github_downloads(repo):
    try:
        rels = _get_json(
            "https://api.github.com/repos/%s/%s/releases?per_page=100" % (OWNER, repo))
        return sum(int(a.get("download_count") or 0)
                   for r in rels for a in (r.get("assets") or []))
    except Exception as e:
        print("  [WARN] GitHub 下载数取不到: %s" % e, file=sys.stderr)
        return None


def hits_count(url):
    """从 hits.sh 的 SVG 里解析出计数值。失败返回 None。"""
    try:
        svg = _get(url)
        texts = re.findall(r"<text[^>]*>(.*?)</text>", svg, re.S)
        nums = [t.strip() for t in texts if re.fullmatch(r"[0-9][0-9,]*", t.strip())]
        return int(nums[-1].replace(",", "")) if nums else None
    except Exception as e:
        print("  [WARN] hits.sh 取不到 %s: %s" % (url, e), file=sys.stderr)
        return None


def views(repo):
    return hits_count("https://hits.sh/github.com/%s/%s.svg" % (OWNER, repo))


def _write_endpoint(path, label, total):
    payload = {"schemaVersion": 1, "label": label, "message": str(total), "color": "blue"}
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write("\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, help="仓库名，例如 FoxPath")
    ap.add_argument("--out", default="", help="下载数 JSON 路径（docs/downloads.json）")
    ap.add_argument("--views-out", default="", help="浏览量 JSON 路径（docs/views.json）")
    ap.add_argument("--print", action="store_true", help="只打印，不写文件")
    a = ap.parse_args()

    gh = github_downloads(a.repo)
    v = views(a.repo)

    if gh is None:
        print("下载数取不到，放弃下载数更新", file=sys.stderr)
    else:
        print("下载：GitHub=%s" % gh)
    if v is None:
        print("浏览量取不到，放弃浏览量更新", file=sys.stderr)
    else:
        print("浏览：GitHub=%s" % v)

    if a.print:
        return 0
    if a.out and gh is not None:
        _write_endpoint(a.out, "下载", gh)
        print("已写入 %s" % a.out)
    if a.views_out and v is not None:
        _write_endpoint(a.views_out, "浏览", v)
        print("已写入 %s" % a.views_out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
