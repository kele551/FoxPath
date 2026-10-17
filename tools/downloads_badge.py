# -*- coding: utf-8 -*-
"""生成「真实下载数 = GitHub + GitCode」和「浏览量 = Gitee + GitCode」徽章数据。

被 .github/workflows/downloads-badge.yml 每天调用一次：
  · docs/downloads.json —— 下载数（GitHub 发行版附件 + GitCode download_statistics）
  · docs/views.json     —— 浏览量（hits.sh 的 Gitee 计数 + GitCode 计数）
README 里两枚徽章都用 shields.io 的 endpoint 读它们。

为什么合并：国外仓（GitHub）有下载数接口；国内新仓（GitCode = AtomGit）有
`download_statistics` 接口、也有 hits.sh 浏览量；国内老仓（Gitee）只有 hits.sh 浏览量、
没有下载数接口 —— 所以下载数 = GitHub + GitCode，浏览量 = Gitee + GitCode。

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


def gitcode_downloads(repo):
    try:
        d = _get_json(
            "https://gitcode.com/api/v5/repos/%s/%s/download_statistics" % (OWNER, repo))
        return int(d.get("download_statistics_total") or 0)
    except Exception as e:
        print("  [WARN] GitCode 下载数取不到: %s" % e, file=sys.stderr)
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
    gitee = hits_count("https://hits.sh/gitee.com/%s/%s.svg" % (OWNER, repo))
    gitcode = hits_count("https://hits.sh/gitcode.com/%s/%s.svg" % (OWNER, repo))
    return gitee, gitcode


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
    gc = gitcode_downloads(a.repo)
    g_old, g_new = views(a.repo)

    if gh is None and gc is None:
        print("下载数两边都取不到，放弃下载数更新", file=sys.stderr)
    else:
        dl_total = (gh or 0) + (gc or 0)
        print("下载：GitHub=%s GitCode=%s 合计=%s" % (gh, gc, dl_total))
    if g_old is None and g_new is None:
        print("浏览量两边都取不到，放弃浏览量更新", file=sys.stderr)
    else:
        v_total = (g_old or 0) + (g_new or 0)
        print("浏览：Gitee=%s GitCode=%s 合计=%s" % (g_old, g_new, v_total))

    if a.print:
        return 0
    if a.out and (gh is not None or gc is not None):
        _write_endpoint(a.out, "下载", (gh or 0) + (gc or 0))
        print("已写入 %s" % a.out)
    if a.views_out and (g_old is not None or g_new is not None):
        _write_endpoint(a.views_out, "浏览", (g_old or 0) + (g_new or 0))
        print("已写入 %s" % a.views_out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
