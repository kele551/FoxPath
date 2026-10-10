#!/usr/bin/env python3
"""把狐径的源码文件发布到 GitHub 仓库。

用法:
    GH_TOKEN=<token> python publish_files.py

用 API 逐个上传文件, 不依赖 git push(本机 git push 走代理有问题)。
"""
import base64
import json
import os
import sys
import urllib.error
import urllib.request

OWNER = 'kele551'
REPO = 'FoxPath'
API = 'https://api.github.com'

# 2026-10-10：删掉四个一次性图标脚本条目。
#   create_icon_octocat.py —— 仓库里早已不存在（本体已归档到 logs\归档-遗留脚本\），
#       却一直留在清单里；put_file 对不存在的文件只打印"跳过(不存在)"并返回 False，
#       于是其余文件全成功也永远打印"完成 14/15"并返回失败码。
#   create_icon.py / create_icon_from_image.py / make_icon_from_user_image.py ——
#       一次性脚本，写死了作者机器路径（其中一个还写着 Octocat 素材），与
#       COMPLIANCE.md「图标为自绘、不含任何第三方吉祥物或标志」的声明冲突。
#       app.ico 已入库，构建完全不需要它们。
FILES = [
    'README.md',
    'LICENSE',
    '.gitignore',
    'github_direct.py',
    'build_exe.py',
    'publish_files.py',
    'app.ico',
    '使用说明.txt',
    'release-notes.md',
    'Fix-GitHub.ps1',
    'Run-GitHubFix.bat',
]

VERSION = 'v1.0.8'      # 提交信息里的版本号, 改版本时同步改这里(已并入 tools/publish.py 的自动改版)

HERE = os.path.dirname(os.path.abspath(__file__))


def get_sha(token, path):
    """取远端同名文件当前的 sha。

    GitHub 的 contents API 更新已存在的文件时**必须**带 sha, 否则返回
    422 "sha wasn't supplied" —— 旧版只在首次上传时能用, 再跑一次每个
    已存在的文件都会 FAIL。
    """
    req = urllib.request.Request(
        '%s/repos/%s/%s/contents/%s' % (API, OWNER, REPO, path),
        headers={'Authorization': 'Bearer ' + token,
                 'Accept': 'application/vnd.github+json',
                 'User-Agent': 'foxpath-publisher'})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read().decode('utf-8')).get('sha')
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def put_file(token, path, message):
    src = os.path.join(HERE, path)
    if not os.path.exists(src):
        print('  跳过(不存在): %s' % path)
        return False
    with open(src, 'rb') as f:
        content = base64.b64encode(f.read()).decode('ascii')
    body = {'message': message, 'content': content}
    try:
        sha = get_sha(token, path)
    except Exception as e:
        # 403(令牌/限流)/网络异常都在这里接住, 不要让整轮发布直接 traceback 中断
        print('  FAIL %-32s 取远端 sha 失败: %s' % (path, e))
        return False
    if sha:
        body['sha'] = sha
    data = json.dumps(body).encode('utf-8')
    req = urllib.request.Request(
        '%s/repos/%s/%s/contents/%s' % (API, OWNER, REPO, path),
        data=data, method='PUT',
        headers={
            'Authorization': 'Bearer ' + token,
            'Accept': 'application/vnd.github+json',
            'Content-Type': 'application/json',
            'User-Agent': 'foxpath-publisher',
        })
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            res = json.loads(r.read().decode('utf-8'))
        print('  OK  %-32s %s' % (path, res.get('content', {}).get('size', '?')))
        return True
    except urllib.error.HTTPError as e:
        detail = e.read().decode('utf-8', 'replace')[:200]
        print('  FAIL %-32s %s %s' % (path, e.code, detail))
        return False


def main():
    token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
    if not token:
        print('需要 GH_TOKEN 环境变量')
        sys.exit(1)
    print('发布到 %s/%s' % (OWNER, REPO))
    ok = 0
    for p in FILES:
        if put_file(token, p, '狐径 FoxPath %s' % VERSION):
            ok += 1
    print('完成: %d/%d' % (ok, len(FILES)))
    return 0 if ok == len(FILES) else 1


if __name__ == '__main__':
    sys.exit(main())