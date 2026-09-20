#!/usr/bin/env python3
"""把狐径的源码文件发布到 GitHub 仓库。

用法:
    GH_TOKEN=<token> python publish_files.py

用 API 逐个上传文件, 绕过 git push(本机 git push 走代理有问题)。
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

FILES = [
    'README.md',
    'LICENSE',
    '.gitignore',
    'github_direct.py',
    'build_exe.py',
    'make_icon_from_user_image.py',
    'app.ico',
]

HERE = os.path.dirname(os.path.abspath(__file__))


def put_file(token, path, message):
    src = os.path.join(HERE, path)
    if not os.path.exists(src):
        print('  跳过(不存在): %s' % path)
        return False
    with open(src, 'rb') as f:
        content = base64.b64encode(f.read()).decode('ascii')
    body = {'message': message, 'content': content}
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
        if put_file(token, p, '狐径 FoxPath v1.0.0 首次提交'):
            ok += 1
    print('完成: %d/%d' % (ok, len(FILES)))


if __name__ == '__main__':
    main()