# -*- coding: utf-8 -*-
r"""狐径 FoxPath —— 一键发布流水线（Gitee 主 + GitHub 镜像）

和壁纸助手那份 `tools/publish.py` 是同一套路，只是产物/版本来源不同。

依赖: 一枚 Gitee 私人令牌（仅勾 projects 权限），存一次长期复用。
GitHub 侧走 `F:\Harness\tools\github_push.py`（纯 API，不用 github.com 的 git 端口）。

用法:
    python tools/publish.py set-token <令牌>
    python tools/publish.py whoami
    python tools/publish.py release 1.0.6              # 只发 Gitee
    python tools/publish.py release 1.0.6 --github     # 双平台（用户要求两个都发）
    python tools/publish.py release 1.0.6 --skip-build # 已有 exe，只做发布
    python tools/publish.py release 1.0.6 --notes 文件.md

release 依次做:
    ① 改版本号 (github_direct.py 的 APP_VERSION + README 徽章)
    ② 打包 (build_exe.py) -> FoxPath.exe（文件名不带版本号）
    ③ 生成升级源 version.json（必须与本次 exe 同一份）
    ④ 提交 + 打 tag + 推 Gitee
    ⑤ Gitee 建发行版 + 上传 FoxPath.exe / version.json
    ⑥ 同步 GitHub（代码 + tag + Release + 附件）
    ⑦ 验真：两个平台各下载回来比对 SHA256
"""
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import time
from urllib.parse import quote
from pathlib import Path

import requests

REPO_DIR = Path(__file__).resolve().parent.parent
OWNER, REPO = 'kele551', 'FoxPath'
BRANCH = 'main'
GITEE_API = 'https://gitee.com/api/v5'
GITEE_WEB = 'https://gitee.com'
TOKEN_CANDIDATES = [
    r'F:\Harness\secrets\raw\workbuddy-secrets\gitee_token',
    r'C:\Users\kele551\.workbuddy\secrets\gitee_token',
]
PY = r'F:\Harness\toolchain\python\envs\default\Scripts\python.exe'
GIT_EXEC_PATH = r'F:/Harness/toolchain/PortableGit/versions/1.2.0/mingw64/bin'
GIT_EXE = GIT_EXEC_PATH + '/git.exe'        # 绝对路径: 有的执行环境按名字找不到 git(WinError 2)
GH_PUSH = r'F:\Harness\tools\github_push.py'
EXE_NAME = 'FoxPath.exe'            # version.json 里写的就是这个名字

VER_FILES = [
    ('github_direct.py', re.compile(r"(APP_VERSION\s*=\s*')[0-9.]+(')"),
     lambda v: r"\g<1>%s\g<2>" % v),
    ('README.md', re.compile(r'(version-v)[0-9.]+(-blue)'),
     lambda v: r"\g<1>%s\g<2>" % v),
]


# ---------- 令牌 ----------
def save_token(tok):
    p = Path(TOKEN_CANDIDATES[0])
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(tok.strip(), encoding='utf-8')
    print('令牌已存到', p)


def load_token():
    t = os.environ.get('GITEE_TOKEN')
    if t:
        return t.strip()
    for c in TOKEN_CANDIDATES:
        p = Path(c)
        if p.exists():
            return p.read_text(encoding='utf-8').strip()
    return None


def api(method, path, token, **kw):
    p = dict(kw.get('params') or {})
    p['access_token'] = token
    kw['params'] = p
    kw.setdefault('timeout', 60)
    r = requests.request(method, GITEE_API + path, **kw)
    if r.status_code >= 400:
        raise RuntimeError('API %s %s -> %s %s' % (method, path, r.status_code, r.text[:300]))
    return r.json() if r.text.strip() else {}


# ---------- 本地 ----------
def bump_version(ver):
    changed = []
    for name, pat, rep in VER_FILES:
        f = REPO_DIR / name
        txt = f.read_text(encoding='utf-8')
        new = pat.sub(rep(ver), txt, count=1)
        if new != txt:
            f.write_text(new, encoding='utf-8', newline='')   # 保住原行尾(CRLF)
            changed.append(name)
    print('① 版本号已改:', ', '.join(changed) if changed else '(已是该版本)')
    return changed


def make_version_json(notes=''):
    out = run([PY, 'make_version_json.py', '--notes', notes or ''])
    print('③ 升级源 version.json:', out.strip().splitlines()[-1] if out.strip() else '')
    return REPO_DIR / 'version.json'


def run(cmd, cwd=REPO_DIR, check=True):
    e = os.environ.copy()
    e['GIT_EXEC_PATH'] = GIT_EXEC_PATH
    e['PATH'] = GIT_EXEC_PATH.replace('/', os.sep) + os.pathsep + e.get('PATH', '')
    cmd = list(cmd)
    if cmd and cmd[0] == 'git':             # 不靠 PATH 找, 直接用绝对路径
        cmd[0] = GIT_EXE.replace('/', os.sep)
    print('   $', ' '.join(cmd))
    r = subprocess.run(cmd, cwd=str(cwd), env=e,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = r.stdout.decode('utf-8', 'replace')
    if check and r.returncode != 0:
        print(out)
        raise RuntimeError('命令失败: %s' % ' '.join(cmd))
    return out


def git_commit_push(ver):
    run(['git', 'add', '-A'])
    if run(['git', 'diff', '--cached', '--name-only']).strip():
        run(['git', '-c', 'user.name=kele551', '-c', 'user.email=75219857@qq.com',
             'commit', '-m', 'release: v%s' % ver])
    else:
        print('   工作区没有新改动, 跳过本次提交(只补发版)')
    if not run(['git', 'tag', '-l', 'v%s' % ver]).strip():
        run(['git', '-c', 'user.name=kele551', '-c', 'user.email=75219857@qq.com',
             'tag', '-a', 'v%s' % ver, '-m', 'v%s' % ver])   # 打 tag 同样要显式带身份
        run(['git', 'push', 'origin', 'v%s' % ver])
    else:
        print('   tag v%s 已存在, 不重复创建' % ver)
    run(['git', 'push', 'origin', BRANCH])
    print('④ 代码与 tag 已推 Gitee')


# ---------- 发行版 ----------
def gitee_release(ver, token, assets, notes):
    tag = 'v%s' % ver
    try:
        rel = api('GET', '/repos/%s/%s/releases/tags/%s' % (OWNER, REPO, tag), token)
    except Exception:
        rel = None
    if rel and rel.get('id'):
        print('⑤ 发行版已存在, id =', rel['id'])
    else:
        rel = api('POST', '/repos/%s/%s/releases' % (OWNER, REPO), token, json={
            'tag_name': tag, 'name': tag, 'body': notes or tag,
            'target_commitish': BRANCH, 'prerelease': False})
        print('⑤ 发行版已创建, id =', rel.get('id'))
    rid = rel['id']
    exist = api('GET', '/repos/%s/%s/releases/%s/attach_files' % (OWNER, REPO, rid), token)
    have = {a.get('name'): a['id'] for a in (exist if isinstance(exist, list) else [])}
    for path in assets:
        name = os.path.basename(str(path))
        if name in have:
            api('DELETE', '/repos/%s/%s/releases/%s/attach_files/%s'
                % (OWNER, REPO, rid, have[name]), token)
            print('   旧附件已删:', name)
        with open(str(path), 'rb') as f:
            r = requests.post(
                '%s/repos/%s/%s/releases/%s/attach_files' % (GITEE_API, OWNER, REPO, rid),
                params={'access_token': token},
                files={'file': (name, f, 'application/octet-stream')}, timeout=1800)
        if r.status_code >= 400:
            raise RuntimeError('附件上传失败 %s %s %s' % (name, r.status_code, r.text[:200]))
        print('   附件已上传:', name, os.path.getsize(str(path)), 'B')


def sync_github(ver, assets, notes_file):
    cmd = [PY, GH_PUSH, '--dir', str(REPO_DIR), '--repo', '%s/%s' % (OWNER, REPO),
           '--branch', BRANCH, '--tag', 'v%s' % ver,
           '--message', 'release: v%s' % ver]
    for a in assets:
        cmd += ['--asset', str(a)]
    if notes_file and os.path.exists(str(notes_file)):
        cmd += ['--notes-file', str(notes_file)]
    run(cmd)
    print('⑥ GitHub 代码 / tag / Release / 附件 已同步')


# ---------- 验真 ----------
def _download(url):
    for _ in range(3):
        try:
            r = requests.get(url, timeout=900)
            if r.status_code == 200:
                return r.content
        except Exception:
            pass
        time.sleep(4)
    return None


def verify(ver, assets):
    ok = True
    for p in assets:
        p = str(p)
        name = os.path.basename(p)
        want = hashlib.sha256(open(p, 'rb').read()).hexdigest()
        for label, url in (
                ('Gitee ', '%s/%s/%s/releases/download/v%s/%s'
                 % (GITEE_WEB, OWNER, REPO, ver, quote(name))),
                ('GitHub', 'https://github.com/%s/%s/releases/download/v%s/%s'
                 % (OWNER, REPO, ver, quote(name)))):
            data = _download(url)
            if data is None:
                print('  [FAIL] %s %-16s 下载失败' % (label, name))
                ok = False
                continue
            same = hashlib.sha256(data).hexdigest() == want
            ok = ok and same
            print('  [%s] %s %-16s %9d B  一致=%s'
                  % ('PASS' if same else 'FAIL', label, name, len(data), same))
    print('   下载页:', '%s/%s/%s/releases/tag/v%s' % (GITEE_WEB, OWNER, REPO, ver))
    return ok


# ---------- 入口 ----------
def cmd_release(ver, skip_build=False, notes_file=None, with_github=False):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
    token = load_token()
    if not token:
        sys.exit('没有令牌, 先跑: python tools/publish.py set-token <令牌>')
    t0 = time.time()

    notes = None
    if notes_file:
        notes = Path(notes_file).read_text(encoding='utf-8')
    else:
        rn = REPO_DIR / 'release-notes.md'
        if rn.exists():
            notes = rn.read_text(encoding='utf-8')

    bump_version(ver)
    if not skip_build:
        out = run([PY, 'build_exe.py'])
        print('② 打包完成:', out.strip().splitlines()[-1] if out.strip() else '')

    exe = REPO_DIR / EXE_NAME
    if not exe.exists():
        sys.exit('找不到 %s, 打包可能失败了' % exe)
    print('   exe =', exe, exe.stat().st_size, 'B')

    vj = make_version_json('')
    assets = [exe, vj]

    git_commit_push(ver)
    gitee_release(ver, token, assets, notes)
    if with_github:
        nf = notes_file
        if not nf:
            nf = REPO_DIR / '_notes.md'
            nf.write_text(notes or ('v%s' % ver), encoding='utf-8')
        sync_github(ver, assets, nf)
        if not notes_file and Path(nf).exists():
            Path(nf).unlink()
    else:
        print('⑥ 跳过 GitHub (加 --github 才同步)')
    print('⑦ 验真:')
    ok = verify(ver, assets)
    print('全部完成, 用时 %.0f 秒, 验真=%s' % (time.time() - t0, ok))
    return 0 if ok else 1


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    a = sys.argv[1]
    if a == 'set-token' and len(sys.argv) > 2:
        save_token(sys.argv[2])
        u = api('GET', '/user', sys.argv[2].strip())
        print('令牌有效, 用户 =', u.get('login') or u.get('name'))
    elif a == 'whoami':
        t = load_token()
        if not t:
            sys.exit('没有存过令牌')
        u = api('GET', '/user', t)
        print('用户 =', u.get('login') or u.get('name'))
    elif a == 'release' and len(sys.argv) > 2:
        sys.exit(cmd_release(sys.argv[2],
                             skip_build='--skip-build' in sys.argv,
                             with_github='--github' in sys.argv,
                             notes_file=(sys.argv[sys.argv.index('--notes') + 1]
                                         if '--notes' in sys.argv else None)))
    else:
        print(__doc__)


if __name__ == '__main__':
    main()
