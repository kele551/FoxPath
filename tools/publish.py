# -*- coding: utf-8 -*-
r"""狐径 FoxPath —— 一键发布流水线（Gitee 主 + GitHub 镜像）

和壁纸助手那份 `tools/publish.py` 是同一套路，只是产物/版本来源不同。

依赖: 一枚 Gitee 私人令牌（仅勾 projects 权限），存一次长期复用。
GitHub 侧走一个纯 REST 的推送脚本（不用 github.com 的 git 端口；路径可用环境变量 FOXPATH_GH_PUSH 覆盖）。

用法:
    python tools/publish.py set-token <令牌>
    python tools/publish.py whoami
    python tools/publish.py release 1.0.6              # 只发 Gitee
    python tools/publish.py release 1.0.6 --github     # 双平台（用户要求两个都发）
    python tools/publish.py release 1.0.6 --skip-build # 已有 exe，只做发布
    python tools/publish.py release 1.0.6 --notes 文件.md

不带 --notes 时读 release-notes.md，但会校验它首行的版本号与本次要发的版本一致：
不一致（还是上一版的文案）直接中止，不拿旧文案发新版。

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
# ---- 本机私有配置（可选，永不进仓库）----------------------------------------
# 公开仓库里不写任何维护者本机路径。本机要用的解释器 / git / 推送脚本 / 令牌位置，
# 一律按：① 环境变量 → ② 本机私有配置 ~/.foxpath-publish.json → ③ 与机器无关的默认值。
# 私有配置文件示例（放在用户主目录，文件名前面有个点）：
#   {"python": "C:\\\\Python313\\\\python.exe", "git_dir": "C:\\\\Program Files\\\\Git\\\\mingw64\\\\bin",
#    "gh_push": "D:\\\\tools\\\\github_push.py", "token_file": "D:\\\\private\\\\gitee_token"}
_CFG_PATH = Path.home() / '.foxpath-publish.json'
_CFG = {}
if _CFG_PATH.is_file():
    try:
        _CFG = json.loads(_CFG_PATH.read_text(encoding='utf-8'))
    except Exception as _e:
        print('警告: %s 解析失败(%s)，按"没有本机配置"继续' % (_CFG_PATH, _e), file=sys.stderr)

_ENV_TOKEN_FILE = os.environ.get('GITEE_TOKEN_FILE') or _CFG.get('token_file')
# 都没给就落到仓库内的 .gitee_token（已 gitignore）；也可以直接用环境变量 GITEE_TOKEN 传令牌本身
TOKEN_CANDIDATES = [_ENV_TOKEN_FILE] if _ENV_TOKEN_FILE else [str(REPO_DIR / '.gitee_token')]
# 2026-10-10 记下的坑（务必保留这条知识）：打包用的解释器必须能覆盖 —— 这个 PY 既用来跑
# build_exe.py（打包），也用来跑发版前自检。**打包绝不能用 venv 混搭环境**：那种「独立
# 3.13 的 DLL + 另一个 venv 的库」组合打出来的 exe 一启动就弹
#   Security validation failure: unexpected name of application's home directory!
# （真机复现过，见维护者工作区的发布记录）。所以要打包时请用环境变量 FOXPATH_PY 或
# ~/.foxpath-publish.json 里的 python 明确指定一个独立的 Python 3.13。
PY = os.environ.get('FOXPATH_PY') or _CFG.get('python') or sys.executable


def _find_git_dir():
    """找 git.exe 所在目录：环境变量 → 本机配置 → PATH → 常见安装位置；找不到返回空串。"""
    for _c in (os.environ.get('FOXPATH_GIT'), _CFG.get('git_dir')):
        if _c and Path(_c, 'git.exe').is_file():
            return str(_c).replace('\\', '/')
    _w = shutil.which('git')
    if _w:
        return str(Path(_w).parent).replace('\\', '/')
    for _c in (r'C:\Program Files\Git\cmd', r'C:\Program Files (x86)\Git\cmd'):
        if Path(_c, 'git.exe').is_file():
            return _c.replace('\\', '/')
    return ''


GIT_EXEC_PATH = _find_git_dir()
# 有绝对路径就用绝对路径: 有的执行环境按名字找不到 git(WinError 2)
GIT_EXE = (GIT_EXEC_PATH + '/git.exe') if GIT_EXEC_PATH else 'git'
GH_PUSH = os.environ.get('FOXPATH_GH_PUSH') or _CFG.get('gh_push') or str(REPO_DIR / 'tools' / 'github_push.py')
EXE_NAME = 'FoxPath.exe'            # version.json 里写的就是这个名字

VER_FILES = [
    ('github_direct.py', re.compile(r"(APP_VERSION\s*=\s*')[0-9.]+(')"),
     lambda v: r"\g<1>%s\g<2>" % v),
    ('README.md', re.compile(r'(version-v)[0-9.]+(-blue)'),
     lambda v: r"\g<1>%s\g<2>" % v),
    ('publish_files.py', re.compile(r"^(VERSION\s*=\s*'v)[0-9.]+(')", re.M),
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
    if GIT_EXEC_PATH:                       # 没找到 git 目录就交给 PATH 上那个 git
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
        run(['git', '-c', 'user.name=kele551', '-c', 'user.email=kele551@users.noreply.github.com',
             'commit', '-m', 'release: v%s' % ver])
    else:
        print('   工作区没有新改动, 跳过本次提交(只补发版)')
    if not run(['git', 'tag', '-l', 'v%s' % ver]).strip():
        run(['git', '-c', 'user.name=kele551', '-c', 'user.email=kele551@users.noreply.github.com',
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


def load_notes(ver, notes_file=None):
    """取本次的发布说明。

    优先 --notes 指定的文件；否则读 release-notes.md —— 但那份文件的首行版本号必须与
    本次要发的版本一致。以前是无条件拿它当文案，于是"忘了带 --notes"就会把上一版的
    说明发到新版发行页上（张冠李戴）。现在不一致直接中止，宁可停下来也不发错。
    """
    if notes_file:
        p = Path(notes_file)
        if not p.exists():
            sys.exit('--notes 指定的文件不存在: %s' % p)
        return p.read_text(encoding='utf-8')

    rn = REPO_DIR / 'docs' / 'release-notes.md'
    if not rn.exists():
        sys.exit('既没有 --notes，也找不到 docs/release-notes.md，无法确定发布说明。\n'
                 '请补一份 docs/release-notes.md（首行形如「狐径 FoxPath v%s — 标题」）'
                 '或用 --notes <文件> 指定。' % ver)
    text = rn.read_text(encoding='utf-8')
    first = next((l for l in text.splitlines() if l.strip()), '')
    m = re.search(r'v?(\d+(?:\.\d+)+)', first)
    if not m:
        sys.exit('release-notes.md 首行没有版本号（应形如「狐径 FoxPath v%s — 标题」）:\n  %s' % (ver, first))
    if m.group(1) != ver:
        sys.exit('release-notes.md 还是 v%s 的文案，本次要发的是 v%s —— 直接发会让发行页挂着旧说明。\n'
                 '请先把 release-notes.md 改成 v%s 的内容，或用 --notes <文件> 指定。'
                 % (m.group(1), ver, ver))
    print('   发布说明: release-notes.md (首行版本 v%s, 与本次一致)' % m.group(1))
    return text


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

    notes = load_notes(ver, notes_file)

    bump_version(ver)
    if not skip_build:
        out = run([PY, 'build_exe.py'])
        print('② 打包完成:', out.strip().splitlines()[-1] if out.strip() else '')

    exe = REPO_DIR / EXE_NAME
    if not exe.exists():
        sys.exit('找不到 %s, 打包可能失败了' % exe)
    print('   exe =', exe, exe.stat().st_size, 'B')

    vj = make_version_json('')

    # ── 发版铁律：先自检、后发布（2026-10-08 用户要求「以后都这样」）──────
    # 起因：v1.0.6 发布后才发现"升级后程序可能起不来"(杀软拦第一次启动)。
    # 位置很关键：必须在 make_version_json 之后 —— 自检要校验"即将发出去的
    # version.json 与 exe 是否一致"，放前面会永远报不一致。
    if '--skip-preflight' in sys.argv:
        print('   ⚠ 已显式跳过发版前自检（--skip-preflight）—— 请在 logs\\ 里写明原因')
    else:
        pf = REPO_DIR.parent / 'tools' / 'preflight_release.py'
        if not pf.exists():
            sys.exit('找不到发版前自检脚本 %s —— 不许发布（铁律）' % pf)
        print('   ── 发版前自检（必须全绿）──')
        r = subprocess.run([PY, str(pf), str(exe)], cwd=str(REPO_DIR.parent))
        if r.returncode != 0:
            sys.exit('❌ 发版前自检未通过，已中止发布。修好再发（或 --skip-preflight 紧急跳过）')
        print('   ✅ 自检全绿，继续发布')

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
