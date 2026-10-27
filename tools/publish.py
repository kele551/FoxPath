# -*- coding: utf-8 -*-
r"""狐径 FoxPath —— 一键发布流水线（GitCode 主 + GitHub 镜像）

和壁纸助手那份 `tools/publish.py` 是同一套路，只是产物/版本来源不同。

依赖: 一枚 GitCode 私人令牌（存一次长期复用）。HTTP 层只用 Python 标准库 ——
本机没有 third-party HTTP 库，以前那版依赖它，结果在这台机器上**整条流水线跑不起来**，
只能临时手搓脚本发版（2026-10-26 就是这个坑，见工作区发布记录）。
GitHub 侧走本机登录态的 gh.exe（它自己会挑线路，比手搓 REST 稳）；路径可用
环境变量 FOXPATH_GH 或 ~/.foxpath-publish.json 的 "gh" 覆盖。

【2026-10-26 换目标】Gitee 那份老仓库已停更、客户端也不再去取（老地址一律不出现），
所以本脚本的发布目标改成：GitCode（国内主源）+ GitHub（国外镜像）。
AtomGit 不用推 —— 它按分钟级自动镜像 GitHub。

用法:
    python tools/publish.py set-token <令牌>
    python tools/publish.py whoami
    python tools/publish.py release 1.2.3                # 只发 GitCode
    python tools/publish.py release 1.2.3 --github       # 双平台（用户要求两个都发）
    python tools/publish.py release 1.2.3 --skip-build   # 已有 exe，只做发布
    python tools/publish.py release 1.2.3 --notes 文件.md
    python tools/publish.py verify 1.2.3                 # 只读：线上验真，什么都不发

不带 --notes 时读 release-notes.md，但会校验它首行的版本号与本次要发的版本一致：
不一致（还是上一版的文案）直接中止，不拿旧文案发新版。

release 依次做:
    ① 改版本号 (github_direct.py 的 APP_VERSION + README 徽章)
    ② 打包 (build_exe.py) -> FoxPath.exe（文件名不带版本号）
    ③ 生成升级源 version.json（必须与本次 exe 同一份）
    ③+ 用 Ed25519 私钥给 version.json 的**原始字节**签名 -> version.json.sig（2026-10-16 起）
       私钥位置：环境变量 FOXPATH_ED25519_KEY → ~/.foxpath-publish.json 的 "ed25519_key" → 找不到就中止
    ④ 提交 + 打 tag + 推 GitCode（含 version.json.sig）
    ⑤ GitCode 建发行版 + 上传 FoxPath.exe / version.json / version.json.sig
    ⑥ 同步 GitHub（代码 + tag + Release + 附件）
    ⑦ 验真：两个平台各下载回来比对 SHA256；并**回读线上 version.json + .sig**，
       用客户端内置公钥真验一遍（验不过就算发布失败 —— 别让用户先发现升级通道是断的）

发版铁律（顺序不能换）：④ 里 **tag 先推、main 最后推**。升级源就是 main 上那份
version.json，main 一推上去线上立刻开始提示升级 —— 那时附件必须已经躺好。
"""
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
from urllib import request as _rq
from pathlib import Path

quote = urllib.parse.quote          # 老代码里到处直接用 quote()，这里补个名字

# 2026-10-27：与另外两款同一套做法 —— Windows 控制台默认 GBK，模块顶上就钉成 UTF-8，
# 免得哪天文档/日志里出现一个 GBK 编不了的字符，脚本在打印 help 这一步就退出。
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

REPO_DIR = Path(__file__).resolve().parent.parent
OWNER, REPO = 'kele551', 'FoxPath'
BRANCH = 'main'
GC_API = 'https://gitcode.com/api/v5'
GC_WEB = 'https://gitcode.com'
GH_REPO = '%s/%s' % (OWNER, REPO)
# 推送目标：GitCode（国内主源）+ GitHub（国外镜像）。origin 是停更的 Gitee，不再往那儿推。
REMOTES = ('gitcode', 'github')
# ---- 本机私有配置（可选，永不进仓库）----------------------------------------
# 公开仓库里不写任何维护者本机路径。本机要用的解释器 / git / gh / 令牌位置，
# 一律按：① 环境变量 → ② 本机私有配置 ~/.foxpath-publish.json → ③ 与机器无关的默认值。
# 私有配置文件示例（放在用户主目录，文件名前面有个点）：
#   {"python": "C:\\\\Python313\\\\python.exe", "git_dir": "C:\\\\Program Files\\\\Git\\\\mingw64\\\\bin",
#    "gh": "C:\\\\tools\\\\gh.exe", "token_file": "D:\\\\private\\\\gitcode_token"}
_CFG_PATH = Path.home() / '.foxpath-publish.json'
_CFG = {}
if _CFG_PATH.is_file():
    try:
        _CFG = json.loads(_CFG_PATH.read_text(encoding='utf-8'))
    except Exception as _e:
        print('警告: %s 解析失败(%s)，按"没有本机配置"继续' % (_CFG_PATH, _e), file=sys.stderr)

_ENV_TOKEN_FILE = os.environ.get('GITCODE_TOKEN_FILE') or _CFG.get('token_file')
# 都没给就落到仓库内的 .gitcode_token（已 gitignore）；也可以直接用环境变量 GITCODE_TOKEN 传令牌本身
TOKEN_CANDIDATES = [_ENV_TOKEN_FILE] if _ENV_TOKEN_FILE else [str(REPO_DIR / '.gitcode_token')]
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
GH = os.environ.get('FOXPATH_GH') or _CFG.get('gh') or shutil.which('gh') or 'gh'
# GitHub 的 git 端口在这台机器上时通时断，失败时借本地代理重试（只在命令行 -c 上带，不改 config）
GIT_PROXY = os.environ.get('FOXPATH_GIT_PROXY') or _CFG.get('git_proxy') or 'http://127.0.0.1:8787'
EXE_NAME = 'FoxPath.exe'            # version.json 里写的就是这个名字

# ---- Ed25519 签名私钥（升级通道加固，2026-10-16）------------------------------
# 取值顺序与上面那套完全一致：① 环境变量 FOXPATH_ED25519_KEY →
# ② 本机私有配置 ~/.foxpath-publish.json 的 "ed25519_key" → ③ 找不到就**明确报错**。
# 私钥内容只在签名那一刻读一次；本文件里既不打印它、也不把路径写死成维护者机器上的样子。
ED25519_KEY = os.environ.get('FOXPATH_ED25519_KEY') or _CFG.get('ed25519_key') or ''


def resolve_sign_key():
    """确定本次发版用哪把私钥；拿不到就报清楚"该怎么办"，绝不静默跳过签名。

    为什么宁可不发版：客户端**只认验过签的升级源**。要是这次漏了签名，线上就会多出
    一份"新版本号但签名为空/不匹配"的 version.json —— 已装用户一律被拒绝，等于升级通道断掉。
    """
    if ED25519_KEY:
        p = Path(ED25519_KEY)
        if p.is_file():
            return p
        sys.exit('配置里的 Ed25519 私钥文件不存在: %s\n'
                 '（环境变量 FOXPATH_ED25519_KEY，或 ~/.foxpath-publish.json 的 "ed25519_key"）' % p)
    sys.exit('找不到 Ed25519 签名私钥 —— 拒绝发布（客户端只认验过签的升级源）。\n'
             '任选一种方式告诉本脚本私钥在哪（私钥本身**不要**放进仓库）：\n'
             '  ① 环境变量:  set FOXPATH_ED25519_KEY=<私钥文件路径>\n'
             '  ② 本机私有配置 ~/.foxpath-publish.json 里加一行:  "ed25519_key": "<私钥文件路径>"\n'
             '私钥文件的内容是 64 个十六进制字符（32 字节种子）。')

VER_FILES = [
    ('github_direct.py', re.compile(r"(APP_VERSION\s*=\s*')[0-9.]+(')"),
     lambda v: r"\g<1>%s\g<2>" % v),
    # README 早已不用静态版本徽章（改用 shields.io 动态徽章 img.shields.io/github/v/release），
    # 所以不能再匹配 version-vX.Y.Z-blue —— 那条规则早就一条都命中不了（死配置）。
    # 现在要改的是「版本记录」一节里那句当前版本文字。
    ('README.md', re.compile(r'(当前对外发布版本 \*\*v)[0-9.]+(\*\*)'),
     lambda v: r"\g<1>%s\g<2>" % v),
    # 安全政策里也写着「最新发布版（当前 **vX.Y.Z**）」，发版同样要改。
    ('docs/SECURITY.md', re.compile(r'(当前 \*\*v)[0-9.]+(\*\*)'),
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
    t = os.environ.get('GITCODE_TOKEN')
    if t:
        return t.strip()
    for c in TOKEN_CANDIDATES:
        p = Path(c)
        if p.exists():
            return p.read_text(encoding='utf-8').strip()
    return None


def api(method, path, token, payload=None, timeout=120, raw_body=None, headers=None, extra=None):
    """GitCode v5 接口：令牌走 access_token 查询参数（本机没有第三方 HTTP 库，纯标准库）。

    payload 走 JSON；raw_body 直接发原始字节。extra 是额外的查询参数（如 file_name）。
    返回解析后的 dict/list；非 2xx 抛 RuntimeError（带上前 300 字符正文，便于现场判断）。
    """
    p = {'access_token': token}
    p.update(extra or {})
    url = GC_API + path + '?' + urllib.parse.urlencode(p)
    hd = {'User-Agent': 'foxpath-publish'}
    hd.update(headers or {})
    data = None
    if payload is not None:
        data = json.dumps(payload).encode('utf-8')
        hd['Content-Type'] = 'application/json'
    elif raw_body is not None:
        data = raw_body
    req = _rq.Request(url, data=data, headers=hd, method=method)
    try:
        with _rq.urlopen(req, timeout=timeout) as r:
            body = r.read()
    except urllib.error.HTTPError as e:
        raise RuntimeError('API %s %s -> %s %s'
                           % (method, path, e.code, e.read()[:300].decode('utf-8', 'replace')))
    if not body.strip():
        return {}
    return json.loads(body.decode('utf-8', 'replace'))


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


def make_version_json(notes='', sign_key=None):
    """生成升级源 version.json；给了私钥就同时生成 version.json.sig（签名同一批字节）。"""
    cmd = [PY, 'make_version_json.py', '--notes', notes or '']
    if sign_key:
        cmd += ['--sign-key', str(sign_key)]
    out = run(cmd)
    print('③ 升级源 version.json:', out.strip().splitlines()[-1] if out.strip() else '')
    vj = REPO_DIR / 'version.json'
    sig = Path(str(vj) + '.sig')
    if sign_key:
        txt = sig.read_text(encoding='utf-8').strip() if sig.is_file() else ''
        if not re.fullmatch(r'[0-9a-fA-F]{128}', txt):
            sys.exit('version.json.sig 没生成或格式不对（应为 128 个十六进制字符，实际 %d 个）—— 拒绝发布。\n'
                     '客户端只认验过签的升级源，发一份没签名的出去会让已装用户一律被拒绝。' % len(txt))
        print('③+ Ed25519 签名: %s（%d 个十六进制字符，前 16 位 %s…）'
              % (sig.name, len(txt), txt[:16]))
    return vj, sig


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


GIT_ID = ['-c', 'user.name=海风（kele551）',
          '-c', 'user.email=kele551@users.noreply.github.com']
# 全局 git config 里没有身份（用户要求不改 config），所以每次提交/打标签都显式带上。


def _remote_exists(name):
    return name in run(['git', 'remote'], check=False)


def _git_raw(args):
    """跑一条 git，返回 (退出码, 输出)。推送成败只信退出码 —— 管道会把真实状态吞掉（踩过）。"""
    e = os.environ.copy()
    if GIT_EXEC_PATH:
        e['GIT_EXEC_PATH'] = GIT_EXEC_PATH
        e['PATH'] = GIT_EXEC_PATH.replace('/', os.sep) + os.pathsep + e.get('PATH', '')
    args = list(args)
    if args and args[0] == 'git':
        args[0] = GIT_EXE.replace('/', os.sep)
    print('   $', ' '.join(args))
    r = subprocess.run(args, cwd=str(REPO_DIR), env=e,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return r.returncode, r.stdout.decode('utf-8', 'replace')


def _push(remote, ref):
    """推一个 ref；GitHub 那条线本机时不时裸连不上，失败就带一次本地代理重试。

    代理地址优先环境变量 FOXPATH_GIT_PROXY / 本机配置 git_proxy（默认 127.0.0.1:8787，
    就是狐径自己的本地代理）。代理只在"这次推送"上用 -c 传进去，同样不落 git config。
    推完一律用 ls-remote 复核远端 sha：退出码只说明"这条命令没崩"，说明不了"远端变了"。
    """
    if not _remote_exists(remote):
        print('   跳过 %s：本仓库没有这个 remote' % remote)
        return False
    want = _git_raw(['git', 'rev-parse', 'HEAD' if ref == BRANCH else ref])[1].split()[-1]
    code, out = _git_raw(['git', 'push', remote, ref])
    if code != 0:
        print('   裸推失败(%s)，带本地代理 %s 再试一次' % (out.strip()[-160:], GIT_PROXY))
        code, out = _git_raw(['git', '-c', 'http.https://github.com/.proxy=' + GIT_PROXY,
                              'push', remote, ref])
        if code != 0:
            print('   带代理也失败:', out.strip()[-200:])
    remote_sha = (_git_raw(['git', 'ls-remote', remote, ref])[1].split() or ['', ''])[1:2]
    if remote_sha and remote_sha[0] == want:
        print('   pushed %s -> %s（远端 sha %s… 与本地一致）' % (ref, remote, want[:10]))
        return True
    raise RuntimeError('推送 %s -> %s 没生效：本地 %s，远端 %s'
                       % (ref, remote, want[:10], (remote_sha or ['(取不到)'])[0][:10]))


def git_commit_and_tag(ver):
    """提交 + 打 tag + **只推 tag**（升级源在 main 上，main 必须等附件就位后再推）。"""
    run(['git', 'add', '-A'])
    if run(['git', 'diff', '--cached', '--name-only']).strip():
        run(['git'] + GIT_ID + ['commit', '-m', 'release: v%s' % ver])
    else:
        print('   工作区没有新改动, 跳过本次提交(只补发版)')
    tag = 'v%s' % ver
    if not run(['git', 'tag', '-l', tag]).strip():
        run(['git'] + GIT_ID + ['tag', '-a', tag, '-m', tag])   # 打 tag 同样要显式带身份
    else:
        print('   tag %s 已存在, 不重复创建' % tag)
    for remote in REMOTES:
        _push(remote, tag)
    print('④ 代码已提交、tag %s 已推 %s（main 还没推，附件就位后再推 —— 顺序是铁律）'
          % (tag, '+'.join(REMOTES)))


def git_push_branch():
    """⑤⑥ 都做完、附件已验真之后，才让升级源在两个平台上生效。"""
    for remote in REMOTES:
        _push(remote, BRANCH)
    print('④+ main 已推 %s —— 此刻起线上才开始提示升级' % '+'.join(REMOTES))


# ---------- 发行版 ----------
def _gc_get_release(tag, token):
    """按 tag 取发行版。注意 GitCode 的响应里**没有 id 字段**（Gitee 有），一切按 tag 寻址。"""
    try:
        return api('GET', '/repos/%s/%s/releases/tags/%s' % (OWNER, REPO, quote(tag)), token)
    except Exception:
        return None


def gitcode_release(ver, token, assets, notes):
    """GitCode：建发行版 + 逐个附件走"取上传地址 → PUT 原始字节"两步。

    2026-10-26 实测过的正解（Gitee 那套 attach_files 接口在 GitCode 一律 404/405）：
      ① POST /repos/{o}/{r}/releases                 body 里 target_commitish=main
      ② GET  /repos/{o}/{r}/releases/{tag}/upload_url?file_name=xxx   → {url, headers}
      ③ PUT  文件原始字节到那个 OBS url，平台回调把附件登记到发行版上
    同名附件：先比大小，大小一致就当已传好跳过；**大小不同必须人工到网页上删掉旧的**
    （GitCode 没有可靠的删除附件接口，宁可停下来也不能让线上留两份不同字节的同名包）。
    """
    tag = 'v%s' % ver
    rel = _gc_get_release(tag, token)
    if rel and rel.get('tag_name') == tag:
        print('⑤ GitCode 发行版已存在:', tag, '| 附件', len(rel.get('assets') or []), '个')
    else:
        rel = api('POST', '/repos/%s/%s/releases' % (OWNER, REPO), token, payload={
            'tag_name': tag, 'name': tag, 'body': notes or tag,
            'target_commitish': BRANCH, 'prerelease': False})
        if not rel or not rel.get('tag_name'):
            raise RuntimeError('GitCode 建发行版失败: %s' % json.dumps(rel, ensure_ascii=False)[:300])
        print('⑤ GitCode 发行版已创建:', rel.get('tag_name'))
    have = {a.get('name'): a for a in ((_gc_get_release(tag, token) or {}).get('assets') or [])}
    for path in assets:
        p = str(path)
        name = os.path.basename(p)
        size = os.path.getsize(p)
        old = have.get(name)
        if old and old.get('size') == size:
            print('   附件已在（同名同大小，跳过）:', name, size, 'B')
            continue
        if old:
            raise RuntimeError('GitCode 上同名附件字节不同（线上 %s B / 本地 %d B）：%s\n'
                               '请到 %s/%s/%s/releases/tag/%s 删掉旧附件再重发。'
                               % (old.get('size'), size, name, GC_WEB, OWNER, REPO, tag))
        j = api('GET', '/repos/%s/%s/releases/%s/upload_url' % (OWNER, REPO, quote(tag)),
                token, extra={'file_name': name}, timeout=120)
        up = (j or {}).get('url') or ((j or {}).get('data') or {}).get('url')
        hd = (j or {}).get('headers') or ((j or {}).get('data') or {}).get('headers') or {}
        if not up:
            raise RuntimeError('拿不到上传地址: %s' % json.dumps(j, ensure_ascii=False)[:200])
        data = io.open(p, 'rb').read()
        h = dict(hd)
        h['Content-Length'] = str(len(data))
        req = _rq.Request(up, data=data, headers=h, method='PUT')
        with _rq.urlopen(req, timeout=1800) as r:
            if r.status not in (200, 201, 204):
                raise RuntimeError('附件 PUT 失败 %s -> %s' % (name, r.status))
        print('   附件已上传:', name, size, 'B')
    chk = _gc_get_release(tag, token) or {}
    names = [a.get('name') for a in (chk.get('assets') or [])]
    missing = [os.path.basename(str(p)) for p in assets if os.path.basename(str(p)) not in names]
    if missing:
        raise RuntimeError('GitCode 回读缺少附件（平台没登记上）:', ', '.join(missing))
    print('   下载页:', '%s/%s/%s/releases/tag/%s' % (GC_WEB, OWNER, REPO, tag))


def sync_github(ver, assets, notes_file):
    """GitHub 侧走 gh.exe（本机登录态自己挑线路），不用 github.com 的 git 端口。

    两个写死的坑：
      · `release create` **不能带 --target**：tag 已经 push 上去了，带了会报 already exists；
      · 附件名必须 ASCII（FoxPath.exe），中文名传上去会被破坏，老用户按名字取就 404。
    """
    tag = 'v%s' % ver
    code, out = _gh(['release', 'create', tag, '--title', tag,
                     '--notes-file', str(notes_file), '--repo', GH_REPO])
    if code != 0 and 'already exists' not in out.lower():
        raise RuntimeError('gh release create 失败: %s' % out.strip()[-400:])
    if code != 0:
        print('   GitHub 发行版已存在, 继续补附件')
    code, out = _gh(['release', 'upload', tag, '--clobber'] +
                    [str(a) for a in assets] + ['--repo', GH_REPO])
    if code != 0:
        raise RuntimeError('gh release upload 失败: %s' % out.strip()[-400:])
    print('⑥ GitHub 代码 / tag / Release / 附件 已同步')


def _gh(args):
    cmd = [GH] + args
    print('   $', ' '.join(cmd[:7]), '...' if len(cmd) > 7 else '')
    r = subprocess.run(cmd, cwd=str(REPO_DIR), capture_output=True, text=True,
                       encoding='utf-8', errors='replace', timeout=1800)
    return r.returncode, ((r.stdout or '') + (r.stderr or ''))


# ---------- 验真 ----------
# 两条超时口径必须分开（2026-10-26 热点那边踩过，这里一起收掉，免得下次发版重演）：
#   SOCK_TMO  一条连接上「一次 recv」的上限 —— 链路断了 60 s 就该换下一条，
#             而不是像从前那样 900 s × 3 轮：那等于"卡死了也看不出来"。
#   DEADLINE  **总时长**预算 —— 本机走代理从 GitHub 取字节的实测速率只有 ~48 KB/s，
#             十几兆的附件本来就要五六分钟；慢不等于错，但到点必须收，否则整条发版
#             流程会被一次验真拖成"看不出在跑还是卡住"。
SOCK_TMO = int(os.environ.get('FOXPATH_SOCK_TMO') or 60)
DEADLINE_SMALL = int(os.environ.get('FOXPATH_DEADLINE_SMALL') or 180)
DEADLINE_BIG = int(os.environ.get('FOXPATH_DEADLINE_BIG') or 900)


def _progress(label, got, expect, secs):
    print('  … %s 已取回 %.1f MB / %.1f MB（%.0f KB/s，用了 %d s）'
          % (label, got / 1048576.0, expect / 1048576.0 if expect else 0,
             got / max(secs, 1) / 1024.0, int(secs)))
    sys.stdout.flush()


def _download(url, timeout=SOCK_TMO, tries=2, headers=None, deadline=None, expect=0, label=''):
    """取一个 URL 的原始字节；失败重试，GitHub 那侧再借一次本地代理。

    维护机到 GitHub 的路**时通时断**（狐径自己就是为这个存在的），直连拿不到就
    走 GIT_PROXY（FOXPATH_GIT_PROXY / 本机配置里的 git_proxy，默认 127.0.0.1:8787，
    即狐径本体的代理端口）。代理只影响这台机器怎么"取到"字节，
    比对的是字节本身，结论不受影响。

    边下边攒、每 15 秒报一次进度；超过 deadline **整条放弃**（重试只会再扔进去十分钟）。
    """
    ops = [_rq.build_opener(_rq.ProxyHandler({}))]
    if GIT_PROXY and 'github' in url:
        ops.append(_rq.build_opener(_rq.ProxyHandler(
            {'http': GIT_PROXY, 'https': GIT_PROXY})))
    hd = {'User-Agent': 'foxpath-verify', 'Accept-Encoding': 'identity'}
    hd.update(headers or {})
    for _ in range(tries):
        for op in ops:
            t0 = time.time()
            next_report = 15
            try:
                req = _rq.Request(url, headers=hd)
                with op.open(req, timeout=timeout) as r:
                    if r.status != 200:
                        continue
                    buf = bytearray()
                    over = False
                    while True:
                        # read1：有多少取多少。read(n) 会一直等到凑满 n 字节或连接关闭 ——
                        # 那种慢链路下 deadline 永远轮不到（2026-10-26 那 15 MB 就是这么空转到没人知道在跑还是卡死）。
                        chunk = (r.read1(262144) if hasattr(r, "read1") else r.read(262144))
                        if not chunk:
                            break
                        buf += chunk
                        spent = time.time() - t0
                        if spent >= next_report:
                            _progress(label or url.split('//')[-1][:52], len(buf), expect, spent)
                            next_report = spent + 15
                        if deadline and spent > deadline:
                            print('  x %s 总时长预算 %d s 用尽：只取回 %d B / 需要 %d B'
                                  '（这是链路慢，不代表包有问题；要等它就调大预算环境变量）'
                                  % (label or url.split('//')[-1][:52], deadline,
                                     len(buf), expect))
                            sys.stdout.flush()
                            over = True
                            break
                    if over:
                        return None
                    if buf:
                        return bytes(buf)
            except Exception:
                continue
        time.sleep(4)
    return None


def gc_asset_url(ver, name):
    """GitCode 附件的下载口形状（2026-10-26 实测：与 Gitee 同名同形，不带令牌也能下）。"""
    return '%s/%s/%s/releases/download/%s/%s' % (GC_WEB, OWNER, REPO, 'v%s' % ver, quote(name))


def _gh_token():
    """问 gh.exe 要一次本机登录态的令牌 —— 只是给验真抬一次 API 速率上限，拿不到照样能验。

    这里**不走 _gh()**：那个的超时是 1800 s（上传附件要那么久），拿个令牌要不了 30 s，
    给它一小时只会把整轮验真拖成"看不出是在跑还是卡死"（热点那边 2026-10-26 就这么拖过）。
    """
    try:
        r = subprocess.run([GH, 'auth', 'token'], capture_output=True, text=True,
                           encoding='utf-8', errors='replace', timeout=30)
        return r.stdout.strip() if r.returncode == 0 else ''
    except Exception:
        return ''


def _gh_asset(ver, name, deadline=DEADLINE_BIG, expect=0):
    """github.com 裸下载口拿不到时，改走 api.github.com 的 assets 口取**同一个附件对象**。

    热点、壁纸两份早就有这条兜底，狐径以前没有 —— GitHub 裸口一抖就直接 FAIL。
    2026-10-26 实测：/releases/download/ 会 302 跳到 objects.githubusercontent.com，
    这台机器上要么几秒回来、要么慢到没边（走代理 ~36 KB/s），还撞过裸连 WinError 10060 /
    代理 502；同一天 api.github.com 的元数据口 0.9 s 就回。
    返回 (原始字节 or None, 平台自报的 sha256 or '')。**digest 一致不等于通过** ——
    那只是 GitHub 自己说"我这儿是这个 sha256"，闸门要的始终是真把字节取回来比。
    """
    hd = {'Accept': 'application/vnd.github+json', 'User-Agent': 'foxpath-verify'}
    tok = _gh_token()
    if tok:
        hd['Authorization'] = 'token ' + tok
    # 元数据口本机实测 0.9 s 就回，60 s × 1 次足够；拿不到就放弃这条路，别拖整轮
    raw = _download('https://api.github.com/repos/%s/%s/releases/tags/v%s'
                    % (OWNER, REPO, ver), 60, 1, hd, deadline=60, label='GitHub 发行元数据')
    if not raw:
        return None, ''
    try:
        rel = json.loads(raw.decode('utf-8', 'replace'))
    except Exception:
        return None, ''
    for a in rel.get('assets') or []:
        if a.get('name') != name:
            continue
        digest = (a.get('digest') or '').replace('sha256:', '').strip().lower()
        if not a.get('url'):
            return None, digest
        h = dict(hd)
        h['Accept'] = 'application/octet-stream'
        return (_download(a['url'], SOCK_TMO, 1, h, deadline=deadline,
                          expect=a.get('size') or expect,
                          label='GitHub %s（API 附件口）' % name), digest)
    return None, ''


def verify(ver, assets):
    ok = True
    for p in assets:
        p = str(p)
        name = os.path.basename(p)
        size = os.path.getsize(p)
        want = hashlib.sha256(open(p, 'rb').read()).hexdigest()
        dl = DEADLINE_BIG if size > 2 * 1024 * 1024 else DEADLINE_SMALL
        for label, url in (
                ('GitCode', gc_asset_url(ver, name)),
                ('GitHub', 'https://github.com/%s/%s/releases/download/v%s/%s'
                 % (OWNER, REPO, ver, quote(name)))):
            # GitHub 那条浏览器下载口只试一次：它 302 到 objects CDN，这台机器上
            # 要么几秒回来、要么慢得没边，卡在那里重试没有意义。
            # 拿不到立刻换 api.github.com 的附件口 —— 拿的是同一个附件对象，字节一样才算数。
            data = _download(url, SOCK_TMO, 1 if label == 'GitHub' else 2,
                             deadline=dl, expect=size, label='%s %s' % (label, name))
            via = ''
            digest = ''
            if data is None and label == 'GitHub':
                data, digest = _gh_asset(ver, name, deadline=dl, expect=size)
                via = '（改走 api.github.com 附件口）'
            if data is None:
                extra = ''
                if digest and digest == want:
                    extra = '；GitHub 自报 digest 与本地一致（%s…）—— 但**自报不算通过**，' \
                            '闸门要的是真字节，换台网络正常的机器再跑一次' % want[:16]
                print('  [FAIL] %s %-16s 下载失败%s%s' % (label, name, via, extra))
                ok = False
                continue
            same = hashlib.sha256(data).hexdigest() == want
            ok = ok and same
            print('  [%s] %s %-16s %9d B  一致=%s%s'
                  % ('PASS' if same else 'FAIL', label, name, len(data), same, via))
            sys.stdout.flush()
    print('   下载页:', '%s/%s/%s/releases/tag/v%s' % (GC_WEB, OWNER, REPO, ver))
    return ok


def _client_pubkey():
    """从**客户端源码** github_direct.py 里解析出内置公钥。

    故意解析源码、而不是在这里另写一份常量：签名的公钥和客户端内置的那把必须是同一把，
    解析得到就天然一致；哪天换了钥匙却忘了改客户端，这里当场就对不上。
    """
    src = (REPO_DIR / 'github_direct.py').read_text(encoding='utf-8')
    m = re.search(r"""UPDATE_PUBKEY\s*=\s*['"]([0-9a-fA-F]{64})['"]""", src)
    if not m:
        sys.exit('从 github_direct.py 里解析不到内置公钥 UPDATE_PUBKEY —— 拒绝发布')
    return m.group(1)


def verify_signature(vj, vsig):
    """回读两平台线上的 version.json + version.json.sig，用客户端内置公钥**真验一遍**。

    这一步验的是"用户点检查更新时到底能不能过"：
      · 线上 version.json 的原始字节 → 与本地发布的那份一致；
      · 同目录的 version.json.sig 拿得到、且用客户端内置公钥验得过。
    任何一条不过就返回 False（发版算失败，别让用户自己发现升级通道是断的）。
    """
    import urllib.request          # noqa: F401  (老代码留个记号，实际取数走 _download)
    print('⑦+ 线上升级源验签（用客户端内置公钥，两个平台各一次）:')
    if str(REPO_DIR) not in sys.path:
        sys.path.insert(0, str(REPO_DIR))
    try:
        import _ed25519
    except Exception as e:
        sys.exit('加载 _ed25519.py 失败(%s) —— 拒绝发布（没法自证签名可用）' % type(e).__name__)
    pub = bytes.fromhex(_client_pubkey())
    local_raw = open(str(vj), 'rb').read()
    ok = True
    # 客户端读的就是这两个地址：GitCode 的 raw 走 API（它没有 Gitee 那种 /raw/分支 直链），
    # GitHub 用 raw.githubusercontent.com。带一个时间戳参数是防 CDN 给回半新半旧的缓存。
    bust = int(time.time())
    gc_base = GC_API + '/repos/%s/%s/raw' % (OWNER, REPO)
    gh_base = 'https://raw.githubusercontent.com/%s/%s/%s' % (OWNER, REPO, BRANCH)
    for label, mk in (
            ('GitCode', lambda f: '%s/%s?ref=%s&t=%d' % (gc_base, f, BRANCH, bust)),
            ('GitHub', lambda f: '%s/%s?v=%d' % (gh_base, f, bust))):
        raw = _download(mk('version.json'), SOCK_TMO, 3, deadline=120,
                        label='%s version.json' % label)
        sig_raw = _download(mk('version.json.sig'), SOCK_TMO, 3, deadline=120,
                            label='%s version.json.sig' % label)
        if raw is None or sig_raw is None:
            print('  [FAIL] %s 线上 version.json / .sig 取不到（GitCode 与 GitHub 都必须能取到）' % label)
            ok = False
            continue
        same_bytes = raw == local_raw
        sig_txt = sig_raw.decode('utf-8', 'replace').strip()
        sig_ok = False
        if re.fullmatch(r'[0-9a-fA-F]{128}', sig_txt):
            try:
                sig_ok = bool(_ed25519.checkvalid(bytes.fromhex(sig_txt), raw, pub))
            except Exception:
                sig_ok = False
        ok = ok and same_bytes and sig_ok
        print('  [%s] %s 线上 version.json 与本地一致=%s，Ed25519 验签=%s（公钥 %s…）'
              % ('PASS' if (same_bytes and sig_ok) else 'FAIL', label, same_bytes, sig_ok,
                 pub.hex()[:16]))
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

    # 私钥在这一步就定下来（找不到直接中止，不会走到"已经打包/已改版本号"才发现发不了）
    sign_key = resolve_sign_key()
    vj, vsig = make_version_json('', sign_key)

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

    # ⚠ version.json.sig 必须与 version.json **一起**发出去：客户端拿到 version.json
    # 会立刻去取同目录的 .sig 验签，取不到就拒绝这次升级（fail-closed）。
    # 老客户端只读 version.json（多一个附件对它无害）—— 这就是"兼容老版本"的做法。
    assets = [exe, vj, vsig]

    # ── 发版顺序是铁律（2026-10-26 定）：tag 先推 → 两平台建发行版传附件 →
    #    附件验真 → **main 最后推**（升级源就是 main 上那份 version.json，它一上线
    #    全体老用户立刻开始提示升级；那时附件必须已经躺好，否则用户点了个 404）。
    git_commit_and_tag(ver)
    gitcode_release(ver, token, assets, notes)
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
    print('⑦ 验真（附件字节，两个平台各一次）:')
    ok = verify(ver, assets)
    if not ok:
        sys.exit('❌ 附件验真没通过 —— main 先不推，线上仍是上一版；修好再重跑本脚本')
    git_push_branch()
    # 验签必须放在 main 推完之后：推之前线上那份 version.json 还是上一版的字节，
    # 拿它跟本次发布的本地文件比必然"不一致"，那是假警报。
    ok = verify_signature(vj, vsig) and ok
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
    elif a == 'verify' and len(sys.argv) > 2:
        sys.exit(cmd_verify(sys.argv[2]))
    elif a == 'release' and len(sys.argv) > 2:
        sys.exit(cmd_release(sys.argv[2],
                             skip_build='--skip-build' in sys.argv,
                             with_github='--github' in sys.argv,
                             notes_file=(sys.argv[sys.argv.index('--notes') + 1]
                                         if '--notes' in sys.argv else None)))
    else:
        print(__doc__)


def cmd_verify(ver):
    """只读验真：不发任何东西，把线上那一版按用户的口径重跑一遍。

    什么时候用它：① 发完版想确认"用户点检查更新真的能过"；② 用户报"升级失败"时，
    先在这里判断是通道断了还是包坏了，别一上来就改代码发新版。
    附件比的是本地仓库里那份 version.json 指向的字节 —— 所以它同时回答
    "线上清单说的 size/sha256，跟两个平台上真实能被下载到的文件对不对得上"。
    """
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
    vj = REPO_DIR / 'version.json'
    vsig = REPO_DIR / 'version.json.sig'
    if not vj.is_file() or not vsig.is_file():
        sys.exit('找不到本地 %s / %s —— 先确认仓库里的升级源是不是这一版' % (vj, vsig))
    d = json.loads(vj.read_text(encoding='utf-8-sig'))
    if str(d.get('version')) != str(ver):
        print('⚠ 本地 version.json 是 v%s，你要验的是 v%s —— 清单可能对不上号'
              % (d.get('version'), ver))
    exe = REPO_DIR / EXE_NAME
    assets = [a for a in (exe, vj, vsig) if Path(a).exists()]
    exe_info = d.get('exe') or {}
    print('① 清单: version=%s  size=%s  sha256=%s…  mirrors=%d 个'
          % (d.get('version'), exe_info.get('size'), (exe_info.get('sha256') or '')[:16],
             len(exe_info.get('mirrors') or [])))
    print('② 附件验真（两个平台各一次）:')
    ok = verify(ver, assets)
    ok = verify_signature(vj, vsig) and ok
    print('验真结果:', 'PASS' if ok else 'FAIL')
    return 0 if ok else 1


if __name__ == '__main__':
    main()
