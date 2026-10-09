# -*- coding: utf-8 -*-
"""狐径 —— 发版前自检闸门（必须全绿才允许发布）

为什么有这个文件（2026-10-08 用户原话）：
    「你怎么经常干，新版本发布了，又发现问题，又要迭代版本号，能不能测试成功再发布」
上一版就是漏在：只测了"能升级"，没测"升级后程序能不能自己回来"（杀软会拦第一次启动）。
这个脚本把那次漏掉的步骤固化下来，以后发版前必跑，红一条就不许发。

检查项：
  1. 版本一致性：exe 文件版本 / 源码 APP_VERSION / version.json 三者一致
  2. 冷启动演练：把候选 exe 复制成"刚下载落地"的样子，**立刻用隐藏 PowerShell 启动**
     （复刻升级小助手的动作）—— 必须能起来。这是上一版漏掉的那一步。
  3. 完整升级演练：旧版跑起来 -> 本地升级源 -> 检查更新 -> 立即升级 ->
     必须看到小助手日志出现"新版本已起来"，且换上去的 exe 指纹等于候选
  4. 失败分支：升级源里的 sha256 故意写错 -> 必须拒绝并保留旧版（不能把用户搞死）
  5. 接口自测：/pac 纯 ASCII 且含 raw 主机；/api/diag 格式正常；
     /api/set-ip 非法值被拒；连点两次 /api/enable 不污染备份；/api/quit 后注册表还原
  6. 收尾：注册表/升级源/缓存全部还原，不留垃圾
  7. 一致性警告（WARN，不阻断发布）：
     ① 工作区副本与仓库副本的 sha256 是否一致（M-10，两份漂移了就等于"仓库里写的检查项没跑"）
     ② 两平台已发布的发行版附件 sha256 是否一致、是否等于本地候选（M-11，限速：Gitee 间隔 ≥3 秒）

用法：python tools/preflight_release.py [候选exe路径] [--dry-run] [--skip-remote] [--help]
"""
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

REPO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'repo')
DATA = os.path.join(os.environ['LOCALAPPDATA'], 'FoxPath')
PANEL = 'http://127.0.0.1:8788'
REG = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
HID = ['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden']

# ── 远端附件比对（M-11）用到的常量 ─────────────────────────────────────
OWNER, PROJ = 'kele551', 'FoxPath'
GH_API = 'https://api.github.com'
GITEE_API = 'https://gitee.com/api/v5'
GITEE_MIN_GAP = 3.0            # Gitee 请求间隔 ≥3 秒（别把平台抓急，那是会自找 451 的）
CORE_ASSETS = ('FoxPath.exe', 'version.json')
GITEE_TOKEN_FILE = r'F:\Harness\secrets\raw\workbuddy-secrets\gitee_token'   # 只读，绝不打印明文

USAGE = """狐径发版前自检 —— 用法

  python tools/preflight_release.py [候选exe路径] [开关]

  候选exe路径        默认 <仓库>/FoxPath.exe

开关:
  -h, --help         只打印这段说明就退出（不写注册表、不结束/启动任何进程）
      --dry-run      只跑静态检查：版本一致性 + 两份脚本是否漂移 +（可选）远端附件比对。
                     不写注册表、不结束/启动任何进程、不动系统代理 —— 只想确认脚本没坏时用这个
      --skip-remote  跳过"两平台远端附件比对"（离线、或平台抽风时用）

会动到系统的地方（--dry-run 一律跳过）:
  · 冷启动演练与升级演练会启动/结束 FoxPath.exe；
  · 结束时还原注册表与升级源，并把本机已装的狐径重新拉起来。

判据: 红项（FAIL）一条都不许有 —— 有一条就不许发布；
      警告项（WARN）不阻断发布，但会在结尾单独列出，发布前应当看一眼。
"""

results = []
warnings = []


def check(name, ok, detail=''):
    results.append((name, bool(ok), detail))
    print('  [%s] %s%s' % ('PASS' if ok else 'FAIL', name, ('  ' + detail) if detail else ''))
    return ok


def check_warn(name, ok, detail=''):
    """警告级检查：不计入红项、不阻断发布。

    给"远端平台/网络"这类我们控制不了的事用（M-10 脚本漂移、M-11 远端附件比对）——
    网络抽风不该把发版闸门卡死，但也必须让人看见。
    """
    warnings.append((name, bool(ok), detail))
    print('  [%s] %s%s' % ('PASS' if ok else 'WARN', name, ('  ' + detail) if detail else ''))
    return ok


def sh(args, cwd=None):
    """跑一条外部命令并取回输出（自检自己要用的通用小工具）。

    注意位置：这个函数以前被写在文件最末尾（模块级代码之后），当时靠一句
    `... if False else None` 短路才没炸 —— 靠"永远不会执行"来不报错是个坑，
    所以现在挪到所有 helper 里，和别的工具函数放一起。
    """
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True,
                          encoding='utf-8', errors='replace')


def patch_pe_timestamp(path):
    """把 PE 头里的 TimeDateStamp 改成 0（只动这 4 个字节，不改代码、不影响运行）。

    为什么需要：升级演练里的"旧版"是**候选 exe 的副本**，内容与候选一模一样 ——
    于是"升级后指纹/大小 == 候选"这种判据天然成立，等于没验（M-12）。
    把副本的时间戳改掉，副本与候选的 sha256 就不同了，"换上去的真的是候选"才验得出来。
    改不到（不是 PE / 文件被占）返回 False，调用处按警告处理。
    """
    try:
        with open(path, 'r+b') as f:
            f.seek(0x3C)
            e_lfanew = int.from_bytes(f.read(4), 'little')
            if e_lfanew <= 0 or e_lfanew > 0x1000:
                return False
            f.seek(e_lfanew)
            if f.read(4) != b'PE\x00\x00':
                return False
            f.seek(e_lfanew + 8)
            f.write(b'\x00\x00\x00\x00')
        return True
    except OSError:
        return False


def finish():
    """统一出口：打印汇总（红项 + 警告项）并给出结论。"""
    print()
    print('=' * 62)
    bad_n = [n for n, ok, _ in results if not ok]
    warn_n = [(n, d) for n, ok, d in warnings if not ok]
    print('自检结果: %d 项，通过 %d，失败 %d；警告 %d 项'
          % (len(results), len(results) - len(bad_n), len(bad_n), len(warn_n)))
    for n in bad_n:
        print('   FAIL -> %s' % n)
    for n, d in warn_n:
        print('   WARN -> %s%s' % (n, ('  ' + d) if d else ''))
    if warn_n:
        print('   （警告不阻断发布，但发布前请看一眼上面这些：通常意味着"远端还没传"或"两份脚本不同步"）')
    print('结论: %s' % ('✅ 全绿，可以发布' if not bad_n else '❌ 有红项，禁止发布'))
    sys.exit(0 if not bad_n else 1)


def reg_get():
    import winreg
    out = {}
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG)
        for n in ('AutoConfigURL', 'ProxyEnable', 'ProxyServer'):
            try:
                out[n] = winreg.QueryValueEx(k, n)[0]
            except FileNotFoundError:
                out[n] = None
        winreg.CloseKey(k)
    except Exception as e:
        out['err'] = str(e)
    return out


def get(url, timeout=15):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, r.read().decode('utf-8', 'replace')
    except Exception as e:
        return None, '%s' % type(e).__name__


def post(url, timeout=30):
    try:
        req = urllib.request.Request(url, method='POST', data=b'')
        req.add_header('Host', '127.0.0.1:8788')
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except Exception as e:
        return '%s' % type(e).__name__


def up():
    st, _ = get(PANEL + '/api/status', timeout=3)
    return st == 200


def wait_up(sec=60):
    for i in range(sec):
        if up():
            return i + 1
        time.sleep(1)
    return None


def kill_app():
    subprocess.run(['taskkill', '/IM', 'FoxPath.exe', '/F'], capture_output=True)
    time.sleep(4)


def sha(p):
    return hashlib.sha256(open(p, 'rb').read()).hexdigest().upper()


def sha_lf(p):
    """按"CRLF→LF 归一化"算指纹：本仓库 core.autocrlf=true，工作区是 CRLF、仓库里存 LF，
    纯文本文件光比原始字节会因为换行符报假不一致。"""
    return hashlib.sha256(open(p, 'rb').read().replace(b'\r\n', b'\n')).hexdigest().upper()


def exe_ver(p):
    out = sh(['powershell', '-NoProfile', '-Command',
              "(Get-Item -LiteralPath '%s').VersionInfo.FileVersion" % p])
    return (out.stdout or '').strip()


# ── ① 版本一致性（纯读文件/属性，--dry-run 也跑）────────────────────────
def check_version(cand):
    print('① 版本一致性')
    ver_file = exe_ver(cand)
    src = io.open(os.path.join(REPO, 'github_direct.py'), encoding='utf-8').read()
    # 单引号/双引号都认（别写死一种引号，源码换个引号就解析不到）
    m = re.search(r"APP_VERSION\s*=\s*['\"]([^'\"]+)['\"]", src)
    app_ver = m.group(1) if m else '?'
    vjp = os.path.join(REPO, 'version.json')
    vj = json.loads(io.open(vjp, encoding='utf-8').read())
    csha = sha(cand)
    vj_sha = hashlib.sha256(open(vjp, 'rb').read()).hexdigest().upper()
    check('exe 文件版本 == 源码 APP_VERSION', ver_file == app_ver, '%s / %s' % (ver_file, app_ver))
    check('version.json 版本号 == APP_VERSION', vj['version'] == app_ver,
          'json=%s' % vj['version'])
    check('version.json 的 sha256 == 候选 exe 指纹', vj['exe']['sha256'].upper() == csha,
          'json=%s cand=%s' % (vj['exe']['sha256'][:12], csha[:12]))
    check('version.json 的 size == 候选 exe 大小', vj['exe']['size'] == os.path.getsize(cand))
    return app_ver, csha, vj_sha


# ── ①-b 自检脚本两份副本一致（M-10：防止"仓库里写的检查项其实没跑"）──────
def check_script_sync():
    """工作区副本 vs 仓库副本的 sha256。

    仓库里那份是给评审/协作者看的、也是 `publish.py` 实际会调的那份；
    工作区那份是维护者平时在改的。两份一旦漂移，就会出现"仓库里写着的检查项其实没跑"，
    所以这里每次都念一遍。不一致只警告，不判红。
    """
    print()
    print('①-b 自检脚本两份副本一致（M-10）')
    name = '工作区副本与仓库副本 sha256 一致'
    ws = os.path.join(os.path.dirname(REPO), 'tools', 'preflight_release.py')
    rp = os.path.join(REPO, 'tools', 'preflight_release.py')
    me = os.path.abspath(__file__)
    if not os.path.exists(rp):
        return check_warn(name, False, '仓库里还没有 tools/preflight_release.py（应当随仓库入库）')
    if not os.path.exists(ws):
        return check_warn(name, False, '工作区副本不在 %s（在别的机器上只跑仓库那份时属正常）' % ws)
    if os.path.abspath(ws) == os.path.abspath(rp):
        return check_warn(name, False, '两份指向同一个路径，没法比较: %s' % rp)
    a, b = sha(ws), sha(rp)
    note = '' if me in (os.path.abspath(ws), os.path.abspath(rp)) else '（本次运行的是第三份: %s）' % me
    same = a == b
    if not same:
        # 本仓库 core.autocrlf=true：工作区是 CRLF、仓库里存的是 LF，两份内容一样也可能指纹不同，
        # 所以再按"CRLF→LF 归一化"比一次，避免每次发版都为换行符报假警告。
        a2 = sha_lf(ws)
        b2 = sha_lf(rp)
        if a2 == b2:
            same, note = True, '（仅换行符 CRLF/LF 不同）' + note
    return check_warn(name, same, 'workspace=%s repo=%s%s' % (a[:12], b[:12], note))


# ── 网络小工具 + ①-c 远端附件比对（M-11）──────────────────────────────
_GITEE_LAST = [0.0]


def _gitee_wait():
    """Gitee 限速：**任何**一次 gitee 请求之间至少隔 3 秒（API 与附件下载都算）。

    2026-10-08 的教训：密集抓 Gitee 接口会自己把平台抓出 451，然后把假象当事实。
    """
    wait = GITEE_MIN_GAP - (time.time() - _GITEE_LAST[0])
    if wait > 0:
        time.sleep(wait)


def _gitee_done():
    _GITEE_LAST[0] = time.time()


def _gitee_json(path, timeout=30):
    """Gitee API 统一入口（走 _gitee_wait 限速）。

    令牌只从本机文件读、只放进请求参数，**任何情况下都不打印明文**（出错只报异常类型）。
    """
    _gitee_wait()
    tok = ''
    try:
        if os.path.exists(GITEE_TOKEN_FILE):
            tok = io.open(GITEE_TOKEN_FILE, encoding='utf-8').read().strip()
    except OSError:
        tok = ''
    url = GITEE_API + path + (('?' + urllib.parse.urlencode({'access_token': tok})) if tok else '')
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'FoxPath-preflight'})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode('utf-8', 'replace')), None
    except Exception as e:
        return None, type(e).__name__
    finally:
        _gitee_done()


def _get_bytes(url, headers=None, timeout=600, tries=3):
    for i in range(tries):
        try:
            req = urllib.request.Request(
                url, headers=headers or {'User-Agent': 'FoxPath-preflight'})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except Exception:
            if i < tries - 1:
                time.sleep(3)
    return None


def _asset_sha(data):
    return None if data is None else (hashlib.sha256(data).hexdigest().upper(), len(data))


def _remote_assets(tag):
    """取两个平台该 tag 的附件：{平台: {附件名: (sha256, 字节数)}}、{平台: [附件名]}、{平台: 错误}。"""
    got, names, errs = {}, {}, {}
    # 平台自动生成的源码包（v1.0.6.zip / .tar.gz）不算"我们上传的附件"，比清单时忽略掉
    auto = {tag + '.zip', tag + '.tar.gz', tag + '.tar.bz2'}
    rel, err = _gitee_json('/repos/%s/%s/releases/tags/%s' % (OWNER, PROJ, tag))
    if err or not rel:
        errs['Gitee'] = err or '发行版不存在'
    else:
        assets = rel.get('assets') or []
        names['Gitee'] = [a.get('name') for a in assets if a.get('name') not in auto]
        got['Gitee'] = {}
        for a in assets:
            if a.get('name') in CORE_ASSETS:
                _gitee_wait()          # 附件下载同样限速 ≥3 秒
                try:
                    got['Gitee'][a['name']] = _asset_sha(
                        _get_bytes(a.get('browser_download_url') or ''))
                finally:
                    _gitee_done()
    # GitHub 侧走 api.github.com（一直通）+ 附件 assets API（会跳到 objects.githubusercontent.com），
    # 不依赖时通时断的 github.com 下载页。
    try:
        req = urllib.request.Request(
            '%s/repos/%s/%s/releases/tags/%s' % (GH_API, OWNER, PROJ, tag),
            headers={'User-Agent': 'FoxPath-preflight',
                     'Accept': 'application/vnd.github+json'})
        with urllib.request.urlopen(req, timeout=30) as r:
            j = json.loads(r.read().decode('utf-8', 'replace'))
        assets = j.get('assets') or []
        names['GitHub'] = [a.get('name') for a in assets if a.get('name') not in auto]
        got['GitHub'] = {}
        for a in assets:
            if a.get('name') in CORE_ASSETS:
                got['GitHub'][a['name']] = _asset_sha(_get_bytes(
                    a.get('url') or '',
                    headers={'User-Agent': 'FoxPath-preflight',
                             'Accept': 'application/octet-stream'}))
    except Exception as e:
        errs['GitHub'] = type(e).__name__
    return got, names, errs


def _names(lst):
    return ', '.join([n for n in lst if n]) or '无'


def check_remote_assets(ver, cand_sha, vj_sha):
    """M-11：拉两平台发行版附件比对 SHA256。

    以前的自检只比"本地 version.json ↔ 本地 exe"，管不住"本地改了、附件忘了重传"。
    这里把两个平台**已发布**的附件下载回来对指纹。远端拿不到（新版本还没发、平台抽风、
    网络不通）一律只算警告 —— 发版闸门不该被网络问题卡死。

    version.json 是文本，多算一个"CRLF→LF 归一化"的口径：本仓库 core.autocrlf=true，
    工作区是 CRLF、仓库里与已发布的都是 LF，光看原始字节会每次都报假警告。
    """
    tag = 'v%s' % ver
    print()
    print('①-c 远端附件比对（M-11：%s，限速 Gitee ≥3 秒/次，失败只警告）' % tag)
    vjp = os.path.join(REPO, 'version.json')
    alt = {'version.json': hashlib.sha256(
        open(vjp, 'rb').read().replace(b'\r\n', b'\n')).hexdigest().upper()}
    got, names, errs = _remote_assets(tag)
    for plat in ('Gitee', 'GitHub'):
        if plat in errs:
            check_warn('%s 能读到 %s 的发行版' % (plat, tag), False,
                       '%s（本次若为新版本、还没发布，属正常）' % errs[plat])
    for name, want, label in (('FoxPath.exe', cand_sha, '本地候选 exe'),
                              ('version.json', vj_sha, '本地 version.json')):
        for plat in ('Gitee', 'GitHub'):
            if name not in (got.get(plat) or {}):
                continue
            r = got[plat][name]
            if not r:
                check_warn('%s / %s 能下载回来' % (plat, name), False, '下载失败')
                continue
            same = r[0] == want
            note = ''
            if not same and r[0] == alt.get(name):
                same, note = True, '（仅换行符 CRLF/LF 不同）'
            check_warn('%s / %s 指纹 == %s' % (plat, name, label), same,
                       '%s vs %s  %d B%s' % (r[0][:12], want[:12], r[1], note))
    for name in CORE_ASSETS:
        a = (got.get('Gitee') or {}).get(name)
        b = (got.get('GitHub') or {}).get(name)
        if a and b:
            check_warn('%s 两平台指纹一致' % name, a[0] == b[0],
                       '%s vs %s' % (a[0][:12], b[0][:12]))
    ng = [n for n in (names.get('Gitee') or []) if n]
    nh = [n for n in (names.get('GitHub') or []) if n]
    if ng and nh and set(ng) != set(nh):
        print('     · 两平台附件清单不同：仅 Gitee 有 [%s]；仅 GitHub 有 [%s]'
              % (_names([n for n in ng if n not in nh]), _names([n for n in nh if n not in ng])))
        print('       （Gitee 侧多一个中文名演示视频属**已知差异**，见 README「已知边界」；'
              '平台自动生成的源码包不计入比较；核心附件两平台一致才算过）')


# ── 命令行开关 ────────────────────────────────────────────────────────
TMP = os.path.join(tempfile.gettempdir(), 'foxpath_preflight')
KNOWN_ARGS = ('-h', '--help', '--dry-run', '--skip-remote')
ARGS = list(sys.argv[1:])
if '-h' in ARGS or '--help' in ARGS:
    print(USAGE)
    sys.exit(0)
unknown = [a for a in ARGS if a.startswith('-') and a not in KNOWN_ARGS]
if unknown:
    print('不认识的开关: %s\n' % ' '.join(unknown))
    print(USAGE)
    sys.exit(2)
DRY = '--dry-run' in ARGS
SKIP_REMOTE = '--skip-remote' in ARGS
_positional = [a for a in ARGS if not a.startswith('-')]
CAND = _positional[0] if _positional else os.path.join(REPO, 'FoxPath.exe')
# 2026-10-09：升级演练用的"假新版本"是**真的 9.9.9**（tools\造测试版-9.9.9.py 打出来的）。
# 为什么不再用"改 PE 时间戳"：
#   新版小助手**按版本号确认升级成功**；改时间戳造出来的假新版自报版本仍是本版(1.0.7)，
#   于是会被**正确地判为失败并回滚** —— 演练却断言"换上去的应该就是新版"，必然报红（真事）。
NEW999 = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      'builds', '测试用v9.9.9', 'FoxPath-9.9.9-test.exe')
print('狐径发版前自检%s' % ('（--dry-run：只做静态检查）' if DRY else ''))
print('  候选 exe: %s' % CAND)
print('  数据目录: %s' % DATA)
print()

# ── ① 版本一致性；①-b 脚本副本一致；①-c 远端附件比对 ────────────────────
# 这三项都是"纯读"（只读文件/接口、只下载），所以 --dry-run 也照跑。
ver, csha, vj_sha = check_version(CAND)
check_script_sync()
if SKIP_REMOTE:
    print()
    print('①-c 远端附件比对：已按 --skip-remote 跳过')
else:
    try:
        check_remote_assets(ver, csha, vj_sha)
    except Exception as e:
        check_warn('远端附件比对能跑起来', False, type(e).__name__)

if DRY:
    print()
    print('（--dry-run：跳过冷启动演练 / 完整升级演练 / 失败分支 / 清场还原 —— 这些会真的动系统）')
    finish()

# 基线：先**干净退出**（POST /api/quit，它会还原系统代理）再取基准。
# 注意：taskkill 不会还原代理，拿它当基线会误报（2026-10-08 自检抓到的）。
try:
    post(PANEL + '/api/quit')
    time.sleep(6)
except Exception:
    pass
kill_app()
before = reg_get()
tmp_files = []
url_txt = os.path.join(DATA, 'update_url.txt')
cache = os.path.join(DATA, 'update.json')
had_url = os.path.exists(url_txt)
if had_url:
    shutil.copy2(url_txt, url_txt + '.preflight')

try:
    # ── 2 冷启动演练（上一版漏掉的那一步）────────────────────────────
    print()
    print('② 冷启动演练：复制成「刚下载落地」再立刻用隐藏 PowerShell 启动')
    kill_app()
    os.makedirs(TMP, exist_ok=True)
    cold = os.path.join(TMP, 'cold', 'FoxPath.exe')
    shutil.rmtree(os.path.dirname(cold), ignore_errors=True)
    os.makedirs(os.path.dirname(cold), exist_ok=True)
    shutil.copy2(CAND, cold)
    time.sleep(3)
    subprocess.Popen(HID + ['-Command',
                            'Start-Process -FilePath "%s" -ArgumentList "--silent"' % cold],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    n = wait_up(60)
    check('冷启动后 60 秒内面板可用', n is not None, ('等了 %d 秒' % n) if n else '起不来')

    # ── 5a 接口自测（趁这个实例还活着）──────────────────────────────
    print()
    print('③ 接口自测')
    if n:
        st, pac = get(PANEL + '/pac')
        check('/pac 返回 200 且是纯 ASCII', st == 200 and pac.isascii(), 'len=%d' % len(pac or ''))
        check('/pac 含 raw 主机', 'raw.githubusercontent.com' in (pac or ''))
        st, diag = get(PANEL + '/api/diag')
        check('/api/diag 格式正常', st == 200 and '狐径体检 v' in (diag or ''),
              (diag or '').split('\n')[0][:70])
        check('/api/set-ip 拒绝非法值（诊断里仍是「手动IP 无」）', True) if False else None
        post(PANEL + '/api/set-ip?ip=999.1.1.1')
        time.sleep(1)
        st, diag2 = get(PANEL + '/api/diag')
        check('非法 IP 没被写进去', '手动IP 无' in (diag2 or ''))
        post(PANEL + '/api/enable')
        time.sleep(1)
        post(PANEL + '/api/enable')
        time.sleep(1)
        bak = os.path.join(DATA, 'proxy-backup.json')
        polluted = False
        if os.path.exists(bak):
            polluted = '127.0.0.1:8788' in io.open(bak, encoding='utf-8').read()
        check('连点两次启用后备份没被自己的 PAC 污染', not polluted)

    # ── 3 完整升级演练 ─────────────────────────────────────────────
    print()
    print('④ 完整升级演练（旧版 -> 本地源 -> 检查更新 -> 立即升级 -> 必须自动起来）')
    # 2026-10-09：演练会往**真实数据目录**写 update.log / update-result.json。
    # 前者本来就删掉重来；后者**必须备份还原** —— 否则用户面板那行「上次升级结果」
    # 会挂着演练造出来的假记录（真事：面板显示"升级到 v9.9.9 失败, 回滚后也没能自动启动"）。
    _restore = []          # [(备份路径, 原路径)]
    _resf = os.path.join(DATA, 'update-result.json')
    _logf2 = os.path.join(DATA, 'update.log')
    for _p in (_resf, _logf2):
        try:
            if os.path.exists(_p):
                _bak = os.path.join(TMP, os.path.basename(_p) + '.preflight-bak')
                shutil.copy2(_p, _bak)
                _restore.append((_bak, _p))
        except Exception as _e:
            print('     ⚠ 备份 %s 失败（演练结束后它可能被改写）: %s' % (_p, _e))
    kill_app()
    old = os.path.join(TMP, 'upgrade', 'FoxPath.exe')
    shutil.rmtree(os.path.dirname(old), ignore_errors=True)
    os.makedirs(os.path.dirname(old), exist_ok=True)
    # 用【候选自己】当"旧版"：小助手脚本由正在运行的那个版本生成，
    # 只有让候选来发起这次升级，才能验到候选里的加固逻辑。
    oldsrc = CAND
    if not os.path.exists(oldsrc):
        check('找得到用于升级演练的 exe', False, oldsrc)
    else:
        shutil.copy2(oldsrc, old)
        # 2026-10-09：不再改 PE 时间戳造"假新版"。**旧版 = 真实候选(1.0.7)，新版 = 真 9.9.9 测试版**，
        # 两者内容与版本号都不同：sha256 判据、版本号确认、失败回滚三条路才都能真跑。
        if not os.path.exists(NEW999):
            new_sha = ''
            check('找得到 9.9.9 测试版（先跑 tools\\造测试版-9.9.9.py）', False, NEW999)
        else:
            new_sha = sha(NEW999)
            check_warn('升级演练的"旧版"与"新版"指纹不同（比 sha256 才有意义）',
                       sha(old) != new_sha, 'old=%s new999=%s' % (sha(old)[:12], new_sha[:12]))
        feed = {'version': '9.9.9', 'notes': 'preflight',
                'exe': {'sha256': new_sha, 'url': 'file:///' + NEW999.replace('\\', '/'),
                        'size': os.path.getsize(NEW999) if os.path.exists(NEW999) else 0}}
        feedp = os.path.join(TMP, 'upgrade', 'version.json')
        io.open(feedp, 'w', encoding='utf-8', newline='\n').write(
            json.dumps(feed, ensure_ascii=False))
        io.open(url_txt, 'w', encoding='utf-8').write(feedp)
        tmp_files.append(url_txt)
        for f in (cache, os.path.join(DATA, 'update.log')):
            try:
                os.remove(f)
            except OSError:
                pass
        subprocess.Popen([old, '--silent'], cwd=os.path.dirname(old))
        time.sleep(12)
        check('旧版起来了', up())
        post(PANEL + '/api/update/check')
        time.sleep(3)
        st, stt = get(PANEL + '/api/update/status')
        check('读到「有新版本」', '9.9.9' in (stt or ''), (stt or '')[:90])
        post(PANEL + '/api/update/start')
        ok_swap = False
        for i in range(36):
            time.sleep(5)
            # M-12：按 sha256 判"已换成新版"，不再拿文件大小比（新旧恰好同字节数就骗过去了）
            if os.path.exists(old) and sha(old) == new_sha:
                ok_swap = True
                break
        check('升级后 exe 被换成 9.9.9 测试版（= 升级动作本身成功）', ok_swap,
              '第 %d 秒' % ((i + 1) * 5) if ok_swap else '没换掉（sha256 与 9.9.9 测试版不符）')
        # 等终态：要么新实例起来，要么小助手跑完重试并给出提示（约 2~3 分钟）。
        print('     等升级小助手跑完（最多 6 分钟，每 20 秒报一次进度）…')
        brought_up = None
        logf = os.path.join(DATA, 'update.log')
        for tick in range(18):
            time.sleep(20)
            if up():
                brought_up = tick * 20 + 1
                break
            t0 = io.open(logf, encoding='utf-8-sig', errors='replace').read() if os.path.exists(logf) else ''
            if '手动双击' in t0:
                print('     小助手已给出「请手动双击」提示（第 %d 秒）' % ((tick + 1) * 20))
                break
            if tick % 3 == 2:
                print('       …%d 秒，最后一行：%s' % ((tick + 1) * 20,
                                                    (t0.strip().split('\n') or [''])[-1][:70]))
        logtxt = io.open(logf, encoding='utf-8-sig', errors='replace').read() if os.path.exists(logf) else ''
        # 判据（2026-10-08 定）：杀软可能拦掉升级后的第一次启动，这我们控制不了；
        # 能保证的是"要么自己起来，要么重试过、并且明确告诉用户双击一下"。
        retried = logtxt.count('次启动新版本') >= 2
        told_user = ('手动双击' in logtxt) or ('Popup' in logtxt)
        if brought_up is not None:
            check('★ 升级后自动重启：新版本自己起来了', True, '等了 %d 秒' % brought_up)
        else:
            check('★ 升级后自动重启：起不来时必须"重试过 + 明确提示用户"',
                  retried and told_user,
                  '重试=%s 提示=%s（本机装了火绒，实测常拦升级后的第一次启动）' % (retried, told_user))
        # 判据（2026-10-09 更新）：小助手现在**按版本号确认成功**，日志写「已自动/手动升级到 vX」；
        # 旧措辞「新版本已起来」、以及失败路径的「已自动回滚」「手动双击」一并认。
        # ⚠ 取证据行时**绝不能假设一定存在**：曾经这里 [-1] 越界把整个自检崩掉，
        #   而发版闸门把"自检崩了"当成"没通过"，白白中止了一次发版（2026-10-09 真事）。
        # 判据（2026-10-09 再更新）：分两种正当结果 ——
        #   A「成功」：新版起来后往**主日志**写「已自动/手动升级到 vX」；
        #   B「演练固有的人工兜底」：演练里的"新版"其实是候选副本（只改了 PE 时间戳，
        #     版本号仍是本版），新版小助手**按版本号确认成功**，于是必然走
        #     "没升上去 -> 三步兜底 / 请用户手动双击"那条路。这是演练的假象，不是产品问题。
        # 两种都认，但必须能说出个所以然；取证据行时**永不越界**（曾经 [-1] 越界把自检崩掉，
        # 闸门把"自检崩了"当"没通过"，白白中止过一次发版）。
        mainlog = os.path.join(DATA, 'foxpath.log')
        maintxt = io.open(mainlog, encoding='utf-8-sig', errors='replace').read() if os.path.exists(mainlog) else ''
        both = (logtxt or '') + '\n' + (maintxt or '')
        lines = [l for l in both.split('\n') if l.strip()]
        ok_marks = ('已自动升级到 v', '已手动升级到 v', '新版本已起来')
        fb_marks = ('三步兜底', '手动双击', '已自动回滚', '没有生效(当前仍是')
        hit_ok = [l for l in lines if any(m in l for m in ok_marks)]
        hit_fb = [l for l in lines if any(m in l for m in fb_marks)]
        detail = (('成功: ' + hit_ok[-1][:70]) if hit_ok else
                  (('演练固有兜底: ' + hit_fb[-1][:70]) if hit_fb else
                   ('两份日志共 %d 行，没有任何升级结果痕迹（把日志留下排查）' % len(lines))))
        check('升级结果有痕迹（「已升级到 vX」或演练固有的「三步兜底/手动双击/回滚」）',
              bool(hit_ok or hit_fb), detail)
        check('换上去的 exe 指纹 == 9.9.9 测试版', os.path.exists(old) and sha(old) == new_sha)
        # 端到端最强判据：**正在跑的那个实例自报 9.9.9** —— 下载→校验→覆盖→新版起来→按版本号确认，全过。
        _st9, _diag9 = get(PANEL + '/api/diag')
        check('新版自报版本 = 9.9.9（升级链路端到端成功）',
              '狐径体检 v9.9.9' in (_diag9 or ''), (_diag9 or '').split('\n')[0][:70])

    # ── 4 失败分支：sha 故意写错 ─────────────────────────────────────
    print()
    print('⑤ 失败分支：升级源 sha256 故意写错，必须拒绝且不覆盖')
    kill_app()
    bad = os.path.join(TMP, 'bad', 'FoxPath.exe')
    for attempt in range(4):
        try:
            shutil.rmtree(os.path.dirname(bad), ignore_errors=True)
            os.makedirs(os.path.dirname(bad), exist_ok=True)
            shutil.copy2(CAND, bad)
            break
        except PermissionError:
            print('     测试目录被占用，等 5 秒再试（第 %d 次）' % (attempt + 1))
            kill_app()
            time.sleep(5)
    bad_sha = 'F' * 64
    # 2026-10-09：这里必须用**比当前(9.9.9)更高**的版本号 —— 否则会被"拒绝降级"的新护栏
    # 挡在下载之前，压根走不到"校验不过"那条路（那次演练报的就是这个假红）。
    feed2 = {'version': '9.9.10', 'notes': 'preflight-bad',
             'exe': {'sha256': bad_sha, 'url': 'file:///' + CAND.replace('\\', '/'),
                     'size': os.path.getsize(CAND)}}
    feedp2 = os.path.join(TMP, 'bad', 'version.json')
    io.open(feedp2, 'w', encoding='utf-8', newline='\n').write(json.dumps(feed2, ensure_ascii=False))
    io.open(url_txt, 'w', encoding='utf-8').write(feedp2)
    try:
        os.remove(cache)
    except OSError:
        pass
    sha_before = sha(bad)          # M-12：同样按 sha256 判"没被覆盖"，不看大小
    subprocess.Popen([bad, '--silent'], cwd=os.path.dirname(bad))
    time.sleep(12)
    post(PANEL + '/api/update/check')
    time.sleep(3)
    post(PANEL + '/api/update/start')
    time.sleep(20)
    st, stt = get(PANEL + '/api/update/status')
    # 2026-10-09：`/api/update/status` 里的 phase 是**易失**的 —— 之后任何一次"检查更新"
    # 都会把它刷成 idle，演练里就这么读到过一次 idle（假红）。改判**主日志**里那条
    # 「校验不过…已放弃」（持久、可复查），状态只作为补充信息打印。
    _mlog = os.path.join(DATA, 'foxpath.log')
    _mlogtxt = io.open(_mlog, encoding='utf-8-sig', errors='replace').read() if os.path.exists(_mlog) else ''
    _badlines = [l for l in _mlogtxt.split('\n')
                 if ('校验不过' in l) or ('校验失败' in l) or ('实际 FFFFFF' in l)]
    check('校验失败被拒绝（主日志里有「校验不过…已放弃」）',
          bool(_badlines) or ('failed' in (stt or '')) or ('校验' in (stt or '')),
          (_badlines[-1].strip()[:90] if _badlines else ('状态: ' + (stt or '')[:80])))
    check('旧版 exe 没被覆盖（sha256 未变）', sha(bad) == sha_before,
          '%s -> %s' % (sha_before[:12], sha(bad)[:12]))

finally:
    print()
    print('⑥ 收尾')
    try:
        post(PANEL + '/api/quit')
    except Exception:
        pass
    time.sleep(6)
    kill_app()
    # 2026-10-09：把演练碰过的真实文件原样放回去（用户面板不该看到演练的假记录）
    for _bak, _dst in _restore:
        try:
            shutil.copy2(_bak, _dst)
            print('     已还原 %s（演练期间被改写）' % os.path.basename(_dst))
        except Exception as _e:
            print('     ⚠ 还原 %s 失败: %s' % (_dst, _e))
    if had_url:
        shutil.move(url_txt + '.preflight', url_txt)
    else:
        for f in (url_txt,):
            try:
                os.remove(f)
            except OSError:
                pass
    for f in (cache,):
        try:
            os.remove(f)
        except OSError:
            pass
    for f in os.listdir(DATA):
        if f.endswith('.preflight'):
            try:
                os.remove(os.path.join(DATA, f))
            except OSError:
                pass
    after = reg_get()
    check('注册表恢复到自检前', before == after, '%s -> %s' % (before, after))
    shutil.rmtree(TMP, ignore_errors=True)
    # 把用户机器上原来在跑的狐径重新拉起来
    installed = r'D:\Program Files\FoxPath.exe'
    if os.path.exists(installed):
        subprocess.Popen([installed, '--silent'])
        time.sleep(10)
        print('  已把你的狐径重新启动（面板可用: %s）' % up())

finish()
