# -*- coding: utf-8 -*-
"""通用「云端发版」执行器 —— 任何项目都能用，逻辑只在这里写一份。

项目侧只需要一个 `.release/config.json`（声明怎么构建、怎么签名、发到哪），
外加一份 20 行的 `.github/workflows/release.yml`（内容对所有项目完全一样）。

设计的出发点（2026-11-14 用户提出的硬要求）：
  "不该是三个项目，应该是所有项目和未来所有项目" —— 所以这里**没有任何项目名硬编码**，
  也不判断"是不是狐径/壁纸/影视"。新项目接入 = 复制三个文件 + 填一个 json，
  不需要再改 workflow，也不需要连回本机。

只依赖标准库。Windows runner / Linux runner 都能跑。

config.json 字段（带 * 的必填）：
  *name            显示名
  *runs_on         github 建议值（仅作记录，实际由 workflow 决定）
  *build            构建命令数组，逐条执行，任一条非 0 即失败
  *outputs          构建产物（相对仓库根），必须真实存在，否则当场失败
   version_source    "文件名:常量名"，从源码里正则提取版本号（拿不到就报错）
   python           setup-python 的版本（记录用）
   deps             构建前 pip 安装的包（数组，可空）
   sign.enabled      是否需要签名
   sign.command     签名命令模板，可用占位 {key} {notes} {ver}
   sign.outputs      签名后新增的文件
   checksums         生成 SHA256 清单 {file, files}
   publish.github    {owner, repo}；缺省则该平台跳过
   publish.gitcode   {owner, repo}；缺省则该平台跳过
   publish.extra     额外要上传的文件
   commit_back       发版成功后回写并提交到 main 的文件（升级源用；可为空）
   branch            默认 main
"""
import argparse, hashlib, http.client, io, json, os, re, subprocess, sys, tempfile, time
import urllib.error, urllib.parse, urllib.request

GC_API = 'https://gitcode.com/api/v5'
GH_API = 'https://api.github.com'
GH_UPLOAD = 'https://uploads.github.com'
BLOCK = 1 << 18
UA = 'harness-release'


def log(m):
    print(m, flush=True)


def run(cmd, cwd, env=None, timeout=3600):
    log('$ %s' % cmd)
    r = subprocess.run(cmd, cwd=cwd, shell=True, capture_output=True, text=True,
                       encoding='utf-8', errors='replace', timeout=timeout,
                       env={**os.environ, **(env or {})})
    out = (r.stdout or '') + (r.stderr or '')
    if out.strip():
        print(out.rstrip()[-4000:], flush=True)
    if r.returncode != 0:
        raise SystemExit('命令失败（%d）: %s' % (r.returncode, cmd))
    return out


def sha256(path):
    h = hashlib.sha256()
    with io.open(path, 'rb') as f:
        for c in iter(lambda: f.read(BLOCK), b''):
            h.update(c)
    return h.hexdigest().upper()


def timeout_for(path):
    return int(min(600, max(60, os.path.getsize(path) / 300000.0 * 2.0 + 45)))


def http_json(url, method='GET', payload=None, headers=None, timeout=60):
    hd = {'User-Agent': UA}
    hd.update(headers or {})
    data = None
    if payload is not None:
        data = json.dumps(payload).encode('utf-8')
        hd['Content-Type'] = 'application/json'
    req = urllib.request.Request(url, data=data, headers=hd, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            b = r.read()
            return r.status, (json.loads(b.decode('utf-8', 'replace')) if b.strip() else {})
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')[:400]


def gc_call(method, path, token, payload=None, extra=None, timeout=120):
    p = {'access_token': token}
    p.update(extra or {})
    st, body = http_json(GC_API + path + '?' + urllib.parse.urlencode(p), method=method,
                         payload=payload, timeout=timeout)
    if st >= 300:
        raise RuntimeError('GitCode %s %s -> %s %s' % (method, path, st, str(body)[:300]))
    return body


def gh_call(method, path, token, payload=None, timeout=120):
    hd = {'Authorization': 'token ' + token, 'Accept': 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28'}
    st, body = http_json(GH_API + path, method=method, payload=payload, headers=hd, timeout=timeout)
    if st >= 300:
        raise RuntimeError('GitHub %s %s -> %s %s' % (method, path, st, str(body)[:300]))
    return body


def put_stream(url, path, headers=None, method='PUT'):
    """流式上传：不把产物整块读进内存；显式 Content-Length，避免 chunked 被平台拒。"""
    u = urllib.parse.urlsplit(url)
    conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=timeout_for(path))
    target = u.path + (('?' + u.query) if u.query else '')
    size = os.path.getsize(path)
    hd = {'User-Agent': UA}
    hd.update(headers or {})
    hd['Content-Length'] = str(size)
    hd['Connection'] = 'close'
    try:
        conn.putrequest(method, target, skip_accept_encoding=True)
        for k, v in hd.items():
            conn.putheader(k, v)
        conn.endheaders()
        with io.open(path, 'rb') as f:
            while True:
                c = f.read(BLOCK)
                if not c:
                    break
                conn.send(c)
        r = conn.getresponse()
        return r.status, r.read().decode('utf-8', 'replace')[:300]
    finally:
        try:
            conn.close()
        except Exception:
            pass


def publish_gitcode(owner, repo, tag, files, token, notes, branch):
    base = '/repos/%s/%s' % (owner, repo)
    try:
        rel = gc_call('GET', '%s/releases/tags/%s' % (base, urllib.parse.quote(tag)), token)
    except RuntimeError:
        rel = None
    if rel and rel.get('tag_name') == tag:
        log('GitCode 发行版已存在: %s' % tag)
    else:
        rel = gc_call('POST', base + '/releases', token, payload={
            'tag_name': tag, 'name': tag, 'body': notes or tag,
            'target_commitish': branch, 'prerelease': False})
        if not rel or not rel.get('tag_name'):
            raise RuntimeError('GitCode 建发行版失败: %s' % json.dumps(rel, ensure_ascii=False)[:300])
        log('GitCode 发行版已创建: %s' % tag)

    have = {a.get('name'): a for a in ((gc_call('GET', '%s/releases/tags/%s'
                                                % (base, urllib.parse.quote(tag)), token) or {}
                                               ).get('assets') or [])}
    for path in files:
        name = os.path.basename(path)
        size = os.path.getsize(path)
        old = have.get(name)
        if old and old.get('size') == size:
            log('  已在（同名同大小，跳过）: %s' % name)
            continue
        if old:
            raise RuntimeError('GitCode 上同名附件字节不同（线上 %s / 本地 %d）: %s\n'
                               'GitCode 无可靠删附件接口，请到网页删掉旧附件后重跑。'
                               % (old.get('size'), size, name))
        j = gc_call('GET', '%s/releases/%s/upload_url' % (base, urllib.parse.quote(tag)),
                    token, extra={'file_name': name}, timeout=120)
        up = (j or {}).get('url') or ((j or {}).get('data') or {}).get('url')
        hd = (j or {}).get('headers') or ((j or {}).get('data') or {}).get('headers') or {}
        if not up:
            raise RuntimeError('拿不到上传地址: %s' % json.dumps(j, ensure_ascii=False)[:200])
        t0 = time.time()
        st, body = put_stream(up, path, headers=hd, method='PUT')
        if st not in (200, 201, 204):
            raise RuntimeError('GitCode 附件失败 %s -> %s %s' % (name, st, body))
        log('  已上传: %s %d B（%.1f 秒）' % (name, size, time.time() - t0))

    chk = gc_call('GET', '%s/releases/tags/%s' % (base, urllib.parse.quote(tag)), token) or {}
    names = {a.get('name'): a.get('size') for a in (chk.get('assets') or [])}
    for path in files:
        n = os.path.basename(path)
        if names.get(n) != os.path.getsize(path):
            raise RuntimeError('GitCode 回读不符: %s（线上 %s / 本地 %d）'
                               % (n, names.get(n), os.path.getsize(path)))
    log('GitCode 回读核对通过（%d 个附件）' % len(files))


def publish_github(owner, repo, tag, files, token, notes, replace):
    base = '/repos/%s/%s' % (owner, repo)
    try:
        rel = gh_call('GET', '%s/releases/tags/%s' % (base, urllib.parse.quote(tag)), token)
    except RuntimeError:
        rel = None
    if rel and rel.get('tag_name') == tag:
        log('GitHub 发行版已存在: %s' % tag)
    else:
        rel = gh_call('POST', base + '/releases', token, payload={
            'tag_name': tag, 'name': tag, 'body': notes or tag,
            'target_commitish': 'main', 'prerelease': False})
        log('GitHub 发行版已创建: %s' % tag)
    rid = rel['id']
    assets = {a['name']: a for a in (rel.get('assets') or [])}
    for path in files:
        name = os.path.basename(path)
        size = os.path.getsize(path)
        old = assets.get(name)
        if old and old.get('size') == size:
            log('  已在（同名同大小，跳过）: %s' % name)
            continue
        if old:
            if not replace:
                raise RuntimeError('GitHub 上同名附件字节不同（线上 %s / 本地 %d）: %s\n'
                                   '确认覆盖请加 --allow-replace（重发同一版本时用）。'
                                   % (old.get('size'), size, name))
            gh_call('DELETE', '%s/releases/assets/%s' % (base, old['id']), token)
            log('  已删除旧资产: %s' % name)
        t0 = time.time()
        st, body = put_stream('%s/repos/%s/%s/releases/%s/assets?name=%s'
                              % (GH_UPLOAD, owner, repo, rid, urllib.parse.quote(name)),
                              path, headers={'Authorization': 'token ' + token,
                                             'Content-Type': 'application/octet-stream',
                                             'Accept': 'application/vnd.github+json'}, method='POST')
        if st not in (200, 201):
            raise RuntimeError('GitHub 附件失败 %s -> %s %s' % (name, st, body))
        log('  已上传: %s %d B（%.1f 秒）' % (name, size, time.time() - t0))

    chk = gh_call('GET', '%s/releases/tags/%s' % (base, urllib.parse.quote(tag)), token) or {}
    names = {a['name']: a['size'] for a in (chk.get('assets') or [])}
    for path in files:
        n = os.path.basename(path)
        if names.get(n) != os.path.getsize(path):
            raise RuntimeError('GitHub 回读不符: %s（线上 %s / 本地 %d）'
                               % (n, names.get(n), os.path.getsize(path)))
    log('GitHub 回读核对通过（%d 个附件）' % len(files))


def verify_platforms(pub, tag, name):
    """发布后核对 GitCode 与 GitHub 是否一致（附件名 + 大小逐项比）。
    只报告、绝不阻断：任何异常都吞掉，比对失败不影响已经成功的发版结论。"""
    def side(cfg, call, token):
        if not cfg:
            return ('SKIP', {})
        if not token:
            return ('NOTOKEN', {})
        try:
            rel = call('GET', '/repos/%s/%s/releases/tags/%s'
                       % (cfg['owner'], cfg['repo'], urllib.parse.quote(tag)), token, timeout=20) or {}
        except Exception as e:
            return ('MISSING' if ' 404 ' in (' %s ' % e) else 'ERROR(%s)' % type(e).__name__, {})
        if (rel.get('tag_name') or '') != tag:
            return ('MISSING', {})
        auto = {tag + '.zip', tag + '.tar.gz', tag + '.tar.bz2', tag + '.tar'}
        # 上面几个是 GitHub 自己附带的源码包，GitCode 没有，不算两个平台不一致。
        return ('OK', {x.get('name'): x.get('size') for x in (rel.get('assets') or [])
                       if x.get('name') not in auto and x.get('size') is not None})

    try:
        sg, ag = side(pub.get('gitcode'), gc_call, os.environ.get('GITCODE_TOKEN'))
        sh, ah = side(pub.get('github'), gh_call, os.environ.get('GITHUB_TOKEN'))
        log('两平台核对: GitCode=%s GitHub=%s' % (sg, sh))
        bad = []
        both = (sg == 'OK' and sh == 'OK')
        # 只配了一个平台的项目（例如鲸采只发 GitHub）没有另一边可比，不算不一致。
        one_side = sg in ('SKIP', 'NOTOKEN') or sh in ('SKIP', 'NOTOKEN')
        if both:
            for n in sorted(set(ag) | set(ah)):
                g, h = ag.get(n), ah.get(n)
                if g is None:
                    bad.append('GitHub 有 %s，GitCode 没有' % n)
                elif h is None:
                    bad.append('GitCode 有 %s，GitHub 没有' % n)
                elif g != h:
                    bad.append('%s 大小不同（GitCode %s / GitHub %s）' % (n, g, h))
        elif not one_side:
            bad.append('有一边没核对成功（GitCode=%s GitHub=%s），未做逐项比对' % (sg, sh))
        sumf = os.environ.get('GITHUB_STEP_SUMMARY')
        if sumf:
            with io.open(sumf, 'a', encoding='utf-8') as f:
                f.write('\n## 两平台一致性核对 %s %s\n\n' % (name, tag))
                if not bad and both:
                    f.write('一致：GitCode 与 GitHub 附件名、大小逐项相同（%d 个）。\n' % len(ag))
                elif not bad:
                    f.write('单平台发布（GitCode=%s / GitHub=%s），无需双平台核对。\n' % (sg, sh))
                else:
                    f.write('**【不一致，需要处理】**\n\n')
                    for x in bad:
                        f.write('- %s\n' % x)
                    f.write('\nGitCode 删附件没有可靠接口，只能去网页删；GitHub 可用 --allow-replace 覆盖。\n')
        if bad:
            log('!! 两平台不一致: %s' % '；'.join(bad))
        elif both:
            log('两平台一致（%d 个附件）' % len(ag))
        else:
            log('单平台发布，已跳过双平台核对')
    except Exception as e:
        log('平台核对自身出错，已跳过（不影响发版）: %s' % e)


def read_version(root, src):
    """从 "文件名:常量名" 取版本号。取不到就报错 —— 宁可不发版，也不发一个版本号不明的包。"""
    fname, const = src.split(':', 1)
    p = os.path.join(root, fname)
    if not os.path.isfile(p):
        raise SystemExit('version_source 指向的文件不存在: %s' % p)
    txt = io.open(p, encoding='utf-8', errors='replace').read()
    m = re.search(r'^%s\s*=\s*[\'"]([^\'"]+)[\'"]' % re.escape(const), txt, re.M)
    if not m:
        raise SystemExit('在 %s 里找不到常量 %s' % (fname, const))
    return m.group(1).strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--config', default='.release/config.json')
    ap.add_argument('--root', default='.')
    ap.add_argument('--notes', default='')
    ap.add_argument('--allow-replace', action='store_true')
    ap.add_argument('--skip-build', action='store_true')
    ap.add_argument('--skip-publish', action='store_true')
    ap.add_argument('--dry-run', action='store_true')
    a = ap.parse_args()

    root = os.path.abspath(a.root)
    cfg = json.loads(io.open(os.path.join(root, a.config), encoding='utf-8-sig').read())
    name = cfg.get('name') or cfg['publish']['github']['repo']
    branch = cfg.get('branch', 'main')
    log('=== %s 云端发版 ===' % name)

    ver = ''
    if cfg.get('version_source'):
        ver = read_version(root, cfg['version_source'])
        log('版本号（来自源码）: %s' % ver)
    tag = 'v' + ver if ver else ''
    if not tag and not a.skip_publish:
        raise SystemExit('没拿到版本号（version_source 为空或取不到常量），拒绝发布 —— '
                         '发一个版本号不明的包比不发更糟。只构建请加 --skip-publish')

    if not a.skip_build:
        for dep in (cfg.get('deps') or []):
            run('%s -m pip install --disable-pip-version-check %s' % (sys.executable, dep), root)
        for cmd in cfg['build']:
            run(cmd, root)

    outputs = list(cfg.get('outputs') or [])
    for f in outputs:
        p = os.path.join(root, f)
        if not os.path.isfile(p):
            raise SystemExit('构建产物不存在: %s' % p)
        log('产物: %-32s %12d B' % (f, os.path.getsize(p)))

    # 项目自带的发版闸门（版本一致 / 署名 / 仓库地址等）。
    # 这些规则是项目专属知识，所以脚本放在项目仓库里，执行器只负责调用：
    # 任一条非 0 就是"产物不合格"，不上传 —— 不合格的包不该发出去。
    for cmd in (cfg.get('preflight') or []):
        run(cmd, root)
        log('闸门通过: %s' % cmd)

    sign = cfg.get('sign') or {}
    if sign.get('enabled'):
        key = os.environ.get(sign.get('key_env', 'RELEASE_SIGN_KEY'), '')
        if not key:
            raise SystemExit('需要签名但没有拿到私钥（环境变量 %s 为空）。'
                             '拒绝继续：未签名的升级源会被客户端一律拒绝。'
                             % sign.get('key_env', 'RELEASE_SIGN_KEY'))
        keyfile = os.path.join(tempfile.mkdtemp(prefix='relkey_'), 'k.hex')
        try:
            with io.open(keyfile, 'w', encoding='utf-8', newline='') as f:
                f.write(key.strip())
            cmd = sign['command'].format(key=keyfile, notes=a.notes, ver=ver)
            run(cmd, root)
        finally:
            try:
                os.remove(keyfile)
                os.rmdir(os.path.dirname(keyfile))
            except Exception:
                pass
            log('私钥临时文件已删除')
        for f in (sign.get('outputs') or []):
            if not os.path.isfile(os.path.join(root, f)):
                raise SystemExit('签名产物不存在: %s' % f)

    ck = cfg.get('checksums') or {}
    files = list(outputs) + list((sign.get('outputs') or []))
    if ck.get('file'):
        lines = []
        for f in (ck.get('files') or files):
            p = os.path.join(root, f)
            if os.path.isfile(p):
                lines.append('%s  %s  %d bytes' % (sha256(p), f, os.path.getsize(p)))
        with io.open(os.path.join(root, ck['file']), 'w', encoding='utf-8', newline='\n') as f:
            f.write('\n'.join(lines) + '\n')
        log('已写 %s（%d 行）' % (ck['file'], len(lines)))

    # 把本次构建的指纹写进 job summary —— 本机写 version.json 时要的正是这两个值。
    # 签名留本机做（version.json 不到 1 KB，直接 push 即可），所以这里只负责把数字交出去。
    sumf = os.environ.get('GITHUB_STEP_SUMMARY')
    if sumf:
        with io.open(sumf, 'a', encoding='utf-8') as f:
            f.write('\n## %s %s 构建指纹\n\n```\n' % (name, tag or '(仅构建)'))
            for rel in files:
                p = os.path.join(root, rel)
                if os.path.isfile(p):
                    f.write('%s  %s  %d bytes\n' % (sha256(p), rel, os.path.getsize(p)))
            f.write('```\n\n本机写 version.json 时用上面的 sha256 / size，签名后直接 push。\n')

    upload = [os.path.join(root, f) for f in files]
    for f in (cfg.get('publish', {}).get('extra') or []):
        p = os.path.join(root, f)
        if os.path.isfile(p):
            upload.append(p)
    if ck.get('file'):
        upload.append(os.path.join(root, ck['file']))

    log('待上传 %d 个文件' % len(upload))
    if a.dry_run:
        log('[dry-run] 到此为止')
        return

    notes = a.notes
    if not notes:
        notes = '%s %s' % (name, tag)

    pub = cfg.get('publish') or {}
    if not a.skip_publish:
        gc = pub.get('gitcode')
        if gc and os.environ.get('GITCODE_TOKEN'):
            publish_gitcode(gc['owner'], gc['repo'], tag, upload,
                            os.environ['GITCODE_TOKEN'], notes, branch)
        elif gc:
            log('GitCode 跳过（没配 GITCODE_TOKEN）')
        gh = pub.get('github')
        if gh and os.environ.get('GITHUB_TOKEN'):
            publish_github(gh['owner'], gh['repo'], tag, upload,
                           os.environ['GITHUB_TOKEN'], notes, a.allow_replace)
        elif gh:
            log('GitHub 跳过（没有 GITHUB_TOKEN）')

    back = cfg.get('commit_back') or []
    if back:
        changed = [f for f in back if os.path.isfile(os.path.join(root, f))]
        if changed:
            run('git add %s' % ' '.join('"%s"' % f for f in changed), root)
            diff = subprocess.run('git diff --cached --name-only', cwd=root, shell=True,
                                  capture_output=True, text=True, encoding='utf-8')
            if (diff.stdout or '').strip():
                run('git -c user.name="github-actions[bot]" '
                    '-c user.email="41898282+github-actions[bot]@users.noreply.github.com" '
                    'commit -m "chore: 更新升级源 %s [skip ci]"' % tag, root)
                run('git push origin HEAD:%s' % branch, root)
                log('升级源已回写并提交到 %s（此刻起线上才提示升级）' % branch)
            else:
                log('升级源没有变化，跳过提交')
    if not a.skip_publish and tag:
        verify_platforms(pub, tag, name)
    log('=== 完成: %s %s ===' % (name, tag))


if __name__ == '__main__':
    main()
