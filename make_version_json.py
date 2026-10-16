# -*- coding: utf-8 -*-
"""生成狐径的升级源 version.json（发版时跑）
用法: python make_version_json.py [--exe <exe路径>] [--notes "本版说明"]
                                     [--mirror <https下载地址> ...]
                                     [--sign-key <私钥文件>]
读 github_direct.py 里的 APP_VERSION, 算出 exe 的 SHA256 与字节数, 写出 version.json。
--mirror 可给多次(国内/海外镜像仓库的附件地址), 会写进 exe.mirrors 数组;
App 端下载时按 url -> mirrors 依次回退(1.1.0 之后支持, 老版本自动忽略该字段)。
发布时把它提交到 main 分支(升级检查走 raw), 同时作为发行版附件上传。

--sign-key <私钥文件>（2026-10-16 升级通道加固）: 用 Ed25519 私钥给**刚写出的
version.json 原始字节**签名, 同目录写出 `version.json.sig`（128 个十六进制字符）。
客户端内置公钥(github_direct.py 的 UPDATE_PUBKEY)验签, 验不过的升级源一律拒绝。
私钥**只在签名这一刻读取**, 不打印、不复制、不进仓库; 本文件里也不写任何本机路径
（发版走 tools/publish.py, 它按 环境变量 -> ~/.foxpath-publish.json 的顺序找私钥）。
不带 --sign-key 时只生成 version.json（本地开发/演练用）, 并提示"没签名, 不许发布"。
"""
import argparse, hashlib, io, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))


def sha256(p):
    with open(p, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest().upper()


def load_ed25519():
    """加载同目录的 _ed25519.py（纯 Python 实现，零第三方依赖）。"""
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    import _ed25519
    return _ed25519


def load_seed(path):
    """读私钥种子（64 个十六进制字符 = 32 字节）。只读、不打印、不复制到别处。

    单独写成一个函数是为了"读错文件/文件坏了"当场说清楚 —— 宁可不发版，
    也不要发一份签得不对的 version.json.sig（客户端会一律拒绝，等于把升级通道弄断）。
    """
    with io.open(path, encoding='utf-8') as f:
        txt = f.read().strip()
    if not re.fullmatch(r'[0-9a-fA-F]{64}', txt):
        raise SystemExit('私钥文件内容不是 64 个十六进制字符（32 字节种子），拒绝签名: %s' % path)
    return bytes.fromhex(txt)


def sign_file(raw, out_path, key_path):
    """给 raw 字节签名，把 128 个十六进制字符写进 <out_path>.sig。"""
    ed = load_ed25519()
    sig = ed.signature(raw, load_seed(key_path)).hex()
    if not re.fullmatch(r'[0-9a-f]{128}', sig):
        raise SystemExit('签出来的东西长度不对（预期 128 个十六进制字符），拒绝写出: %d' % len(sig))
    with io.open(out_path + '.sig', 'w', encoding='utf-8', newline='') as f:
        f.write(sig)
    return sig


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--exe', default=os.path.join(HERE, 'FoxPath.exe'))
    ap.add_argument('--notes', default='')
    ap.add_argument('--out', default=os.path.join(HERE, 'version.json'))
    ap.add_argument('--mirror', action='append', default=[],
                    help='镜像下载地址(可多次); 非 https 一律拒收')
    ap.add_argument('--sign-key', default='',
                    help='Ed25519 私钥文件(64 个十六进制字符); 给了就同时写出 version.json.sig')
    a = ap.parse_args()
    for m in a.mirror:
        if not m.lower().startswith('https://'):
            raise SystemExit('镜像地址必须是 https:// 开头, 拒收: %s' % m)
    with io.open(os.path.join(HERE, 'github_direct.py'), encoding='utf-8') as f:
        # 单引号/双引号都认（以前只写死单引号，源码里换成双引号就 AttributeError: 'NoneType'）
        m = re.search(r"""^APP_VERSION\s*=\s*['"]([^'"]+)['"]""", f.read(), re.M)
    if not m:
        raise SystemExit('github_direct.py 里找不到 APP_VERSION, 没法确定版本号')
    ver = m.group(1)
    out = {'version': ver, 'notes': a.notes,
           'exe': {'sha256': sha256(a.exe),
                   'url': 'https://gitee.com/kele551/FoxPath/releases/download/v%s/FoxPath.exe' % ver,
                   'size': os.path.getsize(a.exe)}}
    if a.mirror:
        out['exe']['mirrors'] = a.mirror
    # ① 先写 version.json（签名对象是这份文件的**原始字节**，所以必须先落盘、再签名）
    raw = json.dumps(out, ensure_ascii=False, indent=2).encode('utf-8') + b'\n'
    with open(a.out, 'wb') as f:
        f.write(raw)
    # ② 再给**刚写出的字节**签名，保证"盘上的 version.json"与"签名的内容"逐字节一致
    if a.sign_key:
        if not os.path.isfile(a.sign_key):
            raise SystemExit('找不到私钥文件: %s（发版必须能签名，拒绝继续）' % a.sign_key)
        sig = sign_file(raw, a.out, a.sign_key)
        print('已写出 %s (version=%s, exe=%d 字节, 镜像 %d 个)'
              % (a.out, ver, out['exe']['size'], len(a.mirror)))
        print('已写出 %s.sig (Ed25519 签名, %d 个十六进制字符, 前 16 位 %s…)'
              % (a.out, len(sig), sig[:16]))
    else:
        print('已写出 %s (version=%s, exe=%d 字节, 镜像 %d 个)'
              % (a.out, ver, out['exe']['size'], len(a.mirror)))
        print('  [warn] 没带 --sign-key：**没有生成 version.json.sig**。'
              '这份只能本地演练用，不许发布（发版请走 tools/publish.py release）。')


if __name__ == '__main__':
    main()
