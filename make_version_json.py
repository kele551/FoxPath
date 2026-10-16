# -*- coding: utf-8 -*-
"""生成狐径的升级源 version.json（发版时跑）
用法: python make_version_json.py [--exe <exe路径>] [--notes "本版说明"]
                                     [--mirror <https下载地址> ...]
读 github_direct.py 里的 APP_VERSION, 算出 exe 的 SHA256 与字节数, 写出 version.json。
--mirror 可给多次(国内/海外镜像仓库的附件地址), 会写进 exe.mirrors 数组;
App 端下载时按 url -> mirrors 依次回退(1.1.0 之后支持, 老版本自动忽略该字段)。
发布时把它提交到 main 分支(升级检查走 raw), 同时作为发行版附件上传。
"""
import argparse, hashlib, io, json, os, re

HERE = os.path.dirname(os.path.abspath(__file__))

def sha256(p):
    with open(p, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest().upper()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--exe', default=os.path.join(HERE, 'FoxPath.exe'))
    ap.add_argument('--notes', default='')
    ap.add_argument('--out', default=os.path.join(HERE, 'version.json'))
    ap.add_argument('--mirror', action='append', default=[],
                    help='镜像下载地址(可多次); 非 https 一律拒收')
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
    with io.open(a.out, 'w', encoding='utf-8', newline='') as f:
        f.write(json.dumps(out, ensure_ascii=False, indent=2) + '\n')
    print('已写出 %s (version=%s, exe=%d 字节, 镜像 %d 个)'
          % (a.out, ver, out['exe']['size'], len(a.mirror)))


if __name__ == '__main__':
    main()