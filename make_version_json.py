# -*- coding: utf-8 -*-
"""生成狐径的升级源 version.json（发版时跑）
用法: python make_version_json.py [--exe <exe路径>] [--notes "本版说明"]
读 github_direct.py 里的 APP_VERSION, 算出 exe 的 SHA256 与字节数, 写出 version.json。
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
    a = ap.parse_args()
    with io.open(os.path.join(HERE, 'github_direct.py'), encoding='utf-8') as f:
        ver = re.search(r"^APP_VERSION\s*=\s*'([^']+)'", f.read(), re.M).group(1)
    out = {'version': ver, 'notes': a.notes,
           'exe': {'sha256': sha256(a.exe),
                   'url': 'https://gitee.com/kele551/FoxPath/releases/download/v%s/FoxPath.exe' % ver,
                   'size': os.path.getsize(a.exe)}}
    with io.open(a.out, 'w', encoding='utf-8', newline='') as f:
        f.write(json.dumps(out, ensure_ascii=False, indent=2) + '\n')
    print('已写出 %s (version=%s, exe=%d 字节)' % (a.out, ver, out['exe']['size']))

if __name__ == '__main__':
    main()