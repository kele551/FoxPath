# -*- coding: utf-8 -*-
"""把 github_direct.py 打成单文件绿色 exe。

用法:  python build_exe.py

版本号只有一个来源: github_direct.py 里的 APP_VERSION。
产物名一律 ASCII(FoxPath-v<版本>.exe) —— 中文文件名在上传到 GitHub / Gitee 时
会被破坏(实测 狐径-v1.0.0.exe 传上去变成了 -v1.0.0.exe), 所以对外只用 ASCII 名。
"""
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, 'github_direct.py')
ICO = os.path.join(HERE, 'app.ico')


def read_version():
    """版本号以 github_direct.py 的 APP_VERSION 为唯一来源, 免得两处各写各的。"""
    with open(SRC, 'r', encoding='utf-8') as f:
        m = re.search(r"^APP_VERSION\s*=\s*['\"]([^'\"]+)['\"]", f.read(), re.M)
    if not m:
        raise SystemExit('github_direct.py 里找不到 APP_VERSION, 没法确定版本号')
    return m.group(1)


def main():
    for p in (SRC, ICO):
        if not os.path.isfile(p):
            raise SystemExit('缺文件, 没法打包: ' + p)

    ver = read_version()
    name = 'FoxPath-v%s' % ver
    print('版本号: %s   产物: %s.exe' % (ver, name))

    target = os.path.join(HERE, name + '.exe')
    # 覆盖已存在的 exe 在受限环境里会被安全策略拦(删不动在用的文件),
    # 先把它挪开再说。
    if os.path.isfile(target):
        try:
            os.replace(target, target + '.old')
            print('已把旧 exe 挪到 %s.old' % name)
        except Exception as e:
            print('旧 exe 挪不动(%s), 继续尝试直接覆盖' % e)

    cmd = [
        sys.executable, '-m', 'PyInstaller',
        '--onefile',
        '--noconsole',
        # 不加 --clean: 它会批量清缓存触发安全拦截。不 clean 也能正确增量构建。
        '--noconfirm',
        '--name', name,
        '--distpath', HERE,
        '--workpath', os.path.join(HERE, 'build'),
        '--specpath', os.path.join(HERE, 'build'),
        '--icon', ICO,
        SRC,
    ]
    print('打包命令:', ' '.join(cmd))
    r = subprocess.run(cmd, cwd=HERE)
    if r.returncode != 0:
        print('打包失败, 退出码', r.returncode)
        return r.returncode

    exe = target
    if not os.path.isfile(exe):
        print('打包完成但没找到产物:', exe)
        return 1
    print('完成: %s  %d bytes' % (exe, os.path.getsize(exe)))
    print('发布时请用这个 ASCII 文件名; 中文名在 GitHub 上会被破坏。')
    return 0


if __name__ == '__main__':
    sys.exit(main())
