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


VERSION_TEMPLATE = """VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=%(vts)s,
    prodvers=%(vts)s,
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable('040904B0', [
        StringStruct('CompanyName', 'HaiFeng (kele551)'),
        StringStruct('FileDescription', 'FoxPath'),
        StringStruct('FileVersion', '%(ver)s'),
        StringStruct('InternalName', 'FoxPath'),
        StringStruct('LegalCopyright', 'Copyright (C) 2026 HaiFeng (kele551)'),
        StringStruct('OriginalFilename', 'FoxPath.exe'),
        StringStruct('ProductName', 'FoxPath'),
        StringStruct('ProductVersion', '%(ver)s'),
        StringStruct('Comments', 'gitee.com/kele551/FoxPath')
      ])
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)"""

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
    # 2026-09-22 用户要求: 文件名不带版本号(鼠标悬停/属性里看版本), 所以产物固定叫 FoxPath.exe
    name = 'FoxPath'
    # 把版本信息写进 exe 的资源, 悬停与"属性-详细信息"才看得到
    _bd = os.path.join(HERE, 'build')
    os.makedirs(_bd, exist_ok=True)
    verfile = os.path.join(_bd, 'version_info.txt')
    _n = [int(x) for x in re.findall(r'\d+', ver)]
    _n = (_n + [0, 0, 0, 0])[:4]
    with open(verfile, 'w', encoding='utf-8') as _f:
        _f.write(VERSION_TEMPLATE % {'ver': ver, 'vts': tuple(_n)})
    print('版本号: %s   产物: %s.exe (版本号写进 exe 资源, 文件名不带版本)' % (ver, name))

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
        '--version-file', verfile,
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
