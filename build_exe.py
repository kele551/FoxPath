# -*- coding: utf-8 -*-
"""把 github_direct.py 打成单文件绿色 exe。用法: python build_exe.py"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
APP_NAME = '狐径-v1.0.0'
ICO = os.path.join(HERE, 'app.ico')
SRC = os.path.join(HERE, 'github_direct.py')

cmd = [
    sys.executable, '-m', 'PyInstaller',
    '--onefile',
    '--noconsole',
    # 不加 --clean: 它会批量清缓存触发安全拦截。PyInstaller 不 clean 也能正确增量构建。
    '--noconfirm',
    '--name', APP_NAME,
    '--distpath', HERE,
    '--workpath', os.path.join(HERE, 'build'),
    '--specpath', os.path.join(HERE, 'build'),
    '--icon', ICO,
    '--hidden-import', 'PIL',
    SRC,
]

print('打包命令:', ' '.join(cmd))
r = subprocess.run(cmd, cwd=HERE)
if r.returncode != 0:
    print('打包失败, 退出码', r.returncode)
    sys.exit(r.returncode)

exe = os.path.join(HERE, APP_NAME + '.exe')
print('完成:', exe, os.path.getsize(exe), 'bytes')
