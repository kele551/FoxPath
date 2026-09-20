@echo off
rem GitHub 直连助手 - 启动器(会自动申请管理员权限)
rem 改 hosts 必须管理员, 所以这里用 -Verb RunAs 弹 UAC

set "PS1=%~dp0Fix-GitHub.ps1"

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','%PS1%','-Gui' -Verb RunAs"
