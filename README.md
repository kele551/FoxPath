# 狐径 FoxPath

GitHub 直连助手。本机代理 + PAC，绕过 DNS 和 hosts，直连当前实测可用的 GitHub 官方 IP。

**不用管理员权限，不改 hosts，不改系统 DNS。**

## 解决什么问题

国内访问 github.com 时通时断，典型症状：

- 浏览器转圈半天最后超时，但手机开流量却能正常打开
- `api.github.com` 一直是通的，只有 `github.com` 网页打不开
- 手动往 hosts 里钉 IP，过两天又失效

根因通常不在墙，而在**本地 DNS 解析出来的那个 GitHub IP 在当前线路上不通**。浏览器老实地按 DNS 走，就卡死了。

狐径不查 DNS——它自己拿着一批 GitHub 官方 IP 逐个实测握手，挑能用的直连。

## 原理

```
浏览器 ──PAC──> 狐径本地代理 127.0.0.1:8787 ──> 实测可用的 GitHub 官方 IP
              （只代理 github.com）            （绕过 DNS）
```

| 传统做法 | 狐径 |
| --- | --- |
| 改 hosts（要管理员、IP 死了就失效） | 本机代理 + PAC，写在 HKCU，普通用户权限即可 |
| 依赖系统 DNS 解析 | 不查 DNS，直连实测能用的官方 IP |
| IP 失效后彻底打不开 | 每 5 分钟重测一轮，死 IP 自动换 |
| 程序退出后系统代理指向空端口，比原来更糟 | PAC 写了 `PROXY ...; DIRECT` 兜底，退出自动还原 |

## 用法

1. 从 [Releases](../../releases) 下载 `狐径-v1.0.0.exe`
2. 双击运行 → 浏览器自动打开控制面板 `http://127.0.0.1:8788/ui`
3. 勾选「开机自启」即可后台常驻

**首次启动请等 15～20 秒**：程序要并发体检 49 个候选 IP，体检完成前代理还没完全生效。

## 核心机制

- **体检**：每 5 分钟并发重测候选池，条件是 TCP 443 握手 + TLS 证书校验 + HTTP 首包必须返回 2xx/3xx。
  最后这条很关键——有些 IP 证书是对的，但只服务 API/CDN，访问 github.com 首页会返回 400，必须过滤掉。
- **候选池刷新**：定期从 `api.github.com/meta` 重拉 GitHub 官方公布的 IP 段，官方换 IP 了也能跟上。
- **自愈**：候选全部失效时，依次尝试重拉官方表 → 查询系统 DNS → 放宽超时重测。三步都不通才判定真不通，此时退回系统解析（和没装本程序一样，不会更糟）。
- **退出安全**：正常退出或点「退出并还原」都会把系统代理恢复成运行前的状态。

## 从源码构建

```bash
pip install pyinstaller pillow

python make_icon_from_user_image.py   # 生成 app.ico
python build_exe.py                   # 打包成 狐径-v1.0.0.exe
```

| 文件 | 说明 |
| --- | --- |
| `github_direct.py` | 主程序：代理、PAC、体检、控制面板 |
| `build_exe.py` | PyInstaller 打包脚本 |
| `make_icon_from_user_image.py` | 图标生成（抠图 + 圆角底 + 多尺寸 ICO） |
| `app.ico` | 程序图标 |

打包注意：PyInstaller 的 `--clean` 参数在某些受限环境下会因批量删缓存被拦，脚本里已去掉。

## 已知边界

- 只代理 `github.com` / `www.github.com`。GitHub 的 CSS/JS/头像在 `githubassets.com`、`githubusercontent.com` 上，这些域名直连本来就通，**走代理反而连不上**，会导致页面只剩裸 HTML、按钮点不动。
- 不代理 `api.github.com`（本来就通），Git 命令行操作不受影响。
- 绿色单文件，无需安装；但**不能**用 `nohup ... &` 在 shell 里后台启动，那样命令结束进程会被终止。要常驻就双击运行或开开机自启。

## 联系与反馈

遇到打不开、体检全灭、或者觉得哪里不好用，欢迎直接邮件反馈，我会看：

**75219857@qq.com**

反馈时如果能顺手附上控制面板里「可用 IP」那一栏的数字，定位会快很多。

## 许可

MIT
