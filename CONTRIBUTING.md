# 参与贡献（Contributing）

> 狐径 FoxPath —— 作者：**海风（kele551）** · <https://github.com/kele551/FoxPath>

先说清楚这个项目的脾气，能省掉双方很多时间：

- **它只有一个目标：让这台机器上的 GitHub 能正常打开。** 不做全局加速、不接管其它域名、
  不经过任何第三方服务器 —— 原理就是"拿着 GitHub 官方 IP 逐个实测握手，挑当前线路能用的直连"。
- **零第三方依赖是底线。** 主程序全部 `import` 都是 Python 标准库。想合入一个需要 `pip install` 的依赖，
  基本会被拒。
- **版本号只给新功能用。** 修 bug 的改动攒到下一个功能版一起发。你的 PR 合了不等于马上发版。
- **改注册表的地方要格外小心。** 这个程序会写 `HKCU\...\Internet Settings`（系统代理/PAC），
  所有相关改动都必须验证"退出后能原样还原"。

---

## 一、怎么提 Issue

走 [Issues](https://github.com/kele551/FoxPath/issues)，有两个模板：

| 模板 | 什么时候用 | 会问你什么 |
|---|---|---|
| 🐞 报告问题 | 打不开 GitHub、体检全灭、系统代理没还原、面板异常 | 程序版本号、Windows 版本、**宽带运营商**、复现步骤、面板上"当前可用 IP"的数字、`foxpath.log` |
| 💡 提功能建议 | 想要某个功能 / 觉得现在别扭 | 使用场景、期望效果、试过的替代做法 |

**宽带运营商那一栏很关键**：联通 / 移动 / 电信 / 校园网的表现差很多，缺了这一项基本没法定位。

**提之前先做三件事：**

1. 看 README 的[已知边界](https://github.com/kele551/FoxPath#已知边界)一节 —— 哪些域名不走代理、
   被强杀后系统代理可能还指着本程序、端口占用会弹错误框，都写在那里；
2. 看 README 末尾的「路线图（Roadmap）」，已经排进计划的不用重复提；
3. 准备日志：`%LOCALAPPDATA%\FoxPath\foxpath.log` 的末尾几十行（面板的「日志」区块也能看到尾部）。

**安全问题不要开公开 Issue**，请按 [SECURITY.md](SECURITY.md) 私下报告。

---

## 二、PR 流程

1. **先开 Issue 对齐，再动手写代码。** 涉及候选池、注册表还原、升级链路的改动尤其要先说 ——
   这几处历史上都真出过事（见 README「版本记录」）。
2. Fork → 开分支（建议 `fix/xxx`、`feat/xxx`、`docs/xxx`）→ 改 → 自测 → 提 PR。
3. PR 描述请用仓库自带的 [模板](.github/PULL_REQUEST_TEMPLATE.md)：**改了什么 / 怎么验证的 / 自查清单**。
   "怎么验证的"那一栏必须写你实际跑过的命令和看到的结果。
4. 维护者会**在 7 天内**给第一次答复。

---

## 三、代码风格

### 通用

- **中文注释、中文提交信息。** 注释写清"为什么这么做"，尤其是历史坑（这个仓库里很多行注释就是踩坑记录，别删）。
- **不引入第三方依赖。** `github_direct.py` 只用标准库；打包只额外需要 `pyinstaller`。
- **改动要能对得上文档。** 改了行为就顺手改 README / 《使用说明》里对应的话。
- **对外文案有敏感词清单**：凡涉及"网络访问限制"的说法一律不得出现在仓库任何文件里；
  具体清单见工作区章程，**不要在仓库内逐词列举**，避免清单自身被内容扫描命中
  （README、简介、发布说明、注释、Issue/PR 模板都算）—— 仓库曾因措辞被判内容违规，整页打不开。
  这七个词**连列举都不写进仓库**（写在这里就等于命中，本文件因此不再抄词表；维护者手上另存一份）。
  换成中性技术表述：**「不依赖域名解析」「本地网络分流」「连接优化」「DNS 解析异常」**。
  改完对外文案后，按维护者手上的词表搜一遍再提交。
- **不要在对外文档里写私人邮箱、令牌、口令。** 反馈入口一律用 Issues 链接。

### Python（`github_direct.py` 等）

- 缩进 4 空格；保持 `# -*- coding: utf-8 -*-` 头。
- 保命路径（退出还原、`atexit`、`--restore`）里**不要抛出异常**，吞掉异常要写日志说明。
- `.ps1`（升级小助手等内嵌脚本）**必须是 UTF-8 带 BOM**。

### 行尾与编码（这条最容易踩）

- 仓库文本文件是 **CRLF**。**不要整文件重写行尾** —— 会产生"整个文件都变了"的假 diff。
- 提交前 `git diff --stat` 扫一眼：只改了几行的文件显示几百行变动，八成是行尾被改了。

---

## 四、如何在本地构建与自查

### 构建

```bash
pip install pyinstaller

python build_exe.py        # 产出 FoxPath.exe（版本号取自 github_direct.py 的 APP_VERSION）
```

> 仓库里的 `create_icon*.py` / `make_icon_from_user_image.py` 是当初做图标用的一次性脚本，
> 里面的路径写死在作者本机，**在别的机器上跑不通**，正常构建不需要它们。

### 自查（改完自己先过一遍）

```bash
python -m py_compile github_direct.py build_exe.py make_version_json.py tools/publish.py
```

### 测试程序时必须验证的三件事

改动涉及系统代理时，实测一遍这三条再提 PR：

1. **启用 → 退出 → 系统代理确实还原**成运行前的样子（`HKCU\CurrentVersion\Internet Settings` 下的
   `AutoConfigURL` 等值）；
2. **重复启用不会污染还原备份**（连点两次「启用加速」，退出仍能还原）；
3. **备份写不进去时不去改注册表**（宁可不开，也不留下无法还原的状态）。

⚠ 不要用 `nohup ... &` 在 shell 里后台启动来测试：命令结束时进程会被终止，测出来的现象是假的。

---

## 五、提交信息规范

用 [Conventional Commits](https://www.conventionalcommits.org/) 的前缀，正文写中文：

```
fix: 升级源缺少 sha256 时拒绝升级，不再直接放行

原因：原来写的是 if want and sha != want，want 为空时整个判断短路，
     等于把未校验的 exe 装到用户机器上。
改法：want 为空直接判失败并记日志（phase=failed, error=nosha）。
验证：把本地 version.json 的 sha256 改成空串，程序拒绝升级并保留旧版。
```

常用前缀：`fix:`（修缺陷）、`feat:`（新功能）、`docs:`（只改文档）、`chore:`（构建/杂务）、`release:`（发版）。

---

## 六、许可

本项目是 MIT（见 [LICENSE](LICENSE)）。你提交的贡献即表示同意按同一许可发布。

---

## 七、仓库文件与打包注意（维护者备忘，2026-10-14 自 README 迁入）

| 文件 | 说明 |
| --- | --- |
| `github_direct.py` | 主程序：代理、PAC、体检、控制面板（推荐用这个） |
| `Fix-GitHub.ps1` | **历史脚本，仓库里只有它会改 `hosts`**：往 `hosts` 里钉 IP + 装计划任务定时换；**需要管理员权限**，与主程序二选一（主程序不碰 `hosts`） |
| `Run-GitHubFix.bat` | 以管理员身份拉起 `Fix-GitHub.ps1`（会弹 UAC） |
| `build_exe.py` | PyInstaller 打包脚本 |
| `make_version_json.py` | 生成升级源 `version.json`（版本号 + exe 指纹 + 字节数） |
| `tools/preflight_release.py` | **发版前自检闸门**（发布前必须全绿），见下方「发版前自检」 |
| `tools/compare_ips.py` | 把内置候选 IP 与 GitHub 官方 `meta` 网段对照（排查用） |
| `tools/publish.py` | 一键发布流水线（Gitee 主 + GitHub 镜像），内置自检闸门 |
| `requirements.txt` | 依赖口径：主程序零第三方依赖，只有发布脚本需要 `requests` |
| `app.ico` | 程序图标（自绘，不含第三方吉祥物或标志） |
| `release-notes.md` | 发行说明 |
| `使用说明.txt` | 中文使用说明 |

打包注意：

- PyInstaller 的 `--clean` 参数在某些受限环境下会因批量删缓存被拦，脚本里已去掉。
- 产物名与版本号都从 `github_direct.py` 的 `APP_VERSION` 推导，只有一个来源，不用改两处。
- **`.ps1` 文件必须保存为「UTF-8 带 BOM」**。PowerShell 5.1 对没有 BOM 的文件按 ANSI 读，
  中文会变乱码，字符串/花括号被破坏后直接 ParserError —— `Fix-GitHub.ps1` 在 v1.0.1 之前
  就是这样：文件本身完整，但因为没有 BOM 而**从未成功运行过**。

> 图标不用管：`app.ico` 已经入库，且为**自绘**（不含任何第三方吉祥物或标志，见 `COMPLIANCE.md`）。
> 当初做图标用的那几个一次性脚本（`create_icon*.py` / `make_icon_from_user_image.py`）已从仓库
> 移除：它们把输入输出路径写死在作者本机，在别的机器上跑不通，正常构建也不需要它们。

---

## 八、发版前自检（发布闸门，2026-10-14 自 README 迁入）

**发版前自检脚本随仓库提供，位置 `tools/preflight_release.py`**（同目录的 `tools/compare_ips.py`
用于对照官方 `meta` 网段排查候选 IP）：

```bash
python tools/preflight_release.py              # 默认拿仓库根目录的 FoxPath.exe 当候选
python tools/preflight_release.py --help       # 看全部开关
python tools/preflight_release.py --dry-run    # 只跑静态项：不写注册表、不拉程序、不碰系统代理
```

检查内容：

| 类别 | 检查什么 |
| --- | --- |
| 版本一致性 | exe 文件版本 = 源码 `APP_VERSION` = `version.json` 版本，且 `version.json` 的 `sha256` / `size` 与候选 exe 对上 |
| 冷启动演练 | 把候选 exe 复制成「刚下载落地」的样子，立刻用隐藏 PowerShell 启动，必须在限定时间内起来 |
| 完整升级演练 | 旧版 → 本地升级源 → 检查更新 → 立即升级 → 必须自己起来（起不来则必须「重试过 + 明确提示用户」），并核对换上去的文件**指纹**等于候选 |
| 失败分支 | 升级源里的 `sha256` 故意写错 → 必须拒绝并保留旧版 |
| 接口与还原 | `/pac` 纯 ASCII、`/api/diag` 正常、非法 IP 被拒、连点两次启用不污染系统代理备份、退出后注册表还原、不留垃圾 |
| 一致性警告（WARN） | ① 工作区副本与仓库副本 `tools/preflight_release.py` 的 **sha256 是否一致**（两份漂移了就警告）；② **两平台发行版附件 SHA256 是否一致**（Gitee 请求间隔 ≥3 秒限速；网络或平台异常只警告，不判红） |

> 自检会真的改注册表、拉起本机已装的狐径（结束时再把它重新启动），所以**别在有正式发布任务之外随手整轮跑**；
> 只想确认脚本自己没坏，用 `--dry-run`（只做静态检查）。
> 警告级（WARN）不阻断发布，但会在结尾单独列出来，发布前应当看一眼。
> `tools/publish.py release` 已内置这道闸门：自检不全绿直接中止发布（`--skip-preflight` 只留给线上事故回滚，且要在 `logs\` 写明原因）。
