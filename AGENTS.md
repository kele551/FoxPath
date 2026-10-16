# AGENTS.md —— 给 AI 编程助手的协作说明（狐径 FoxPath）

> 这份文件面向用 AI 助手（Claude Code / Codex / Cursor / DSH 等）改这个仓库的人。
> **动手前先读 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**（结构、改哪儿、怎么验）；人类贡献流程见 [CONTRIBUTING.md](docs/CONTRIBUTING.md)。

## 这是什么

**单文件程序**：`github_direct.py`（约 4700 行）打包成 `FoxPath.exe`。
在本机开一个小代理，只接管 GitHub 相关域名并直连"实测可用"的官方 IP；退出时还原系统设置。

**功能边界（合规底线，改代码也不能越过）**：不改 `hosts`、不改系统 DNS、不需要管理员权限、
不提供通用代理服务、不转发他人流量。

## 环境与命令

```powershell
python github_direct.py            # 跑起来（会改系统代理，退出时自动还原）
python github_direct.py --restore  # 只做还原
python -m py_compile github_direct.py
python build_exe.py                # 打包（产物固定 FoxPath.exe）
python tools/preflight_release.py  # 发版前自检（发布前必须全绿）
```

⚠ `tools/preflight_release.py` 的完整模式会**结束正在运行的 FoxPath.exe** 并改系统代理/注册表；
请在自己机器上、心里有数时跑，跑完确认系统代理与注册表已还原。

## 禁区（先看这里，再改）

- **不要引入任何"改 hosts / 改系统 DNS / 要管理员权限"的功能或脚本文案** —— 这是与本项目承诺冲突的红线
  （2026-10 就因此把仓库里的历史 hosts 脚本移除了）。
- **所有写进系统的设置都必须有退出还原路径**；新增任何注册表/代理写入，先想清楚怎么还原、怎么验证。
- **对外文案红线词**：绕过 / 翻墙 / 梯子 / 科学上网 / 墙 / 破解 / 屏蔽 —— 一个都不要出现
  （Gitee 曾因这类措辞把仓库判为违规）。
- **行尾**：本仓库入库/检出**一律 LF**（`.gitattributes` 固定 `* text=auto eol=lf`，2026-10-16 归一）；不要整文件重写行尾。
- **`.ps1` 若新增，必须 UTF-8 带 BOM**。
- **署名不要改**：`海风（kele551）` / `HaiFeng (kele551)` / `Copyright (C) 2026 HaiFeng (kele551)`。
- **仓库里不许出现本机路径、私人邮箱、令牌**（自检会拦，改动前先自查）。

## 提交与验收

- 提交信息：中文，`类型: 说明`（`fix:` / `feat:` / `docs:` / `chore:`），**一次一件事**；
- **版本号只在发版时改**（`tools/publish.py release <版本> --github`）；
- PR / 回复里写清**你怎么验证的**：什么网络环境、测了哪些域名、退出后系统代理与注册表是否还原；
- 涉及挑线路/体检逻辑的改动，请附上实测数据（连通率、吞吐），别只讲原理。

## 平台（三个，代码一致）

代码同时镜像到三处：**Gitee（主源）** / **GitHub（镜像）** / **AtomGit（代码镜像）**。
**二进制发行包只发 Gitee 与 GitHub** —— AtomGit 目前没有附件上传接口（它的 Release 只提供源码归档）。

```powershell
git push origin main --tags                     # Gitee（本仓库 origin 就是 Gitee）
git push atomgit main --tags                    # AtomGit（令牌走 GIT_ASKPASS，不会出现在命令行）
# GitHub 侧走工作区的纯 REST 工具（见维护者工作区工具说明）
```

三个平台改完都要推，**内容必须逐字节一致**（判定方法：`git diff atomgit/main origin/main` 应为空）。

## 任务从哪来

GitHub Issues 里带 `good first issue` / `help wanted` 标签的条目，每条都写了**验收标准**。
仓库里还有一份机器可读的任务清单 [TASKS.md](TASKS.md)。

---

## English summary (for AI agents)

- **What it is**: a **single-file** Windows app — `github_direct.py` (~4700 lines) packaged as `FoxPath.exe`.
  It runs a small local proxy for GitHub-related domains only, connects to GitHub IPs verified by a real TLS
  handshake plus a throughput measurement, and restores system settings on exit.
- **Run / verify**: `python github_direct.py` (use `--restore` to undo) · `python -m py_compile github_direct.py` ·
  `python tools/preflight_release.py` (the release gate — must be all green before publishing).
- **Never**:
  - add anything that modifies `hosts` / system DNS or requires admin rights — that contradicts the project's
    compliance statement (a legacy script doing exactly that was removed in Oct 2026);
  - add a system setting without a matching restore path;
  - rewrite line endings wholesale (this repo stores **LF**, pinned by `.gitattributes`); new `.ps1` files must be **UTF-8 with BOM**;
  - introduce local machine paths, private emails or tokens into the repo;
  - banned wording anywhere: 绕过 / 翻墙 / 梯子 / 科学上网 / 墙 / 破解 / 屏蔽 (Gitee once flagged the repo over this);
  - don't change the author strings (`海风（kele551）` / `HaiFeng (kele551)`).
- **Commits**: one change per commit, Chinese conventional prefixes (`fix:` / `feat:` / `docs:` / `chore:`),
  and state how you verified it (which network, which domains, whether the system proxy was restored).
- **Backlog**: [TASKS.md](TASKS.md) and issues labelled `good first issue`.
