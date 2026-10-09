# 代码签名政策（Code Signing Policy）

> 狐径 FoxPath —— 作者：**海风（kele551）** · <https://github.com/kele551/FoxPath>
> 最近更新：2026-10-09

## 中文

### 1. 发布产物由本仓库源码构建

本项目对外发布的 `FoxPath.exe` 是**从本仓库的源码、用仓库里的构建脚本**打出来的，没有任何部分是线下手工拼装的：

| 项目 | 事实 |
|---|---|
| 源码 | 全部在本仓库；入口与主程序是 `github_direct.py`（代理、PAC、IP 体检、控制面板都在里面） |
| 构建脚本 | 仓库根目录的 `build_exe.py` |
| 构建命令 | `python build_exe.py`（见 README「从源码构建」） |
| 打包工具 | PyInstaller（**只有打包这一步需要它**）；发布出去的 exe **运行时零第三方依赖**，全部 `import` 都是 Python 标准库 |
| 版本号来源 | 唯一来源是 `github_direct.py` 里的 `APP_VERSION` 常量 |
| 指纹登记 | 打包后用 `make_version_json.py` 生成 `version.json`（含 exe 的 SHA256 与字节数），随发行版一起发布 |
| 自动化构建 | [.github/workflows/build.yml](.github/workflows/build.yml)：在 GitHub 的 Windows runner 上执行同一条命令，打印并留存 SHA256 |

**任何人**都可以按上面的命令自己构建一份，并与发行页上的成品逐字节比对 SHA256。

### 2. 免费代码签名

**Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by [SignPath Foundation](https://signpath.org).**

- 本项目正在申请上述免费代码签名服务，**目前发布的 exe 尚未签名**。
- 申请通过之后：
  - 签名在**构建流程（CI）里自动完成**，不手工签、不签名任何非本仓库构建的文件；
  - 签名步骤会插在 [.github/workflows/build.yml](.github/workflows/build.yml) 里标注的占位位置
    （即"先签名、再计算 SHA256"），仓库里能看到完整的签名流程；
  - 签名只表示**该文件由本仓库源码自动构建而来**，不代表任何形式的担保。
- 签名要解决的实际问题：这个程序会改系统代理设置，未签名时部分安全软件会对"首次运行"额外拦一下
  （升级后的第一次启动被杀软拦住的现象，README「升级时请注意」一节有记录）。

### 3. 怎么验证你手上的产物（SHA256）

绕开一切信任假设，只比指纹即可：

```powershell
# 1) 算你手上这个文件的指纹
certutil -hashfile FoxPath.exe SHA256

# 2) 跟下面任一处的值比对（都来自本仓库/本项目的发布流程）
#    a. 发行页（Releases）说明里公布的 SHA256
#    b. 本仓库 version.json 里 exe.sha256 字段（升级时程序自己也是拿它做校验的）
#    c. CI 构建产物里的 SHA256SUMS.txt（.github/workflows/build.yml 生成）
```

一致 → 说明这个文件与"从本仓库源码构建出来的那一份"完全相同，中途没有被替换或改动。
不一致 → **不要运行**，请到 [Issues](https://github.com/kele551/FoxPath/issues) 反馈。

> 顺带一句实话：这个程序**没有购买商业数字签名**，所以 Windows SmartScreen 与部分杀软可能仍然提示风险。
> 这是未签名软件的常态，不是文件损坏。请用上面的 SHA256 比对来判断来源，而不是看杀软的脸色。

### 4. 团队角色（Team roles）

| 角色 | 成员 |
|---|---|
| 提交者与审查者 Committers and reviewers | [@kele551](https://github.com/kele551) |
| 签名批准者 Approvers | [@kele551](https://github.com/kele551) |

本项目目前由作者一人维护，上述角色由同一人承担。

---

## English (summary)

**What is released.** Every published `FoxPath.exe` is built from this repository's source code using the
build script in this repository (`python build_exe.py`). Only the packaging step needs PyInstaller — the
released executable itself has **zero third-party runtime dependencies** (standard library only). The
version number has a single source of truth (`APP_VERSION` in `github_direct.py`), and `version.json`
(published next to the release) records the SHA256 and byte size of the executable. The same build command
runs in CI ([.github/workflows/build.yml](.github/workflows/build.yml)) on a clean Windows runner, which
prints and stores the SHA256 of the artifacts.

**Code signing.** **Free code signing provided by [SignPath.io](https://about.signpath.io),
certificate by [SignPath Foundation](https://signpath.org).** The application for this free service is in
progress; **currently released executables are unsigned**. Once approved, signing happens automatically
inside the CI build (the placeholder step is marked in the workflow file), never by hand and never for
files that were not built from this repository. A signature will mean exactly one thing: *this file was
built automatically from this repository's source.*

**Verifying an artifact.** Compute `certutil -hashfile FoxPath.exe SHA256` and compare it with the value
published on the release page, stored as `exe.sha256` in this repository's `version.json` (the program
itself verifies the same value during self-update), or listed in the CI artifact's `SHA256SUMS.txt`.
If they match, the file is byte-identical to the artifact built from this source. If they do not match,
**do not run it** — please report it in the issue tracker.

**Privacy note for signers.** This program collects no user data and does not route traffic through any
third-party server: it relays locally to GitHub's own published IP addresses. See README "已知边界".

**Team roles.** Committers and reviewers: [@kele551](https://github.com/kele551).
Approvers: [@kele551](https://github.com/kele551).
