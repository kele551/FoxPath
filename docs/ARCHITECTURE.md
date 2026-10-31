# 项目结构与上手路线（狐径 FoxPath）

> 给想改代码的人：**15 分钟看懂这个项目从哪进、改哪儿、改完怎么验。**
> 作者：海风（kele551） · 仓库：https://gitcode.com/kele551/FoxPath

---

## 一、一句话架构

**整个程序就是一个 Python 文件**：`github_direct.py`（约 9000 行）—— 打包成单文件 `FoxPath.exe`。
它在**本机**开一个小代理，只接管 GitHub 相关域名，直连"当前实测可用"的 GitHub 官方 IP；
死掉的 IP 立刻踢掉、定时重测补回来；退出时把系统代理还原回去。

```
FoxPath.exe (github_direct.py)
   ├─ 小代理（只接管 github.com 等域名，其它流量一律直连；8787 被占自动顺延）
   ├─ PAC：系统代理指向它自带的 PAC，按域名分流
   ├─ 线路体检：对候选 IP 真做 TLS 握手 + 短窗口实测吞吐，按吞吐排队
   ├─ 本机 git 接管：只改 ~/.gitconfig 里 http.<url>.proxy 这几条，退出还原；SSH 只读探测、不写配置
   ├─ 控制面板：状态一览、开关、日志入口（含本次会话总账与 DoH 补池结论）
   └─ 退出还原：注册表里自己改过的值写回原样（--restore 可手动收尾）
```

**明确不做什么**（合规底线，也是设计前提）：不改 `hosts`、不改系统 DNS、不需要管理员权限、
不提供通用代理服务、不转发他人流量。

---

## 二、目录与文件职责

| 文件 | 职责 | 改它的场景 |
|---|---|---|
| `github_direct.py` | **全部功能**：代理、PAC、IP 体检与挑线路、控制面板、还原 | 几乎所有功能改动 |
| `_ed25519.py` | **升级源验签**用的纯 Python Ed25519 实现（签名 + 验签），零第三方依赖；发布端签名、客户端验签都用它 | 升级验签相关（一般不用改；改动前先跑 RFC 8032 向量） |
| `version.json` | **升级源**：版本号 + `exe` 的 sha256 + 下载地址 + 字节数 | 发版脚本自动生成，**不要手改** |
| `version.json.sig` | **升级源的 Ed25519 签名**（128 个十六进制字符 = 64 字节）；与 `version.json` 同目录同名，客户端据此验签 | 发版时自动生成，**不要手改、不要入库**（每次改 version.json 都会过期） |
| `build_exe.py` | PyInstaller 打包 → `FoxPath.exe`（文件名不带版本号，版本写进 exe 属性） | 改打包参数 |
| `make_version_json.py` | 生成 `version.json`，并按 `--sign-key` 同时生成 `version.json.sig` | 发版链路 |
| `publish_files.py` | 往 GitCode 仓库推送/更新的文件清单 | 增删随仓库发布的文件 |
| `tools/publish.py` | 一键发布：改版本号 → 打包 → 升级源 → 双平台提交/发行版 → 验真 | 发版链路 |
| `tools/preflight_release.py` | **发版前自检闸门**（版本一致性、冷启动、完整升级演练、失败分支、还原） | 发版前必跑；新增检查项 |
| `tools/compare_ips.py` | 把内置候选 IP 与 GitHub 官方 `meta` 网段对照（排查用） | 排查线路问题 |
| `docs/` | 治理文档（合规 / 安全 / 贡献 / 签名政策 / 行为准则 / 更新记录 / 发布说明） | 文档类改动 |
| `使用说明.txt` | 随程序给用户看的说明书 | 面向用户的功能说明 |

**本机状态**：主要落在 `%LOCALAPPDATA%\FoxPath\`（更新源配置、升级缓存、日志、系统代理备份
`proxy-backup.json`、git 原值备份 `git-backup.json`）；程序**不在 exe 旁边放任何东西**。
设过的东西（注册表代理项、PAC、git 的 `http.<url>.proxy`）在退出时还原。

---

## 三、想改一个功能，该动哪里

| 我想… | 去哪 |
|---|---|
| 加/换候选 GitHub IP | `github_direct.py` 里的候选地址常量表（IPv4 / IPv6 两个池） |
| 改"挑哪条线路"的策略 | 体检与挑线路那几段（真 TLS 握手判活、短窗口**实测吞吐**排序、连续失败降权） |
| 改 PAC 规则 / 接管哪些域名 | PAC 生成段（原则：**只接管 GitHub 相关域名**，其余直连） |
| 改控制面板的显示 | 面板构建与刷新段（状态、开关、日志入口） |
| 改"退出还原"的范围 | 备份/还原注册表那几段（新写任何系统设置前，先想清楚怎么还原） |
| 改 git 接管（键名单 / 按值认领 / 还原口径） | `github_direct.py` 的 `git_*` 段（`GIT_PROXY_HOSTS`、`_git_residue_keys`、`git_takeover` / `git_release`）；**只碰 `http.<url>.proxy`**，改完跑 `tests/test_git_takeover.py` |
| 改端口顺延 / DoH 补池 / 会话统计 | 端口只动 `proxy_port()` 与备选名单 —— 所有对外口径都从它取，别在别处写死；DoH 在 `doh_*` 段（查询必须绕开本机代理，防自环）；会话总账在 `_web_record` / `_SESS`，别往转发热路径再加锁 |
| 改升级/发布流程 | `tools/publish.py`、`make_version_json.py` |
| 改升级**校验**逻辑（验签 / sha256 / 拒降级） | `github_direct.py` 的 `read_update_info` / `_verify_update_sig` / `_verify_download`；改完请跑 `tools/preflight_release.py`（①-e 节含"改一个字节必须验不过"的负例断言） |

---

## 四、本地跑起来 & 提交前要跑的

```powershell
# 1) 直接跑（会改系统代理，退出时自动还原；--restore 可手动还原）
python github_direct.py
python github_direct.py --restore     # 只做还原

# 2) 语法检查
python -m py_compile github_direct.py

# 3) 发版前自检（发布/替换发行版附件前**必须全绿**）
#    ⚠ 完整模式会结束正在运行的 FoxPath.exe 并改系统代理，请在自己的机器上、心里有数时跑
python tools/preflight_release.py
```

**改完请照着这几条自查**：对外文案不要出现"绕过 / 翻墙 / 梯子 / 科学上网 / 墙 / 破解 / 屏蔽"
（**这条踩过坑**：Gitee 曾因 README 里的措辞把仓库判为违规）；
所有涉及系统设置的新代码，都必须有对应的退出还原路径；
行尾保持 **LF**（`.gitattributes` 已固定 `* text=auto eol=lf`）；`.ps1` 若新增，存成 **UTF-8 带 BOM**。

---

## 五、贡献怎么提

1. 先开 Issue 描述现象（**带上 `--verbose` 的日志片段更好**）：什么网络、哪个域名、期望什么；
2. 小步提交、一次一件事，提交信息用中文写清"改了什么、为什么"；
3. PR 里说明**你怎么验证的**（哪家宽带、测了哪些域名、退出后系统代理/注册表是否还原）；
4. 详细约定见 [CONTRIBUTING.md](CONTRIBUTING.md)。
