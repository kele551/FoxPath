# TASKS —— 可认领的任务清单（狐径 FoxPath）

> 这里的每一行都是**能独立做完、且有明确验收**的事。规则很简单：
> **一次一件事 → 先看「涉及文件」→ 做完贴出「验收命令」的输出 → 把状态改成 `done`**。
> 大改动先开 Issue 说方案；验收命令必须**真的跑过**。
> 关联的 issue 写在下表 `issue` 列（**GitCode / GitHub 两侧同步维护；AtomGit 只镜像代码，不收 issue**）（带 `good first issue` 标签的适合第一次上手）。

| id | 任务 | 难度 | 涉及文件 | 验收（跑什么） | issue | 状态 |
|---|---|---|---|---|---|---|
| F-01 | `使用说明.txt` 去掉残留的 Markdown 星号；版本号章节改成免维护写法 | ★ | `使用说明.txt` | `Select-String -Path 使用说明.txt -Pattern '\*\*'` 无命中；版本章节不再停在 v1.0.6 | #2 | done |
| F-02 | `docs/CHANGELOG.md` 补 v1.0.2 / v1.0.3 / v1.0.4，并删掉 README 里的「尚未收录」备忘 | ★ | `docs/CHANGELOG.md`、`README.md` | `git grep -n "^## v1\.0\.[234]" -- docs/CHANGELOG.md` 三条都在；`git grep -n "尚未收录" -- README.md` 无命中 | #3 | done |
| F-03 | `docs/CONTRIBUTING.md` 用现在时介绍**已移除**的图标脚本，改成过去式或删除 | ★ | `docs/CONTRIBUTING.md` | `git ls-files \| Select-String "create_icon"` 无命中，文档也不再指向它 | #4 | done |
| F-04 | `build_exe.py` 文件头文档与实现不一致（写"产物带版本号"，实现是固定 `FoxPath.exe`） | ★ | `build_exe.py` | 文件头说明与代码里的产物名一致 | #5 | done |
| F-05 | 发版时"自动改 README 版本号"的正则已失效（README 改用动态徽章），实际版本文字靠手改 | ★★ | `tools/publish.py` | 在临时副本上跑改版本逻辑，README 里「当前对外发布版本 **vX.Y.Z**」与 `docs/SECURITY.md` 都被改到；或自检里加一条"文档版本 == APP_VERSION"断言 | #6 | done |
| F-06 | `docs/CODE_OF_CONDUCT.md` 是六份治理文档里唯一英文且无中文抬头/署名的 | ★ | `docs/CODE_OF_CONDUCT.md` | 首行有「狐径 FoxPath —— 作者：海风（kele551） · 仓库链接」，与其余五份同构（正文保留 Contributor Covenant 原文） | #7 | done |
| F-07 | 演示页与演示视频文件名停在 v1.0.7（当前 v1.1.1），页面未注明录制版本 | ★ | `docs/demo/index.html` | 页面上注明「录制于 v1.0.7」，不让人误以为等于当前版本 | #8 | done |
| F-08 | 候选 IP 池里没有 GitHub **上传**用的两个域（`uploads.github.com` / `objects.githubusercontent.com`），发版传附件时只能直连撞运气 | ★★ | `github_direct.py`（池常量）、`tests/` | 两个 host 都在池常量里；新增一条确定性测试（桩掉网络，不靠真连）断言它们在池内；`python -m py_compile github_direct.py` 与 `pytest tests -q` 全绿 | 无 | todo |
| F-09 | 源码里还留两处老仓库字样的注释/面板标签（`github_direct.py` 约 2713、2782 行），且 `meta.json` 的回落地址里没有 GitCode | ★ | `github_direct.py` | 按 `tools/preflight_release.py` ⑦ 的判据全仓 0 命中；`meta.json` 回落顺序与 `version.json` 升级源口径一致（GitCode 主、GitHub 兜）；`python tools/preflight_release.py` 全绿 | 无 | todo |

## 验收时请顺手遵守的约定

- **不要引入任何"改 hosts / 改系统 DNS / 要管理员权限"的功能**（与项目承诺冲突，2026-10 已因此移除历史脚本）；
- 所有写进系统的设置都必须有**退出还原**路径；
- 行尾保持 **LF**（`.gitattributes` 已固定）；`.ps1` 若新增必须 **UTF-8 带 BOM**；
- 对外文案不许出现 绕过 / 翻墙 / 梯子 / 科学上网 / 墙 / 破解 / 屏蔽；
- 详细约定见 [AGENTS.md](AGENTS.md)（AI 助手）/ [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md)（人类贡献者）。
