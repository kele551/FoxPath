<!--
提 PR 之前请先读 CONTRIBUTING.md。这份模板不长，但每一栏都对应一次真实踩过的坑。
-->

## 改了什么

<!-- 一两句话说清"为什么改"，比"改了哪个文件"重要。 -->

- 

## 怎么验证的

<!-- 必填。写清你实际跑过的命令与看到的结果；"应该没问题"不算验证。 -->

```
# 例：
python build_exe.py
# 双击 FoxPath.exe → 面板打开、体检出可用 IP、浏览器能开 github.com
# 退出后确认系统代理已还原（注册表 HKCU\...\Internet Settings 的 AutoConfigURL 恢复原值）
```

- [ ] 我自己从源码构建过（`python build_exe.py`），产物能双击打开控制面板
- [ ] 改动涉及注册表/系统代理的：我验证过**启用 → 退出 → 系统代理确实还原成运行前的样子**

## 自查清单

- [ ] 提交信息符合 [Conventional Commits](https://www.conventionalcommits.org/) 风格（`fix:` / `feat:` / `docs:` / `chore:` …），正文中文
- [ ] **没有整文件重写行尾**：仓库文本文件是 **CRLF**，我的编辑器没把它变成 LF（`git diff --stat` 不应出现"整个文件都变了"）
- [ ] 没把私人邮箱、令牌、口令写进任何文件（对外文档里反馈入口一律用 Issues 链接）
- [ ] 没动 `version.json`（升级源）与 `github_direct.py` 里国内分发链路用的地址，除非这就是一次发版
- [ ] 对外文案没有用禁用词，改用中性技术表述（清单见 [CONTRIBUTING.md](../blob/main/CONTRIBUTING.md)）
- [ ] 改了行为的话，README 的「已知边界」或《使用说明》对应段落一起改了 —— 文档与实现不能各说各话
- [ ] **没有新增第三方依赖**（主程序只用 Python 标准库；打包只额外需要 pyinstaller）
- [ ] 新增/修改的 `.ps1` 是 **UTF-8 带 BOM**

## 关联 Issue

<!-- 例：Closes #12 -->
