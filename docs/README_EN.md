# FoxPath — GitHub access helper for Windows

> Author: **HaiFeng (kele551)** · Gitee (primary): <https://gitee.com/kele551/FoxPath> · GitHub (mirror): <https://github.com/kele551/FoxPath> · AtomGit (code mirror): <https://atomgit.com/kele551/FoxPath>
> 中文说明见 [../README.md](../README.md)

A **single-file Windows app** (no installer required). It runs a small local proxy that only handles
GitHub-related domains and connects directly to GitHub IPs that are **currently reachable**, then restores
your system settings when it exits.

## What it does

- Tests candidate IPs with a **real TLS handshake** plus a short-window **throughput** measurement, and re-checks every 5 minutes
- Ships its own **PAC** so only GitHub domains go through the helper — everything else connects directly
- Portable single exe, **no admin rights required**, no installer
- Green/reversible: it writes only to `HKCU` and puts everything back on exit (`--restore` to do it manually)

## What it deliberately does not do

- ❌ It never modifies `hosts` or the system DNS settings
- ❌ It is **not** a general-purpose proxy: it does not provide proxy service and never forwards other people's traffic
- ❌ It does not collect or upload user data; logs stay on your machine

## Download

- **Gitee (primary, faster in mainland China)**: <https://gitee.com/kele551/FoxPath/releases>
- **GitHub (mirror)**: <https://github.com/kele551/FoxPath/releases>

Asset name: `FoxPath.exe` (single file — version number lives in the exe properties, not in the file name).

## Build and verify

```powershell
python build_exe.py                  # builds FoxPath.exe (PyInstaller 6.x; version pinned for reproducibility)
python -m py_compile github_direct.py
python tools/preflight_release.py    # release gate — must be all green before publishing
```

## Repository layout & contributing

- Structure and "where do I change X": [ARCHITECTURE.md](ARCHITECTURE.md)
- Claimable tasks with acceptance commands: [../TASKS.md](../TASKS.md)
- Contributing guide: [CONTRIBUTING.md](CONTRIBUTING.md) · Security policy: [SECURITY.md](SECURITY.md) · Compliance: [COMPLIANCE.md](COMPLIANCE.md)
- For AI coding agents: [../AGENTS.md](../AGENTS.md)

## License

MIT — see [../LICENSE](../LICENSE).
