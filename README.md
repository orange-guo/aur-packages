# AUR Packages Monorepo 📦

This repository contains my maintained Arch User Repository (AUR) packages. The entire build, verification, and publishing process is automated via GitHub Actions.

## 🚀 Packages Managed

| Package | Description | Status |
|---------|-------------|--------|
| [antigravity-tools-bin](https://aur.archlinux.org/packages/antigravity-tools-bin) | Professional Antigravity Account Manager & Switcher | ![Build Status](https://github.com/theorangeguo/aur-packages/actions/workflows/aur-publish.yml/badge.svg) |
| [boxd-cli-bin](https://aur.archlinux.org/packages/boxd-cli-bin) | External CLI for managing boxd cloud VMs | ![Build Status](https://github.com/theorangeguo/aur-packages/actions/workflows/aur-publish.yml/badge.svg) |
| [cli-proxy-api-bin](https://aur.archlinux.org/packages/cli-proxy-api-bin) | Proxy server providing OpenAI/Gemini/Claude compatible API interfaces | ![Build Status](https://github.com/theorangeguo/aur-packages/actions/workflows/aur-publish.yml/badge.svg) |
| [cpa-manager-plus-bin](https://aur.archlinux.org/packages/cpa-manager-plus-bin) | Management panel and analytics server for CLIProxyAPI | ![Build Status](https://github.com/theorangeguo/aur-packages/actions/workflows/aur-publish.yml/badge.svg) |
| [cpa-usage-keeper-bin](https://aur.archlinux.org/packages/cpa-usage-keeper-bin) | Standalone CLIProxyAPI usage persistence and dashboard service | ![Build Status](https://github.com/theorangeguo/aur-packages/actions/workflows/aur-publish.yml/badge.svg) |
| [fingerprint-chromium-bin](https://aur.archlinux.org/packages/fingerprint-chromium-bin) | Fingerprint Chromium (Ungoogled Chromium with fingerprinting protection) | ![Build Status](https://github.com/theorangeguo/aur-packages/actions/workflows/aur-publish.yml/badge.svg) |
| [vibe-kanban-bin](https://aur.archlinux.org/packages/vibe-kanban-bin) | AI-powered Kanban board | ![Build Status](https://github.com/theorangeguo/aur-packages/actions/workflows/aur-publish.yml/badge.svg) |
| [wlroots0.20-vmwgfx](https://aur.archlinux.org/packages/wlroots0.20-vmwgfx) | wlroots 0.20 with a vmwgfx compatibility patch for VMware environments | ![Build Status](https://github.com/theorangeguo/aur-packages/actions/workflows/aur-publish.yml/badge.svg) |
| [zellij-no-mouse-resize-bin](https://aur.archlinux.org/packages/zellij-no-mouse-resize-bin) | Zellij with advanced_mouse_actions also gating pane mouse resize | ![Build Status](https://github.com/theorangeguo/aur-packages/actions/workflows/aur-publish.yml/badge.svg) |

## 🛠 Automation Workflow

The package framework lives in [`scripts/aurpkg.py`](scripts/aurpkg.py). GitHub Actions call [`scripts/ci.sh`](scripts/ci.sh), a small CI entrypoint that keeps workflow YAML thin and delegates package behavior to `aurpkg.py`.

1.  **Discovery**: Automatically scans the repository for PackageSpec v1 definitions (`package.toml` files).
2.  **Resolve**: Fetches upstream versions and direct source URLs.
3.  **Prepare Artifacts**: Produces or locates declared artifacts such as repo-built GitHub Release archives.
4.  **Render**: Generates a temporary `PKGBUILD`, optional `.install`, and other packaging assets.
5.  **Build**: Verifies the package builds successfully in a clean environment.
6.  **Package Validation**: Installs the built package and runs package-level smoke checks.
7.  **Publish**: Pushes the rendered package contents to AUR only after package validation passes.

The package validation workflow and the publish workflow share the same smoke-check path, so scheduled AUR publishes are gated on the same package-level checks used in pull requests.

For a deeper explanation of the moving parts, see [docs/WORKFLOW.md](docs/WORKFLOW.md). For framework boundaries and package extension rules, see [docs/PACKAGE_FRAMEWORK.md](docs/PACKAGE_FRAMEWORK.md).

The publish workflow runs automatically **every 6 hours**. Package validation runs on pull requests, pushes to `main`, and manual dispatches.

## 💻 Local Usage

You can use `scripts/aurpkg.py` to test changes locally.

### Prerequisites
*   Arch Linux based system (or container)
*   `sudo` privileges
*   Docker or Podman for local `run-test`
*   `github-cli` (`gh`) only when publishing missing GitHub Release artifacts

### Commands

**1. Install Dependencies:**
```bash
sudo pacman -Syu --needed --noconfirm git openssh pacman-contrib sudo curl jq python
sudo python3 scripts/aurpkg.py setup-user
```

**2. Run Publish Path (Dry Run):**
```bash
# Syntax: python3 scripts/aurpkg.py run-publish <pkgname-or-path> [flags]
python3 scripts/aurpkg.py run-publish antigravity-tools-bin --dry-run
```

**3. Run Metadata Preflight:**
```bash
python3 scripts/aurpkg.py preflight cli-proxy-api-bin
```

**4. Run Publish Path Verification (Container/CI Recommended):**
```bash
python3 scripts/aurpkg.py run-publish cli-proxy-api-bin --dry-run --verify-install
```

**5. Run Package Validation:**
```bash
python3 scripts/aurpkg.py run-test antigravity-tools-bin
```

This path uses an ephemeral Arch container locally, builds the package, installs it with `pacman -U`, and runs smoke checks against the installed files.

## ➕ Adding a New Package

Please refer to [CONTRIBUTING.md](docs/CONTRIBUTING.md) for the standard process of adding and maintaining packages.

Each package directory now lives under `packages/<pkgname>/` and keeps only:
- `package.toml` as the PackageSpec v1 source of truth
- optional `hooks.sh` for special upstream logic
- optional `files/` for static assets such as service units or licenses

`PKGBUILD` and `.SRCINFO` are generated only in temporary workspaces during local runs and CI.

## 🔑 Integration & Secrets

For detailed setup instructions, including required publishing secrets (`AUR_SSH_PRIVATE_KEY`, `AUR_USERNAME`, and `AUR_EMAIL`) and global configuration, please refer to [INTEGRATION.md](docs/INTEGRATION.md).

---
*Maintained by [theorangeguo](https://github.com/theorangeguo)*
