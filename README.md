# AUR Packages Monorepo 📦

This repository contains my maintained Arch User Repository (AUR) packages. The entire build, verification, and publishing process is automated via GitHub Actions.

## 🚀 Packages Managed

| Package | Description | Status |
|---------|-------------|--------|
| [antigravity-tools-bin](https://aur.archlinux.org/packages/antigravity-tools-bin) | Professional Antigravity Account Manager & Switcher | ![Build Status](https://github.com/orange-guo/aur-packages/actions/workflows/aur-publish.yml/badge.svg) |

## 🛠 Automation Workflow

The system uses a centralized manager script [`scripts/ci_manager.sh`](scripts/ci_manager.sh) to handle the entire lifecycle:

1.  **Discovery**: Automatically scans the repository for packages (`PKGBUILD` files).
2.  **Update**: Checks GitHub releases for upstream updates.
3.  **Build**: Verifies the package builds successfully in a clean environment.
4.  **Publish**: Pushes changes to AUR if all checks pass.

The workflow runs automatically **every 6 hours**.

## 💻 Local Usage

You can use the `ci_manager.sh` script to test changes locally. This script handles dependency installation and user permission switching automatically.

### Prerequisites
*   Arch Linux based system (or container)
*   `sudo` privileges

### Commands

**1. Install Dependencies:**
```bash
sudo ./scripts/ci_manager.sh install
sudo ./scripts/ci_manager.sh setup_user
```

**2. Run Update (Dry Run):**
```bash
# Syntax: ./scripts/ci_manager.sh run_update <package_dir> [flags]
./scripts/ci_manager.sh run_update antigravity-tools-bin --dry-run
```

**3. Force Update & Build:**
```bash
./scripts/ci_manager.sh run_update antigravity-tools-bin --force --dry-run
```

## ➕ Adding a New Package

1.  **Create Directory**: Create a new folder with the package name.
    ```bash
    mkdir my-new-package
    cd my-new-package
    ```
2.  **Add PKGBUILD**: Create your `PKGBUILD`.
    *   *Required Variables*: Ensure `_repouser` and `_reponame` are defined for auto-updates.
3.  **Commit**: Push the changes.
    *   **Zero Config**: The CI system will automatically discover the new package directory. You do **NOT** need to edit any YAML files.

## 🔑 Integration & Secrets

For detailed setup instructions, including required secrets (`AUR_SSH_PRIVATE_KEY`) and global configuration, please refer to [INTEGRATION.md](INTEGRATION.md).

---
*Maintained by [Your Name]*
