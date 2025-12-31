# GitHub Actions Integration Guide

This repository uses a custom CI pipeline to automate the maintenance of AUR packages. This document explains how to configure the integration and maintain the system.

## 1. Prerequisites

### GitHub Repository Settings
Ensure your GitHub repository has the following configured:

1.  Go to **Settings** > **Secrets and variables** > **Actions**.
2.  Add the following **Repository secret**:

| Secret Name | Description |
|-------------|-------------|
| `AUR_SSH_PRIVATE_KEY` | The SSH private key corresponding to the public key uploaded to your AUR account (`https://aur.archlinux.org/account`). |

**Note**: The private key must not be encrypted (no passphrase) for automated usage.

### AUR Account Setup
1.  Generate an SSH key pair: `ssh-keygen -t ed25519 -f aur_key`
2.  Login to [AUR](https://aur.archlinux.org/).
3.  Upload the contents of `aur_key.pub` to your account settings.
4.  Copy the contents of `aur_key` to the GitHub Secret `AUR_SSH_PRIVATE_KEY`.

## 2. Configuration

The pipeline configuration is centralized in two places:

### Global Variables
Edit `.github/workflows/aur-publish.yml` to set global maintainer information:

```yaml
env:
  AUR_USERNAME: "your_aur_username"  # Your username on aur.archlinux.org
  AUR_EMAIL: "your@email.com"        # Your email for git commits
```

### Package Configuration
The system automatically discovers packages. To add a new package:

1.  Create a directory: `mkdir my-package`
2.  Add a `PKGBUILD` file inside.
3.  (Optional) Add `update_config.sh` for custom hooks.

## 3. How It Works

The workflow is defined in `.github/workflows/aur-publish.yml` and delegates logic to `scripts/`.

### Phase 1: Discovery
*   **Script**: `scripts/ci_manager.sh discover`
*   **Action**: Scans the repository for directories containing `PKGBUILD`.
*   **Output**: A JSON matrix of packages (e.g., `["package-a", "package-b"]`).

### Phase 2: Execution (Parallel)
For each package discovered, a new job is spawned:

1.  **Environment Setup**:
    *   Installs Arch Linux dependencies (`base-devel`, `pacman-contrib`, etc.).
    *   Creates a non-root `builder` user (required for `makepkg`).

2.  **Update Logic** (`scripts/auto_update.sh`):
    *   **Check**: Fetches latest release from upstream (GitHub).
    *   **Modify**: Updates `pkgver`, resets `pkgrel`, updates checksums.
    *   **Build**: Runs `makepkg` to verify the build succeeds.
    *   **Publish**: Clones the AUR repo, commits changes, and pushes.

## 4. Local Testing

You can simulate the CI process locally using the manager script. This is useful for debugging before pushing.

**Requirements**: An Arch Linux system (or container).

```bash
# 1. Install dependencies
sudo ./scripts/ci_manager.sh install

# 2. Setup builder user (if needed)
sudo ./scripts/ci_manager.sh setup_user

# 3. Run update (Dry Run)
# Syntax: ./scripts/ci_manager.sh run_update <directory> [flags]
./scripts/ci_manager.sh run_update antigravity-tools-bin --dry-run
```

## 5. Security Measures

The scripts include several security protections:
*   **Input Sanitization**: Package directories and upstream version tags are validated to prevent command injection.
*   **Privilege Separation**: Builds run as a restricted `builder` user, never as root.
*   **SSH Isolation**: SSH keys are stored in temporary files and securely deleted after use.
