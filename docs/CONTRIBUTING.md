# Contributing & Packaging Guide

This guide outlines the standard process for adding and maintaining packages in this repository. Following these steps ensures your package is correctly integrated into the CI/CD pipeline and documentation.

## 📋 Standard Process for New Packages

### 1. Create Package Directory
Create a new directory for your package. The directory name MUST match the `pkgname` in your `PKGBUILD`.

```bash
mkdir my-package-name
cd my-package-name
```

### 2. Create PKGBUILD
Create the `PKGBUILD` file. You can base it on existing packages in this repo.

**Critical Requirements:**
*   **Header**: Include the packaging repository info.
    ```bash
    # Maintainer: Your Name <email>
    # Packaging Repo: https://github.com/orange-guo/aur-packages
    ```
*   **Auto-Update Variables**: If you want the CI to automatically update the package, you MUST define these variables:
    ```bash
    _repouser="upstream-user"    # GitHub username of the upstream project
    _reponame="upstream-repo"    # GitHub repository name
    ```
    *The CI system uses these to check for new GitHub Releases.*

### 3. Add Auxiliary Files (Optional)
*   **`.install` file**: If you need post-install/pre-remove hooks.
    *   *Tip*: Add a feedback link in `post_install()`:
        ```bash
        echo ":: Packaging issues? Report at: https://github.com/orange-guo/aur-packages"
        ```
*   **`SRCINFO`**: Do **NOT** commit `.SRCINFO` files. The CI/CD pipeline generates them automatically during the build process to ensure they are always consistent with the `PKGBUILD`.

### 4. Local Verification
Before committing, test the build locally using the manager script.

```bash
# From the repository root
./scripts/ci_manager.sh run_update my-package-name --dry-run
```
*This verifies dependencies, checksums, and the build process without pushing to AUR.*

### 5. Update Documentation
Once the package is ready, you **MUST** update the repository documentation:

1.  **`README.md`**: Add the new package to the "Packages Managed" table.
    ```markdown
    | [package-name](https://aur.archlinux.org/packages/package-name) | Description | ![Build Status](...) |
    ```
    *Note: Use the same badge link as other packages; the workflow status is shared.*

### 6. Commit & Push
Commit your changes. The CI system will automatically pick up the new folder.

```bash
git add my-package-name README.md
git commit -m "feat: add new package my-package-name"
git push
```

## 🔄 Maintenance

### Manual Updates
The CI runs automatically every 6 hours. If you need to trigger a manual update (e.g., to fix a build error without a version change):

1.  Modify the `PKGBUILD` (e.g., increment `pkgrel`).
2.  Commit the change.
3.  The CI will detect the change and re-run.

### Deprecating a Package
To remove a package from this automation system:

1.  Remove the package directory: `git rm -r my-package-name`
2.  Remove the entry from `README.md`.
3.  Commit and push.
*Note: This does not remove the package from AUR, only from this automation repo.*

## 📏 Technical Standards

### PKGBUILD Standards
*   **Variable Definitions**:
    *   `_repouser` and `_reponame` are **mandatory** for GitHub-based packages.
    *   Do not modify `url` to point to this repo; keep it pointing to the upstream homepage.
*   **License Installation**:
    *   Custom licenses MUST be installed to `/usr/share/licenses/${pkgname}/`.
*   **Install Scripts**:
    *   Name them strictly as `${pkgname}.install`.
    *   Include the standard feedback footer in `post_install`.

### Security & Scripting
*   **Input Validation**: All scripts handling package names or paths MUST validate inputs against directory traversal (`..`) and restrict characters (alphanumeric + `.-_`).
*   **Injection Prevention**: Use `printf %q` when passing variables to `su -c` or `bash -c` commands.
*   **User Isolation**: Build operations MUST run as the `builder` user, never root.

### Versioning
*   **Upstream Tags**: The CI system automatically strips `v` prefixes from GitHub tags (e.g., `v1.2.3` -> `1.2.3`). Ensure your `pkgver` logic aligns with this.

