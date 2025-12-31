#!/bin/bash
set -e

# ==============================================================================
# AUR Package Auto-Update Script
# ==============================================================================
# This script handles the automated update process for AUR packages in this monorepo.
# It supports:
# - Checking upstream GitHub releases
# - Updating PKGBUILD versions and checksums
# - Building packages (verification)
# - Pushing changes to AUR
# - Custom hooks via update_config.sh
# ==============================================================================

# Default Configuration
FORCE_UPDATE=false
DRY_RUN=false
SKIP_BUILD=false
PKG_DIR=""

# Helper: Log with GitHub Actions grouping
log_group_start() {
    echo "::group::$1"
}

log_group_end() {
    echo "::endgroup::"
}

log_info() {
    echo "==> $1"
}

log_error() {
    echo "!! ERROR: $1" >&2
}

show_help() {
    echo "Usage: ./auto_update.sh [package_dir] [options]"
    echo ""
    echo "Options:"
    echo "  -f, --force       Force update even if version matches"
    echo "  --dry-run         Simulate run, do not push to AUR"
    echo "  --skip-build      Skip makepkg step (metadata update only)"
    echo "  -h, --help        Show this help"
}

# Parse Arguments
ARGS=()
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -f|--force) FORCE_UPDATE=true ;;
        --dry-run) DRY_RUN=true ;;
        --skip-build) SKIP_BUILD=true ;;
        -h|--help) show_help; exit 0 ;;
        -*) echo "Unknown parameter: $1"; show_help; exit 1 ;;
        *) PKG_DIR="$1" ;;
    esac
    shift
done

# Validation
if [ -z "$PKG_DIR" ]; then
    log_error "No package directory specified."
    show_help
    exit 1
fi

if [ ! -d "$PKG_DIR" ]; then
    log_error "Directory '$PKG_DIR' does not exist."
    exit 1
fi

# Enter Package Directory
log_group_start "Initialization: $PKG_DIR"
cd "$PKG_DIR"
log_info "Working directory: $(pwd)"

if [ ! -f "PKGBUILD" ]; then
    log_error "PKGBUILD not found in $PKG_DIR"
    exit 1
fi

# Load Custom Hooks/Config if present
if [ -f "update_config.sh" ]; then
    log_info "Loading custom configuration from update_config.sh..."
    source "update_config.sh"
fi

# Parse PKGBUILD metadata
# 1. Try to get variables directly from file (simple parsing)
get_var() {
    local var_name=$1
    local line=$(grep "^$var_name=" PKGBUILD | head -n 1)
    if [ -z "$line" ]; then
        return
    fi

    if [[ "$line" == *\"* ]]; then
        echo "$line" | cut -d'"' -f2
    else
        echo "$line" | cut -d'=' -f2
    fi
}

REPO_USER=$(get_var "_repouser")
REPO_NAME=$(get_var "_reponame")
PKG_NAME=$(get_var "pkgname")
CURRENT_VER=$(get_var "pkgver")

# Validation
if [ -z "$PKG_NAME" ]; then
    # Fallback to directory name if pkgname parsing fails
    PKG_NAME=$(basename "$PKG_DIR")
    log_info "Could not parse pkgname, using directory name: $PKG_NAME"
fi

# AUR Configuration
AUR_REPO_URL="ssh://aur@aur.archlinux.org/${PKG_NAME}.git"
AUR_USERNAME="${AUR_USERNAME:-lbjlaq}"
AUR_EMAIL="${AUR_EMAIL:-youremail@example.com}"

log_info "Package: $PKG_NAME"
log_info "Upstream: $REPO_USER/$REPO_NAME"
log_info "Current Version: $CURRENT_VER"
log_group_end

# ------------------------------------------------------------------------------
# 1. Check Upstream Version
# ------------------------------------------------------------------------------
log_group_start "Check Upstream"

# Define a function for checking version so it can be overridden by update_config.sh
check_upstream_version() {
    if [ -z "$REPO_USER" ] || [ -z "$REPO_NAME" ]; then
        log_error "Missing _repouser or _reponame in PKGBUILD, and no custom check_upstream_version provided."
        return 1
    fi

    if ! command -v curl &> /dev/null; then
        log_error "curl is not installed."
        return 1
    fi

    local api_url="https://api.github.com/repos/$REPO_USER/$REPO_NAME/releases/latest"
    local response
    response=$(curl -sS "$api_url")

    if [ -z "$response" ]; then
        log_error "Empty response from GitHub API."
        return 1
    fi

    local tag=$(echo "$response" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

    if [ -z "$tag" ]; then
        log_error "Could not extract tag_name from response."
        log_error "Response snippet: $(echo "$response" | head -n 5)"
        return 1
    fi

    echo "$tag"
}

# Run the check
LATEST_TAG=$(check_upstream_version)

if [ -z "$LATEST_TAG" ]; then
    log_error "Failed to fetch upstream version."
    exit 1
fi

# SECURITY: Sanitize version number to prevent injection
# Allow only alphanumeric, dots, underscores, hyphens, and plus signs.
if [[ ! "$LATEST_TAG" =~ ^v?[0-9a-zA-Z._+-]+$ ]]; then
    log_error "Security Alert: Upstream tag contains invalid characters: '$LATEST_TAG'"
    exit 1
fi

# Strip 'v' prefix if present
NEW_VER=${LATEST_TAG#v}

log_info "Upstream Version: $NEW_VER"

if [ "$NEW_VER" == "$CURRENT_VER" ]; then
    if [ "$FORCE_UPDATE" = true ]; then
        log_info "Versions match, but forcing update..."
    else
        log_info "Package is up to date."
        log_group_end
        exit 0
    fi
else
    log_info "New version available!"
fi
log_group_end

# ------------------------------------------------------------------------------
# 2. Update Metadata
# ------------------------------------------------------------------------------
log_group_start "Update Metadata"

# Update pkgver
sed -i "s/^pkgver=.*/pkgver=$NEW_VER/" PKGBUILD

# Reset pkgrel if version changed
if [ "$NEW_VER" != "$CURRENT_VER" ]; then
    sed -i "s/^pkgrel=.*/pkgrel=1/" PKGBUILD
    log_info "Reset pkgrel to 1"
fi

# Update checksums
if ! command -v updpkgsums >/dev/null 2>&1; then
    log_error "pacman-contrib not installed (missing updpkgsums)."
    exit 1
fi

log_info "Running updpkgsums..."
updpkgsums

# Generate .SRCINFO
log_info "Generating .SRCINFO..."
makepkg --printsrcinfo > .SRCINFO

log_group_end

# ------------------------------------------------------------------------------
# 3. Build & Verify
# ------------------------------------------------------------------------------
log_group_start "Build & Verify"

if [ "$SKIP_BUILD" = true ]; then
    log_info "Skipping build (--skip-build)"
else
    log_info "Running makepkg..."

    MAKEPKG_OPTS="-sf"
    if [ "$CI" = "true" ]; then
        MAKEPKG_OPTS="$MAKEPKG_OPTS --noconfirm"
    fi

    if makepkg $MAKEPKG_OPTS; then
        log_info "Build successful."
        # Optional: Check if the artifact exists
        # BUILT_PKG=$(find . -name "${PKG_NAME}-${NEW_VER}-*.pkg.tar.zst" | head -n 1)
    else
        log_error "Build failed."
        exit 1
    fi
fi
log_group_end

# ------------------------------------------------------------------------------
# 4. Publish to AUR
# ------------------------------------------------------------------------------
log_group_start "Publish to AUR"

if [ "$CI" = "true" ] && [ -n "$AUR_SSH_PRIVATE_KEY" ]; then
    log_info "Setting up SSH..."
    SSH_KEY_FILE=$(mktemp)
    echo "$AUR_SSH_PRIVATE_KEY" > "$SSH_KEY_FILE"
    chmod 600 "$SSH_KEY_FILE"
    export GIT_SSH_COMMAND="ssh -i $SSH_KEY_FILE -o StrictHostKeyChecking=no"

    # Cleanup trap
    trap 'rm -f "$SSH_KEY_FILE"' EXIT

    TEMP_AUR_DIR=$(mktemp -d)
    trap 'rm -f "$SSH_KEY_FILE"; rm -rf "$TEMP_AUR_DIR"' EXIT

    log_info "Cloning AUR repository ($AUR_REPO_URL)..."
    git clone "$AUR_REPO_URL" "$TEMP_AUR_DIR"

    log_info "Syncing files..."
    cp PKGBUILD .SRCINFO "$TEMP_AUR_DIR/"

    # Sync install files if present
    if [ -f "${PKG_NAME}.install" ]; then
        cp "${PKG_NAME}.install" "$TEMP_AUR_DIR/"
    fi

    # Optional: copy other files if needed (patches, etc.)
    # find . -name "*.patch" -exec cp {} "$TEMP_AUR_DIR/" \;

    pushd "$TEMP_AUR_DIR" > /dev/null

    git config user.name "$AUR_USERNAME"
    git config user.email "$AUR_EMAIL"

    git add PKGBUILD .SRCINFO
    if [ -f "${PKG_NAME}.install" ]; then
        git add "${PKG_NAME}.install"
    fi
    # git add *.patch 2>/dev/null || true

    if git diff --staged --quiet; then
        log_info "No changes to commit."
    else
        COMMIT_MSG="update: $NEW_VER"
        if [ "$DRY_RUN" = true ]; then
            log_info "[DRY RUN] Would commit: $COMMIT_MSG"
            log_info "[DRY RUN] Would push to master"
        else
            git commit -m "$COMMIT_MSG"
            log_info "Pushing to AUR..."
            git push origin master
            log_info "Success!"
        fi
    fi
    popd > /dev/null
else
    log_info "Skipping publish (Local run or missing SSH key)."
    log_info "Manual steps to publish:"
    log_info "  1. git clone $AUR_REPO_URL"
    log_info "  2. cp PKGBUILD .SRCINFO <repo_dir>/"
    log_info "  3. git commit & push"
fi

log_group_end
