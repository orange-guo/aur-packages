#!/bin/bash
set -e

# ==============================================================================
# AUR Monorepo CI Manager
# ==============================================================================
# This script centralizes the logic for the CI pipeline.
# It minimizes logic in the .yaml workflow file.
#
# Commands:
#   discover   : Scans for packages and outputs JSON for GitHub Actions matrix
#   install    : Installs system dependencies (pacman)
#   setup_user : Creates and configures the 'builder' user
#   run_update : Wraps auto_update.sh with correct user permissions
# ==============================================================================

COMMAND=$1
shift || true

# Helper: Log
log() { echo "==> [CI Manager] $1"; }

case "$COMMAND" in
    discover)
        # Find all directories containing a PKGBUILD file
        PACKAGES=()
        # Use find to be more robust, looking only at depth 1
        while IFS= read -r file; do
            dir=$(dirname "$file")
            # remove ./ prefix
            dir=${dir#./}
            PACKAGES+=("$dir")
        done < <(find . -maxdepth 2 -name PKGBUILD)

        # Output as JSON for GitHub Actions matrix
        # If running locally, just print list
        if [ -z "$GITHUB_OUTPUT" ]; then
            printf '%s\n' "${PACKAGES[@]}"
        else
            # Install jq if missing (rare but possible in bare environments)
            if ! command -v jq &> /dev/null; then
                sudo apt-get update && sudo apt-get install -y jq || true
            fi

            count=${#PACKAGES[@]}
            # Use jq -c for compact output (single line) which is required for GITHUB_OUTPUT
            json_array=$(printf '%s\n' "${PACKAGES[@]}" | jq -R . | jq -sc .)

            echo "matrix={\"package\": $json_array}" >> $GITHUB_OUTPUT

            if [ "$count" -gt 0 ]; then
                echo "has_packages=true" >> $GITHUB_OUTPUT
            else
                echo "has_packages=false" >> $GITHUB_OUTPUT
            fi

            log "Discovered $count packages: $json_array"
        fi
        ;;

    install)
        log "Installing dependencies..."
        if [ -f /etc/arch-release ]; then
            pacman -Syu --noconfirm git openssh pacman-contrib sudo
        else
            log "Not an Arch system. Skipping pacman install. Ensure dependencies are met manually."
        fi
        ;;

    setup_user)
        log "Setting up builder user..."
        if ! id -u builder >/dev/null 2>&1; then
            useradd -m builder
            echo "builder ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
            # Fix permissions for current directory so builder can write
            chown -R builder:builder .
        else
            log "User 'builder' already exists."
        fi
        ;;

    run_update)
        PKG_DIR=$1
        shift || true
        ARGS="$@"

        # SECURITY: Validate PKG_DIR
        # Prevent directory traversal and injection. Allow only ./pkgname or pkgname
        if [[ "$PKG_DIR" =~ [^a-zA-Z0-9._/-] ]] || [[ "$PKG_DIR" == *".."* ]]; then
             echo "!! ERROR: Invalid package directory name: $PKG_DIR"
             exit 1
        fi

        log "Preparing to run update for: $PKG_DIR"

        # Ensure script is executable
        chmod +x scripts/auto_update.sh

        # If running as root (typical in Docker), switch to builder
        if [ "$(id -u)" -eq 0 ]; then
            log "Running as root, switching to 'builder' user..."

            # Pass through critical environment variables
            # Note: We don't print keys to log for security

            # SECURITY: Use printf %q to shell-escape arguments to prevent injection within the su string
            # This is safer than direct interpolation
            SAFE_PKG_DIR=$(printf %q "$PKG_DIR")

            # Construct the command string safely
            CMD="export CI='$CI'; \
                 export AUR_USERNAME='$AUR_USERNAME'; \
                 export AUR_EMAIL='$AUR_EMAIL'; \
                 export AUR_SSH_PRIVATE_KEY='$AUR_SSH_PRIVATE_KEY'; \
                 bash scripts/auto_update.sh $SAFE_PKG_DIR $ARGS"

            su builder -c "$CMD"
        else
            # Already non-root (local run?), just run it
            log "Running as current user ($(whoami))..."
            bash scripts/auto_update.sh "$PKG_DIR" $ARGS
        fi
        ;;

    *)
        echo "Usage: $0 {discover|install|setup_user|run_update <pkg> [args]}"
        exit 1
        ;;
esac
