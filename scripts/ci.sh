#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)
cd "${REPO_ROOT}"

usage() {
    cat >&2 <<'USAGE'
Usage: scripts/ci.sh <command> [args]

Commands:
  package-test-boundary
  package-test-discover
  package-test-run <pkgname-or-path>
  aur-publish-discover
  aur-publish-run <pkgname-or-path>
USAGE
}

fail() {
    echo "!! ERROR: $*" >&2
    exit 1
}

log() {
    echo "==> [ci] $*"
}

retry() {
    local description=$1
    shift
    local attempt=1
    until "$@"; do
        if [ "$attempt" -ge 3 ]; then
            fail "${description} failed after ${attempt} attempts"
        fi
        log "${description} failed (attempt ${attempt}/3); retrying..."
        sleep $((attempt * 2))
        attempt=$((attempt + 1))
    done
}

install_arch_deps() {
    if [ ! -f /etc/arch-release ]; then
        command -v python3 >/dev/null 2>&1 || fail "python3 is required outside Arch CI containers"
        return 0
    fi

    [ "$(id -u)" -eq 0 ] || fail "Arch dependency installation must run as root"

    if [ "${CI:-}" = true ] && command -v pacman-key >/dev/null 2>&1; then
        log "Initializing pacman keyring"
        pacman-key --init >/dev/null 2>&1 || fail "Failed to initialize pacman keyring"
    fi

    log "Installing Arch CI dependencies"
    retry "Install Arch CI dependencies" \
        pacman -Syu --needed --noconfirm git openssh pacman-contrib sudo curl jq python
}

install_github_cli() {
    if command -v gh >/dev/null 2>&1; then
        return 0
    fi
    [ -f /etc/arch-release ] || fail "gh is required outside Arch CI containers"
    [ "$(id -u)" -eq 0 ] || fail "GitHub CLI installation must run as root"
    log "Installing GitHub CLI for artifact publishing"
    retry "Install GitHub CLI" pacman -S --needed --noconfirm github-cli
}

aurpkg() {
    if ! command -v python3 >/dev/null 2>&1; then
        install_arch_deps
    fi
    python3 scripts/aurpkg.py "$@"
}

require_package_arg() {
    [ "$#" -eq 1 ] || fail "Expected exactly one package argument"
    printf '%s' "$1"
}

package_test_discover() {
    local args=()
    if [ -n "${MANUAL_PACKAGE:-}" ]; then
        args+=(--package "${MANUAL_PACKAGE}")
    elif [ "${EVENT_NAME:-}" = "pull_request" ] && [ -n "${PR_BASE_SHA:-}" ] && [ -n "${PR_COMPARE_SHA:-}" ]; then
        args+=(--base-ref "${PR_BASE_SHA}" --head-ref "${PR_COMPARE_SHA}")
    elif [ "${EVENT_NAME:-}" = "push" ] && [ -n "${PUSH_BEFORE_SHA:-}" ] && [ "${PUSH_BEFORE_SHA}" != "0000000000000000000000000000000000000000" ]; then
        args+=(--base-ref "${PUSH_BEFORE_SHA}" --head-ref "${PUSH_SHA:-}")
    fi
    aurpkg discover "${args[@]}"
}

package_test_run() {
    local package_arg
    package_arg=$(require_package_arg "$@")
    install_arch_deps
    aurpkg setup-user
    CI=true aurpkg run-test "${package_arg}" --artifact-mode local
}

aur_publish_discover() {
    local cache_policy=${CACHE_POLICY:-normal}
    local dispatch_policy=${DISPATCH_POLICY:-auto}
    local failure_policy=${DETECTION_FAILURE_POLICY:-}
    local args=(--cache-policy "${cache_policy}" --dispatch-policy "${dispatch_policy}")

    if [ -n "${MANUAL_PACKAGE:-}" ]; then
        args+=(--package "${MANUAL_PACKAGE}")
    elif [ "${dispatch_policy}" = "selected" ]; then
        fail "dispatch_policy=selected requires package"
    fi

    if [ -z "${failure_policy}" ]; then
        if [ -z "${MANUAL_PACKAGE:-}" ] && [ "${dispatch_policy}" != "selected" ]; then
            failure_policy=continue
        else
            failure_policy=strict
        fi
    fi
    args+=(--failure-policy "${failure_policy}")

    if [ "$(id -u)" -eq 0 ]; then
        aurpkg setup-user
    else
        sudo -n python3 scripts/aurpkg.py setup-user
    fi

    AURPKG_PACKAGE_CONTROLLED_USER=builder aurpkg detect-updates "${args[@]}"
}

aur_publish_run() {
    local package_arg
    package_arg=$(require_package_arg "$@")
    local args=()

    install_arch_deps
    aurpkg setup-user
    aurpkg preflight "${package_arg}"

    if [ "${DRY_RUN:-false}" = "true" ]; then
        args+=(--dry-run)
    else
        install_github_cli
    fi

    aurpkg run-publish "${package_arg}" --verify-install "${args[@]}"
}

command=${1:-}
if [ -z "${command}" ]; then
    usage
    exit 2
fi
shift

case "${command}" in
    package-test-boundary)
        aurpkg check-framework-boundaries
        ;;
    package-test-discover)
        package_test_discover
        ;;
    package-test-run)
        package_test_run "$@"
        ;;
    aur-publish-discover)
        aur_publish_discover
        ;;
    aur-publish-run)
        aur_publish_run "$@"
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        usage
        fail "Unknown CI command: ${command}"
        ;;
esac
