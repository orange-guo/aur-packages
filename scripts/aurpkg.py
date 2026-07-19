#!/usr/bin/env python3
"""Single-file PackageSpec v1 automation CLI.

This intentionally keeps the framework implementation in one Python file. The
package model, discovery, update detection, rendering, build/test, AUR sync, and
artifact preparation live here.
"""

from __future__ import annotations

import base64
import dataclasses
import functools
import hashlib
import json
import os
import re
import shutil
import shlex
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path
from typing import Any, Iterable


SUPPORTED_SPEC_VERSION = 1
VALID_ARCH_RE = re.compile(r"^[A-Za-z0-9_+-]+$")
VALID_ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
VALID_PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9._+-]+$")
VALID_COMPONENT_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
VALID_PACKAGE_PATH_RE = re.compile(r"^packages/[A-Za-z0-9._-]+$")
TEMPLATE_PLACEHOLDER_RE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_.]*\}|\$[A-Za-z_][A-Za-z0-9_]*")
SENSITIVE_ENV_NAME_RE = re.compile(r"(?:TOKEN|SECRET|PASSWORD|PRIVATE[_-]?KEY|CREDENTIAL)", re.IGNORECASE)
SENSITIVE_ENV_NAMES = {
    "AUR_SSH_PRIVATE_KEY",
    "AUR_USERNAME",
    "AUR_EMAIL",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GIT_SSH_COMMAND",
    "SSH_AUTH_SOCK",
}
PACKAGE_CONTROLLED_USER_ENV = "AURPKG_PACKAGE_CONTROLLED_USER"

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
PACKAGE_ROOT = REPO_ROOT / "packages"
DEFAULT_ARCH_BASE_DEVEL_IMAGE = "archlinux:base-devel@sha256:01bd0ee1c23c3dec1dcb0fce558150a222ee2ef0a3776404de33d0714bcefbb0"
AUR_SSH_HOST = "aur.archlinux.org"
AUR_SSH_HOST_ED25519_FINGERPRINT = "SHA256:RFzBCUItH9LZS0cKB5UE6ceAYhBD5C8GeOBip8Z11+4"


ROOT_KEYS = {
    "spec_version",
    "name",
    "template",
    "packaging_repo_url",
    "metadata",
    "upstream",
    "package",
    "build",
    "files",
    "install",
    "service",
    "state",
    "tests",
    "artifacts",
    "sources",
}

TABLE_KEYS = {
    "metadata": {
        "desc",
        "url",
        "licenses",
        "arches",
        "depends",
        "makedepends",
        "checkdepends",
        "optdepends",
        "options",
        "provides",
        "conflicts",
        "validpgpkeys",
    },
    "upstream": {
        "type",
        "value",
        "repo",
        "repo_user",
        "repo_name",
        "tag_prefix",
        "release_tag_prefix",
        "allow_prerelease",
        "assets",
    },
    "package": {
        "binary_name",
        "binary_source_path",
        "install_bin_path",
        "wrapper_source_path",
        "wrapper_install_path",
        "wrapper_mode",
        "version_artifact",
    },
    "build": {
        "source_rename",
        "source_dir",
        "build_dir",
        "meson_options",
        "run_check",
        "check_args",
        "deb_relocate_usr_local",
        "appimage_appdir_name",
        "appimage_install_dir",
        "desktop_candidates",
        "icon_candidates",
        "desktop_exec_rewrite",
        "desktop_name_rewrite",
    },
    "files": {"local", "patches", "docs", "licenses"},
    "install": {"mode", "hints", "file"},
    "service": {"mode", "scope", "name", "file", "exec", "restart", "restart_sec"},
    "state": {"persist"},
    "tests": {"paths", "executables", "commands"},
}

ASSET_KEYS = {"selector", "asset_name", "source_rename"}
ARTIFACT_KEYS = {
    "type",
    "rev",
    "version_template",
    "arches",
    "recipe",
    "storage",
    "outputs",
}
ARTIFACT_RECIPE_KEYS = {
    "type",
    "source",
    "source_dir",
    "patches",
    "makedepends",
    "cargo_fetch_args",
    "cargo_build_args",
    "cargo_check_args",
    "run_check",
    "archive_files",
}
ARTIFACT_RECIPE_SOURCE_KEYS = {"type", "repo", "repo_user", "repo_name", "tag_prefix"}
ARTIFACT_STORAGE_KEYS = {"type", "repo", "repo_user", "repo_name", "tag_prefix"}
ARTIFACT_OUTPUT_KEYS = {"asset_name"}
SOURCE_KEYS = {"artifact", "arch", "rename"}
INPUT_SOURCE_KEYS = {"from", "origin", "artifact", "arch", "selector", "asset_name", "rename", "url"}
VERSION_KEYS = {"from", "origin", "artifact", "value"}
ORIGIN_KEYS = {"type", "repo", "repo_user", "repo_name", "tag_prefix", "release_tag_prefix", "allow_prerelease"}
ARTIFACT_MODES = {"readonly", "local", "publish", "force"}


class SpecError(Exception):
    pass


class CliError(Exception):
    pass


class GithubApiError(Exception):
    pass


def fail(message: str) -> None:
    raise SpecError(message)


def log_info(message: str) -> None:
    print(f"==> {message}")


def log_cli(message: str) -> None:
    print(f"==> [aurpkg] {message}")


def log_error(message: str) -> None:
    print(f"!! ERROR: {message}", file=sys.stderr)


def log_group_start(title: str) -> None:
    print(f"::group::{title}")


def log_group_end() -> None:
    print("::endgroup::")


def bool_text(value: bool) -> str:
    return "true" if value else "false"


def require_cmd(command: str) -> None:
    if shutil.which(command) is None:
        raise CliError(f"Required command not found: {command}")


def run(
    args: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
    capture: bool = False,
    text: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        text=text,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        check=False,
    )
    if check and result.returncode != 0:
        detail = ""
        if capture and result.stderr:
            detail = f": {result.stderr.strip()}"
        raise CliError(f"Command failed ({result.returncode}): {shlex.join(args)}{detail}")
    return result


def sanitized_environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Return an environment suitable for package- or upstream-controlled code."""
    env = os.environ.copy()
    if extra:
        env.update(extra)
    return {
        name: value
        for name, value in env.items()
        if name not in SENSITIVE_ENV_NAMES and name != PACKAGE_CONTROLLED_USER_ENV and not SENSITIVE_ENV_NAME_RE.search(name)
    }


def run_package_controlled(
    args: list[str],
    *,
    cwd: Path | None = None,
    check: bool = True,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    env = sanitized_environment()
    root = os.geteuid() == 0
    if not root and os.environ.get(PACKAGE_CONTROLLED_USER_ENV) != "builder":
        return run(args, cwd=cwd, env=env, check=check, capture=capture)
    if run(["id", "-u", "builder"], check=False, capture=True).returncode != 0:
        raise CliError("builder user not found; run: python3 scripts/aurpkg.py setup-user")
    if root:
        require_cmd("runuser")
        command = ["runuser", "-u", "builder", "--", "env", "HOME=/home/builder", *args]
    else:
        require_cmd("sudo")
        command = ["sudo", "-n", "-u", "builder", "--", "env", "HOME=/home/builder", *args]
    return run(
        command,
        cwd=cwd,
        env=env,
        check=check,
        capture=capture,
    )


def make_traversable_tempdir() -> Path:
    path = Path(tempfile.mkdtemp())
    path.chmod(0o755)
    return path


def retry(description: str, attempts: int, fn: Any) -> Any:
    last_exc: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - caller decides retryable surface
            last_exc = exc
            if attempt >= attempts:
                break
            delay = attempt * 2
            log_info(f"{description} failed (attempt {attempt}/{attempts}: {exc}); retrying in {delay}s.")
            time.sleep(delay)
    raise CliError(f"{description} failed after {attempts} attempts: {last_exc}")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@functools.lru_cache(maxsize=8192)
def bash_percent_quote(value: str) -> str:
    if shutil.which("bash") is None:
        return shlex.quote(value)
    result = subprocess.run(["bash", "-c", "printf '%q' \"$1\"", "bash", value], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    if result.returncode != 0:
        return shlex.quote(value)
    return result.stdout


def q(value: str | int | bool | None) -> str:
    if value is None:
        value = ""
    if isinstance(value, bool):
        value = bool_text(value)
    return bash_percent_quote(str(value))


def render_array_assignment(name: str, values: Iterable[str]) -> str:
    quoted_values = [q(value) for value in values]
    rendered = "".join(f"{value} " for value in quoted_values)
    return f"{name}=({rendered})"


def render_string_assignment(name: str, value: str | int | bool | None) -> str:
    return f"{name}={q(value)}"


def ensure_inside(path: Path, root: Path, role: str) -> Path:
    real = path.resolve()
    root_real = root.resolve()
    try:
        real.relative_to(root_real)
    except ValueError as exc:
        raise CliError(f"{role} must resolve inside {root}: {path}") from exc
    return real


def arch_suffix(arch: str) -> str:
    if arch == "x86_64":
        return "X86_64"
    if arch == "aarch64":
        return "AARCH64"
    return arch.upper().replace("-", "_").replace("+", "_").replace(".", "_")


def shell_var_suffix(arch: str) -> str:
    return arch_suffix(arch)


# ---------------------------------------------------------------------------
# PackageSpec parsing and normalization


def load_spec(path: str) -> dict[str, Any]:
    spec_path = Path(path)
    if not spec_path.is_file():
        fail(f"PackageSpec file not found: {path}")
    if spec_path.name != "package.toml":
        fail(f"PackageSpec file must be named package.toml: {path}")

    try:
        with spec_path.open("rb") as handle:
            data = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise SpecError(f"Invalid TOML in {path}: {exc}") from exc

    if not isinstance(data, dict):
        fail(f"PackageSpec root must be a TOML table: {path}")
    data = normalize_input_domain_schema(data, path)
    validate_spec(data, path)
    return data


def normalize_input_domain_schema(data: dict[str, Any], path: str) -> dict[str, Any]:
    if not any(key in data for key in ("version", "origins", "inputs")):
        return data
    legacy_keys = {"upstream", "artifacts", "sources"}
    if any(key in data for key in legacy_keys):
        fail(f"PackageSpec must not mix [version]/[origins]/[inputs] with legacy tables in {path}: {', '.join(sorted(legacy_keys & set(data)))}")

    normalized = dict(data)
    version = normalized.pop("version", None)
    origins = normalized.pop("origins", {})
    inputs = normalized.pop("inputs", {})
    if not isinstance(version, dict):
        fail(f"[version] is required and must be a TOML table in {path}")
    if not isinstance(origins, dict):
        fail(f"[origins] must be a TOML table in {path}")
    if not isinstance(inputs, dict):
        fail(f"[inputs] must be a TOML table in {path}")
    reject_unknown_keys(version, VERSION_KEYS, f"{path} [version]")
    reject_unknown_keys(inputs, {"sources", "artifacts"}, f"{path} [inputs]")

    for origin_name, origin in origins.items():
        if not VALID_COMPONENT_NAME_RE.fullmatch(origin_name):
            fail(f"Unsupported origin name in {path} [origins]: {origin_name}")
        if not isinstance(origin, dict):
            fail(f"{path} [origins.{origin_name}] must be a TOML table")
        reject_unknown_keys(origin, ORIGIN_KEYS, f"{path} [origins.{origin_name}]")
        require_string(origin, "type", f"{path} [origins.{origin_name}]")
        optional_repo(origin, f"{path} [origins.{origin_name}]")
        optional_string(origin, "tag_prefix", f"{path} [origins.{origin_name}]")
        optional_string(origin, "release_tag_prefix", f"{path} [origins.{origin_name}]")
        optional_bool(origin, "allow_prerelease", f"{path} [origins.{origin_name}]")

    version_from = require_string(version, "from", f"{path} [version]")
    package = dict(normalized.get("package", {}))
    legacy_sources: dict[str, Any] = {}
    legacy_artifacts: dict[str, Any] = {}
    legacy_upstream: dict[str, Any]

    input_sources = inputs.get("sources", {})
    if not isinstance(input_sources, dict):
        fail(f"{path} [inputs.sources] must be a TOML table")
    input_artifacts = inputs.get("artifacts", {})
    if not isinstance(input_artifacts, dict):
        fail(f"{path} [inputs.artifacts] must be a TOML table")

    def origin_table(origin_name: str, context: str) -> dict[str, Any]:
        if origin_name not in origins:
            fail(f"{context} references unknown origin in {path}: {origin_name}")
        origin = dict(origins[origin_name])
        return origin

    if version_from == "origin":
        version_origin = require_string(version, "origin", f"{path} [version]")
        legacy_upstream = origin_table(version_origin, f"{path} [version]")
    elif version_from == "hook":
        legacy_upstream = {"type": "custom-hook"}
    elif version_from == "fixed":
        fixed_value = require_string(version, "value", f"{path} [version]")
        legacy_upstream = {"type": "fixed", "value": fixed_value}
    elif version_from == "artifact":
        version_artifact = require_string(version, "artifact", f"{path} [version]")
        package["version_artifact"] = version_artifact
        artifact_table = input_artifacts.get(version_artifact)
        if not isinstance(artifact_table, dict):
            fail(f"[version] references unknown artifact in {path}: {version_artifact}")
        recipe = artifact_table.get("recipe", {})
        if not isinstance(recipe, dict):
            fail(f"{path} [inputs.artifacts.{version_artifact}.recipe] must be a TOML table")
        recipe_origin = require_string(recipe, "origin", f"{path} [inputs.artifacts.{version_artifact}.recipe]")
        legacy_upstream = origin_table(recipe_origin, f"{path} [inputs.artifacts.{version_artifact}.recipe]")
    else:
        fail(f"Unsupported [version] from in {path}: {version_from}")

    legacy_upstream.setdefault("assets", {})

    for artifact_name, artifact in input_artifacts.items():
        if not VALID_COMPONENT_NAME_RE.fullmatch(artifact_name):
            fail(f"Unsupported artifact name in {path} [inputs.artifacts]: {artifact_name}")
        if not isinstance(artifact, dict):
            fail(f"{path} [inputs.artifacts.{artifact_name}] must be a TOML table")
        legacy_artifact = dict(artifact)
        recipe = dict(legacy_artifact.get("recipe", {}))
        recipe_origin = recipe.pop("origin", "")
        if recipe_origin:
            source_origin = origin_table(recipe_origin, f"{path} [inputs.artifacts.{artifact_name}.recipe]")
            recipe_source = {"type": "github-source-archive" if source_origin.get("type") == "github-release" else source_origin.get("type", "")}
            for key in ("repo", "repo_user", "repo_name", "tag_prefix"):
                if source_origin.get(key):
                    recipe_source[key] = source_origin[key]
            recipe["source"] = recipe_source
        legacy_artifact["recipe"] = recipe
        legacy_artifacts[artifact_name] = legacy_artifact

    common_source_seen = ""
    build = dict(normalized.get("build", {}))
    for source_name, source in input_sources.items():
        if not VALID_COMPONENT_NAME_RE.fullmatch(source_name):
            fail(f"Unsupported source name in {path} [inputs.sources]: {source_name}")
        if not isinstance(source, dict):
            fail(f"{path} [inputs.sources.{source_name}] must be a TOML table")
        reject_unknown_keys(source, INPUT_SOURCE_KEYS, f"{path} [inputs.sources.{source_name}]")
        source_from = require_string(source, "from", f"{path} [inputs.sources.{source_name}]")
        arch = source.get("arch", "")
        rename = source.get("rename", "")
        if source_from == "github-release-asset":
            source_origin = require_string(source, "origin", f"{path} [inputs.sources.{source_name}]")
            if legacy_upstream.get("type") == "github-release" and source_origin == version.get("origin", ""):
                legacy_upstream["type"] = "github-release-assets"
            if source_origin != version.get("origin", ""):
                fail(f"{path} [inputs.sources.{source_name}] currently must use the version origin for github-release-asset")
            if not arch:
                fail(f"{path} [inputs.sources.{source_name}] arch is required for github-release-asset")
            legacy_upstream["assets"][arch] = {
                "selector": source.get("selector", ""),
                "asset_name": source.get("asset_name", ""),
                "source_rename": rename,
            }
        elif source_from == "hook":
            if arch:
                legacy_upstream["assets"][arch] = {"source_rename": rename}
            else:
                if common_source_seen:
                    fail(f"{path} [inputs.sources.{source_name}] and [inputs.sources.{common_source_seen}] both declare a common hook source")
                common_source_seen = source_name
                build.setdefault("source_rename", rename)
        elif source_from == "artifact":
            legacy_sources[source_name] = {
                "artifact": require_string(source, "artifact", f"{path} [inputs.sources.{source_name}]"),
                "arch": require_string(source, "arch", f"{path} [inputs.sources.{source_name}]"),
                "rename": rename,
            }
        else:
            fail(f"Unsupported source from in {path} [inputs.sources.{source_name}]: {source_from}")

    normalized["package"] = package
    normalized["build"] = build
    normalized["upstream"] = legacy_upstream
    normalized["artifacts"] = legacy_artifacts
    normalized["sources"] = legacy_sources
    return normalized


def reject_unknown_keys(table: dict[str, Any], allowed: set[str], context: str) -> None:
    for key in table:
        if key not in allowed:
            fail(f"Unsupported key in {context}: {key}")


def expect_table(data: dict[str, Any], key: str, path: str) -> dict[str, Any]:
    value = data.get(key, {})
    if value == {}:
        return {}
    if not isinstance(value, dict):
        fail(f"{key} must be a TOML table in {path}")
    return value


def require_table(data: dict[str, Any], key: str, context: str) -> dict[str, Any]:
    if key not in data:
        fail(f"Missing required table in {context}: {key}")
    value = data[key]
    if not isinstance(value, dict):
        fail(f"{key} must be a TOML table in {context}")
    return value


def expect_nested_table(table: dict[str, Any], key: str, context: str) -> dict[str, Any]:
    value = table.get(key, {})
    if value == {}:
        return {}
    if not isinstance(value, dict):
        fail(f"{context}.{key} must be a TOML table")
    return value


def require_int(data: dict[str, Any], key: str, context: str) -> int:
    if key not in data:
        fail(f"Missing required key in {context}: {key}")
    value = data[key]
    if not isinstance(value, int) or isinstance(value, bool):
        fail(f"{key} must be an integer in {context}")
    return value


def require_string(data: dict[str, Any], key: str, context: str) -> str:
    if key not in data:
        fail(f"Missing required key in {context}: {key}")
    return expect_string(data[key], key, context)


def optional_string(data: dict[str, Any], key: str, context: str) -> str | None:
    if key not in data:
        return None
    return expect_string(data[key], key, context)


def expect_string(value: Any, key: str, context: str) -> str:
    if not isinstance(value, str):
        fail(f"{key} must be a string in {context}")
    if any(ord(char) < 32 for char in value):
        fail(f"{key} must not contain control characters or newlines in {context}")
    return value


def optional_bool(data: dict[str, Any], key: str, context: str) -> bool | None:
    if key not in data:
        return None
    value = data[key]
    if not isinstance(value, bool):
        fail(f"{key} must be a boolean in {context}")
    return value


def optional_int_or_string(data: dict[str, Any], key: str, context: str) -> str | None:
    if key not in data:
        return None
    value = data[key]
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        fail(f"{key} must be an integer or string in {context}")
    return str(value)


def require_string_list(data: dict[str, Any], key: str, context: str) -> list[str]:
    if key not in data:
        fail(f"Missing required key in {context}: {key}")
    return expect_string_list(data[key], key, context)


def optional_string_list(data: dict[str, Any], key: str, context: str) -> list[str] | None:
    if key not in data:
        return None
    return expect_string_list(data[key], key, context)


def expect_string_list(value: Any, key: str, context: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        fail(f"{key} must be an array of strings in {context}")
    return value


def validate_optional_strings(table: dict[str, Any], keys: set[str], context: str) -> None:
    for key in keys:
        optional_string(table, key, context)


def optional_repo(table: dict[str, Any], context: str) -> None:
    optional_string(table, "repo", context)
    optional_string(table, "repo_user", context)
    optional_string(table, "repo_name", context)
    if "repo" in table and ("repo_user" in table or "repo_name" in table):
        fail(f"Use either repo or repo_user/repo_name in {context}, not both")
    if ("repo_user" in table) != ("repo_name" in table):
        fail(f"repo_user and repo_name must be set together in {context}")


def validate_arch_tables(assets: dict[str, Any], allowed: set[str], context: str) -> None:
    for arch, table in assets.items():
        if not VALID_ARCH_RE.match(arch):
            fail(f"Unsupported architecture table in {context}: {arch}")
        if not isinstance(table, dict):
            fail(f"{context}.{arch} must be a TOML table")
        reject_unknown_keys(table, allowed, f"{context}.{arch}")
        for key in allowed:
            optional_string(table, key, f"{context}.{arch}")


def validate_artifact_tables(artifacts: dict[str, Any], context: str) -> None:
    for artifact_name, table in artifacts.items():
        if not VALID_COMPONENT_NAME_RE.fullmatch(artifact_name):
            fail(f"Unsupported artifact name in {context}: {artifact_name}")
        if not isinstance(table, dict):
            fail(f"{context}.{artifact_name} must be a TOML table")
        artifact_context = f"{context}.{artifact_name}"
        reject_unknown_keys(table, ARTIFACT_KEYS, artifact_context)
        require_string(table, "type", artifact_context)
        optional_int_or_string(table, "rev", artifact_context)
        optional_string(table, "version_template", artifact_context)
        optional_string_list(table, "arches", artifact_context)

        recipe = expect_nested_table(table, "recipe", artifact_context)
        reject_unknown_keys(recipe, ARTIFACT_RECIPE_KEYS, f"{artifact_context}.recipe")
        require_string(recipe, "type", f"{artifact_context}.recipe")
        optional_string(recipe, "source_dir", f"{artifact_context}.recipe")
        for key in ("patches", "makedepends", "cargo_fetch_args", "cargo_build_args", "cargo_check_args", "archive_files"):
            optional_string_list(recipe, key, f"{artifact_context}.recipe")
        optional_bool(recipe, "run_check", f"{artifact_context}.recipe")

        source = expect_nested_table(recipe, "source", f"{artifact_context}.recipe")
        reject_unknown_keys(source, ARTIFACT_RECIPE_SOURCE_KEYS, f"{artifact_context}.recipe.source")
        require_string(source, "type", f"{artifact_context}.recipe.source")
        optional_repo(source, f"{artifact_context}.recipe.source")
        optional_string(source, "tag_prefix", f"{artifact_context}.recipe.source")

        storage = expect_nested_table(table, "storage", artifact_context)
        reject_unknown_keys(storage, ARTIFACT_STORAGE_KEYS, f"{artifact_context}.storage")
        require_string(storage, "type", f"{artifact_context}.storage")
        optional_repo(storage, f"{artifact_context}.storage")
        optional_string(storage, "tag_prefix", f"{artifact_context}.storage")

        validate_arch_tables(expect_nested_table(table, "outputs", artifact_context), ARTIFACT_OUTPUT_KEYS, f"{artifact_context}.outputs")


def validate_source_tables(sources: dict[str, Any], context: str) -> None:
    for source_name, table in sources.items():
        if not VALID_COMPONENT_NAME_RE.fullmatch(source_name):
            fail(f"Unsupported source name in {context}: {source_name}")
        if not isinstance(table, dict):
            fail(f"{context}.{source_name} must be a TOML table")
        source_context = f"{context}.{source_name}"
        reject_unknown_keys(table, SOURCE_KEYS, source_context)
        require_string(table, "artifact", source_context)
        require_string(table, "arch", source_context)
        optional_string(table, "rename", source_context)


def split_repo(table: dict[str, Any], context: str) -> tuple[str, str] | None:
    if "repo" in table:
        repo = table["repo"]
        parts = repo.split("/", 1)
        if len(parts) != 2 or not parts[0] or not parts[1]:
            fail(f"repo must use owner/name format in {context}: {repo}")
        return parts[0], parts[1]
    if "repo_user" in table and "repo_name" in table:
        return table["repo_user"], table["repo_name"]
    return None


def validate_spec(data: dict[str, Any], path: str) -> None:
    reject_unknown_keys(data, ROOT_KEYS, path)
    version = require_int(data, "spec_version", path)
    if version != SUPPORTED_SPEC_VERSION:
        fail(f"Unsupported spec_version in {path}: {version}")
    require_string(data, "name", path)
    require_string(data, "template", path)
    optional_string(data, "packaging_repo_url", path)

    metadata = require_table(data, "metadata", path)
    reject_unknown_keys(metadata, TABLE_KEYS["metadata"], f"{path} [metadata]")
    require_string(metadata, "desc", f"{path} [metadata]")
    require_string(metadata, "url", f"{path} [metadata]")
    require_string_list(metadata, "licenses", f"{path} [metadata]")
    require_string_list(metadata, "arches", f"{path} [metadata]")
    for key in TABLE_KEYS["metadata"] - {"desc", "url", "licenses", "arches"}:
        optional_string_list(metadata, key, f"{path} [metadata]")

    upstream = require_table(data, "upstream", path)
    reject_unknown_keys(upstream, TABLE_KEYS["upstream"], f"{path} [upstream]")
    require_string(upstream, "type", f"{path} [upstream]")
    optional_repo(upstream, f"{path} [upstream]")
    optional_string(upstream, "tag_prefix", f"{path} [upstream]")
    optional_string(upstream, "release_tag_prefix", f"{path} [upstream]")
    optional_bool(upstream, "allow_prerelease", f"{path} [upstream]")
    validate_arch_tables(expect_nested_table(upstream, "assets", f"{path} [upstream]"), ASSET_KEYS, f"{path} [upstream.assets]")

    for table_name in ("package", "build", "files", "install", "service", "state", "tests"):
        table = expect_table(data, table_name, path)
        reject_unknown_keys(table, TABLE_KEYS[table_name], f"{path} [{table_name}]")

    validate_optional_strings(expect_table(data, "package", path), TABLE_KEYS["package"], f"{path} [package]")

    build = expect_table(data, "build", path)
    for key in ("source_rename", "source_dir", "build_dir", "appimage_appdir_name", "appimage_install_dir", "desktop_exec_rewrite", "desktop_name_rewrite"):
        optional_string(build, key, f"{path} [build]")
    for key in ("meson_options", "check_args", "desktop_candidates", "icon_candidates"):
        optional_string_list(build, key, f"{path} [build]")
    for key in ("run_check", "deb_relocate_usr_local"):
        optional_bool(build, key, f"{path} [build]")

    files = expect_table(data, "files", path)
    for key in TABLE_KEYS["files"]:
        optional_string_list(files, key, f"{path} [files]")

    install = expect_table(data, "install", path)
    optional_string(install, "mode", f"{path} [install]")
    optional_string_list(install, "hints", f"{path} [install]")
    optional_string(install, "file", f"{path} [install]")

    service = expect_table(data, "service", path)
    for key in TABLE_KEYS["service"]:
        optional_string(service, key, f"{path} [service]")

    state = expect_table(data, "state", path)
    optional_string_list(state, "persist", f"{path} [state]")
    tests = expect_table(data, "tests", path)
    for key in TABLE_KEYS["tests"]:
        optional_string_list(tests, key, f"{path} [tests]")

    validate_artifact_tables(expect_table(data, "artifacts", path), f"{path} [artifacts]")
    validate_source_tables(expect_table(data, "sources", path), f"{path} [sources]")
    validate_cross_fields(data, path)


def validate_cross_fields(data: dict[str, Any], path: str) -> None:
    metadata = data["metadata"]
    arches = set(metadata["arches"])
    upstream = data["upstream"]
    upstream_assets = upstream.get("assets", {})
    for arch in upstream_assets:
        if arch not in arches:
            fail(f"[upstream.assets.{arch}] is not listed in [metadata] arches in {path}")
    if upstream["type"] == "github-release-assets":
        for arch in arches:
            asset = upstream_assets.get(arch)
            if asset is None:
                fail(f"[upstream.assets.{arch}] is required for github-release-assets in {path}")
            if not asset.get("selector") and not asset.get("asset_name"):
                fail(f"[upstream.assets.{arch}] requires selector or asset_name in {path}")
            if not asset.get("source_rename"):
                fail(f"[upstream.assets.{arch}] requires source_rename in {path}")

    artifacts = data.get("artifacts", {})
    package = data.get("package", {})
    version_artifact = package.get("version_artifact", "")
    if version_artifact and version_artifact not in artifacts:
        fail(f"[package] version_artifact references unknown artifact in {path}: {version_artifact}")
    sources = data.get("sources", {})
    source_arches: dict[str, str] = {}
    for source_name, source in sources.items():
        arch = source.get("arch", "")
        if arch not in arches:
            fail(f"[sources.{source_name}] arch is not listed in [metadata] arches in {path}: {arch}")
        if arch in source_arches:
            fail(f"[sources.{source_name}] and [sources.{source_arches[arch]}] both target arch {arch} in {path}")
        source_arches[arch] = source_name
        artifact_name = source.get("artifact", "")
        if artifact_name not in artifacts:
            fail(f"[sources.{source_name}] references unknown artifact in {path}: {artifact_name}")

    for artifact_name, artifact_table in artifacts.items():
        artifact_arches = set(artifact_table.get("arches", []))
        artifact_outputs = artifact_table.get("outputs", {})
        recipe = artifact_table.get("recipe", {})
        recipe_source = recipe.get("source", {})
        if artifact_table.get("type") != "archive":
            fail(f"[artifacts.{artifact_name}] unsupported type in {path}: {artifact_table.get('type')}")
        if recipe.get("type") != "cargo-build":
            fail(f"[artifacts.{artifact_name}.recipe] unsupported type in {path}: {recipe.get('type')}")
        if not artifact_arches:
            fail(f"[artifacts.{artifact_name}] arches must not be empty in {path}")
        for arch in artifact_outputs:
            if arch not in artifact_arches:
                fail(f"[artifacts.{artifact_name}.outputs.{arch}] is not listed in [artifacts.{artifact_name}] arches in {path}")
        for arch in artifact_arches:
            output = artifact_outputs.get(arch)
            if output is None or not output.get("asset_name"):
                fail(f"[artifacts.{artifact_name}.outputs.{arch}] asset_name is required in {path}")
        if recipe_source.get("type") != "github-source-archive":
            fail(f"[artifacts.{artifact_name}.recipe.source] unsupported type in {path}: {recipe_source.get('type')}")
        if not split_repo(recipe_source, f"{path} [artifacts.{artifact_name}.recipe.source]"):
            fail(f"[artifacts.{artifact_name}.recipe.source] repo is required in {path}")
        storage = artifact_table.get("storage", {})
        if storage.get("type") != "github-release":
            fail(f"[artifacts.{artifact_name}.storage] unsupported type in {path}: {storage.get('type')}")
        if not split_repo(storage, f"{path} [artifacts.{artifact_name}.storage]"):
            fail(f"[artifacts.{artifact_name}.storage] repo is required in {path}")
        if not recipe.get("archive_files"):
            fail(f"[artifacts.{artifact_name}.recipe] archive_files must not be empty in {path}")
        for archive_file in recipe.get("archive_files", []):
            validate_artifact_archive_file(Path(path), archive_file)
        for source_name, source in sources.items():
            if source.get("artifact") != artifact_name:
                continue
            arch = source.get("arch", "")
            if arch not in artifact_arches:
                fail(f"[sources.{source_name}] references artifact {artifact_name}, but {arch} is not listed in [artifacts.{artifact_name}] arches in {path}")
            if not source.get("rename"):
                fail(f"[sources.{source_name}] requires rename in {path}")


@dataclasses.dataclass
class ArtifactOutput:
    asset_name: str


@dataclasses.dataclass
class PackageArtifact:
    name: str
    type: str
    rev: str
    version_template: str
    arches: list[str]
    recipe_type: str
    recipe_source_type: str
    recipe_source_repo_user: str
    recipe_source_repo_name: str
    recipe_source_tag_prefix: str
    storage_type: str
    storage_repo_value: str
    storage_repo_user: str
    storage_repo_name: str
    storage_tag_prefix: str
    source_dir: str
    patches: list[str]
    makedepends: list[str]
    cargo_fetch_args: list[str]
    cargo_build_args: list[str]
    cargo_check_args: list[str]
    run_check: bool
    archive_files: list[str]
    outputs: dict[str, ArtifactOutput]
    resolved_upstream_version: str = ""
    resolved_version: str = ""
    release_tag: str = ""
    resolved_asset_urls: dict[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class PackageSource:
    name: str
    artifact: str
    arch: str
    rename: str


@dataclasses.dataclass
class PackageSpec:
    package_dir: Path
    rel_dir: str
    definition_path: Path
    raw: dict[str, Any]
    spec_version: int
    name: str
    template: str
    packaging_repo_url: str
    desc: str
    url: str
    licenses: list[str]
    arches: list[str]
    depends: list[str]
    makedepends: list[str]
    checkdepends: list[str]
    optdepends: list[str]
    options: list[str]
    provides: list[str]
    conflicts: list[str]
    validpgpkeys: list[str]
    upstream_type: str
    upstream_repo_user: str
    upstream_repo_name: str
    upstream_tag_prefix: str
    upstream_release_tag_prefix: str
    upstream_allow_prerelease: bool
    upstream_fixed_version: str
    asset_selectors: dict[str, str]
    upstream_asset_names: dict[str, str]
    source_renames: dict[str, str]
    binary_name: str
    binary_source_path: str
    install_bin_path: str
    wrapper_source_path: str
    wrapper_install_path: str
    wrapper_mode: str
    version_artifact: str
    source_rename: str
    source_dir: str
    build_dir: str
    meson_options: list[str]
    run_check: bool
    check_args: list[str]
    deb_relocate_usr_local: bool
    appimage_appdir_name: str
    appimage_install_dir: str
    desktop_candidates: list[str]
    icon_candidates: list[str]
    desktop_exec_rewrite: str
    desktop_name_rewrite: str
    local_files: list[str]
    patch_files: list[str]
    doc_files: list[str]
    license_files: list[str]
    install_mode: str
    install_hints: list[str]
    install_file: str
    service_mode: str
    service_scope: str
    service_name: str
    service_file: str
    service_exec: str
    service_restart: str
    service_restart_sec: str
    persist_state_keys: list[str]
    test_paths: list[str]
    test_executables: list[str]
    test_commands: list[str]
    artifacts: dict[str, PackageArtifact]
    sources: dict[str, PackageSource]
    resolved_version: str = ""
    resolved_source_url: str = ""
    resolved_source_urls: dict[str, str] = dataclasses.field(default_factory=dict)
    github_release_tag: str = ""
    state_values: dict[str, str] = dataclasses.field(default_factory=dict)
    aur_current_ver: str = ""
    aur_current_rel: int = 0
    aur_repo_dir: Path | None = None


def list_value(table: dict[str, Any], key: str) -> list[str]:
    return list(table.get(key, []))


def str_value(table: dict[str, Any], key: str, default: str = "") -> str:
    value = table.get(key, default)
    return str(value) if value is not None else default


def bool_value(table: dict[str, Any], key: str, default: bool = False) -> bool:
    value = table.get(key, default)
    return bool(value)


def validate_package_name_value(value: str, role: str, config_path: Path) -> None:
    if not VALID_PACKAGE_NAME_RE.fullmatch(value):
        raise CliError(f"{role} contains unsupported characters in {config_path}: {value}")


def validate_absolute_install_path(role: str, path_value: str, config_path: Path) -> None:
    if not path_value:
        return
    if not path_value.startswith("/") or "/../" in path_value or path_value.endswith("/..") or path_value == "/":
        raise CliError(f"{role} must be a normalized absolute install path in {config_path}: {path_value}")


def validate_relative_source_pattern(role: str, pattern: str, config_path: Path) -> None:
    if not pattern:
        return
    if pattern.startswith("/") or pattern.startswith("../") or "/../" in pattern or pattern.endswith("/.."):
        raise CliError(f"{role} must be relative and must not escape source roots in {config_path}: {pattern}")


def validate_package_asset_path(pkg: PackageSpec | None, package_dir: Path, definition_path: Path, role: str, relative_path: str) -> None:
    if not relative_path:
        return
    if relative_path.startswith("/") or relative_path.startswith("../") or "/../" in relative_path or relative_path.endswith("/.."):
        raise CliError(f"{role} must be package-relative in {definition_path}: {relative_path}")
    asset_path = (package_dir / relative_path).resolve()
    try:
        asset_path.relative_to(package_dir.resolve())
    except ValueError as exc:
        raise CliError(f"{role} must resolve inside the package directory in {definition_path}: {relative_path}") from exc
    if not asset_path.is_file():
        raise CliError(f"{role} must resolve to a file in {definition_path}: {relative_path}")


def validate_artifact_archive_file(config_path: Path, archive_spec: str) -> None:
    if ":" not in archive_spec:
        raise CliError(f"Artifact archive_files entry must be source:destination[:mode] in {config_path}: {archive_spec}")
    parts = archive_spec.split(":")
    if len(parts) not in {2, 3}:
        raise CliError(f"Artifact archive_files mode must not contain ':' in {config_path}: {archive_spec}")
    source_path, destination_path = parts[0], parts[1]
    file_mode = parts[2] if len(parts) == 3 else "644"
    if not source_path:
        raise CliError(f"Artifact archive_files source is required in {config_path}: {archive_spec}")
    if not destination_path:
        raise CliError(f"Artifact archive_files destination is required in {config_path}: {archive_spec}")
    validate_relative_source_pattern("artifact archive_files source", source_path, config_path)
    validate_relative_source_pattern("artifact archive_files destination", destination_path, config_path)
    if not re.fullmatch(r"[0-7]{3,4}", file_mode):
        raise CliError(f"Artifact archive_files mode must be octal in {config_path}: {archive_spec}")


def package_definition_path(package_dir: Path) -> Path | None:
    spec_candidate = package_dir / "package.toml"
    legacy_candidate = package_dir / "package.conf"
    if spec_candidate.is_file() and legacy_candidate.is_file():
        raise CliError(f"Package directory must not contain both package.toml and package.conf: {package_dir}")
    if spec_candidate.is_file():
        return spec_candidate
    return None


def package_has_definition(package_dir: Path) -> bool:
    return package_definition_path(package_dir) is not None


def package_path_for_output(path: Path) -> str:
    return path.resolve().relative_to(REPO_ROOT).as_posix()


def discover_package_definition_files(package_root: Path = PACKAGE_ROOT) -> list[Path]:
    if not package_root.is_dir():
        return []
    return sorted(package_root.glob("*/package.toml"))


def collect_all_packages() -> list[str]:
    return [package_path_for_output(path.parent) for path in discover_package_definition_files()]


def canonical_package_dir(package_input: str) -> str:
    value = package_input.removeprefix("./")
    if value.startswith("packages/"):
        if not VALID_PACKAGE_PATH_RE.fullmatch(value):
            raise CliError(f"Invalid package directory name: {package_input}")
        candidate = REPO_ROOT / value
    else:
        if not VALID_COMPONENT_NAME_RE.fullmatch(value):
            raise CliError(f"Invalid package directory name: {package_input}")
        candidate = PACKAGE_ROOT / value
    if package_definition_path(candidate) is None:
        raise CliError(f"PackageSpec definition not found in {package_path_for_output(candidate)}")
    return package_path_for_output(candidate)


def load_package_artifact(artifact_name: str, table: dict[str, Any]) -> PackageArtifact:
    recipe = table.get("recipe", {})
    recipe_source = recipe.get("source", {})
    storage = table.get("storage", {})
    recipe_source_repo = split_repo(recipe_source, f"[artifacts.{artifact_name}.recipe.source]") or ("", "")
    storage_repo = split_repo(storage, f"[artifacts.{artifact_name}.storage]") or ("", "")
    return PackageArtifact(
        name=artifact_name,
        type=str_value(table, "type"),
        rev=str_value(table, "rev", "1") or "1",
        version_template=str_value(table, "version_template", "${upstream_version}.r${artifact_rev}") or "${upstream_version}.r${artifact_rev}",
        arches=list_value(table, "arches"),
        recipe_type=str_value(recipe, "type"),
        recipe_source_type=str_value(recipe_source, "type"),
        recipe_source_repo_user=recipe_source_repo[0],
        recipe_source_repo_name=recipe_source_repo[1],
        recipe_source_tag_prefix=str_value(recipe_source, "tag_prefix"),
        storage_type=str_value(storage, "type"),
        storage_repo_value=str_value(storage, "repo"),
        storage_repo_user=storage_repo[0],
        storage_repo_name=storage_repo[1],
        storage_tag_prefix=str_value(storage, "tag_prefix"),
        source_dir=str_value(recipe, "source_dir"),
        patches=list_value(recipe, "patches"),
        makedepends=list_value(recipe, "makedepends"),
        cargo_fetch_args=list_value(recipe, "cargo_fetch_args"),
        cargo_build_args=list_value(recipe, "cargo_build_args"),
        cargo_check_args=list_value(recipe, "cargo_check_args"),
        run_check=bool_value(recipe, "run_check", False),
        archive_files=list_value(recipe, "archive_files"),
        outputs={
            arch: ArtifactOutput(asset_name=output.get("asset_name", ""))
            for arch, output in table.get("outputs", {}).items()
        },
    )


def load_package_source(source_name: str, table: dict[str, Any]) -> PackageSource:
    return PackageSource(
        name=source_name,
        artifact=str_value(table, "artifact"),
        arch=str_value(table, "arch"),
        rename=str_value(table, "rename"),
    )


def load_package(package_input: str) -> PackageSpec:
    rel_dir = canonical_package_dir(package_input)
    package_dir = (REPO_ROOT / rel_dir).resolve()
    definition_path = package_definition_path(package_dir)
    if definition_path is None:
        raise CliError(f"PackageSpec definition not found in {rel_dir}")
    data = load_spec(str(definition_path))
    metadata = data["metadata"]
    upstream = data["upstream"]
    package = data.get("package", {})
    build = data.get("build", {})
    files = data.get("files", {})
    install = data.get("install", {})
    service = data.get("service", {})
    state = data.get("state", {})
    tests = data.get("tests", {})
    artifacts = data.get("artifacts", {})
    sources = data.get("sources", {})

    upstream_repo = split_repo(upstream, "[upstream]") or ("", "")

    name = data["name"]
    pkg = PackageSpec(
        package_dir=package_dir,
        rel_dir=rel_dir,
        definition_path=definition_path.resolve(),
        raw=data,
        spec_version=data["spec_version"],
        name=name,
        template=data["template"],
        packaging_repo_url=data.get("packaging_repo_url") or f"https://github.com/theorangeguo/aur-packages/tree/main/packages/{name}",
        desc=metadata["desc"],
        url=metadata["url"],
        licenses=list_value(metadata, "licenses"),
        arches=list_value(metadata, "arches"),
        depends=list_value(metadata, "depends"),
        makedepends=list_value(metadata, "makedepends"),
        checkdepends=list_value(metadata, "checkdepends"),
        optdepends=list_value(metadata, "optdepends"),
        options=list_value(metadata, "options"),
        provides=list_value(metadata, "provides"),
        conflicts=list_value(metadata, "conflicts"),
        validpgpkeys=list_value(metadata, "validpgpkeys"),
        upstream_type=upstream["type"],
        upstream_repo_user=upstream_repo[0],
        upstream_repo_name=upstream_repo[1],
        upstream_tag_prefix=str_value(upstream, "tag_prefix"),
        upstream_release_tag_prefix=str_value(upstream, "release_tag_prefix"),
        upstream_allow_prerelease=bool_value(upstream, "allow_prerelease", False),
        upstream_fixed_version=str_value(upstream, "value"),
        asset_selectors={arch: asset.get("selector", "") for arch, asset in upstream.get("assets", {}).items()},
        upstream_asset_names={arch: asset.get("asset_name", "") for arch, asset in upstream.get("assets", {}).items()},
        source_renames={arch: asset.get("source_rename", "") for arch, asset in upstream.get("assets", {}).items()},
        binary_name=str_value(package, "binary_name"),
        binary_source_path=str_value(package, "binary_source_path"),
        install_bin_path=str_value(package, "install_bin_path"),
        wrapper_source_path=str_value(package, "wrapper_source_path"),
        wrapper_install_path=str_value(package, "wrapper_install_path"),
        wrapper_mode=str_value(package, "wrapper_mode", "755") or "755",
        version_artifact=str_value(package, "version_artifact"),
        source_rename=str_value(build, "source_rename"),
        source_dir=str_value(build, "source_dir", name) or name,
        build_dir=str_value(build, "build_dir", "build") or "build",
        meson_options=list_value(build, "meson_options"),
        run_check=bool_value(build, "run_check", False),
        check_args=list_value(build, "check_args"),
        deb_relocate_usr_local=bool_value(build, "deb_relocate_usr_local", False),
        appimage_appdir_name=str_value(build, "appimage_appdir_name", "squashfs-root") or "squashfs-root",
        appimage_install_dir=str_value(build, "appimage_install_dir"),
        desktop_candidates=list_value(build, "desktop_candidates"),
        icon_candidates=list_value(build, "icon_candidates"),
        desktop_exec_rewrite=str_value(build, "desktop_exec_rewrite"),
        desktop_name_rewrite=str_value(build, "desktop_name_rewrite"),
        local_files=list_value(files, "local"),
        patch_files=list_value(files, "patches"),
        doc_files=list_value(files, "docs"),
        license_files=list_value(files, "licenses"),
        install_mode=str_value(install, "mode", "none") or "none",
        install_hints=list_value(install, "hints"),
        install_file=str_value(install, "file"),
        service_mode=str_value(service, "mode", "none") or "none",
        service_scope=str_value(service, "scope", "user") or "user",
        service_name=str_value(service, "name"),
        service_file=str_value(service, "file"),
        service_exec=str_value(service, "exec"),
        service_restart=str_value(service, "restart", "always") or "always",
        service_restart_sec=str_value(service, "restart_sec", "10") or "10",
        persist_state_keys=list_value(state, "persist"),
        test_paths=list_value(tests, "paths"),
        test_executables=list_value(tests, "executables"),
        test_commands=list_value(tests, "commands"),
        artifacts={artifact_name: load_package_artifact(artifact_name, artifact_table) for artifact_name, artifact_table in artifacts.items()},
        sources={source_name: load_package_source(source_name, source_table) for source_name, source_table in sources.items()},
    )
    validate_normalized_package(pkg)
    return pkg


def validate_normalized_package(pkg: PackageSpec) -> None:
    config_path = pkg.definition_path
    validate_package_name_value(pkg.name, "PKGNAME", config_path)
    if pkg.name != pkg.package_dir.name:
        raise CliError(f"Package directory must match PKGNAME: {pkg.package_dir.name} != {pkg.name}")
    if pkg.template not in {"binary-archive", "deb-repack", "appimage-desktop", "source-meson"}:
        raise CliError(f"Unsupported PACKAGE_TEMPLATE in {config_path}: {pkg.template}")
    if pkg.upstream_type not in {"github-release", "github-release-assets", "custom-hook", "fixed"}:
        raise CliError(f"Unsupported UPSTREAM_TYPE in {config_path}: {pkg.upstream_type}")
    if not pkg.arches:
        raise CliError(f"ARCHES must not be empty in {config_path}")
    if not pkg.licenses:
        raise CliError(f"LICENSES must not be empty in {config_path}")
    if not pkg.provides and pkg.name.endswith("-bin"):
        pkg.provides = [pkg.name.removesuffix("-bin")]
    if not pkg.conflicts and pkg.name.endswith("-bin"):
        pkg.conflicts = [pkg.name.removesuffix("-bin")]
    if pkg.install_mode not in {"none", "generated", "static"}:
        raise CliError(f"Unsupported INSTALL_MODE in {config_path}: {pkg.install_mode}")
    if pkg.service_mode not in {"none", "generated", "static"}:
        raise CliError(f"Unsupported SERVICE_MODE in {config_path}: {pkg.service_mode}")
    if pkg.service_scope not in {"user", "system"}:
        raise CliError(f"Unsupported SERVICE_SCOPE in {config_path}: {pkg.service_scope}")
    if pkg.upstream_type in {"github-release", "github-release-assets"} and (not pkg.upstream_repo_user or not pkg.upstream_repo_name):
        raise CliError(f"UPSTREAM_REPO_USER and UPSTREAM_REPO_NAME are required for {pkg.upstream_type}")
    if pkg.version_artifact and pkg.version_artifact not in pkg.artifacts:
        raise CliError(f"VERSION_ARTIFACT references unknown artifact in {config_path}: {pkg.version_artifact}")
    for artifact_name, artifact in pkg.artifacts.items():
        if artifact.type != "archive":
            raise CliError(f"Unsupported artifact type for {artifact_name}: {artifact.type}")
        if artifact.recipe_type != "cargo-build":
            raise CliError(f"Unsupported artifact recipe type for {artifact_name}: {artifact.recipe_type}")
        if artifact.recipe_source_type != "github-source-archive":
            raise CliError(f"Unsupported artifact recipe source type for {artifact_name}: {artifact.recipe_source_type}")
        if artifact.storage_type != "github-release":
            raise CliError(f"Unsupported artifact storage type for {artifact_name}: {artifact.storage_type}")
        if not artifact.recipe_source_repo_user or not artifact.recipe_source_repo_name:
            raise CliError(f"Artifact recipe source repo is required for {artifact_name}")
        if not artifact.storage_repo_user or not artifact.storage_repo_name:
            raise CliError(f"Artifact storage repo is required for {artifact_name}")
        if not artifact.arches:
            raise CliError(f"Artifact arches must not be empty for {artifact_name}")
        if not artifact.archive_files:
            raise CliError(f"Artifact recipe archive_files must not be empty for {artifact_name}")
        for arch in artifact.arches:
            if arch not in artifact.outputs or not artifact.outputs[arch].asset_name:
                raise CliError(f"Artifact output asset_name is required for {artifact_name}/{arch}")
        for archive_file in artifact.archive_files:
            validate_artifact_archive_file(config_path, archive_file)
    source_arches: dict[str, str] = {}
    for source in pkg.sources.values():
        if source.arch not in pkg.arches:
            raise CliError(f"Source arch is not listed in ARCHES for {source.name}: {source.arch}")
        if source.arch in source_arches:
            raise CliError(f"Sources {source.name} and {source_arches[source.arch]} both target architecture {source.arch}")
        source_arches[source.arch] = source.name
        if source.artifact not in pkg.artifacts:
            raise CliError(f"Source references unknown artifact for {source.name}: {source.artifact}")
        artifact = pkg.artifacts[source.artifact]
        if source.arch not in artifact.arches:
            raise CliError(f"Source {source.name} references artifact {source.artifact}, but {source.arch} is not supported")
        if not source.rename:
            raise CliError(f"Source {source.name} requires rename")
    if pkg.template in {"binary-archive", "appimage-desktop"}:
        if not pkg.binary_name:
            raise CliError(f"BINARY_NAME is required for template {pkg.template}")
        if not pkg.install_bin_path:
            raise CliError(f"INSTALL_BIN_PATH is required for template {pkg.template}")
        validate_package_name_value(pkg.binary_name, "BINARY_NAME", config_path)
        validate_relative_source_pattern("BINARY_SOURCE_PATH", pkg.binary_source_path or pkg.binary_name, config_path)
        validate_absolute_install_path("INSTALL_BIN_PATH", pkg.install_bin_path, config_path)
    if pkg.wrapper_source_path or pkg.wrapper_install_path:
        if not pkg.wrapper_source_path or not pkg.wrapper_install_path:
            raise CliError("WRAPPER_SOURCE_PATH and WRAPPER_INSTALL_PATH must be set together")
        validate_relative_source_pattern("WRAPPER_SOURCE_PATH", pkg.wrapper_source_path, config_path)
        validate_absolute_install_path("WRAPPER_INSTALL_PATH", pkg.wrapper_install_path, config_path)
    if pkg.template == "source-meson":
        if not pkg.source_rename:
            raise CliError(f"SOURCE_RENAME is required for template {pkg.template}")
        validate_relative_source_pattern("SOURCE_DIR", pkg.source_dir, config_path)
        validate_relative_source_pattern("BUILD_DIR", pkg.build_dir, config_path)
    if pkg.template == "appimage-desktop":
        validate_relative_source_pattern("APPIMAGE_APPDIR_NAME", pkg.appimage_appdir_name, config_path)
        validate_relative_source_pattern("APPIMAGE_INSTALL_DIR", pkg.appimage_install_dir or pkg.binary_name, config_path)
    if pkg.service_mode != "none":
        if not pkg.service_name:
            raise CliError(f"SERVICE_NAME is required when SERVICE_MODE is {pkg.service_mode}")
        if "/" in pkg.service_name or pkg.service_name.startswith("../") or "/../" in pkg.service_name or pkg.service_name.endswith("/.."):
            raise CliError(f"SERVICE_NAME must be a unit filename, not a path, in {config_path}: {pkg.service_name}")
    if pkg.service_mode == "generated" and not pkg.service_exec:
        raise CliError("SERVICE_EXEC is required when SERVICE_MODE=generated")
    if pkg.service_mode == "static" and not pkg.service_file:
        raise CliError("SERVICE_FILE is required when SERVICE_MODE=static")
    if pkg.install_mode == "static" and not pkg.install_file:
        raise CliError("INSTALL_FILE is required when INSTALL_MODE=static")
    for role, values in (
        ("DOC_FILES entry", pkg.doc_files),
        ("LICENSE_FILES entry", pkg.license_files),
        ("DESKTOP_CANDIDATES entry", pkg.desktop_candidates),
        ("ICON_CANDIDATES entry", pkg.icon_candidates),
    ):
        for value in values:
            validate_relative_source_pattern(role, value, config_path)
    package_asset_lists: list[tuple[str, list[str]]] = [
        ("LOCAL_FILES entry", pkg.local_files),
        ("PATCH_FILES entry", pkg.patch_files),
    ]
    for artifact_name, artifact in pkg.artifacts.items():
        package_asset_lists.append((f"artifacts.{artifact_name}.recipe.patches entry", artifact.patches))
    for role, values in package_asset_lists:
        for value in values:
            validate_package_asset_path(pkg, pkg.package_dir, config_path, role, value)
    if pkg.service_mode == "static":
        validate_package_asset_path(pkg, pkg.package_dir, config_path, "SERVICE_FILE", pkg.service_file)
    if pkg.install_mode == "static":
        validate_package_asset_path(pkg, pkg.package_dir, config_path, "INSTALL_FILE", pkg.install_file)
    for value in pkg.test_paths:
        if value and not value.startswith("/"):
            raise CliError(f"TEST_PATHS entries must be absolute paths in {config_path}: {value}")
    for value in pkg.test_executables:
        if value and not value.startswith("/"):
            raise CliError(f"TEST_EXECUTABLES entries must be absolute paths in {config_path}: {value}")


def emit_shell_for_package(pkg: PackageSpec, raw_defaults: bool = False) -> str:
    # Compatibility output for legacy helper users. Defaults are included because
    # this Python CLI now owns normalization.
    lines: list[str] = []

    def add_scalar(name: str, value: str | int | bool | None) -> None:
        if value is None:
            return
        if not VALID_ENV_NAME_RE.match(name):
            fail(f"Invalid generated variable name: {name}")
        lines.append(render_string_assignment(name, value))

    def add_array(name: str, values: Iterable[str]) -> None:
        if not VALID_ENV_NAME_RE.match(name):
            fail(f"Invalid generated variable name: {name}")
        lines.append(render_array_assignment(name, values))

    add_scalar("PACKAGE_SPEC_VERSION", pkg.spec_version)
    add_scalar("PKGNAME", pkg.name)
    add_scalar("PACKAGE_TEMPLATE", pkg.template)
    add_scalar("PACKAGING_REPO_URL", pkg.packaging_repo_url)
    add_scalar("PKGDESC", pkg.desc)
    add_scalar("URL", pkg.url)
    add_array("LICENSES", pkg.licenses)
    add_array("ARCHES", pkg.arches)
    add_array("DEPENDS", pkg.depends)
    add_array("MAKEDEPENDS", pkg.makedepends)
    add_array("CHECKDEPENDS", pkg.checkdepends)
    add_array("OPTDEPENDS", pkg.optdepends)
    add_array("OPTIONS", pkg.options)
    add_array("PROVIDES", pkg.provides)
    add_array("CONFLICTS", pkg.conflicts)
    add_array("VALIDPGPKEYS", pkg.validpgpkeys)
    add_scalar("UPSTREAM_TYPE", pkg.upstream_type)
    add_scalar("UPSTREAM_REPO_USER", pkg.upstream_repo_user)
    add_scalar("UPSTREAM_REPO_NAME", pkg.upstream_repo_name)
    add_scalar("UPSTREAM_TAG_PREFIX", pkg.upstream_tag_prefix)
    add_scalar("UPSTREAM_RELEASE_TAG_PREFIX", pkg.upstream_release_tag_prefix)
    add_scalar("UPSTREAM_ALLOW_PRERELEASE", pkg.upstream_allow_prerelease)
    add_scalar("UPSTREAM_FIXED_VERSION", pkg.upstream_fixed_version)
    for arch in sorted(set(pkg.asset_selectors) | set(pkg.upstream_asset_names) | set(pkg.source_renames)):
        suffix = shell_var_suffix(arch)
        add_scalar(f"ASSET_SELECTOR_{suffix}", pkg.asset_selectors.get(arch, ""))
        add_scalar(f"UPSTREAM_ASSET_NAME_{suffix}", pkg.upstream_asset_names.get(arch, ""))
        add_scalar(f"SOURCE_RENAME_{suffix}", pkg.source_renames.get(arch, ""))
    add_scalar("BINARY_NAME", pkg.binary_name)
    add_scalar("BINARY_SOURCE_PATH", pkg.binary_source_path)
    add_scalar("INSTALL_BIN_PATH", pkg.install_bin_path)
    add_scalar("WRAPPER_SOURCE_PATH", pkg.wrapper_source_path)
    add_scalar("WRAPPER_INSTALL_PATH", pkg.wrapper_install_path)
    add_scalar("WRAPPER_MODE", pkg.wrapper_mode)
    add_scalar("VERSION_ARTIFACT", pkg.version_artifact)
    add_scalar("SOURCE_RENAME", pkg.source_rename)
    add_scalar("SOURCE_DIR", pkg.source_dir)
    add_scalar("BUILD_DIR", pkg.build_dir)
    add_array("PATCH_FILES", pkg.patch_files)
    add_array("MESON_OPTIONS", pkg.meson_options)
    add_scalar("RUN_CHECK", pkg.run_check)
    add_array("CHECK_ARGS", pkg.check_args)
    add_scalar("DEB_RELOCATE_USR_LOCAL", pkg.deb_relocate_usr_local)
    add_scalar("APPIMAGE_APPDIR_NAME", pkg.appimage_appdir_name)
    add_scalar("APPIMAGE_INSTALL_DIR", pkg.appimage_install_dir)
    add_array("DESKTOP_CANDIDATES", pkg.desktop_candidates)
    add_array("ICON_CANDIDATES", pkg.icon_candidates)
    add_scalar("DESKTOP_EXEC_REWRITE", pkg.desktop_exec_rewrite)
    add_scalar("DESKTOP_NAME_REWRITE", pkg.desktop_name_rewrite)
    add_array("LOCAL_FILES", pkg.local_files)
    add_array("DOC_FILES", pkg.doc_files)
    add_array("LICENSE_FILES", pkg.license_files)
    add_scalar("INSTALL_MODE", pkg.install_mode)
    add_array("INSTALL_HINTS", pkg.install_hints)
    add_scalar("INSTALL_FILE", pkg.install_file)
    add_scalar("SERVICE_MODE", pkg.service_mode)
    add_scalar("SERVICE_SCOPE", pkg.service_scope)
    add_scalar("SERVICE_NAME", pkg.service_name)
    add_scalar("SERVICE_FILE", pkg.service_file)
    add_scalar("SERVICE_EXEC", pkg.service_exec)
    add_scalar("SERVICE_RESTART", pkg.service_restart)
    add_scalar("SERVICE_RESTART_SEC", pkg.service_restart_sec)
    add_array("PERSIST_STATE_KEYS", pkg.persist_state_keys)
    add_array("TEST_PATHS", pkg.test_paths)
    add_array("TEST_EXECUTABLES", pkg.test_executables)
    add_array("TEST_COMMANDS", pkg.test_commands)
    return "\n".join(lines) + "\n"


def command_validate(args: list[str]) -> int:
    if len(args) != 1:
        raise CliError("Usage: aurpkg.py validate <pkgname-or-path>")
    load_package(args[0])
    return 0


# ---------------------------------------------------------------------------
# Discovery and framework boundary checks


def git_diff_changed_files(base_ref: str, head_ref: str) -> list[str]:
    for ref, role in ((base_ref, "base"), (head_ref, "head")):
        result = run(["git", "rev-parse", "--verify", f"{ref}^{{commit}}"], cwd=REPO_ROOT, check=False, capture=True)
        if result.returncode != 0:
            raise CliError(f"Unknown discovery {role} ref: {ref}")
    result = run(["git", "diff", "--name-only", "--diff-filter=ACMR", base_ref, head_ref], cwd=REPO_ROOT, capture=True)
    return [line for line in result.stdout.splitlines() if line]


def discover_changed_packages(base_ref: str, head_ref: str) -> list[str]:
    packages: list[str] = []
    seen: set[str] = set()
    for changed_file in git_diff_changed_files(base_ref, head_ref):
        if changed_file.startswith("scripts/") or changed_file.startswith(".github/workflows/"):
            return collect_all_packages()
        parts = changed_file.split("/")
        if len(parts) < 3 or parts[0] != "packages":
            continue
        candidate = f"packages/{parts[1]}"
        if candidate in seen:
            continue
        if package_has_definition(REPO_ROOT / candidate):
            seen.add(candidate)
            packages.append(candidate)
    return packages


def parse_discovery_args(command: str, args: list[str]) -> tuple[str | None, str | None, str | None]:
    package_filter: str | None = None
    base_ref: str | None = None
    head_ref: str | None = None
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--package":
            index += 1
            if index >= len(args):
                raise CliError("Missing value for --package")
            package_filter = args[index]
        elif arg == "--base-ref":
            index += 1
            if index >= len(args):
                raise CliError("Missing value for --base-ref")
            base_ref = args[index]
        elif arg == "--head-ref":
            index += 1
            if index >= len(args):
                raise CliError("Missing value for --head-ref")
            head_ref = args[index]
        else:
            raise CliError(f"Unknown {command} parameter: {arg}")
        index += 1
    if bool(base_ref) != bool(head_ref):
        raise CliError("--base-ref and --head-ref must be provided together")
    return package_filter, base_ref, head_ref


def selected_packages(command: str, args: list[str]) -> list[str]:
    package_filter, base_ref, head_ref = parse_discovery_args(command, args)
    if package_filter:
        return [canonical_package_dir(package_filter)]
    if base_ref and head_ref:
        return discover_changed_packages(base_ref, head_ref)
    return collect_all_packages()


def emit_package_matrix(packages: list[str], label: str) -> None:
    github_output = os.environ.get("GITHUB_OUTPUT")
    if not github_output:
        if packages:
            print("\n".join(packages))
        return
    matrix_json = json.dumps({"package": packages}, separators=(",", ":"))
    with open(github_output, "a", encoding="utf-8") as handle:
        handle.write(f"matrix={matrix_json}\n")
        handle.write(f"has_packages={'true' if packages else 'false'}\n")
    log_info(f"[aurpkg] Discovered {len(packages)} {label}: {json.dumps(packages)}")


def command_discover(args: list[str]) -> int:
    emit_package_matrix(selected_packages("discover", args), "packages")
    return 0


def collect_package_names() -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for definition_path in discover_package_definition_files():
        for name in (definition_path.parent.name, load_spec(str(definition_path))["name"]):
            if name and name not in seen:
                seen.add(name)
                names.append(name)
    return names


def shared_automation_files() -> list[Path]:
    roots = [SCRIPT_DIR, REPO_ROOT / ".github" / "workflows"]
    suffixes = {".sh", ".py", ".yml", ".yaml"}
    files: list[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if path.is_file() and path.suffix in suffixes:
                files.append(path)
    return sorted(files)


def command_check_framework_boundaries(args: list[str]) -> int:
    if args:
        raise CliError(f"Unknown check-framework-boundaries parameter: {args[0]}")
    failures: list[str] = []
    package_names = collect_package_names()
    shared_files = shared_automation_files()
    for definition_path in discover_package_definition_files():
        load_package(package_path_for_output(definition_path.parent))
    for package_name in package_names:
        package_name_pattern = re.compile(rf"(^|[^A-Za-z0-9._-]){re.escape(package_name)}([^A-Za-z0-9._-]|$)")
        for path in shared_files:
            text = path.read_text(encoding="utf-8", errors="ignore")
            for line_number, line in enumerate(text.splitlines(), start=1):
                if package_name_pattern.search(line):
                    rel = path.relative_to(REPO_ROOT).as_posix()
                    failures.append(f"Package-specific name '{package_name}' found in shared automation: {rel}:{line_number}:{line}")
    branch_patterns = [
        re.compile(r'''case\s+["']?\$\{?PKGNAME\}?'''),
        re.compile(r'''if\s+.*\$\{?PKGNAME\}?.*(=|==|!=)\s*["']?[A-Za-z0-9._+-]+'''),
    ]
    for path in shared_files:
        text = path.read_text(encoding="utf-8", errors="ignore")
        for line_number, line in enumerate(text.splitlines(), start=1):
            if any(pattern.search(line) for pattern in branch_patterns):
                rel = path.relative_to(REPO_ROOT).as_posix()
                failures.append(f"Potential package-name branching found in shared automation: {rel}:{line_number}:{line}")
    if failures:
        for failure in failures:
            log_error(failure)
        print(
            "\nShared automation must stay package-agnostic.\n"
            "Move package-specific behavior into PackageSpec v1 package.toml, package-local hooks.sh, package-local files/, or a new generic framework feature.\n"
            "See docs/PACKAGE_FRAMEWORK.md.",
            file=sys.stderr,
        )
        return 1
    print("Framework boundary check passed.")
    return 0


# ---------------------------------------------------------------------------
# Upstream resolution


def expand_template(
    template: str,
    *,
    pkg: PackageSpec,
    pkgver: str = "",
    carch: str = "",
    upstream_version: str = "",
    origin_version: str = "",
    release_rev: str = "",
    artifact_rev: str = "",
    artifact_name: str = "",
    artifact_version: str = "",
) -> str:
    result = template
    values = {
        "pkgname": pkg.name,
        "pkg.name": pkg.name,
        "pkgver": pkgver,
        "pkg.version": pkgver,
        "carch": carch,
        "arch": carch,
        "upstream_version": upstream_version,
        "origin_version": origin_version or upstream_version,
        "origin.version": origin_version or upstream_version,
        "release_rev": release_rev,
        "artifact_rev": artifact_rev,
        "artifact.rev": artifact_rev,
        "artifact_name": artifact_name,
        "artifact.name": artifact_name,
        "artifact_version": artifact_version,
        "artifact.version": artifact_version,
    }
    for key, value in values.items():
        result = result.replace(f"${{{key}}}", value)
    if TEMPLATE_PLACEHOLDER_RE.search(result):
        raise CliError(f"Unsupported template placeholder in: {template}")
    return result


def curl_bytes(args: list[str]) -> bytes:
    require_cmd("curl")
    result = subprocess.run(["curl", *args], env=sanitized_environment(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode != 0:
        err = result.stderr.decode("utf-8", errors="replace").strip().replace("\n", " ")
        raise CliError(f"curl failed ({result.returncode}): {err}")
    return result.stdout


def github_api_get_json(api_url: str) -> Any:
    require_cmd("curl")
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    headers = ["-H", "Accept: application/vnd.github+json", "-H", "User-Agent: aur-packages-ci"]
    if token:
        headers.extend(["-H", f"Authorization: Bearer {token}"])
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        output_path = Path(tmp.name)
    try:
        result = subprocess.run(
            [
                "curl",
                "-sS",
                "-L",
                "--retry",
                "5",
                "--retry-all-errors",
                "--retry-delay",
                "2",
                "--connect-timeout",
                "20",
                *headers,
                "-o",
                str(output_path),
                "-w",
                "%{http_code}",
                api_url,
            ],
            env=sanitized_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        http_code = result.stdout.strip()
        if result.returncode != 0:
            reason = f"curl exit {result.returncode}"
            if http_code and http_code != "000":
                reason += f", HTTP {http_code}"
            if result.stderr.strip():
                reason += f": {result.stderr.strip().replace(chr(10), ' ')}"
            raise GithubApiError(reason)
        text = output_path.read_text(encoding="utf-8", errors="replace")
        if not re.fullmatch(r"2\d\d", http_code):
            message = ""
            try:
                message = json.loads(text).get("message", "")
            except Exception:  # noqa: BLE001
                pass
            reason = f"HTTP {http_code}"
            if message:
                reason += f": {message}"
            raise GithubApiError(reason)
        return json.loads(text)
    finally:
        output_path.unlink(missing_ok=True)


def version_sort_key(value: str) -> list[Any]:
    parts = re.split(r"([0-9]+)", value)
    return [int(part) if part.isdigit() else part for part in parts]


def github_exact_asset_name_for_arch(pkg: PackageSpec, arch: str) -> str:
    template = pkg.upstream_asset_names.get(arch, "")
    if not template:
        return ""
    return expand_template(template, pkg=pkg, pkgver=pkg.resolved_version, carch=arch)


def github_asset_selector_for_arch(pkg: PackageSpec, arch: str) -> str:
    return pkg.asset_selectors.get(arch, "")


def github_asset_match_description_for_arch(pkg: PackageSpec, arch: str) -> str:
    exact_name = github_exact_asset_name_for_arch(pkg, arch)
    if exact_name:
        return f"exact asset name: {exact_name}"
    selector = github_asset_selector_for_arch(pkg, arch)
    if not exact_name and selector:
        return f"regex: {selector}"
    return "<none>"


def github_arch_has_asset_matcher(pkg: PackageSpec, arch: str) -> bool:
    return bool(github_exact_asset_name_for_arch(pkg, arch) or github_asset_selector_for_arch(pkg, arch))


def try_resolve_github_asset_for_arch(pkg: PackageSpec, arch: str, release_json: dict[str, Any]) -> bool:
    exact_name = github_exact_asset_name_for_arch(pkg, arch)
    selector = github_asset_selector_for_arch(pkg, arch)
    if not exact_name and not selector:
        return True
    for asset in release_json.get("assets", []):
        name = asset.get("name", "")
        if exact_name and name == exact_name:
            pkg.resolved_source_urls[arch] = asset.get("browser_download_url", "")
            return bool(pkg.resolved_source_urls[arch])
    if not exact_name and selector:
        matches = [
            asset
            for asset in release_json.get("assets", [])
            if asset.get("name", "") and asset.get("browser_download_url", "") and re.search(selector, asset.get("name", ""))
        ]
        if len(matches) > 1:
            names = ", ".join(str(asset["name"]) for asset in matches)
            raise CliError(f"GitHub release asset regex for {arch} matched multiple assets: {names}")
        if matches:
            pkg.resolved_source_urls[arch] = matches[0]["browser_download_url"]
            return True
    return False


def log_github_asset_match_failure(pkg: PackageSpec, arch: str, release_json: dict[str, Any]) -> None:
    log_error(f"Failed to match GitHub release asset for {arch}")
    log_error(f"Release tag: {pkg.github_release_tag or 'unknown'}")
    log_error(f"Regex: {github_asset_match_description_for_arch(pkg, arch)}")
    names = [asset.get("name", "") for asset in release_json.get("assets", []) if asset.get("name")]
    if names:
        log_error("Available assets:")
        for name in names:
            log_error(f"  {name}")
    else:
        log_error("Available assets: <none>")


def resolve_github_asset_for_arch(pkg: PackageSpec, arch: str, release_json: dict[str, Any]) -> None:
    if not github_arch_has_asset_matcher(pkg, arch):
        return
    if try_resolve_github_asset_for_arch(pkg, arch, release_json):
        return
    log_github_asset_match_failure(pkg, arch, release_json)
    raise CliError(f"Failed to match GitHub release asset for {arch}")


def try_resolve_github_assets_for_configured_arches(pkg: PackageSpec, release_json: dict[str, Any]) -> bool:
    snapshot = dict(pkg.resolved_source_urls)
    for arch in pkg.arches:
        if not github_arch_has_asset_matcher(pkg, arch):
            raise CliError(f"Missing UPSTREAM_ASSET_NAME or ASSET_SELECTOR for architecture: {arch}")
        if not try_resolve_github_asset_for_arch(pkg, arch, release_json):
            pkg.resolved_source_urls = snapshot
            return False
    return True


def resolve_github_release_family_assets(pkg: PackageSpec) -> None:
    releases: list[dict[str, Any]] = []
    page = 1
    while True:
        page_releases = github_api_get_json(f"https://api.github.com/repos/{pkg.upstream_repo_user}/{pkg.upstream_repo_name}/releases?per_page=100&page={page}")
        if not page_releases:
            break
        if not isinstance(page_releases, list):
            raise CliError("Unexpected GitHub releases API response")
        releases.extend(page_releases)
        page += 1
    release_tags = sorted(
        [release.get("tag_name", "") for release in releases if release.get("tag_name", "").startswith(pkg.upstream_release_tag_prefix)],
        key=version_sort_key,
        reverse=True,
    )
    if not release_tags:
        raise CliError(f"No GitHub releases found with tag prefix: {pkg.upstream_release_tag_prefix}")
    failed_tags: list[str] = []
    by_tag = {release.get("tag_name", ""): release for release in releases}
    for latest_tag in release_tags:
        release_json = by_tag.get(latest_tag)
        if not release_json:
            continue
        pkg.github_release_tag = latest_tag
        pkg.resolved_version = latest_tag.removeprefix(pkg.upstream_release_tag_prefix)
        if not pkg.resolved_version:
            continue
        if try_resolve_github_assets_for_configured_arches(pkg, release_json):
            return
        failed_tags.append(latest_tag)
    if failed_tags:
        log_error("Checked release tags without finding all required assets:")
        for tag in failed_tags:
            log_error(f"  {tag}")
    raise CliError(f"No GitHub release with required assets found for tag prefix: {pkg.upstream_release_tag_prefix}")


def github_fetch_latest_release_url(url: str) -> str:
    result = run(
        ["curl", "-fsSLI", "--retry", "5", "--retry-all-errors", "--retry-delay", "2", "--connect-timeout", "20", "-H", "User-Agent: aur-packages-ci", "-o", "/dev/null", "-w", "%{url_effective}", url],
        env=sanitized_environment(),
        capture=True,
    )
    return result.stdout.strip()


def resolve_github_release_assets_via_web(pkg: PackageSpec) -> None:
    latest_url = github_fetch_latest_release_url(f"https://github.com/{pkg.upstream_repo_user}/{pkg.upstream_repo_name}/releases/latest")
    latest_tag = latest_url.rstrip("/").split("/")[-1]
    if not latest_tag:
        raise CliError("Could not determine latest GitHub release tag")
    pkg.github_release_tag = latest_tag
    pkg.resolved_version = latest_tag
    if pkg.upstream_tag_prefix and pkg.resolved_version.startswith(pkg.upstream_tag_prefix):
        pkg.resolved_version = pkg.resolved_version[len(pkg.upstream_tag_prefix):]
    assets_html = curl_bytes(["-fsSL", "--retry", "5", "--retry-all-errors", "--retry-delay", "2", "--connect-timeout", "20", "-H", "User-Agent: aur-packages-ci", f"https://github.com/{pkg.upstream_repo_user}/{pkg.upstream_repo_name}/releases/expanded_assets/{latest_tag}"]).decode("utf-8", errors="replace")
    asset_urls = [f"https://github.com{match}" for match in re.findall(r'href="(/[^\"]+/releases/download/[^\"]+)"', assets_html)]
    if not asset_urls:
        raise CliError("No downloadable assets found on GitHub expanded assets page")
    release_json = {
        "assets": [
            {"name": asset_url.rsplit("/", 1)[-1], "browser_download_url": asset_url}
            for asset_url in asset_urls
        ],
    }
    for arch in pkg.arches:
        resolve_github_asset_for_arch(pkg, arch, release_json)


def resolve_github_release_assets(pkg: PackageSpec) -> None:
    require_cmd("curl")
    if pkg.upstream_release_tag_prefix:
        resolve_github_release_family_assets(pkg)
        return
    api_url = f"https://api.github.com/repos/{pkg.upstream_repo_user}/{pkg.upstream_repo_name}/releases"
    if not pkg.upstream_allow_prerelease:
        api_url += "/latest"
    try:
        response = github_api_get_json(api_url)
    except GithubApiError as exc:
        log_info(f"GitHub API unavailable ({exc}); falling back to release page scraping.")
        resolve_github_release_assets_via_web(pkg)
        return
    release_json = response[0] if pkg.upstream_allow_prerelease else response
    latest_tag = release_json.get("tag_name", "")
    if not latest_tag:
        raise CliError("Could not extract tag_name from GitHub release metadata")
    pkg.github_release_tag = latest_tag
    pkg.resolved_version = latest_tag
    if pkg.upstream_tag_prefix and pkg.resolved_version.startswith(pkg.upstream_tag_prefix):
        pkg.resolved_version = pkg.resolved_version[len(pkg.upstream_tag_prefix):]
    for arch in pkg.arches:
        resolve_github_asset_for_arch(pkg, arch, release_json)


def resolve_github_release_version(pkg: PackageSpec) -> None:
    require_cmd("curl")
    try:
        release_json = github_api_get_json(f"https://api.github.com/repos/{pkg.upstream_repo_user}/{pkg.upstream_repo_name}/releases/latest")
        latest_tag = release_json.get("tag_name", "")
    except GithubApiError as exc:
        log_info(f"GitHub API unavailable ({exc}); falling back to release page scraping.")
        latest_url = github_fetch_latest_release_url(f"https://github.com/{pkg.upstream_repo_user}/{pkg.upstream_repo_name}/releases/latest")
        latest_tag = latest_url.rstrip("/").split("/")[-1]
    if not latest_tag:
        raise CliError("Could not determine latest GitHub release tag")
    pkg.github_release_tag = latest_tag
    pkg.resolved_version = latest_tag
    if pkg.upstream_tag_prefix and pkg.resolved_version.startswith(pkg.upstream_tag_prefix):
        pkg.resolved_version = pkg.resolved_version[len(pkg.upstream_tag_prefix):]
    if not pkg.resolved_version:
        raise CliError(f"Could not normalize GitHub release tag for {pkg.name}: {latest_tag}")


def hook_spec_vars(pkg: PackageSpec) -> list[str]:
    names = [
        "PACKAGE_SPEC_VERSION", "PKGNAME", "PACKAGE_TEMPLATE", "UPSTREAM_TYPE", "PKGDESC", "URL", "LICENSES", "ARCHES", "DEPENDS", "MAKEDEPENDS", "CHECKDEPENDS", "OPTDEPENDS", "OPTIONS", "PROVIDES", "CONFLICTS", "VALIDPGPKEYS", "PACKAGING_REPO_URL",
        "UPSTREAM_REPO_USER", "UPSTREAM_REPO_NAME", "UPSTREAM_TAG_PREFIX", "UPSTREAM_RELEASE_TAG_PREFIX", "UPSTREAM_ALLOW_PRERELEASE", "UPSTREAM_FIXED_VERSION",
        "SOURCE_RENAME", "BINARY_NAME", "BINARY_SOURCE_PATH", "INSTALL_BIN_PATH", "WRAPPER_SOURCE_PATH", "WRAPPER_INSTALL_PATH", "WRAPPER_MODE", "VERSION_ARTIFACT",
        "LOCAL_FILES", "PATCH_FILES", "DOC_FILES", "LICENSE_FILES", "INSTALL_MODE", "INSTALL_HINTS", "INSTALL_FILE", "SERVICE_MODE", "SERVICE_SCOPE", "SERVICE_NAME", "SERVICE_FILE", "SERVICE_EXEC", "SERVICE_RESTART", "SERVICE_RESTART_SEC",
        "DEB_RELOCATE_USR_LOCAL", "APPIMAGE_APPDIR_NAME", "APPIMAGE_INSTALL_DIR", "DESKTOP_CANDIDATES", "ICON_CANDIDATES", "DESKTOP_EXEC_REWRITE", "DESKTOP_NAME_REWRITE",
        "SOURCE_DIR", "BUILD_DIR", "MESON_OPTIONS", "RUN_CHECK", "CHECK_ARGS",
        "PERSIST_STATE_KEYS", "TEST_PATHS", "TEST_EXECUTABLES", "TEST_COMMANDS",
    ]
    for arch in sorted(set(pkg.asset_selectors) | set(pkg.upstream_asset_names) | set(pkg.source_renames)):
        suffix = shell_var_suffix(arch)
        names.extend([f"ASSET_SELECTOR_{suffix}", f"UPSTREAM_ASSET_NAME_{suffix}", f"SOURCE_RENAME_{suffix}"])
    return sorted(set(names))


def run_custom_hook_resolution(pkg: PackageSpec) -> None:
    hooks_path = pkg.package_dir / "hooks.sh"
    if not hooks_path.is_file():
        raise CliError("UPSTREAM_TYPE=custom-hook requires hooks.sh with resolve_upstream_state()")
    env_assignments = emit_shell_for_package(pkg)
    spec_vars = render_array_assignment("__AURPKG_SPEC_VARS", hook_spec_vars(pkg))
    script = f"""#!/bin/bash
set -e
die() {{ echo "!! ERROR: $1" >&2; exit 1; }}
log_info() {{ echo "==> $1" >&2; }}
require_cmd() {{ command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"; }}
fetch_url_text_with_retry() {{ local url=$1; [ -n "$url" ] || die "URL is required"; require_cmd curl; curl -fsSL --retry 20 --retry-all-errors --retry-delay 2 --connect-timeout 20 "$url"; }}
pkgbuild_var_from_file() {{
    local file_path=$1
    local var_name=$2
    local line
    local value
    [ -f "$file_path" ] || return 0
    line=$(grep -E "^${{var_name}}=" "$file_path" | head -n 1 || true)
    [ -n "$line" ] || return 0
    value=${{line#*=}}
    value=$(printf '%s\\n' "$value" | sed -E 's/^"//; s/"$//')
    printf '%s\\n' "$value"
}}
{env_assignments}
PACKAGE_DIR={q(str(pkg.package_dir))}
PACKAGE_DEFINITION_PATH={q(str(pkg.definition_path))}
REPO_ROOT={q(str(REPO_ROOT))}
AUR_CURRENT_VER={q(pkg.aur_current_ver)}
AUR_CURRENT_REL={q(str(pkg.aur_current_rel))}
AUR_REPO_DIR={q(str(pkg.aur_repo_dir or ''))}
{spec_vars}
package_state_digest() {{ local var; for var in "${{__AURPKG_SPEC_VARS[@]}}"; do declare -p "$var" 2>/dev/null || true; done | sha256sum | cut -d' ' -f1; }}
package_state_before=$(package_state_digest)
source {q(str(hooks_path))}
package_state_after=$(package_state_digest)
[ "$package_state_before" = "$package_state_after" ] || die "hooks.sh must not mutate PackageSpec fields while loading; use resolve_upstream_state() outputs"
declare -F resolve_upstream_state >/dev/null 2>&1 || die "UPSTREAM_TYPE=custom-hook requires hooks.sh with resolve_upstream_state()"
RESOLVED_VERSION=""
package_state_before=$(package_state_digest)
resolve_upstream_state
package_state_after=$(package_state_digest)
[ "$package_state_before" = "$package_state_after" ] || die "resolve_upstream_state() must not mutate PackageSpec fields; use RESOLVED_* or STATE_* outputs"
[ -n "$RESOLVED_VERSION" ] || die "resolve_upstream_state() must set RESOLVED_VERSION"
while IFS= read -r var; do
    case "$var" in
        RESOLVED_VERSION|RESOLVED_SOURCE_URL|GITHUB_RELEASE_TAG|RESOLVED_SOURCE_URL_*|STATE_*)
            value=${{!var}}
            encoded=$(printf '%s' "$value" | base64 | tr -d '\\n')
            printf '__AURPKG_ENV__%s=%s\\n' "$var" "$encoded"
            ;;
    esac
done < <(compgen -A variable | sort)
"""
    result = run_package_controlled(
        ["bash", "-c", script],
        cwd=REPO_ROOT,
        check=False,
        capture=True,
    )
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    for line in result.stdout.splitlines():
        if not line.startswith("__AURPKG_ENV__"):
            print(line, file=sys.stderr)
            continue
        key, encoded = line.removeprefix("__AURPKG_ENV__").split("=", 1)
        value = base64.b64decode(encoded.encode("ascii")).decode("utf-8")
        if key == "RESOLVED_VERSION":
            pkg.resolved_version = value
        elif key == "RESOLVED_SOURCE_URL":
            pkg.resolved_source_url = value
        elif key == "GITHUB_RELEASE_TAG":
            pkg.github_release_tag = value
        elif key.startswith("RESOLVED_SOURCE_URL_"):
            suffix = key.removeprefix("RESOLVED_SOURCE_URL_")
            for arch in pkg.arches:
                if shell_var_suffix(arch) == suffix:
                    pkg.resolved_source_urls[arch] = value
                    break
        elif key.startswith("STATE_"):
            pkg.state_values[key.removeprefix("STATE_")] = value
    if result.returncode != 0:
        raise CliError(f"Custom upstream hook failed for {pkg.name}")


def dispatch_upstream_resolution(pkg: PackageSpec) -> None:
    pkg.resolved_version = ""
    pkg.resolved_source_url = ""
    pkg.resolved_source_urls = {}
    pkg.github_release_tag = ""
    pkg.state_values = {}
    if pkg.upstream_type == "github-release":
        resolve_github_release_version(pkg)
    elif pkg.upstream_type == "github-release-assets":
        resolve_github_release_assets(pkg)
    elif pkg.upstream_type == "custom-hook":
        run_custom_hook_resolution(pkg)
    elif pkg.upstream_type == "fixed":
        pkg.resolved_version = pkg.upstream_fixed_version
    else:
        raise CliError(f"Unsupported UPSTREAM_TYPE: {pkg.upstream_type}")
    if not pkg.resolved_version:
        raise CliError("Upstream resolution did not set RESOLVED_VERSION")


# ---------------------------------------------------------------------------
# Rendering and build pipeline


@dataclasses.dataclass
class WorkspaceState:
    common_source_files: list[str] = dataclasses.field(default_factory=list)
    sync_files: list[str] = dataclasses.field(default_factory=list)
    install_file_name: str = ""
    service_file_name: str = ""


def render_pkgbuild_header(pkg: PackageSpec) -> str:
    return f"# Maintainer: theorangeguo\n# Packaging Repo: {pkg.packaging_repo_url}"


def service_install_path(pkg: PackageSpec) -> str:
    if pkg.service_scope == "user":
        return f"/usr/lib/systemd/user/{pkg.service_name}"
    if pkg.service_scope == "system":
        return f"/usr/lib/systemd/system/{pkg.service_name}"
    raise CliError(f"Unsupported SERVICE_SCOPE: {pkg.service_scope}")


def copy_package_asset(pkg: PackageSpec, relative_path: str, workspace: Path) -> Path:
    source_path = pkg.package_dir / relative_path
    if not source_path.is_file():
        raise CliError(f"Package asset not found: {relative_path}")
    destination_path = workspace / Path(relative_path).name
    if destination_path.exists():
        raise CliError(f"Refusing to overwrite existing generated asset: {destination_path.name}")
    shutil.copy2(source_path, destination_path)
    return destination_path


def register_workspace_sync_file(state: WorkspaceState, relative_path: str) -> None:
    if relative_path not in state.sync_files:
        state.sync_files.append(relative_path)


def register_common_source_file(state: WorkspaceState, relative_path: str) -> None:
    if relative_path not in state.common_source_files:
        state.common_source_files.append(relative_path)
    register_workspace_sync_file(state, relative_path)


def generate_service_file(pkg: PackageSpec) -> str:
    wanted_by = "default.target" if pkg.service_scope == "user" else "multi-user.target"
    return f"""[Unit]
Description={pkg.name} Service
After=network.target

[Service]
Type=simple
ExecStart={pkg.service_exec}
Restart={pkg.service_restart}
RestartSec={pkg.service_restart_sec}

[Install]
WantedBy={wanted_by}
"""


def install_echo_line(value: str) -> str:
    return f"    echo {q(value)}\n"


def generate_install_script(pkg: PackageSpec) -> str:
    parts: list[str] = [
        "post_install() {\n",
        "    echo \":: Packaging issues? Report at: https://github.com/theorangeguo/aur-packages\"\n",
    ]
    for hint in pkg.install_hints:
        parts.append(install_echo_line(hint))
    if pkg.service_mode != "none":
        parts.extend(["    echo \"\"\n", "    echo \":: Service Management\"\n"])
        if pkg.service_scope == "user":
            parts.extend([
                "    echo \"   > User Level (Recommended):\"\n",
                f"    echo \"     systemctl --user enable --now {pkg.service_name}\"\n",
                "    echo \"   > System Level:\"\n",
                "    echo \"     (System Service is not available for this package)\"\n",
            ])
        else:
            parts.extend(["    echo \"   > System Level:\"\n", f"    echo \"     systemctl enable --now {pkg.service_name}\"\n"])
    parts.append("}\n\npost_upgrade() {\n")
    if pkg.service_mode != "none":
        if pkg.service_scope == "user":
            parts.extend([
                "    echo \":: Service Management\"\n",
                "    echo \"   > User Level:\"\n",
                "    echo \"     systemctl --user daemon-reload\"\n",
                f"    echo \"     systemctl --user restart {pkg.service_name}\"\n",
                "    echo \"   > System Level:\"\n",
                "    echo \"     (System Service is not available for this package)\"\n",
            ])
        else:
            parts.extend([
                "    echo \":: Service Management\"\n",
                "    echo \"   > System Level:\"\n",
                "    echo \"     systemctl daemon-reload\"\n",
                f"    echo \"     systemctl restart {pkg.service_name}\"\n",
            ])
    else:
        parts.append("    :\n")
    parts.append("}\n\npost_remove() {\n")
    if pkg.service_mode != "none":
        if pkg.service_scope == "user":
            parts.extend([
                "    echo \":: Service Management\"\n",
                "    echo \"   > User Level:\"\n",
                "    echo \"     The service file has been removed. Stop the service if running:\"\n",
                f"    echo \"     systemctl --user stop {pkg.service_name}\"\n",
                "    echo \"   > System Level:\"\n",
                "    echo \"     (System Service is not available for this package)\"\n",
            ])
        else:
            parts.extend([
                "    echo \":: Service Management\"\n",
                "    echo \"   > System Level:\"\n",
                "    echo \"     The service file has been removed. Stop the service if running:\"\n",
                f"    echo \"     systemctl stop {pkg.service_name}\"\n",
            ])
    else:
        parts.append("    :\n")
    parts.append("}\n")
    return "".join(parts)


def prepare_workspace_package_files(pkg: PackageSpec, workspace: Path, state: WorkspaceState) -> None:
    for relative_path in pkg.local_files:
        if relative_path:
            copied = copy_package_asset(pkg, relative_path, workspace)
            register_common_source_file(state, copied.name)
    for relative_path in pkg.patch_files:
        if relative_path:
            copied = copy_package_asset(pkg, relative_path, workspace)
            register_common_source_file(state, copied.name)
    if pkg.service_mode == "generated":
        state.service_file_name = pkg.service_name
        (workspace / state.service_file_name).write_text(generate_service_file(pkg), encoding="utf-8")
        register_common_source_file(state, state.service_file_name)
    elif pkg.service_mode == "static":
        copied = copy_package_asset(pkg, pkg.service_file, workspace)
        state.service_file_name = copied.name
        register_common_source_file(state, state.service_file_name)
    if pkg.install_mode == "generated":
        state.install_file_name = f"{pkg.name}.install"
        (workspace / state.install_file_name).write_text(generate_install_script(pkg), encoding="utf-8")
        register_workspace_sync_file(state, state.install_file_name)
    elif pkg.install_mode == "static":
        copied = copy_package_asset(pkg, pkg.install_file, workspace)
        state.install_file_name = copied.name
        register_workspace_sync_file(state, state.install_file_name)


def resolved_source_url_for_arch(pkg: PackageSpec, arch: str) -> str:
    return pkg.resolved_source_urls.get(arch, "")


def resolved_source_name_for_arch(pkg: PackageSpec, arch: str, target_pkgver: str) -> str:
    template = pkg.source_renames.get(arch, "")
    if not template:
        raise CliError(f"Missing source rename template for architecture: {arch}")
    return expand_template(template, pkg=pkg, pkgver=target_pkgver, carch=arch)


def resolved_common_source_name(pkg: PackageSpec, target_pkgver: str) -> str:
    if not pkg.source_rename:
        raise CliError("Missing common source rename template")
    return expand_template(pkg.source_rename, pkg=pkg, pkgver=target_pkgver)


def render_common_source_arrays(pkg: PackageSpec, state: WorkspaceState, target_pkgver: str) -> str:
    lines: list[str] = []
    common_sources = list(state.common_source_files)
    if pkg.resolved_source_url:
        common_sources.append(f"{resolved_common_source_name(pkg, target_pkgver)}::{pkg.resolved_source_url}")
    lines.append(render_array_assignment("source", common_sources))
    lines.append(render_array_assignment("sha256sums", ["SKIP" for _ in common_sources]))
    for arch in pkg.arches:
        resolved_url = resolved_source_url_for_arch(pkg, arch)
        if not resolved_url:
            continue
        source_name = resolved_source_name_for_arch(pkg, arch, target_pkgver)
        lines.append(render_array_assignment(f"source_{arch}", [f"{source_name}::{resolved_url}"]))
        lines.append(render_array_assignment(f"sha256sums_{arch}", ["SKIP"]))
    return "\n".join(lines)


def render_persisted_state_assignments(pkg: PackageSpec) -> str:
    lines: list[str] = []
    for state_key in pkg.persist_state_keys:
        if not state_key:
            continue
        if state_key not in pkg.state_values or not pkg.state_values[state_key]:
            raise CliError(f"Missing persisted state value for STATE_{state_key}")
        lines.append(render_string_assignment(f"_{state_key.lower()}", pkg.state_values[state_key]))
    return "\n".join(lines)


def render_pkgbuild_metadata(pkg: PackageSpec, state: WorkspaceState, target_pkgver: str, target_pkgrel: int) -> str:
    lines = [
        render_pkgbuild_header(pkg),
        render_string_assignment("pkgname", pkg.name),
        render_string_assignment("pkgver", target_pkgver),
        render_string_assignment("pkgrel", target_pkgrel),
        render_string_assignment("pkgdesc", pkg.desc),
        render_array_assignment("arch", pkg.arches),
        render_string_assignment("url", pkg.url),
        render_array_assignment("license", pkg.licenses),
        render_array_assignment("depends", pkg.depends),
        render_array_assignment("makedepends", pkg.makedepends),
        render_array_assignment("checkdepends", pkg.checkdepends),
        render_array_assignment("optdepends", pkg.optdepends),
        render_array_assignment("options", pkg.options),
        render_array_assignment("provides", pkg.provides),
        render_array_assignment("conflicts", pkg.conflicts),
        render_array_assignment("validpgpkeys", pkg.validpgpkeys),
    ]
    if state.install_file_name:
        lines.append(render_string_assignment("install", state.install_file_name))
    else:
        lines.append("")
    lines.append(render_common_source_arrays(pkg, state, target_pkgver))
    return "\n".join(lines)


def render_binary_archive_pkgbuild(pkg: PackageSpec, workspace: Path, state: WorkspaceState, target_pkgver: str, target_pkgrel: int) -> None:
    register_workspace_sync_file(state, "PKGBUILD")
    binary_source_path = expand_template(pkg.binary_source_path or pkg.binary_name, pkg=pkg, pkgver=target_pkgver)
    wrapper_source_path = pkg.wrapper_source_path
    wrapper_install_path = pkg.wrapper_install_path
    service_path = service_install_path(pkg) if pkg.service_mode != "none" else ""
    content = f"""{render_pkgbuild_metadata(pkg, state, target_pkgver, target_pkgrel)}

_binary_source_path={q(binary_source_path)}
_install_bin_path={q(pkg.install_bin_path)}
_wrapper_source_path={q(wrapper_source_path)}
_wrapper_install_path={q(wrapper_install_path)}
_wrapper_mode={q(pkg.wrapper_mode)}
_service_file={q(state.service_file_name)}
_service_install_path={q(service_path)}
{render_array_assignment("_doc_files", pkg.doc_files)}
{render_array_assignment("_license_files", pkg.license_files)}
{render_persisted_state_assignments(pkg)}

package() {{
    _resolve_required_source_file() {{
        local pattern=$1
        local matches=()
        local nullglob_was_set=false

        shopt -q nullglob && nullglob_was_set=true
        shopt -s nullglob
        matches=("${{srcdir}}"/$pattern)
        [ "$nullglob_was_set" = true ] || shopt -u nullglob

        if [ "${{#matches[@]}}" -ne 1 ]; then
            printf 'Expected exactly one source match for pattern %s, found %s\\n' "$pattern" "${{#matches[@]}}" >&2
            return 1
        fi

        [ -f "${{matches[0]}}" ] || {{
            printf 'Matched source is not a file: %s\\n' "${{matches[0]}}" >&2
            return 1
        }}

        printf '%s\\n' "${{matches[0]}}"
    }}

    _install_optional_source_files() {{
        local pattern=$1
        local target_dir=$2
        local mode=$3
        local matches=()
        local matched_file
        local nullglob_was_set=false

        shopt -q nullglob && nullglob_was_set=true
        shopt -s nullglob
        matches=("${{srcdir}}"/$pattern)
        [ "$nullglob_was_set" = true ] || shopt -u nullglob

        for matched_file in "${{matches[@]}}"; do
            [ -f "$matched_file" ] || continue
            install -Dm"$mode" "$matched_file" "${{pkgdir}}${{target_dir}}/$(basename "$matched_file")"
        done
    }}

    local binary_source_file
    binary_source_file=$(_resolve_required_source_file "${{_binary_source_path}}")
    install -Dm755 "$binary_source_file" "${{pkgdir}}${{_install_bin_path}}"

    if [ -n "${{_wrapper_source_path}}" ] && [ -n "${{_wrapper_install_path}}" ]; then
        local wrapper_source_file
        wrapper_source_file=$(_resolve_required_source_file "${{_wrapper_source_path}}")
        install -Dm${{_wrapper_mode}} "$wrapper_source_file" "${{pkgdir}}${{_wrapper_install_path}}"
    fi

    local doc_file
    for doc_file in "${{_doc_files[@]}}"; do
        _install_optional_source_files "$doc_file" "/usr/share/doc/${{pkgname}}" 644
    done

    local license_file
    for license_file in "${{_license_files[@]}}"; do
        _install_optional_source_files "$license_file" "/usr/share/licenses/${{pkgname}}" 644
    done

    if [ -n "${{_service_file}}" ] && [ -f "${{srcdir}}/${{_service_file}}" ]; then
        install -Dm644 "${{srcdir}}/${{_service_file}}" "${{pkgdir}}${{_service_install_path}}"
    fi
}}
"""
    (workspace / "PKGBUILD").write_text(content, encoding="utf-8")


def render_deb_repack_pkgbuild(pkg: PackageSpec, workspace: Path, state: WorkspaceState, target_pkgver: str, target_pkgrel: int) -> None:
    register_workspace_sync_file(state, "PKGBUILD")
    service_path = service_install_path(pkg) if pkg.service_mode != "none" else ""
    source_name_x86_64 = resolved_source_name_for_arch(pkg, "x86_64", target_pkgver)
    content = f"""{render_pkgbuild_metadata(pkg, state, target_pkgver, target_pkgrel)}

_deb_source_file={q(source_name_x86_64)}
_deb_relocate_usr_local={q(pkg.deb_relocate_usr_local)}
_service_file={q(state.service_file_name)}
_service_install_path={q(service_path)}
{render_array_assignment("_doc_files", pkg.doc_files)}
{render_array_assignment("_license_files", pkg.license_files)}
{render_persisted_state_assignments(pkg)}

prepare() {{
    rm -rf "${{srcdir}}/_deb_extract" "${{srcdir}}/_deb_root"
    mkdir -p "${{srcdir}}/_deb_extract" "${{srcdir}}/_deb_root"

    bsdtar -xf "${{srcdir}}/${{_deb_source_file}}" -C "${{srcdir}}/_deb_extract"

    local data_archives=("${{srcdir}}/_deb_extract"/data.tar.*)
    [ -e "${{data_archives[0]}}" ] || {{
        echo "Missing data.tar.* inside Debian package" >&2
        return 1
    }}

    bsdtar -xf "${{data_archives[0]}}" -C "${{srcdir}}/_deb_root"
}}

package() {{
    install -d "${{pkgdir}}"
    cp -a "${{srcdir}}/_deb_root/." "${{pkgdir}}/"

    if [ "${{_deb_relocate_usr_local}}" = true ] && [ -d "${{pkgdir}}/usr/local" ]; then
        install -d "${{pkgdir}}/usr"
        cp -a "${{pkgdir}}/usr/local/." "${{pkgdir}}/usr/"
        rm -rf "${{pkgdir}}/usr/local"
    fi

    local doc_file
    for doc_file in "${{_doc_files[@]}}"; do
        [ -f "${{srcdir}}/${{doc_file}}" ] || continue
        install -Dm644 "${{srcdir}}/${{doc_file}}" "${{pkgdir}}/usr/share/doc/${{pkgname}}/$(basename "${{doc_file}}")"
    done

    local license_file
    for license_file in "${{_license_files[@]}}"; do
        [ -f "${{srcdir}}/${{license_file}}" ] || continue
        install -Dm644 "${{srcdir}}/${{license_file}}" "${{pkgdir}}/usr/share/licenses/${{pkgname}}/$(basename "${{license_file}}")"
    done

    if [ -n "${{_service_file}}" ] && [ -f "${{srcdir}}/${{_service_file}}" ]; then
        install -Dm644 "${{srcdir}}/${{_service_file}}" "${{pkgdir}}${{_service_install_path}}"
    fi
}}
"""
    (workspace / "PKGBUILD").write_text(content, encoding="utf-8")


def render_appimage_desktop_pkgbuild(pkg: PackageSpec, workspace: Path, state: WorkspaceState, target_pkgver: str, target_pkgrel: int) -> None:
    register_workspace_sync_file(state, "PKGBUILD")
    service_path = service_install_path(pkg) if pkg.service_mode != "none" else ""
    source_name_x86_64 = resolved_source_name_for_arch(pkg, "x86_64", target_pkgver)
    appimage_install_dir = pkg.appimage_install_dir or pkg.binary_name
    install_bin_dir = str(Path(pkg.install_bin_path).parent)
    content = f"""{render_pkgbuild_metadata(pkg, state, target_pkgver, target_pkgrel)}

_appimage_source_file={q(source_name_x86_64)}
_appimage_appdir_name={q(pkg.appimage_appdir_name)}
_appimage_install_dir={q(appimage_install_dir)}
_install_bin_path={q(pkg.install_bin_path)}
_install_bin_dir={q(install_bin_dir)}
_desktop_exec_rewrite={q(pkg.desktop_exec_rewrite)}
_desktop_name_rewrite={q(pkg.desktop_name_rewrite)}
_service_file={q(state.service_file_name)}
_service_install_path={q(service_path)}
{render_array_assignment("_desktop_candidates", pkg.desktop_candidates)}
{render_array_assignment("_icon_candidates", pkg.icon_candidates)}
{render_array_assignment("_license_files", pkg.license_files)}
{render_persisted_state_assignments(pkg)}

prepare() {{
    rm -rf "${{srcdir}}/${{_appimage_appdir_name}}"
    chmod +x "${{srcdir}}/${{_appimage_source_file}}"
    "${{srcdir}}/${{_appimage_source_file}}" --appimage-extract >/dev/null
}}

package() {{
    install -d "${{pkgdir}}/opt/${{_appimage_install_dir}}"
    cp -r "${{srcdir}}/${{_appimage_appdir_name}}/." "${{pkgdir}}/opt/${{_appimage_install_dir}}/"
    chmod -R a+rX "${{pkgdir}}/opt/${{_appimage_install_dir}}"

    install -d "${{pkgdir}}${{_install_bin_dir}}"
    ln -sf "/opt/${{_appimage_install_dir}}/AppRun" "${{pkgdir}}${{_install_bin_path}}"

    local desktop_candidate=""
    local candidate
    for candidate in "${{_desktop_candidates[@]}}"; do
        if [ -f "${{srcdir}}/${{_appimage_appdir_name}}/${{candidate}}" ]; then
            desktop_candidate="${{candidate}}"
            break
        fi
    done

    if [ -n "${{desktop_candidate}}" ]; then
        install -Dm644 "${{srcdir}}/${{_appimage_appdir_name}}/${{desktop_candidate}}" "${{pkgdir}}/usr/share/applications/{pkg.binary_name}.desktop"
        if [ -n "${{_desktop_exec_rewrite}}" ]; then
            sed -i "s|^Exec=.*|Exec=${{_desktop_exec_rewrite}}|" "${{pkgdir}}/usr/share/applications/{pkg.binary_name}.desktop"
        fi
        if [ -n "${{_desktop_name_rewrite}}" ]; then
            sed -i "s|^Name=.*|Name=${{_desktop_name_rewrite}}|" "${{pkgdir}}/usr/share/applications/{pkg.binary_name}.desktop"
        fi
    fi

    local icon_candidate=""
    for candidate in "${{_icon_candidates[@]}}"; do
        if [ -f "${{srcdir}}/${{_appimage_appdir_name}}/${{candidate}}" ]; then
            icon_candidate="${{candidate}}"
            break
        fi
    done

    if [ -n "${{icon_candidate}}" ]; then
        install -Dm644 "${{srcdir}}/${{_appimage_appdir_name}}/${{icon_candidate}}" "${{pkgdir}}/usr/share/pixmaps/{pkg.binary_name}.png"
        if [ -f "${{pkgdir}}/usr/share/applications/{pkg.binary_name}.desktop" ]; then
            sed -i "s|^Icon=.*|Icon={pkg.binary_name}|" "${{pkgdir}}/usr/share/applications/{pkg.binary_name}.desktop"
        fi
    fi

    local license_file
    for license_file in "${{_license_files[@]}}"; do
        [ -f "${{srcdir}}/${{license_file}}" ] || [ -f "${{srcdir}}/${{_appimage_appdir_name}}/${{license_file}}" ] || continue
        if [ -f "${{srcdir}}/${{license_file}}" ]; then
            install -Dm644 "${{srcdir}}/${{license_file}}" "${{pkgdir}}/usr/share/licenses/${{pkgname}}/$(basename "${{license_file}}")"
        else
            install -Dm644 "${{srcdir}}/${{_appimage_appdir_name}}/${{license_file}}" "${{pkgdir}}/usr/share/licenses/${{pkgname}}/$(basename "${{license_file}}")"
        fi
    done

    if [ -n "${{_service_file}}" ] && [ -f "${{srcdir}}/${{_service_file}}" ]; then
        install -Dm644 "${{srcdir}}/${{_service_file}}" "${{pkgdir}}${{_service_install_path}}"
    fi
}}
"""
    (workspace / "PKGBUILD").write_text(content, encoding="utf-8")


def render_source_meson_pkgbuild(pkg: PackageSpec, workspace: Path, state: WorkspaceState, target_pkgver: str, target_pkgrel: int) -> None:
    register_workspace_sync_file(state, "PKGBUILD")
    source_dir = expand_template(pkg.source_dir, pkg=pkg, pkgver=target_pkgver)
    build_dir = expand_template(pkg.build_dir, pkg=pkg, pkgver=target_pkgver)
    patch_basenames = [Path(patch).name for patch in pkg.patch_files if patch]
    content = f"""{render_pkgbuild_metadata(pkg, state, target_pkgver, target_pkgrel)}

_source_dir={q(source_dir)}
_build_dir={q(build_dir)}
_run_check={q(pkg.run_check)}
{render_array_assignment("_patch_files", patch_basenames)}
{render_array_assignment("_meson_options", pkg.meson_options)}
{render_array_assignment("_check_args", pkg.check_args)}
{render_array_assignment("_doc_files", pkg.doc_files)}
{render_array_assignment("_license_files", pkg.license_files)}
{render_persisted_state_assignments(pkg)}

prepare() {{
    local patch_file

    cd "${{srcdir}}/${{_source_dir}}"

    for patch_file in "${{_patch_files[@]}}"; do
        patch -Np1 -i "${{srcdir}}/${{patch_file}}"
    done
}}

build() {{
    cd "${{srcdir}}"
    arch-meson "${{srcdir}}/${{_source_dir}}" "${{srcdir}}/${{_build_dir}}" "${{_meson_options[@]}}"
    meson compile -C "${{srcdir}}/${{_build_dir}}"
}}

check() {{
    [ "${{_run_check}}" = true ] || return 0
    meson test -C "${{srcdir}}/${{_build_dir}}" "${{_check_args[@]}}"
}}

package() {{
    DESTDIR="${{pkgdir}}" meson install -C "${{srcdir}}/${{_build_dir}}"

    local doc_file
    local doc_source
    for doc_file in "${{_doc_files[@]}}"; do
        doc_source=""
        if [ -f "${{srcdir}}/${{_source_dir}}/${{doc_file}}" ]; then
            doc_source="${{srcdir}}/${{_source_dir}}/${{doc_file}}"
        elif [ -f "${{srcdir}}/${{doc_file}}" ]; then
            doc_source="${{srcdir}}/${{doc_file}}"
        else
            continue
        fi

        install -Dm644 "${{doc_source}}" "${{pkgdir}}/usr/share/doc/${{pkgname}}/$(basename "${{doc_file}}")"
    done

    local license_file
    local license_source
    for license_file in "${{_license_files[@]}}"; do
        license_source=""
        if [ -f "${{srcdir}}/${{_source_dir}}/${{license_file}}" ]; then
            license_source="${{srcdir}}/${{_source_dir}}/${{license_file}}"
        elif [ -f "${{srcdir}}/${{license_file}}" ]; then
            license_source="${{srcdir}}/${{license_file}}"
        else
            continue
        fi

        install -Dm644 "${{license_source}}" "${{pkgdir}}/usr/share/licenses/${{pkgname}}/$(basename "${{license_file}}")"
    done
}}
"""
    (workspace / "PKGBUILD").write_text(content, encoding="utf-8")


def render_pkgbuild(pkg: PackageSpec, workspace: Path, state: WorkspaceState, target_pkgver: str, target_pkgrel: int) -> None:
    if pkg.template == "binary-archive":
        render_binary_archive_pkgbuild(pkg, workspace, state, target_pkgver, target_pkgrel)
    elif pkg.template == "deb-repack":
        render_deb_repack_pkgbuild(pkg, workspace, state, target_pkgver, target_pkgrel)
    elif pkg.template == "appimage-desktop":
        render_appimage_desktop_pkgbuild(pkg, workspace, state, target_pkgver, target_pkgrel)
    elif pkg.template == "source-meson":
        render_source_meson_pkgbuild(pkg, workspace, state, target_pkgver, target_pkgrel)
    else:
        raise CliError(f"Unsupported PACKAGE_TEMPLATE: {pkg.template}")


def is_http_source_url(url: str) -> bool:
    return url.startswith("http://") or url.startswith("https://")


def prefetch_remote_source(url: str, target_path: Path, srcdest: Path) -> None:
    if not url or not is_http_source_url(url):
        return
    require_cmd("curl")
    srcdest.mkdir(parents=True, exist_ok=True)
    partial_path = Path(f"{target_path}.part")
    if target_path.is_file() and target_path.stat().st_size > 0:
        log_info(f"Using cached source: {target_path.name}")
        return
    if target_path.exists():
        target_path.unlink()
    if partial_path.exists() and partial_path.stat().st_size == 0:
        partial_path.unlink()
    log_info(f"Prefetching source: {target_path.name}")
    result = subprocess.run(["curl", "-fsSL", "--retry", "20", "--retry-all-errors", "--retry-delay", "2", "--connect-timeout", "20", "-C", "-", "-o", str(partial_path), url], env=sanitized_environment(), check=False)
    if result.returncode != 0:
        log_info(f"Resume attempt failed for {target_path.name}; retrying from scratch.")
        partial_path.unlink(missing_ok=True)
        run(["curl", "-fsSL", "--retry", "20", "--retry-all-errors", "--retry-delay", "2", "--connect-timeout", "20", "-o", str(partial_path), url], env=sanitized_environment())
    if not partial_path.is_file() or partial_path.stat().st_size == 0:
        raise CliError(f"Prefetched source is empty: {target_path.name}")
    partial_path.replace(target_path)


def prefetch_resolved_sources(pkg: PackageSpec, target_pkgver: str, srcdest: Path) -> None:
    if pkg.resolved_source_url:
        prefetch_remote_source(pkg.resolved_source_url, srcdest / resolved_common_source_name(pkg, target_pkgver), srcdest)
    for arch in pkg.arches:
        resolved_url = resolved_source_url_for_arch(pkg, arch)
        if not resolved_url:
            continue
        prefetch_remote_source(resolved_url, srcdest / resolved_source_name_for_arch(pkg, arch, target_pkgver), srcdest)


def ensure_valid_pgp_keys(validpgpkeys: list[str]) -> None:
    if not validpgpkeys:
        return
    require_cmd("gpg")
    for key in validpgpkeys:
        if not key:
            continue
        if run(["gpg", "--list-keys", key], check=False, capture=True).returncode == 0:
            continue
        log_info(f"Importing PGP key: {key}")
        imported = False
        for keyserver in ("hkps://keyserver.ubuntu.com", "hkps://keys.openpgp.org"):
            if run(["gpg", "--batch", "--keyserver", keyserver, "--recv-keys", key], check=False, capture=True).returncode == 0:
                imported = True
                break
        if not imported or run(["gpg", "--list-keys", key], check=False, capture=True).returncode != 0:
            raise CliError(f"Failed to import required PGP key: {key}")


def prepare_workspace_for_build(pkg: PackageSpec, workspace: Path, target_pkgver: str, target_pkgrel: int, srcdest: Path) -> WorkspaceState:
    state = WorkspaceState()
    prepare_workspace_package_files(pkg, workspace, state)
    render_pkgbuild(pkg, workspace, state, target_pkgver, target_pkgrel)
    prefetch_resolved_sources(pkg, target_pkgver, srcdest)
    return state


def validate_pacman_targets(targets: list[str], context: str) -> list[str]:
    for target in targets:
        if target.startswith("-"):
            raise CliError(f"{context} must not start with '-': {target}")
    return targets


def install_build_dependencies(pkg: PackageSpec, skip_build: bool) -> None:
    if skip_build:
        return
    dependencies: list[str] = []
    for dependency in [*pkg.depends, *pkg.makedepends, *pkg.checkdepends]:
        if dependency and dependency not in dependencies:
            dependencies.append(dependency)
    if dependencies:
        run(["pacman", "-S", "--noconfirm", "--needed", "--asdeps", "--", *validate_pacman_targets(dependencies, "package dependency")], env=sanitized_environment())


def build_workspace_as_builder(pkg: PackageSpec, workspace: Path, tmp_root: Path, srcdest: Path, pkgdest: Path, skip_build: bool, noninteractive: bool) -> None:
    builder_script = tmp_root / "builder-build.sh"
    script = f"""#!/bin/bash
set -e
log_info() {{ echo "==> $1"; }}
ensure_valid_pgp_keys() {{
    [ "${{#VALIDPGPKEYS[@]}}" -gt 0 ] || return 0
    command -v gpg >/dev/null 2>&1 || {{ echo "Required command not found: gpg" >&2; exit 1; }}
    local key keyserver
    for key in "${{VALIDPGPKEYS[@]}}"; do
        [ -n "$key" ] || continue
        if gpg --list-keys "$key" >/dev/null 2>&1; then continue; fi
        log_info "Importing PGP key: $key"
        for keyserver in hkps://keyserver.ubuntu.com hkps://keys.openpgp.org; do
            if gpg --batch --keyserver "$keyserver" --recv-keys "$key" >/dev/null 2>&1; then break; fi
        done
        gpg --list-keys "$key" >/dev/null 2>&1 || {{ echo "Failed to import required PGP key: $key" >&2; exit 1; }}
    done
}}
{render_array_assignment("VALIDPGPKEYS", pkg.validpgpkeys)}
export SRCDEST={q(str(srcdest))}
export PKGDEST={q(str(pkgdest))}
cd {q(str(workspace))}
ensure_valid_pgp_keys
updpkgsums
makepkg --printsrcinfo > .SRCINFO
if [ {q(skip_build)} = true ]; then
    log_info "Skipping build (--skip-build)"
else
    makepkg_opts="-f"
    if [ {q(noninteractive)} = true ]; then
        makepkg_opts="$makepkg_opts --noconfirm"
    fi
    makepkg $makepkg_opts
    makepkg --packagelist > .packagelist
fi
"""
    builder_script.write_text(script, encoding="utf-8")
    builder_script.chmod(0o755)
    tmp_root.chmod(0o755)
    run(["chown", "builder:builder", str(builder_script)])
    run(["chown", "-R", "builder:builder", str(workspace), str(srcdest), str(pkgdest)])
    run(
        ["su", "builder", "-c", f"HOME=/home/builder bash {q(str(builder_script))}"],
        env=sanitized_environment(),
    )


def build_workspace_as_current_user(pkg: PackageSpec, workspace: Path, srcdest: Path, pkgdest: Path, skip_build: bool, noninteractive: bool) -> None:
    env = sanitized_environment({"SRCDEST": str(srcdest), "PKGDEST": str(pkgdest)})
    ensure_valid_pgp_keys(pkg.validpgpkeys)
    run(["updpkgsums"], cwd=workspace, env=env)
    with (workspace / ".SRCINFO").open("w", encoding="utf-8") as handle:
        result = subprocess.run(["makepkg", "--printsrcinfo"], cwd=workspace, env=env, text=True, stdout=handle, check=False)
    if result.returncode != 0:
        raise CliError("makepkg --printsrcinfo failed")
    if skip_build:
        log_info("Skipping build (--skip-build)")
        return
    makepkg_opts = ["-sf"]
    if noninteractive:
        makepkg_opts.append("--noconfirm")
    run(["makepkg", *makepkg_opts], cwd=workspace, env=env)
    packagelist = run(["makepkg", "--packagelist"], cwd=workspace, env=env, capture=True)
    (workspace / ".packagelist").write_text(packagelist.stdout, encoding="utf-8")


def build_workspace(pkg: PackageSpec, workspace: Path, tmp_root: Path, srcdest: Path, pkgdest: Path, skip_build: bool = False, noninteractive: bool = False) -> None:
    if os.geteuid() == 0:
        if run(["id", "-u", "builder"], check=False, capture=True).returncode != 0:
            raise CliError("builder user not found; run: python3 scripts/aurpkg.py setup-user")
        install_build_dependencies(pkg, skip_build)
        build_workspace_as_builder(pkg, workspace, tmp_root, srcdest, pkgdest, skip_build, noninteractive)
    else:
        build_workspace_as_current_user(pkg, workspace, srcdest, pkgdest, skip_build, noninteractive)


def assert_path_exists(path: str) -> None:
    if not path.startswith("/"):
        raise CliError(f"Smoke-test paths must be absolute: {path}")
    if not Path(path).exists():
        raise CliError(f"Expected installed path missing: {path}")


def assert_path_executable(path: str) -> None:
    if not path.startswith("/"):
        raise CliError(f"Smoke-test executable paths must be absolute: {path}")
    if not os.access(path, os.X_OK):
        raise CliError(f"Expected executable path missing or not executable: {path}")


def assert_path_owned_by_package(pkg: PackageSpec, path: str) -> None:
    if not path.startswith("/"):
        raise CliError(f"Owned-path checks require absolute paths: {path}")
    result = run(["pacman", "-Qoq", path], check=False, capture=True)
    owner = result.stdout.strip()
    if owner != pkg.name:
        raise CliError(f"Expected installed path to be owned by {pkg.name}: {path}")


def assert_packaged_path_exists(pkg: PackageSpec, path: str) -> None:
    assert_path_exists(path)
    assert_path_owned_by_package(pkg, path)


def assert_packaged_path_executable(pkg: PackageSpec, path: str) -> None:
    assert_path_executable(path)
    assert_path_owned_by_package(pkg, path)


def run_smoke_checks(pkg: PackageSpec) -> None:
    if run(["pacman", "-Q", pkg.name], check=False, capture=True).returncode != 0:
        raise CliError(f"Installed package not found in pacman database: {pkg.name}")
    if pkg.install_bin_path:
        assert_packaged_path_executable(pkg, pkg.install_bin_path)
    if pkg.service_mode != "none":
        assert_packaged_path_exists(pkg, service_install_path(pkg))
    if pkg.template == "appimage-desktop" and pkg.binary_name:
        assert_packaged_path_exists(pkg, f"/usr/share/applications/{pkg.binary_name}.desktop")
    for license_file in pkg.license_files:
        if license_file:
            assert_packaged_path_exists(pkg, f"/usr/share/licenses/{pkg.name}/{Path(license_file).name}")
    for test_path in pkg.test_paths:
        if test_path:
            assert_packaged_path_exists(pkg, test_path)
    for test_executable in pkg.test_executables:
        if test_executable:
            assert_packaged_path_executable(pkg, test_executable)
    for test_command in pkg.test_commands:
        if test_command:
            log_info(f"Running smoke-test command: {test_command}")
            run_package_controlled(["bash", "-lc", test_command])


def install_and_verify_workspace(pkg: PackageSpec, workspace: Path) -> None:
    if os.geteuid() != 0:
        raise CliError("Package validation must run as root")
    package_files = [line for line in (workspace / ".packagelist").read_text(encoding="utf-8").splitlines() if line]
    if not package_files:
        raise CliError("No built package files were produced")
    log_group_start("Install Package")
    try:
        run(["pacman", "-U", "--noconfirm", "--", *package_files])
        run_smoke_checks(pkg)
        log_info(f"Package install smoke tests passed: {pkg.name}")
    finally:
        log_group_end()


# ---------------------------------------------------------------------------
# AUR sync and publish


def fetch_http_status_with_retry(url: str) -> str:
    require_cmd("curl")
    result = run(["curl", "-sS", "-L", "--retry", os.environ.get("HTTP_STATUS_RETRY_ATTEMPTS", "10"), "--retry-all-errors", "--retry-delay", "2", "--connect-timeout", "20", "-o", "/dev/null", "-w", "%{http_code}", url], env=sanitized_environment(), capture=True)
    return result.stdout.strip()


def prepare_aur_ssh(temp_paths: list[Path]) -> tuple[Path, Path]:
    key = os.environ.get("AUR_SSH_PRIVATE_KEY", "")
    if not key:
        raise CliError("AUR_SSH_PRIVATE_KEY is required")
    require_cmd("ssh-keyscan")
    require_cmd("ssh-keygen")
    key_fd, key_name = tempfile.mkstemp()
    hosts_fd, hosts_name = tempfile.mkstemp()
    os.close(key_fd)
    os.close(hosts_fd)
    key_file = Path(key_name)
    known_hosts_file = Path(hosts_name)
    temp_paths.extend([key_file, known_hosts_file])
    key_file.write_text(key.replace("\r", "") + ("" if key.endswith("\n") else "\n"), encoding="utf-8")
    key_file.chmod(0o600)

    def fetch_key() -> None:
        with known_hosts_file.open("w", encoding="utf-8") as handle:
            result = subprocess.run(["ssh-keyscan", "-t", "ed25519", AUR_SSH_HOST], env=sanitized_environment(), stdout=handle, stderr=subprocess.DEVNULL, check=False)
        if result.returncode != 0:
            raise CliError("ssh-keyscan failed")

    retry("Fetch AUR SSH host key", int(os.environ.get("AUR_SSH_HOST_KEY_MAX_ATTEMPTS", "5")), fetch_key)
    if not known_hosts_file.is_file() or known_hosts_file.stat().st_size == 0:
        raise CliError("Fetched empty AUR SSH host key set")
    fingerprint = run(["ssh-keygen", "-lf", str(known_hosts_file), "-E", "sha256"], capture=True).stdout.split()[1]
    if fingerprint != AUR_SSH_HOST_ED25519_FINGERPRINT:
        raise CliError(f"Unexpected AUR SSH host key fingerprint: {fingerprint or 'unknown'}")
    known_hosts_file.chmod(0o600)
    return key_file, known_hosts_file


def git_ssh_command(key_file: Path, known_hosts_file: Path) -> str:
    return f"ssh -i {key_file} -o UserKnownHostsFile={known_hosts_file} -o StrictHostKeyChecking=yes -o BatchMode=yes -o IdentitiesOnly=yes"


def prepare_aur_repo(pkg: PackageSpec, aur_dir: Path, ssh_files: tuple[Path, Path] | None) -> Path:
    readonly_url = f"https://aur.archlinux.org/{pkg.name}.git"
    ssh_url = f"ssh://aur@aur.archlinux.org/{pkg.name}.git"
    package_url = f"https://aur.archlinux.org/packages/{pkg.name}"
    clone_attempts = int(os.environ.get("AUR_CLONE_MAX_ATTEMPTS", "8"))

    def clone_repo() -> None:
        if aur_dir.exists():
            shutil.rmtree(aur_dir)
        env = os.environ.copy()
        url = readonly_url
        if ssh_files is not None:
            url = ssh_url
            env["GIT_SSH_COMMAND"] = git_ssh_command(*ssh_files)
        run(["git", "clone", "-q", url, str(aur_dir)], env=env)

    try:
        retry(f"Clone AUR repository for {pkg.name}", clone_attempts, clone_repo)
        pkg.aur_repo_dir = aur_dir
        return aur_dir
    except CliError:
        package_status = fetch_http_status_with_retry(package_url)
        if package_status == "200":
            raise CliError(f"Failed to clone existing AUR repository for {pkg.name}")
        if package_status != "404":
            raise CliError(f"Could not determine AUR package status for {pkg.name} (HTTP {package_status or 'unknown'})")
    log_info(f"AUR repository not found for {pkg.name}; treating this as a new package.")
    run(["git", "init", "-q", "-b", "master", str(aur_dir)])
    pkg.aur_repo_dir = aur_dir
    return aur_dir


def pkgbuild_var_from_file(file_path: Path, var_name: str) -> str:
    if not file_path.is_file():
        return ""
    pattern = re.compile(rf"^{re.escape(var_name)}=(.*)$")
    for line in file_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        match = pattern.match(line)
        if not match:
            continue
        value = match.group(1).strip()
        if '"' in value:
            parts = value.split('"')
            return parts[1] if len(parts) > 1 else ""
        return value
    return ""


def load_aur_state(pkg: PackageSpec) -> None:
    if pkg.aur_repo_dir is None:
        raise CliError("AUR repo dir is not initialized")
    pkgbuild_path = pkg.aur_repo_dir / "PKGBUILD"
    pkg.aur_current_ver = pkgbuild_var_from_file(pkgbuild_path, "pkgver")
    rel = pkgbuild_var_from_file(pkgbuild_path, "pkgrel")
    try:
        pkg.aur_current_rel = int(rel or "0")
    except ValueError:
        pkg.aur_current_rel = 0


def safe_managed_file_path(root: Path, relative_path: str) -> Path:
    if not relative_path or Path(relative_path).is_absolute() or ".." in Path(relative_path).parts:
        raise CliError(f"Unsafe managed AUR file path: {relative_path}")
    candidate = (root / relative_path).resolve()
    root_resolved = root.resolve()
    try:
        candidate.relative_to(root_resolved)
    except ValueError as exc:
        raise CliError(f"Managed AUR file path escapes repository: {relative_path}") from exc
    return candidate


def sync_workspace_to_aur_repo(pkg: PackageSpec, workspace: Path, sync_files: list[str]) -> None:
    if pkg.aur_repo_dir is None:
        raise CliError("AUR repo dir is not initialized")
    manifest_file = pkg.aur_repo_dir / ".aur-managed-files"
    sync_set = set(sync_files)
    if manifest_file.is_file():
        for managed_file in manifest_file.read_text(encoding="utf-8").splitlines():
            if managed_file and managed_file not in sync_set:
                safe_managed_file_path(pkg.aur_repo_dir, managed_file).unlink(missing_ok=True)
    for relative_path in sync_files:
        source_path = safe_managed_file_path(workspace, relative_path)
        destination_path = safe_managed_file_path(pkg.aur_repo_dir, relative_path)
        shutil.copy2(source_path, destination_path)
    manifest_file.write_text("\n".join(sync_files) + "\n", encoding="utf-8")
    run(["git", "-C", str(pkg.aur_repo_dir), "add", "-A"])


def aur_repo_has_staged_changes(pkg: PackageSpec) -> bool:
    if pkg.aur_repo_dir is None:
        raise CliError("AUR repo dir is not initialized")
    return run(["git", "-C", str(pkg.aur_repo_dir), "diff", "--cached", "--quiet"], check=False).returncode != 0


def aur_repo_staged_paths(pkg: PackageSpec) -> list[str]:
    if pkg.aur_repo_dir is None:
        raise CliError("AUR repo dir is not initialized")
    return run(["git", "-C", str(pkg.aur_repo_dir), "diff", "--cached", "--name-only"], capture=True).stdout.splitlines()


def aur_repo_has_packaging_changes(pkg: PackageSpec) -> bool:
    return any(path and path != ".aur-managed-files" for path in aur_repo_staged_paths(pkg))


def build_and_stage_workspace(pkg: PackageSpec, tmp_root: Path, srcdest: Path, pkgdest: Path, target_pkgver: str, target_pkgrel: int, skip_build: bool) -> tuple[Path, WorkspaceState]:
    workspace = tmp_root / f"workspace-{target_pkgrel}"
    if workspace.exists():
        shutil.rmtree(workspace)
    workspace.mkdir(parents=True)
    state = prepare_workspace_for_build(pkg, workspace, target_pkgver, target_pkgrel, srcdest)
    log_group_start(f"Render + Build ({target_pkgver}-{target_pkgrel})")
    try:
        build_workspace(pkg, workspace, tmp_root, srcdest, pkgdest, skip_build, os.environ.get("CI", "false") == "true")
    finally:
        log_group_end()
    register_workspace_sync_file(state, ".SRCINFO")
    sync_workspace_to_aur_repo(pkg, workspace, state.sync_files)
    return workspace, state


def publish_to_aur(pkg: PackageSpec, target_pkgver: str, target_pkgrel: int, dry_run: bool, ssh_files: tuple[Path, Path] | None) -> None:
    if pkg.aur_repo_dir is None:
        raise CliError("AUR repo dir is not initialized")
    commit_msg = f"update: {target_pkgver}-{target_pkgrel}"
    if dry_run:
        log_info(f"[DRY RUN] Would commit: {commit_msg}")
        log_info("[DRY RUN] Staged files:")
        run(["git", "-C", str(pkg.aur_repo_dir), "status", "--short"])
        return
    if os.environ.get("CI") == "true" and not os.environ.get("AUR_SSH_PRIVATE_KEY"):
        raise CliError("AUR_SSH_PRIVATE_KEY is required to publish from CI")
    if os.environ.get("CI") == "true" and os.environ.get("AUR_SSH_PRIVATE_KEY"):
        if ssh_files is None:
            raise CliError("AUR SSH files are not prepared")
        remote_url = f"ssh://aur@aur.archlinux.org/{pkg.name}.git"
        if run(["git", "-C", str(pkg.aur_repo_dir), "remote", "get-url", "origin"], check=False, capture=True).returncode == 0:
            run(["git", "-C", str(pkg.aur_repo_dir), "remote", "set-url", "origin", remote_url])
        else:
            run(["git", "-C", str(pkg.aur_repo_dir), "remote", "add", "origin", remote_url])
        env = os.environ.copy()
        env["GIT_SSH_COMMAND"] = git_ssh_command(*ssh_files)
        aur_username = os.environ.get("AUR_USERNAME", "")
        aur_email = os.environ.get("AUR_EMAIL", "")
        if not aur_username:
            raise CliError("AUR_USERNAME is required")
        if not aur_email:
            raise CliError("AUR_EMAIL is required")
        run([
            "git",
            "-C",
            str(pkg.aur_repo_dir),
            "-c",
            f"user.name={aur_username}",
            "-c",
            f"user.email={aur_email}",
            "commit",
            "-m",
            commit_msg,
        ], env=env)

        def push() -> None:
            run(["git", "-C", str(pkg.aur_repo_dir), "push", "origin", "master"], env=env)

        retry(f"Push AUR update for {pkg.name}", 3, push)
    else:
        log_info("Skipping push (local run or missing AUR SSH key).")
        log_info(f"AUR repository prepared at: {pkg.aur_repo_dir}")


# ---------------------------------------------------------------------------
# Command implementations: publish/test/update detection/artifact preparation


def run_preflight(pkg: PackageSpec) -> None:
    log_group_start(f"Preflight: {pkg.rel_dir}")
    try:
        log_info(f"Package: {pkg.name}")
        log_info(f"Template: {pkg.template}")
        log_info(f"Upstream Resolver: {pkg.upstream_type}")
    finally:
        log_group_end()
    log_group_start("Resolve Upstream")
    try:
        dispatch_upstream_resolution(pkg)
        log_info(f"Resolved Upstream Version: {pkg.resolved_version}")
    finally:
        log_group_end()
    log_info(f"Preflight passed for {pkg.name}.")


def artifact_storage_repo(artifact: PackageArtifact) -> str:
    return artifact.storage_repo_value or f"{artifact.storage_repo_user}/{artifact.storage_repo_name}"


def artifact_normalize_requested_version(artifact: PackageArtifact, requested: str) -> str:
    version = requested.removeprefix("v")
    if artifact.recipe_source_tag_prefix and version.startswith(artifact.recipe_source_tag_prefix):
        version = version[len(artifact.recipe_source_tag_prefix):]
    return version


def artifact_resolve_upstream_version(pkg: PackageSpec, artifact: PackageArtifact, requested_version: str = "") -> str:
    if requested_version:
        return artifact_normalize_requested_version(artifact, requested_version)
    if (
        pkg.upstream_type == "github-release"
        and pkg.upstream_repo_user == artifact.recipe_source_repo_user
        and pkg.upstream_repo_name == artifact.recipe_source_repo_name
        and pkg.github_release_tag
    ):
        return artifact_normalize_requested_version(artifact, pkg.github_release_tag)
    if artifact.recipe_source_type != "github-source-archive":
        raise CliError(f"Unsupported artifact recipe source type for {artifact.name}: {artifact.recipe_source_type}")
    try:
        response = github_api_get_json(f"https://api.github.com/repos/{artifact.recipe_source_repo_user}/{artifact.recipe_source_repo_name}/releases/latest")
    except GithubApiError as exc:
        raise CliError(f"Failed to resolve latest artifact recipe source release for {artifact.recipe_source_repo_user}/{artifact.recipe_source_repo_name}: {exc}") from exc
    latest_tag = response.get("tag_name", "")
    if not latest_tag:
        raise CliError(f"Could not extract artifact recipe source release tag for {pkg.name}/{artifact.name}")
    version = artifact_normalize_requested_version(artifact, latest_tag)
    if not version:
        raise CliError(f"Could not normalize artifact recipe source release tag for {pkg.name}/{artifact.name}: {latest_tag}")
    return version


def artifact_version(pkg: PackageSpec, artifact: PackageArtifact, upstream_version: str) -> str:
    pkgver = expand_template(
        artifact.version_template,
        pkg=pkg,
        upstream_version=upstream_version,
        release_rev=artifact.rev,
        artifact_rev=artifact.rev,
        artifact_name=artifact.name,
    )
    if not pkgver:
        raise CliError(f"Computed empty artifact version for {pkg.name}/{artifact.name}")
    if not re.fullmatch(r"[A-Za-z0-9._+]+", pkgver):
        raise CliError(f"Artifact version contains unsupported characters for {pkg.name}/{artifact.name}: {pkgver}")
    return pkgver


def artifact_tag(artifact: PackageArtifact) -> str:
    if not artifact.storage_tag_prefix:
        raise CliError(f"Artifact storage tag_prefix is required for {artifact.name}")
    if not artifact.resolved_version:
        raise CliError(f"Artifact version has not been resolved for {artifact.name}")
    return f"{artifact.storage_tag_prefix}{artifact.resolved_version}"


def artifact_asset_name_for_arch(pkg: PackageSpec, artifact: PackageArtifact, arch: str) -> str:
    output = artifact.outputs.get(arch)
    if output is None or not output.asset_name:
        raise CliError(f"Artifact output asset_name is required for {artifact.name}/{arch}")
    return expand_template(
        output.asset_name,
        pkg=pkg,
        pkgver=artifact.resolved_version,
        carch=arch,
        upstream_version=artifact.resolved_upstream_version,
        artifact_rev=artifact.rev,
        artifact_name=artifact.name,
        artifact_version=artifact.resolved_version,
    )


def artifact_source_name(pkg: PackageSpec, artifact: PackageArtifact, source: PackageSource) -> str:
    template = source.rename
    if not template:
        raise CliError(f"Source rename is required for {source.name}")
    return expand_template(
        template,
        pkg=pkg,
        pkgver=artifact.resolved_version,
        carch=source.arch,
        upstream_version=artifact.resolved_upstream_version,
        artifact_rev=artifact.rev,
        artifact_name=artifact.name,
        artifact_version=artifact.resolved_version,
    )


def artifact_source_archive_url(artifact: PackageArtifact) -> str:
    if artifact.recipe_source_type != "github-source-archive":
        raise CliError(f"Unsupported artifact recipe source type for {artifact.name}: {artifact.recipe_source_type}")
    upstream_tag = f"{artifact.recipe_source_tag_prefix}{artifact.resolved_upstream_version}"
    return f"https://github.com/{artifact.recipe_source_repo_user}/{artifact.recipe_source_repo_name}/archive/refs/tags/{upstream_tag}.tar.gz"


def artifact_source_dir(pkg: PackageSpec, artifact: PackageArtifact) -> str:
    template = artifact.source_dir or f"{artifact.recipe_source_repo_name}-{artifact.resolved_upstream_version}"
    return expand_template(
        template,
        pkg=pkg,
        pkgver=artifact.resolved_version,
        upstream_version=artifact.resolved_upstream_version,
        release_rev=artifact.rev,
        artifact_rev=artifact.rev,
        artifact_name=artifact.name,
        artifact_version=artifact.resolved_version,
    )


def github_release_asset_map(repo: str, tag: str) -> dict[str, str]:
    try:
        release_json = github_api_get_json(f"https://api.github.com/repos/{repo}/releases/tags/{tag}")
    except GithubApiError as exc:
        if "HTTP 404" in str(exc):
            return {}
        raise
    assets = release_json.get("assets", [])
    if not isinstance(assets, list):
        raise CliError(f"Unexpected GitHub release assets response for {repo}/{tag}")
    return {asset.get("name", ""): asset.get("browser_download_url", "") for asset in assets if asset.get("name")}


def github_release_download_url(repo: str, tag: str, asset_name: str) -> str:
    return f"https://github.com/{repo}/releases/download/{tag}/{asset_name}"


def github_release_asset_url_exists(repo: str, tag: str, asset_name: str) -> bool:
    return fetch_http_status_with_retry(github_release_download_url(repo, tag, asset_name)) == "200"


def artifact_asset_complete(asset_urls: dict[str, str], asset_name: str) -> bool:
    return all(name in asset_urls for name in (asset_name, f"{asset_name}.sha256sum", f"{asset_name}.buildinfo"))


def write_artifact_buildinfo(pkg: PackageSpec, artifact: PackageArtifact, output_path: Path, arch: str, asset_name: str) -> None:
    git_sha = os.environ.get("GITHUB_SHA", "")
    if not git_sha and shutil.which("git"):
        git_sha = run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, check=False, capture=True).stdout.strip()
    output_path.write_text(
        f"package={pkg.name}\n"
        f"artifact={artifact.name}\n"
        f"arch={arch}\n"
        f"artifact_version={artifact.resolved_version}\n"
        f"upstream_version={artifact.resolved_upstream_version}\n"
        f"artifact_rev={artifact.rev}\n"
        f"release_tag={artifact.release_tag}\n"
        f"asset_name={asset_name}\n"
        f"recipe={artifact.recipe_type}\n"
        f"git_sha={git_sha or 'unknown'}\n",
        encoding="utf-8",
    )


def publish_artifact_asset(pkg: PackageSpec, artifact: PackageArtifact, asset_path: Path) -> None:
    require_cmd("gh")
    repo = artifact_storage_repo(artifact)
    target = os.environ.get("GITHUB_SHA", "")
    if not target and shutil.which("git"):
        target = run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, check=False, capture=True).stdout.strip()
    if run(["gh", "release", "view", artifact.release_tag, "--repo", repo], check=False, capture=True).returncode == 0:
        run(["gh", "release", "upload", artifact.release_tag, str(asset_path), str(asset_path) + ".sha256sum", str(asset_path) + ".buildinfo", "--clobber", "--repo", repo])
    else:
        run([
            "gh",
            "release",
            "create",
            artifact.release_tag,
            str(asset_path),
            str(asset_path) + ".sha256sum",
            str(asset_path) + ".buildinfo",
            "--repo",
            repo,
            "--target",
            target,
            "--title",
            f"{pkg.name} {artifact.name} v{artifact.resolved_version}",
            "--notes",
            f"Prepared artifact {artifact.name} for {pkg.name} {artifact.resolved_version}.",
        ])


def artifact_build_direct_allowed() -> bool:
    return os.environ.get("CI") == "true" and Path("/etc/arch-release").is_file() and os.geteuid() == 0


def artifact_cargo_builder_script(
    pkg: PackageSpec,
    artifact: PackageArtifact,
    source_url: str,
    source_dir: str,
    work_root: str,
    build_root: str,
    output_root: str,
) -> str:
    return f"""#!/bin/bash
set -e
source_url={q(source_url)}
source_dir={q(source_dir)}
work_root={q(work_root)}
build_root={q(build_root)}
output_root={q(output_root)}
package_rel_dir={q(pkg.rel_dir)}
{render_array_assignment("ARTIFACT_PATCHES", artifact.patches)}
{render_array_assignment("ARTIFACT_CARGO_FETCH_ARGS", artifact.cargo_fetch_args)}
{render_array_assignment("ARTIFACT_CARGO_BUILD_ARGS", artifact.cargo_build_args)}
{render_array_assignment("ARTIFACT_CARGO_CHECK_ARGS", artifact.cargo_check_args)}
{render_array_assignment("ARTIFACT_ARCHIVE_FILES", artifact.archive_files)}
run_check={q(artifact.run_check)}

cd "$build_root"
curl -fsSL \
    --retry 8 --retry-all-errors --retry-delay 2 --connect-timeout 20 \
    -o source.tar.gz \
    "$source_url"

tar -xzf source.tar.gz
cd "$source_dir"

for patch_file in "${{ARTIFACT_PATCHES[@]}}"; do
    [ -n "$patch_file" ] || continue
    patch -Np1 -i "${{work_root}}/${{package_rel_dir}}/${{patch_file}}"
done

if [ "${{#ARTIFACT_CARGO_FETCH_ARGS[@]}}" -gt 0 ]; then
    cargo fetch "${{ARTIFACT_CARGO_FETCH_ARGS[@]}}"
else
    target=$(rustc -vV | sed -n 's/^host: //p')
    cargo fetch --locked --target "$target"
fi

if [ "${{#ARTIFACT_CARGO_BUILD_ARGS[@]}}" -gt 0 ]; then
    cargo build "${{ARTIFACT_CARGO_BUILD_ARGS[@]}}"
else
    cargo build --release --frozen
fi

if [ "$run_check" = true ]; then
    if [ "${{#ARTIFACT_CARGO_CHECK_ARGS[@]}}" -gt 0 ]; then
        cargo test "${{ARTIFACT_CARGO_CHECK_ARGS[@]}}"
    else
        cargo test --frozen
    fi
fi

for archive_file in "${{ARTIFACT_ARCHIVE_FILES[@]}}"; do
    IFS=: read -r source_path destination_path file_mode <<< "$archive_file"
    [ -n "$source_path" ] || {{ echo "Invalid archive file spec: $archive_file" >&2; exit 1; }}
    [ -n "$destination_path" ] || {{ echo "Invalid archive file spec: $archive_file" >&2; exit 1; }}
    [ -n "$file_mode" ] || file_mode=644
    case "$source_path" in
        /*|../*|*/../*|*/..) echo "Archive source must be relative and stay inside the source tree: $source_path" >&2; exit 1 ;;
    esac
    case "$destination_path" in
        /*|../*|*/../*|*/..) echo "Archive destination must be relative and stay inside archive: $destination_path" >&2; exit 1 ;;
    esac
    case "$file_mode" in
        *[!0-7]*|''|?????*) echo "Archive mode must be octal: $file_mode" >&2; exit 1 ;;
    esac
    [ -f "$source_path" ] || {{ echo "Archive source not found: $source_path" >&2; exit 1; }}
    install -Dm"$file_mode" "$source_path" "${{output_root}}/$destination_path"
done
"""


def ensure_builder_user() -> None:
    if run(["id", "-u", "builder"], check=False, capture=True).returncode != 0:
        if os.geteuid() != 0:
            raise CliError("builder user is required for artifact preparation")
        run(["useradd", "-m", "builder"])


def artifact_makedepends(artifact: PackageArtifact) -> list[str]:
    return validate_pacman_targets(
        artifact.makedepends or ["ca-certificates", "curl", "git", "patch", "rust", "tar"],
        "artifact makedepends",
    )


def build_artifact_cargo_direct(pkg: PackageSpec, artifact: PackageArtifact, arch: str, asset_path: Path) -> None:
    require_cmd("pacman")
    require_cmd("runuser")
    if os.geteuid() != 0:
        raise CliError("direct artifact preparation must run as root")
    makedepends = artifact_makedepends(artifact)
    tmp_root = Path(tempfile.mkdtemp())
    try:
        tmp_root.chmod(0o755)
        build_dir = tmp_root / "build"
        output_dir = tmp_root / "output"
        builder_script = tmp_root / "builder.sh"
        build_dir.mkdir()
        output_dir.mkdir()
        asset_path.parent.mkdir(parents=True, exist_ok=True)
        run(["pacman", "-Syu", "--noconfirm", "--needed", "--", *makedepends], env=sanitized_environment())
        ensure_builder_user()
        run(["chown", "-R", "builder:builder", str(build_dir), str(output_dir)])
        source_url = artifact_source_archive_url(artifact)
        source_dir = artifact_source_dir(pkg, artifact)
        builder_script.write_text(
            artifact_cargo_builder_script(pkg, artifact, source_url, source_dir, str(REPO_ROOT), str(build_dir), str(output_dir)),
            encoding="utf-8",
        )
        builder_script.chmod(0o755)
        log_info(f"Building artifact {artifact.name} {artifact.resolved_version} ({arch}) in current Arch environment")
        run(
            ["runuser", "-u", "builder", "--", "env", "HOME=/home/builder", "/bin/bash", str(builder_script)],
            cwd=build_dir,
            env=sanitized_environment(),
        )
        archive_destinations = [spec.split(":", 2)[1] for spec in artifact.archive_files]
        run(["tar", "-C", str(output_dir), "-czf", str(asset_path), *archive_destinations])
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


def build_artifact_cargo(pkg: PackageSpec, artifact: PackageArtifact, arch: str, asset_path: Path) -> None:
    if arch != "x86_64":
        raise CliError(f"cargo-build artifact recipe currently supports x86_64 only: {arch}")
    if artifact_build_direct_allowed():
        build_artifact_cargo_direct(pkg, artifact, arch, asset_path)
        return
    runtime = detect_container_runtime()
    makedepends = artifact_makedepends(artifact)
    tmp_root = Path(tempfile.mkdtemp())
    try:
        output_dir = tmp_root / "output"
        container_script = tmp_root / "container.sh"
        builder_script = tmp_root / "builder.sh"
        output_dir.mkdir()
        asset_path.parent.mkdir(parents=True, exist_ok=True)
        source_url = artifact_source_archive_url(artifact)
        source_dir = artifact_source_dir(pkg, artifact)
        container_script.write_text(f"""#!/bin/bash
set -e
{render_array_assignment("ARTIFACT_MAKEDEPENDS", makedepends)}

pacman -Syu --noconfirm --needed -- "${{ARTIFACT_MAKEDEPENDS[@]}}"

if ! id -u builder >/dev/null 2>&1; then
    useradd -m builder
fi

mkdir -p /build /output
chown -R builder:builder /build /output
runuser -u builder -- env HOME=/home/builder /bin/bash /builder.sh
chown -R "${{HOST_UID}}:${{HOST_GID}}" /output
""", encoding="utf-8")
        builder_script.write_text(artifact_cargo_builder_script(pkg, artifact, source_url, source_dir, "/work", "/build", "/output"), encoding="utf-8")
        container_script.chmod(0o755)
        builder_script.chmod(0o755)
        log_info(f"Building artifact {artifact.name} {artifact.resolved_version} ({arch}) with {runtime}")
        image = os.environ.get("ARCH_BASE_DEVEL_IMAGE", DEFAULT_ARCH_BASE_DEVEL_IMAGE)
        run([
            runtime,
            "run",
            "--rm",
            "-e",
            f"HOST_UID={os.getuid()}",
            "-e",
            f"HOST_GID={os.getgid()}",
            "-v",
            f"{REPO_ROOT}:/work:ro",
            "-v",
            f"{output_dir}:/output",
            "-v",
            f"{container_script}:/container.sh:ro",
            "-v",
            f"{builder_script}:/builder.sh:ro",
            image,
            "bash",
            "/container.sh",
        ], env=sanitized_environment())
        archive_destinations = [spec.split(":", 2)[1] for spec in artifact.archive_files]
        run(["tar", "-C", str(output_dir), "-czf", str(asset_path), *archive_destinations])
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


def prepare_artifact_source(pkg: PackageSpec, artifact: PackageArtifact, source: PackageSource, mode: str, srcdest: Path) -> None:
    arch = source.arch
    asset_name = artifact_asset_name_for_arch(pkg, artifact, arch)
    source_name = artifact_source_name(pkg, artifact, source)
    repo = artifact_storage_repo(artifact)
    asset_urls: dict[str, str] = {}
    if mode in {"readonly", "publish", "force"}:
        try:
            asset_urls = github_release_asset_map(repo, artifact.release_tag)
        except GithubApiError as exc:
            log_info(f"GitHub release asset API unavailable ({exc}); checking release download URL directly.")
    existing_url = asset_urls.get(asset_name, "")
    if not existing_url and mode in {"readonly", "publish"} and github_release_asset_url_exists(repo, artifact.release_tag, asset_name):
        existing_url = github_release_download_url(repo, artifact.release_tag, asset_name)
    artifact_is_complete = artifact_asset_complete(asset_urls, asset_name) if asset_urls else bool(existing_url)
    should_build = mode in {"local", "force"} or (mode == "publish" and not artifact_is_complete)

    if mode == "readonly" and not existing_url:
        raise CliError(
            f"Missing prepared artifact asset for {pkg.name}/{artifact.name}/{arch}: {repo}/{artifact.release_tag}/{asset_name}. "
            f"Run: python3 scripts/aurpkg.py prepare-artifacts {pkg.name} --artifact-mode publish"
        )
    if not should_build and existing_url:
        log_info(f"Using prepared artifact asset: {repo}/{artifact.release_tag}/{asset_name}")
        artifact.resolved_asset_urls[arch] = existing_url
        pkg.resolved_source_urls[arch] = existing_url
        pkg.source_renames[arch] = source_name
        return

    asset_path = srcdest / asset_name
    if artifact.recipe_type == "cargo-build":
        build_artifact_cargo(pkg, artifact, arch, asset_path)
    else:
        raise CliError(f"Unsupported artifact recipe type for {artifact.name}: {artifact.recipe_type}")
    sha = sha256_file(asset_path)
    Path(str(asset_path) + ".sha256sum").write_text(f"{sha}  {asset_path.name}\n", encoding="utf-8")
    write_artifact_buildinfo(pkg, artifact, Path(str(asset_path) + ".buildinfo"), arch, asset_name)

    if mode == "local":
        source_url = asset_path.resolve().as_uri()
        log_info(f"Using locally prepared artifact asset: {asset_path}")
    else:
        publish_artifact_asset(pkg, artifact, asset_path)
        source_url = github_release_download_url(repo, artifact.release_tag, asset_name)
        log_info(f"Published prepared artifact asset: {repo}/{artifact.release_tag}/{asset_name}")
    artifact.resolved_asset_urls[arch] = source_url
    pkg.resolved_source_urls[arch] = source_url
    pkg.source_renames[arch] = source_name


def prepare_package_artifacts(pkg: PackageSpec, mode: str, srcdest: Path, requested_upstream_version: str = "") -> None:
    if mode not in ARTIFACT_MODES:
        raise CliError(f"Unsupported artifact preparation mode: {mode}")
    if not pkg.artifacts:
        return
    log_group_start("Prepare Artifacts")
    try:
        for artifact in pkg.artifacts.values():
            artifact.resolved_upstream_version = artifact_resolve_upstream_version(pkg, artifact, requested_upstream_version)
            artifact.resolved_version = artifact_version(pkg, artifact, artifact.resolved_upstream_version)
            artifact.release_tag = artifact_tag(artifact)
            artifact.resolved_asset_urls = {}
            log_info(
                f"Artifact {artifact.name}: upstream {artifact.resolved_upstream_version}, "
                f"version {artifact.resolved_version}, storage {artifact_storage_repo(artifact)}/{artifact.release_tag}"
            )
        if pkg.version_artifact:
            pkg.resolved_version = pkg.artifacts[pkg.version_artifact].resolved_version
            log_info(f"Package version from artifact {pkg.version_artifact}: {pkg.resolved_version}")
        for source in pkg.sources.values():
            artifact = pkg.artifacts[source.artifact]
            prepare_artifact_source(pkg, artifact, source, mode, srcdest)
    finally:
        log_group_end()


def parse_run_publish_args(args: list[str]) -> tuple[str, bool, bool, bool, bool, str]:
    dry_run = False
    skip_build = False
    verify_install = False
    preflight_only = False
    artifact_mode = ""
    pkg_input = ""
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--dry-run":
            dry_run = True
        elif arg == "--skip-build":
            skip_build = True
        elif arg == "--verify-install":
            verify_install = True
        elif arg == "--preflight":
            preflight_only = True
        elif arg == "--artifact-mode":
            index += 1
            if index >= len(args):
                raise CliError("Missing value for --artifact-mode")
            artifact_mode = args[index]
        elif arg in {"-h", "--help"}:
            print("Usage: aurpkg.py run-publish <pkgname-or-path> [--dry-run] [--skip-build] [--verify-install] [--preflight] [--artifact-mode <readonly|local|publish|force>]")
            raise SystemExit(0)
        elif arg.startswith("-"):
            raise CliError(f"Unknown parameter: {arg}")
        else:
            pkg_input = arg
        index += 1
    if not pkg_input:
        raise CliError("No package directory specified.")
    if skip_build and verify_install:
        raise CliError("--verify-install cannot be used with --skip-build")
    if preflight_only and verify_install:
        raise CliError("--verify-install cannot be used with --preflight")
    if verify_install and os.geteuid() != 0:
        raise CliError("--verify-install requires running as root")
    if not artifact_mode:
        artifact_mode = "readonly" if dry_run else "publish"
    if artifact_mode not in ARTIFACT_MODES:
        raise CliError(f"Unsupported artifact preparation mode: {artifact_mode}")
    if artifact_mode == "local" and not dry_run:
        raise CliError("--artifact-mode local is only allowed with --dry-run")
    return pkg_input, dry_run, skip_build, verify_install, preflight_only, artifact_mode


def command_run_publish(args: list[str]) -> int:
    pkg_input, dry_run, skip_build, verify_install, preflight_only, artifact_mode = parse_run_publish_args(args)
    pkg = load_package(pkg_input)
    if preflight_only:
        run_preflight(pkg)
        return 0
    require_cmd("git")
    require_cmd("makepkg")
    require_cmd("updpkgsums")
    temp_paths: list[Path] = []
    tmp_root_path: Path | None = None
    try:
        tmp_root_path = make_traversable_tempdir()
        aur_dir = tmp_root_path / "aur"
        srcdest = tmp_root_path / "srcdest"
        pkgdest = tmp_root_path / "pkgdest"
        srcdest.mkdir()
        pkgdest.mkdir()
        ssh_files: tuple[Path, Path] | None = None
        log_group_start(f"Initialization: {pkg.rel_dir}")
        try:
            prepare_aur_repo(pkg, aur_dir, None)
            load_aur_state(pkg)
            log_info(f"Package: {pkg.name}")
            log_info(f"Template: {pkg.template}")
            log_info(f"Upstream Resolver: {pkg.upstream_type}")
            log_info(f"Current AUR Version: {pkg.aur_current_ver or '<none>'}")
            log_info(f"Current AUR pkgrel: {pkg.aur_current_rel}")
        finally:
            log_group_end()
        log_group_start("Resolve Upstream")
        try:
            dispatch_upstream_resolution(pkg)
            log_info(f"Resolved Upstream Version: {pkg.resolved_version}")
        finally:
            log_group_end()
        prepare_package_artifacts(pkg, artifact_mode, srcdest)
        target_pkgver = pkg.resolved_version
        target_pkgrel = pkg.aur_current_rel if pkg.aur_current_ver and target_pkgver == pkg.aur_current_ver else 1
        if target_pkgrel < 1:
            target_pkgrel = 1
        final_workspace, _state = build_and_stage_workspace(pkg, tmp_root_path, srcdest, pkgdest, target_pkgver, target_pkgrel, skip_build)
        if pkg.aur_current_ver and target_pkgver == pkg.aur_current_ver and aur_repo_has_packaging_changes(pkg):
            target_pkgrel = pkg.aur_current_rel + 1
            log_info(f"Packaging content changed without upstream version change; bumping pkgrel to {target_pkgrel}.")
            final_workspace, _state = build_and_stage_workspace(pkg, tmp_root_path, srcdest, pkgdest, target_pkgver, target_pkgrel, skip_build)
        elif pkg.aur_current_ver and target_pkgver == pkg.aur_current_ver and aur_repo_has_staged_changes(pkg):
            log_info(f"Only sync metadata changed; keeping pkgrel at {target_pkgrel}.")
        if not aur_repo_has_staged_changes(pkg):
            log_info("No changes to publish.")
            return 0
        if verify_install:
            install_and_verify_workspace(pkg, final_workspace)
        log_group_start("Publish to AUR")
        try:
            if not dry_run and os.environ.get("CI", "false") == "true" and os.environ.get("AUR_SSH_PRIVATE_KEY"):
                ssh_files = prepare_aur_ssh(temp_paths)
            publish_to_aur(pkg, target_pkgver, target_pkgrel, dry_run, ssh_files)
        finally:
            log_group_end()
    finally:
        for path in temp_paths:
            path.unlink(missing_ok=True)
        if tmp_root_path and tmp_root_path.exists():
            shutil.rmtree(tmp_root_path)
    return 0


def parse_run_test_args(args: list[str]) -> tuple[str, str]:
    pkg_input = ""
    artifact_mode = "readonly"
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--artifact-mode":
            index += 1
            if index >= len(args):
                raise CliError("Missing value for --artifact-mode")
            artifact_mode = args[index]
        elif arg in {"-h", "--help"}:
            print("Usage: aurpkg.py run-test <pkgname-or-path> [--artifact-mode <readonly|local>]")
            raise SystemExit(0)
        elif arg.startswith("-"):
            raise CliError(f"Unknown parameter: {arg}")
        else:
            pkg_input = arg
        index += 1
    if not pkg_input:
        raise CliError("No package directory specified.")
    if artifact_mode not in ARTIFACT_MODES:
        raise CliError(f"Unsupported artifact preparation mode: {artifact_mode}")
    if artifact_mode not in {"readonly", "local"}:
        raise CliError("run-test supports readonly or local artifact preparation only; use prepare-artifacts for publish modes")
    return pkg_input, artifact_mode


def run_package_validation_direct(args: list[str]) -> int:
    if os.geteuid() != 0:
        raise CliError("package validation direct mode must run as root inside the test container")
    require_cmd("git")
    require_cmd("makepkg")
    require_cmd("updpkgsums")
    require_cmd("pacman")
    pkg_input, artifact_mode = parse_run_test_args(args)
    pkg = load_package(pkg_input)
    tmp_root = make_traversable_tempdir()
    try:
        srcdest = tmp_root / "srcdest"
        pkgdest = tmp_root / "pkgdest"
        workspace = tmp_root / "workspace"
        aur_repo_dir = tmp_root / "aur"
        srcdest.mkdir()
        pkgdest.mkdir()
        workspace.mkdir()
        aur_repo_dir.mkdir()
        pkg.aur_repo_dir = aur_repo_dir
        pkg.aur_current_ver = ""
        pkg.aur_current_rel = 0
        log_group_start(f"Test Initialization: {pkg.rel_dir}")
        try:
            dispatch_upstream_resolution(pkg)
            log_info(f"Package: {pkg.name}")
            log_info(f"Resolved Upstream Version: {pkg.resolved_version}")
        finally:
            log_group_end()
        prepare_package_artifacts(pkg, artifact_mode, srcdest)
        target_pkgver = pkg.resolved_version
        target_pkgrel = 1
        log_info(f"Resolved Package Version: {target_pkgver}")
        prepare_workspace_for_build(pkg, workspace, target_pkgver, target_pkgrel, srcdest)
        log_group_start("Build Package")
        try:
            build_workspace(pkg, workspace, tmp_root, srcdest, pkgdest, False, True)
        finally:
            log_group_end()
        install_and_verify_workspace(pkg, workspace)
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)
    return 0


def detect_container_runtime() -> str:
    if shutil.which("docker") and run(["docker", "info"], check=False, capture=True).returncode == 0:
        return "docker"
    if shutil.which("podman") and run(["podman", "info"], check=False, capture=True).returncode == 0:
        return "podman"
    raise CliError("docker or podman is required for local package tests")


def container_token_environment_args() -> list[str]:
    return ["-e", "GITHUB_TOKEN", "-e", "GH_TOKEN"]


def command_run_test(args: list[str]) -> int:
    pkg_input, artifact_mode = parse_run_test_args(args)
    pkg_dir = canonical_package_dir(pkg_input)
    if os.environ.get("RUN_TEST_DIRECT") == "true" or os.environ.get("CI") == "true":
        log_cli("Running package validation directly in current Arch environment...")
        return run_package_validation_direct([pkg_dir, "--artifact-mode", artifact_mode])
    runtime = detect_container_runtime()
    image = os.environ.get("ARCH_BASE_DEVEL_IMAGE", DEFAULT_ARCH_BASE_DEVEL_IMAGE)
    log_cli(f"Running package validation in ephemeral {runtime} container...")
    inner = (
        "set -e && "
        "mkdir -p /work && cp -a /src/. /work/ && rm -rf /work/.git && cd /work && "
        "pacman-key --init >/dev/null 2>&1 && "
        "pacman -Syu --needed --noconfirm git openssh pacman-contrib sudo curl jq python && "
        "python3 scripts/aurpkg.py setup-user && "
        f"RUN_TEST_DIRECT=true python3 scripts/aurpkg.py run-test {q(pkg_dir)} --artifact-mode {q(artifact_mode)}"
    )
    run([
        runtime,
        "run",
        "--rm",
        "-e",
        "CI=true",
        *container_token_environment_args(),
        "-v",
        f"{REPO_ROOT}:/src:ro",
        image,
        "bash",
        "-lc",
        inner,
    ])
    return 0


def package_definition_digest(pkg: PackageSpec) -> str:
    files = [pkg.definition_path]
    hooks = pkg.package_dir / "hooks.sh"
    if hooks.is_file():
        files.append(hooks)
    files_dir = pkg.package_dir / "files"
    if files_dir.is_dir():
        files.extend(sorted(path for path in files_dir.rglob("*") if path.is_file()))
    lines = []
    for file in files:
        if not file.is_file():
            continue
        lines.append(f"{file.relative_to(REPO_ROOT).as_posix()}\t{sha256_file(file)}")
    return sha256_text("\n".join(lines) + "\n")


def package_framework_digest() -> str:
    files: list[Path] = []
    for path in SCRIPT_DIR.rglob("*"):
        if path.is_file() and path.suffix in {".py", ".sh"}:
            files.append(path)
    lines = [f"{file.relative_to(REPO_ROOT).as_posix()}\t{sha256_file(file)}" for file in sorted(files)]
    return sha256_text("\n".join(lines) + "\n")


def detection_fingerprint(pkg: PackageSpec) -> str:
    lines = [
        f"PKGNAME={pkg.name}",
        f"PACKAGE_SPEC_VERSION={pkg.spec_version}",
        f"UPSTREAM_TYPE={pkg.upstream_type}",
        f"RESOLVED_VERSION={pkg.resolved_version}",
        f"PACKAGE_DEFINITION={package_definition_digest(pkg)}",
        f"PACKAGE_FRAMEWORK={package_framework_digest()}",
        f"VERSION_ARTIFACT={pkg.version_artifact}",
    ]
    if pkg.github_release_tag:
        lines.append(f"GITHUB_RELEASE_TAG={pkg.github_release_tag}")
    if pkg.resolved_source_url:
        lines.append(f"RESOLVED_SOURCE_URL={pkg.resolved_source_url}")
    for arch, url in sorted(pkg.resolved_source_urls.items()):
        lines.append(f"RESOLVED_SOURCE_URL_{shell_var_suffix(arch)}={url}")
    for key, value in sorted(pkg.state_values.items()):
        lines.append(f"STATE_{key}={value}")
    for arch, name in sorted(pkg.upstream_asset_names.items()):
        if name:
            lines.append(f"UPSTREAM_ASSET_NAME_{shell_var_suffix(arch)}={name}")
    for artifact_name, artifact in sorted(pkg.artifacts.items()):
        lines.append(f"ARTIFACT_{artifact_name}_REV={artifact.rev}")
        lines.append(f"ARTIFACT_{artifact_name}_RECIPE={artifact.recipe_type}")
        for arch, output in sorted(artifact.outputs.items()):
            if output.asset_name:
                lines.append(f"ARTIFACT_{artifact_name}_ASSET_{shell_var_suffix(arch)}={output.asset_name}")
    return sha256_text("\n".join(lines) + "\n")


def parse_detect_updates_args(args: list[str]) -> tuple[str, str, str, str, str]:
    state_file = os.environ.get("UPDATE_STATE_FILE", ".update-state/upstream-state.tsv")
    package_filter = ""
    cache_policy = "normal"
    dispatch_policy = "auto"
    failure_policy = "strict"
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--package":
            index += 1
            if index >= len(args):
                raise CliError("Missing value for --package")
            package_filter = args[index]
        elif arg == "--state-file":
            index += 1
            if index >= len(args):
                raise CliError("Missing value for --state-file")
            state_file = args[index]
        elif arg == "--cache-policy":
            index += 1
            if index >= len(args):
                raise CliError("Missing value for --cache-policy")
            cache_policy = args[index]
        elif arg == "--dispatch-policy":
            index += 1
            if index >= len(args):
                raise CliError("Missing value for --dispatch-policy")
            dispatch_policy = args[index]
        elif arg == "--failure-policy":
            index += 1
            if index >= len(args):
                raise CliError("Missing value for --failure-policy")
            failure_policy = args[index]
        elif arg in {"-h", "--help"}:
            print("Usage: aurpkg.py detect-updates [--package <pkg>] [--state-file <path>] [--cache-policy <normal|refresh>] [--dispatch-policy <auto|changed-only|selected>] [--failure-policy <strict|continue>]")
            raise SystemExit(0)
        else:
            raise CliError(f"Unknown detect-updates parameter: {arg}")
        index += 1
    if cache_policy not in {"normal", "refresh"}:
        raise CliError(f"Unsupported cache policy: {cache_policy}")
    if dispatch_policy not in {"auto", "changed-only", "selected"}:
        raise CliError(f"Unsupported dispatch policy: {dispatch_policy}")
    if failure_policy not in {"strict", "continue"}:
        raise CliError(f"Unsupported failure policy: {failure_policy}")
    if dispatch_policy == "selected" and not package_filter:
        raise CliError("dispatch-policy=selected requires --package")
    return state_file, package_filter, cache_policy, dispatch_policy, failure_policy


def effective_dispatch_policy(dispatch_policy: str, package_filter: str) -> str:
    if dispatch_policy != "auto":
        return dispatch_policy
    return "selected" if package_filter else "changed-only"


def load_previous_state(state_file: Path) -> tuple[dict[str, str], dict[str, str]]:
    previous_fingerprints: dict[str, str] = {}
    previous_lines: dict[str, str] = {}
    if not state_file.is_file():
        return previous_fingerprints, previous_lines
    for line in state_file.read_text(encoding="utf-8").splitlines():
        parts = line.split("\t")
        if len(parts) < 4 or not parts[0]:
            continue
        previous_fingerprints[parts[0]] = parts[1]
        previous_lines[parts[0]] = "\t".join(parts[:4])
    return previous_fingerprints, previous_lines


def write_detection_state(state_file: Path, packages: list[str], previous_lines: dict[str, str], processed: set[str], fingerprints: dict[str, str], versions: dict[str, str]) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    detected_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    lines: list[str] = []
    for package, line in previous_lines.items():
        if package not in processed:
            lines.append(line)
    for package in packages:
        if package in fingerprints:
            lines.append(f"{package}\t{fingerprints[package]}\t{versions[package]}\t{detected_at}")
    state_file.write_text("\n".join(sorted(lines)) + ("\n" if lines else ""), encoding="utf-8")


def command_detect_updates(args: list[str]) -> int:
    state_file_arg, package_filter, cache_policy, dispatch_policy_arg, failure_policy = parse_detect_updates_args(args)
    state_file = (REPO_ROOT / state_file_arg).resolve() if not Path(state_file_arg).is_absolute() else Path(state_file_arg)
    dispatch_policy = effective_dispatch_policy(dispatch_policy_arg, package_filter)
    previous_fingerprints, previous_lines = load_previous_state(state_file)
    packages = [canonical_package_dir(package_filter)] if package_filter else collect_all_packages()
    changed_packages: list[str] = []
    processed: set[str] = set()
    fingerprints: dict[str, str] = {}
    versions: dict[str, str] = {}
    failed_packages: list[str] = []
    for package in packages:
        print(f"==> Detecting upstream state for {package}", file=sys.stderr)
        try:
            pkg = load_package(package)
            dispatch_upstream_resolution(pkg)
            fingerprint = detection_fingerprint(pkg)
        except (SpecError, CliError, GithubApiError) as exc:
            if failure_policy != "continue":
                raise
            failed_packages.append(package)
            print(f"error: failed to detect upstream state for {package}: {exc}", file=sys.stderr)
            continue
        processed.add(package)
        fingerprints[package] = fingerprint
        versions[package] = pkg.resolved_version
        previous_fingerprint = previous_fingerprints.get(package, "")
        should_dispatch = False
        if dispatch_policy == "selected":
            should_dispatch = True
        elif cache_policy == "refresh":
            should_dispatch = False
        elif not previous_fingerprint or fingerprint != previous_fingerprint:
            should_dispatch = True
        if should_dispatch:
            changed_packages.append(package)
    write_detection_state(state_file, packages, previous_lines, processed, fingerprints, versions)
    matrix_json = json.dumps({"package": changed_packages}, separators=(",", ":"))
    failed_packages_json = json.dumps(failed_packages, separators=(",", ":"))
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as handle:
            handle.write(f"matrix={matrix_json}\n")
            handle.write(f"has_packages={'true' if changed_packages else 'false'}\n")
            handle.write(f"state_file={state_file_arg}\n")
            handle.write(f"failed_packages={failed_packages_json}\n")
            handle.write(f"has_detection_failures={'true' if failed_packages else 'false'}\n")
            handle.write(f"detection_failure_count={len(failed_packages)}\n")
        log_info(f"Detected {len(changed_packages)} package(s) to dispatch: {matrix_json}")
    elif changed_packages:
        print("\n".join(changed_packages))
    return 0


def parse_prepare_artifacts_args(args: list[str]) -> tuple[str, str, str]:
    pkg_input = ""
    requested_upstream_version = ""
    artifact_mode = "publish"
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--upstream-version":
            index += 1
            if index >= len(args):
                raise CliError("Missing value for --upstream-version")
            requested_upstream_version = args[index]
        elif arg == "--artifact-mode":
            index += 1
            if index >= len(args):
                raise CliError("Missing value for --artifact-mode")
            artifact_mode = args[index]
        elif arg == "--force":
            artifact_mode = "force"
        elif arg in {"-h", "--help"}:
            print("Usage: aurpkg.py prepare-artifacts <pkgname-or-path> [--upstream-version <version>] [--artifact-mode <readonly|local|publish|force>] [--force]")
            raise SystemExit(0)
        elif arg.startswith("-"):
            raise CliError(f"Unknown parameter: {arg}")
        else:
            pkg_input = arg
        index += 1
    if not pkg_input:
        raise CliError("No package specified.")
    if artifact_mode not in ARTIFACT_MODES:
        raise CliError(f"Unsupported artifact preparation mode: {artifact_mode}")
    return pkg_input, requested_upstream_version, artifact_mode


def command_prepare_artifacts(args: list[str]) -> int:
    pkg_input, requested, artifact_mode = parse_prepare_artifacts_args(args)
    pkg = load_package(pkg_input)
    if not pkg.artifacts:
        log_info(f"Package has no declared artifacts: {pkg.name}")
        return 0
    tmp_root = make_traversable_tempdir()
    try:
        srcdest = tmp_root / "srcdest"
        srcdest.mkdir()
        if not requested:
            dispatch_upstream_resolution(pkg)
        prepare_package_artifacts(pkg, artifact_mode, srcdest, requested)
    finally:
        if artifact_mode != "local":
            shutil.rmtree(tmp_root, ignore_errors=True)
        else:
            log_info(f"Local prepared artifacts kept at: {srcdest}")
    return 0


def command_preflight(args: list[str]) -> int:
    if len(args) != 1:
        raise CliError("Usage: aurpkg.py preflight <pkgname-or-path>")
    log_cli("Running package metadata preflight...")
    run_preflight(load_package(args[0]))
    return 0


def remove_builder_sudoers(sudoers: Path = Path("/etc/sudoers.d/builder")) -> None:
    sudoers.unlink(missing_ok=True)


def command_setup_user(args: list[str]) -> int:
    if args:
        raise CliError(f"Unknown setup-user parameter: {args[0]}")
    if os.geteuid() != 0:
        raise CliError("setup-user must be run as root")
    log_cli("Setting up builder user...")
    if run(["id", "-u", "builder"], check=False, capture=True).returncode != 0:
        run(["useradd", "-m", "builder"])
    else:
        log_cli("User 'builder' already exists.")
    remove_builder_sudoers()
    return 0


def show_help() -> None:
    print(
        "Usage: aurpkg.py <command> [args]\n\n"
        "Commands:\n"
        "  validate <pkgname-or-path>\n"
        "  discover\n"
        "  detect-updates <args>\n"
        "  check-framework-boundaries\n"
        "  setup-user\n"
        "  preflight <pkgname-or-path>\n"
        "  prepare-artifacts <pkgname-or-path> [args]\n"
        "  run-publish <pkgname-or-path> [args]\n"
        "  run-test <pkgname-or-path>\n"
    )


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        show_help()
        return 2
    command = argv[1]
    args = argv[2:]
    try:
        if command == "validate":
            return command_validate(args)
        if command == "discover":
            return command_discover(args)
        if command == "check-framework-boundaries":
            return command_check_framework_boundaries(args)
        if command == "detect-updates":
            return command_detect_updates(args)
        if command == "setup-user":
            return command_setup_user(args)
        if command == "preflight":
            return command_preflight(args)
        if command == "run-publish":
            return command_run_publish(args)
        if command == "run-test":
            return command_run_test(args)
        if command == "prepare-artifacts":
            return command_prepare_artifacts(args)
        if command in {"-h", "--help", "help"}:
            show_help()
            return 0
        print(f"Unknown command: {command}", file=sys.stderr)
        return 2
    except SystemExit as exc:
        return int(exc.code or 0)
    except (SpecError, CliError, GithubApiError) as exc:
        print(exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
