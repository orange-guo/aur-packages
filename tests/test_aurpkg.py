import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "aurpkg.py"
SPEC = importlib.util.spec_from_file_location("aurpkg", SCRIPT_PATH)
assert SPEC and SPEC.loader
aurpkg = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = aurpkg
SPEC.loader.exec_module(aurpkg)


class AurpkgSecurityTests(unittest.TestCase):
    def test_sanitized_environment_removes_credentials(self):
        with patch.dict(os.environ, {
            "AUR_SSH_PRIVATE_KEY": "key",
            "GITHUB_TOKEN": "github-token",
            "GH_TOKEN": "gh-token",
            "GIT_SSH_COMMAND": "ssh command",
            "SSH_AUTH_SOCK": "/tmp/agent",
            "CUSTOM_SECRET": "secret",
            "DATABASE_PASSWORD": "password",
            "ORDINARY_BUILD_SETTING": "keep",
        }, clear=True):
            environment = aurpkg.sanitized_environment({"SRCDEST": "/tmp/src", "EXTRA_TOKEN": "token"})
        self.assertEqual(environment, {"ORDINARY_BUILD_SETTING": "keep", "SRCDEST": "/tmp/src"})

    def test_root_package_command_uses_builder_with_sanitized_environment(self):
        completed = SimpleNamespace(returncode=0)
        with patch.dict(os.environ, {"GITHUB_TOKEN": "token", "PATH": "/usr/bin"}, clear=True), \
             patch.object(aurpkg.os, "geteuid", return_value=0), \
             patch.object(aurpkg, "require_cmd"), \
             patch.object(aurpkg, "run", side_effect=[completed, completed]) as run:
            aurpkg.run_package_controlled(["bash", "-c", "true"])
        self.assertEqual(
            run.call_args_list[1].args[0],
            ["runuser", "-u", "builder", "--", "env", "HOME=/home/builder", "bash", "-c", "true"],
        )
        self.assertEqual(run.call_args_list[1].kwargs["env"], {"PATH": "/usr/bin"})

    def test_nonroot_package_command_uses_current_user(self):
        completed = SimpleNamespace(returncode=0)
        with patch.object(aurpkg.os, "geteuid", return_value=1000), \
             patch.object(aurpkg, "run", return_value=completed) as run:
            aurpkg.run_package_controlled(["bash", "-c", "true"])
        self.assertEqual(run.call_args.args[0], ["bash", "-c", "true"])

    def test_nonroot_builder_package_command_uses_noninteractive_sudo(self):
        completed = SimpleNamespace(returncode=0)
        with patch.dict(os.environ, {"AURPKG_PACKAGE_CONTROLLED_USER": "builder", "GITHUB_TOKEN": "token", "PATH": "/usr/bin"}, clear=True), \
             patch.object(aurpkg.os, "geteuid", return_value=1000), \
             patch.object(aurpkg, "require_cmd"), \
             patch.object(aurpkg, "run", side_effect=[completed, completed]) as run:
            aurpkg.run_package_controlled(["bash", "-c", "true"])
        self.assertEqual(
            run.call_args_list[1].args[0],
            ["sudo", "-n", "-u", "builder", "--", "env", "HOME=/home/builder", "bash", "-c", "true"],
        )
        self.assertEqual(run.call_args_list[1].kwargs["env"], {"PATH": "/usr/bin"})

    def test_nonroot_builder_package_command_requires_builder(self):
        with patch.dict(os.environ, {"AURPKG_PACKAGE_CONTROLLED_USER": "builder"}, clear=True), \
             patch.object(aurpkg.os, "geteuid", return_value=1000), \
             patch.object(aurpkg, "run", return_value=SimpleNamespace(returncode=1)):
            with self.assertRaisesRegex(aurpkg.CliError, "builder user not found"):
                aurpkg.run_package_controlled(["bash", "-c", "true"])

    def test_remove_builder_sudoers(self):
        with tempfile.TemporaryDirectory() as directory:
            sudoers = Path(directory) / "builder"
            sudoers.write_text("builder ALL=(ALL) NOPASSWD: ALL\n", encoding="utf-8")
            aurpkg.remove_builder_sudoers(sudoers)
            self.assertFalse(sudoers.exists())

    def test_traversable_tempdir_has_expected_mode(self):
        directory = aurpkg.make_traversable_tempdir()
        try:
            self.assertEqual(directory.stat().st_mode & 0o777, 0o755)
        finally:
            directory.rmdir()

    def test_install_build_dependencies_deduplicates_with_sanitized_environment(self):
        package = SimpleNamespace(
            depends=["libfoo>=1", "shared"],
            makedepends=["build-tool", "shared"],
            checkdepends=["test-tool", "libfoo>=1"],
        )
        with patch.dict(os.environ, {"GITHUB_TOKEN": "token", "PATH": "/usr/bin"}, clear=True), \
             patch.object(aurpkg, "run") as run:
            aurpkg.install_build_dependencies(package, False)
        self.assertEqual(
            run.call_args.args[0],
            ["pacman", "-S", "--noconfirm", "--needed", "--asdeps", "--", "libfoo>=1", "shared", "build-tool", "test-tool"],
        )
        self.assertEqual(run.call_args.kwargs["env"], {"PATH": "/usr/bin"})

    def test_install_build_dependencies_skips_empty_and_skip_build(self):
        package = SimpleNamespace(depends=[], makedepends=[], checkdepends=[])
        with patch.object(aurpkg, "run") as run:
            aurpkg.install_build_dependencies(package, False)
            aurpkg.install_build_dependencies(package, True)
        run.assert_not_called()

    def test_install_build_dependencies_rejects_option_like_target(self):
        package = SimpleNamespace(depends=["--root=/tmp"], makedepends=[], checkdepends=[])
        with patch.object(aurpkg, "run") as run:
            with self.assertRaisesRegex(aurpkg.CliError, "package dependency must not start"):
                aurpkg.install_build_dependencies(package, False)
        run.assert_not_called()

    def test_artifact_makedepends_rejects_option_like_target(self):
        artifact = SimpleNamespace(makedepends=["--cachedir=/tmp"])
        with self.assertRaisesRegex(aurpkg.CliError, "artifact makedepends must not start"):
            aurpkg.artifact_makedepends(artifact)

    def test_container_token_environment_args_forward_names_only(self):
        self.assertEqual(aurpkg.container_token_environment_args(), ["-e", "GITHUB_TOKEN", "-e", "GH_TOKEN"])


class GithubAssetResolutionTests(unittest.TestCase):
    def package(self, *, exact_name="", selector=""):
        return SimpleNamespace(
            name="test-package",
            upstream_asset_names={"x86_64": exact_name},
            asset_selectors={"x86_64": selector},
            resolved_version="1.0.0",
            resolved_source_urls={},
        )

    def test_exact_asset_name_resolves(self):
        package = self.package(exact_name="app.tar.gz")
        matched = aurpkg.try_resolve_github_asset_for_arch(package, "x86_64", {
            "assets": [{"name": "app.tar.gz", "browser_download_url": "https://example.test/app.tar.gz"}],
        })
        self.assertTrue(matched)
        self.assertEqual(package.resolved_source_urls["x86_64"], "https://example.test/app.tar.gz")

    def test_exact_asset_name_does_not_fall_back_to_regex(self):
        package = self.package(exact_name="app.tar.gz", selector=r"^app-.*\.tar\.gz$")
        matched = aurpkg.try_resolve_github_asset_for_arch(package, "x86_64", {
            "assets": [{"name": "app-linux.tar.gz", "browser_download_url": "https://example.test/app-linux.tar.gz"}],
        })
        self.assertFalse(matched)
        self.assertEqual(package.resolved_source_urls, {})

    def test_regex_asset_zero_matches_fails(self):
        package = self.package(selector=r"^app-.*\.tar\.gz$")
        matched = aurpkg.try_resolve_github_asset_for_arch(package, "x86_64", {
            "assets": [{"name": "other.tar.gz", "browser_download_url": "https://example.test/other.tar.gz"}],
        })
        self.assertFalse(matched)

    def test_regex_asset_unique_match_resolves(self):
        package = self.package(selector=r"^app-.*\.tar\.gz$")
        matched = aurpkg.try_resolve_github_asset_for_arch(package, "x86_64", {
            "assets": [{"name": "app-linux.tar.gz", "browser_download_url": "https://example.test/app-linux.tar.gz"}],
        })
        self.assertTrue(matched)
        self.assertEqual(package.resolved_source_urls["x86_64"], "https://example.test/app-linux.tar.gz")

    def test_regex_asset_ambiguous_match_fails_with_names(self):
        package = self.package(selector=r"^app-.*\.tar\.gz$")
        with self.assertRaisesRegex(aurpkg.CliError, "app-linux.tar.gz, app-musl.tar.gz"):
            aurpkg.try_resolve_github_asset_for_arch(package, "x86_64", {
                "assets": [
                    {"name": "app-linux.tar.gz", "browser_download_url": "https://example.test/app-linux.tar.gz"},
                    {"name": "app-musl.tar.gz", "browser_download_url": "https://example.test/app-musl.tar.gz"},
                ],
            })


if __name__ == "__main__":
    unittest.main()
