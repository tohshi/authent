"""Exercise both release phases against disposable Git repositories."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("release.py")
VERSION = "v0.1.0"
OLD_CORE = "v0.0.0-20261127045728-eded06a89c9f"


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.remote = self.root / "remote.git"
        self.repo.mkdir()
        self.git("init", "--bare", str(self.remote), cwd=self.root)
        self.git("init", "-b", "main", cwd=self.repo)
        self.git("config", "user.name", "Release Test")
        self.git("config", "user.email", "test@example.com")
        self.git("remote", "add", "origin", str(self.remote))
        (self.repo / "redis").mkdir()
        self.set_changelog("## v0.1.0 - 2026-11-29\n### Added\n- Passkeys\n\n## v0.0.1 - 2026-01-01\n- Older\n")
        self.set_redis_version(OLD_CORE)
        self.commit()
        self.git("push", "origin", "main")
        self.env = os.environ.copy()
        self.env.update(GITHUB_REF="refs/heads/main", GITHUB_SHA=self.sha())

    def git(self, *args, cwd=None):
        return subprocess.run(
            ["git", *args], cwd=cwd or self.repo, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        ).stdout.strip()

    def sha(self):
        return self.git("rev-parse", "HEAD")

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-m", "fixture")
        if hasattr(self, "env"):
            self.env["GITHUB_SHA"] = self.sha()

    def set_changelog(self, text):
        (self.repo / "CHANGELOG.md").write_text("# Changelog\n\n" + text)

    def set_redis_version(self, version):
        (self.repo / "redis" / "go.mod").write_text(
            f"module github.com/tohshi/authent/redis\n\nrequire github.com/tohshi/authent {version}\n\n"
            "replace github.com/tohshi/authent => ../\n"
        )

    def prepare_redis(self):
        self.set_redis_version(VERSION)
        self.commit()
        self.git("push", "origin", "main")

    def run_release(self, command, version=VERSION):
        return subprocess.run(
            [sys.executable, str(SCRIPT), command, version], cwd=self.repo,
            env=self.env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

    def remote_tags(self):
        return self.git("ls-remote", "--tags", "origin")

    def fake_gh(self):
        bindir = self.root / "bin"
        bindir.mkdir()
        gh = bindir / "gh"
        gh.write_text("""#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
args = sys.argv[1:]
state = Path(os.environ['GH_STATE'])
draft = os.environ.get('GH_DRAFT') == '1'
if args[:2] == ['release', 'view']:
    if state.exists() or draft:
        print(json.dumps({'tagName': os.environ['RELEASE_VERSION'], 'isDraft': draft,
                          'body': state.read_text() if state.exists() else ''}))
        raise SystemExit(0)
    raise SystemExit(1)
if args[:2] in (['release', 'create'], ['release', 'edit']):
    phase = args[1]
    fail_once = os.environ.get('GH_FAIL_' + phase.upper() + '_ONCE')
    if fail_once and not Path(fail_once).exists():
        Path(fail_once).write_text('failed')
        raise SystemExit(1)
    state.write_text(Path(args[args.index('--notes-file') + 1]).read_text())
    raise SystemExit(0)
raise SystemExit(2)
""")
        gh.chmod(0o755)
        self.env["PATH"] = str(bindir) + os.pathsep + self.env["PATH"]
        self.env["GH_STATE"] = str(self.root / "release-notes.md")
        self.env["RELEASE_VERSION"] = VERSION

    def publish_core(self):
        result = self.run_release("publish-core")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_core_check_accepts_changelog_without_redis_bump(self):
        result = self.run_release("check-core")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.remote_tags(), "")

    def test_core_check_rejects_invalid_version_and_missing_notes(self):
        self.assertNotEqual(self.run_release("check-core", "v1.0.0").returncode, 0)
        for text in ("## v0.0.9\n- Old\n", "## v0.1.0\n", "## v0.1.0\n- One\n## v0.1.0\n- Two\n"):
            with self.subTest(text=text):
                self.set_changelog(text)
                self.commit()
                result = self.run_release("check-core")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("CHANGELOG.md", result.stderr)
        self.assertEqual(self.remote_tags(), "")

    def test_core_publishes_root_tag_and_release_only(self):
        self.fake_gh()
        self.publish_core()
        original_tags = self.remote_tags()
        self.assertIn("refs/tags/v0.1.0^{}", original_tags)
        self.assertNotIn("redis/v0.1.0", original_tags)
        notes = (self.root / "release-notes.md").read_text()
        self.assertIn("- Passkeys", notes)
        self.assertNotIn("- Older", notes)
        self.assertNotIn("Redis module tag", notes)
        self.publish_core()
        self.assertEqual(self.remote_tags(), original_tags)

    def test_core_rejects_existing_tag_on_another_commit(self):
        self.git("tag", "-a", VERSION, "-m", "old")
        self.git("push", "origin", VERSION)
        old_tags = self.remote_tags()
        (self.repo / "new.txt").write_text("new")
        self.commit()
        self.fake_gh()
        self.assertNotEqual(self.run_release("publish-core").returncode, 0)
        self.assertEqual(self.remote_tags(), old_tags)

    def test_core_rejects_draft_release(self):
        self.fake_gh()
        self.env["GH_DRAFT"] = "1"
        result = self.run_release("publish-core")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("draft", result.stderr.lower())
        self.assertEqual(self.remote_tags(), "")

    def test_core_recovers_from_release_creation_failure(self):
        self.fake_gh()
        self.env["GH_FAIL_CREATE_ONCE"] = str(self.root / "create-failed")
        self.assertNotEqual(self.run_release("publish-core").returncode, 0)
        original_tags = self.remote_tags()
        self.assertIn("refs/tags/v0.1.0^{}", original_tags)
        self.assertFalse((self.root / "release-notes.md").exists())
        fresh = self.root / "fresh"
        self.git("clone", "--branch", "main", str(self.remote), str(fresh), cwd=self.root)
        self.repo = fresh
        self.publish_core()
        self.assertEqual(self.remote_tags(), original_tags)
        self.assertIn("- Passkeys", (self.root / "release-notes.md").read_text())

    def test_redis_requires_root_tag_and_matching_requirement(self):
        self.prepare_redis()
        self.assertNotEqual(self.run_release("check-redis").returncode, 0)
        self.git("tag", "-a", VERSION, "-m", "core", self.git("rev-parse", "HEAD~1"))
        self.git("push", "origin", VERSION)
        self.set_redis_version("v0.0.9")
        self.commit()
        result = self.run_release("check-redis")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("redis/go.mod", result.stderr)

    def test_redis_parses_require_directive_only(self):
        self.git("tag", "-a", VERSION, "-m", "core")
        self.git("push", "origin", VERSION)
        (self.repo / "redis" / "go.mod").write_text(
            "module github.com/tohshi/authent/redis\n\n"
            "exclude (\n    github.com/tohshi/authent v0.1.0\n)\n"
        )
        self.commit()
        result = self.run_release("check-redis")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("redis/go.mod", result.stderr)
        (self.repo / "redis" / "go.mod").write_text(
            "module github.com/tohshi/authent/redis\n\n"
            "require github.com/tohshi/authent v0.1.0\n"
            "replace (\n    github.com/tohshi/authent v0.1.0 => ../\n)\n"
        )
        self.commit()
        result = self.run_release("check-redis")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_redis_publishes_later_commit_and_updates_release(self):
        self.fake_gh()
        self.publish_core()
        root_tag = self.remote_tags()
        self.prepare_redis()
        result = self.run_release("publish-redis")
        self.assertEqual(result.returncode, 0, result.stderr)
        both_tags = self.remote_tags()
        self.assertIn(root_tag, both_tags)
        self.assertIn("refs/tags/redis/v0.1.0^{}", both_tags)
        notes = (self.root / "release-notes.md").read_text()
        self.assertIn("- Passkeys", notes)
        self.assertIn("Redis module tag: `redis/v0.1.0`", notes)
        self.assertEqual(self.run_release("publish-redis").returncode, 0)
        self.assertEqual(self.remote_tags(), both_tags)

    def test_redis_rejects_tag_on_another_commit(self):
        self.fake_gh()
        self.publish_core()
        self.prepare_redis()
        self.git("tag", "-a", f"redis/{VERSION}", "-m", "older")
        self.git("push", "origin", f"redis/{VERSION}")
        original_tags = self.remote_tags()
        (self.repo / "new.txt").write_text("new")
        self.commit()
        self.assertNotEqual(self.run_release("publish-redis").returncode, 0)
        self.assertEqual(self.remote_tags(), original_tags)

    def test_redis_requires_published_core_release(self):
        self.git("tag", "-a", VERSION, "-m", "core")
        self.git("push", "origin", VERSION)
        self.prepare_redis()
        self.fake_gh()
        result = self.run_release("publish-redis")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("GitHub Release", result.stderr)
        self.assertNotIn("refs/tags/redis/v0.1.0", self.remote_tags())

    def test_redis_recovers_after_release_edit_fails(self):
        self.fake_gh()
        self.publish_core()
        self.prepare_redis()
        self.env["GH_FAIL_EDIT_ONCE"] = str(self.root / "edit-failed")
        self.assertNotEqual(self.run_release("publish-redis").returncode, 0)
        original_tags = self.remote_tags()
        self.assertIn("refs/tags/redis/v0.1.0^{}", original_tags)
        self.assertNotIn("Redis module tag", (self.root / "release-notes.md").read_text())
        fresh = self.root / "fresh"
        self.git("clone", "--branch", "main", str(self.remote), str(fresh), cwd=self.root)
        self.repo = fresh
        second = self.run_release("publish-redis")
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(self.remote_tags(), original_tags)
        self.assertIn("Redis module tag: `redis/v0.1.0`", (self.root / "release-notes.md").read_text())


if __name__ == "__main__":
    unittest.main()
