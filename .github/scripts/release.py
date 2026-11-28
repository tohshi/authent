#!/usr/bin/env python3
"""Publish the core and Redis Go modules in two guarded phases."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


ROOT_MODULE = "github.com/tohshi/authent"
VERSION_RE = re.compile(r"v0\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
HEADING_RE = re.compile(r"^## (v[0-9]+\.[0-9]+\.[0-9]+)(?:\s|$)")


class ReleaseError(Exception):
    pass


def run(*args, check=True):
    result = subprocess.run(args, text=True, capture_output=True)
    if check and result.returncode:
        raise ReleaseError(f"{' '.join(args)} failed: {result.stderr.strip()}")
    return result


def source_commit():
    branch = os.environ.get("GITHUB_REF") or f"refs/heads/{run('git', 'branch', '--show-current').stdout.strip()}"
    if branch != "refs/heads/main":
        raise ReleaseError("release must run from main")
    commit = run("git", "rev-parse", "HEAD").stdout.strip()
    expected = os.environ.get("GITHUB_SHA")
    if expected and expected != commit:
        raise ReleaseError("checkout does not match GITHUB_SHA")
    if run("git", "status", "--porcelain").stdout.strip():
        raise ReleaseError("checkout has uncommitted changes")
    return commit


def notes_for(version):
    path = Path("CHANGELOG.md")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ReleaseError(f"CHANGELOG.md cannot be read: {exc}") from exc
    starts = [i for i, line in enumerate(lines) if (match := HEADING_RE.match(line)) and match.group(1) == version]
    if len(starts) != 1:
        raise ReleaseError(f"CHANGELOG.md must have exactly one {version} section")
    start = starts[0]
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    section = lines[start:end]
    if not any(line.strip() and not line.lstrip().startswith("#") for line in section[1:]):
        raise ReleaseError(f"CHANGELOG.md {version} section has no changes")
    return "\n".join(section).strip() + "\n"


def check_redis_requirement(version):
    try:
        mod = json.loads(run("go", "mod", "edit", "-json", "redis/go.mod").stdout)
    except (ValueError, KeyError) as exc:
        raise ReleaseError(f"redis/go.mod is invalid: {exc}") from exc
    required = [entry["Version"] for entry in mod.get("Require", []) if entry["Path"] == ROOT_MODULE]
    if required != [version]:
        raise ReleaseError(f"redis/go.mod must require {ROOT_MODULE} {version}")


def remote_tags(version):
    names = (version, f"redis/{version}")
    output = run("git", "ls-remote", "--tags", "origin").stdout
    refs = {}
    for line in output.splitlines():
        sha, ref = line.split("\t", 1)
        refs[ref] = sha
    tags = {}
    for name in names:
        ref = f"refs/tags/{name}"
        tags[name] = refs.get(f"{ref}^{{}}", refs.get(ref))
    return tags


def validate_version(version):
    if not VERSION_RE.fullmatch(version):
        raise ReleaseError("version must be a v0.x.y tag without a prerelease suffix")


def check_core(version):
    validate_version(version)
    commit = source_commit()
    notes = notes_for(version)
    root_tag = remote_tags(version)[version]
    if root_tag is not None and root_tag != commit:
        raise ReleaseError(f"{version} already points to another commit")
    return commit, notes, root_tag is None


def check_redis(version):
    validate_version(version)
    commit = source_commit()
    notes_for(version)
    check_redis_requirement(version)
    tags = remote_tags(version)
    root_commit = tags[version]
    if root_commit is None:
        raise ReleaseError(f"publish the core tag {version} before the Redis module")
    if run("git", "merge-base", "--is-ancestor", root_commit, commit, check=False).returncode:
        raise ReleaseError(f"core tag {version} is not an ancestor of this commit")
    redis_tag = f"redis/{version}"
    if tags[redis_tag] is not None and tags[redis_tag] != commit:
        raise ReleaseError(f"{redis_tag} already points to another commit")
    return commit, tags[redis_tag] is None


def existing_release(version):
    existing = run("gh", "release", "view", version, "--json", "tagName,isDraft,body", check=False)
    if existing.returncode == 0:
        release = json.loads(existing.stdout)
        if release.get("tagName") != version:
            raise ReleaseError(f"GitHub Release for {version} has an unexpected tag")
        if release.get("isDraft") is not False:
            raise ReleaseError(f"GitHub Release for {version} is a draft or has unknown status; publish or delete it manually")
        return release
    return None


def publish_tag(tag, commit):
    run(
        "git", "-c", "user.name=github-actions[bot]",
        "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com",
        "tag", "-a", tag, "-m", f"Release {tag}", commit,
    )
    run("git", "push", "--atomic", "origin", f"refs/tags/{tag}")


def write_release_notes(version, notes, create):
    with tempfile.TemporaryDirectory() as temp_dir:
        notes_file = Path(temp_dir) / "notes.md"
        notes_file.write_text(notes, encoding="utf-8")
        if create:
            run("gh", "release", "create", version, "--verify-tag", "--title", version, "--notes-file", str(notes_file))
        else:
            run("gh", "release", "edit", version, "--notes-file", str(notes_file))


def publish_core(version):
    commit, notes, missing = check_core(version)
    release = existing_release(version)
    if missing:
        publish_tag(version, commit)
    if release is None:
        write_release_notes(version, notes, create=True)


def publish_redis(version):
    commit, missing = check_redis(version)
    release = existing_release(version)
    if release is None:
        raise ReleaseError(f"publish the core GitHub Release {version} before the Redis module")
    if missing:
        publish_tag(f"redis/{version}", commit)
    marker = f"Redis module tag: `redis/{version}`"
    body = release.get("body") or ""
    if marker not in body:
        write_release_notes(version, body.rstrip() + f"\n\n{marker}\n", create=False)


def main():
    commands = {
        "check-core": check_core,
        "check-redis": check_redis,
        "publish-core": publish_core,
        "publish-redis": publish_redis,
    }
    if len(sys.argv) != 3 or sys.argv[1] not in commands:
        raise ReleaseError("usage: release.py check-core|check-redis|publish-core|publish-redis VERSION")
    command, version = sys.argv[1:]
    commands[command](version)
    print(f"{command} {version}: complete")


if __name__ == "__main__":
    try:
        main()
    except ReleaseError as exc:
        print(f"release: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
