from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

from scripts import release as r

ROOT = Path(__file__).resolve().parents[1]
TAG = "v1.2.3"
SHA = "a" * 40
RELEASE = {
    "tag": TAG,
    "tag_object": "c" * 40,
    "version": "1.2.3",
    "commit": SHA,
    "notes": "- Release notes",
    "control_commit": "b" * 40,
    "control_ref": "refs/heads/master",
    "build_run_id": "123",
}


@pytest.fixture
def repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.chdir(repo)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    subprocess.run(["git", "init", "-q", "-b", "main"], check=True)
    (repo / "codex_snapshot_runner").mkdir()
    (repo / "pyproject.toml").write_text(f'[project]\nname = "{r.PACKAGE}"\nversion = "1.2.3"\n')
    (repo / "codex_snapshot_runner/__init__.py").write_text('__version__ = "1.2.3"\n')
    (repo / "CHANGELOG.md").write_text("# Changelog\n\n## Unreleased\n\n## 1.2.3\n\n- Notes\n")
    subprocess.run(
        ["git", "add", "pyproject.toml", "codex_snapshot_runner", "CHANGELOG.md"], check=True
    )
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "fixture",
        ],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "tag",
            "-a",
            TAG,
            "-m",
            "Fixture release",
        ],
        check=True,
    )
    return repo


@pytest.mark.parametrize("tag", ["v1.2.4", "v01.2.3", "archive-v1.2.3"])
def test_tag_version_mismatch_blocks_before_quality_or_build(repository: Path, tag: str) -> None:
    if tag == "v1.2.4":
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "tag",
                "-a",
                tag,
                "-m",
                "Mismatched version",
            ],
            check=True,
        )
    with pytest.raises(r.ReleaseError):
        r.identity(tag)


def test_exact_commit_is_required(repository: Path) -> None:
    with pytest.raises(r.ReleaseError, match="tag/expected commit mismatch"):
        r.identity(TAG, SHA)


def test_lightweight_tag_is_not_a_formal_release(repository: Path) -> None:
    subprocess.run(["git", "tag", "v1.2.4"], check=True)
    with pytest.raises(r.ReleaseError, match="annotated tag"):
        r.identity("v1.2.4")


@pytest.mark.parametrize("kind,object_id", [("commit", SHA), ("tag", "d" * 40)])
def test_public_tag_object_conflict_fails_even_at_same_commit(monkeypatch, kind, object_id) -> None:
    monkeypatch.setattr(r, "api", lambda *_, **__: {"object": {"type": kind, "sha": object_id}})
    with pytest.raises(r.ReleaseError, match="tag object identity conflict"):
        r.github_tag(TAG, RELEASE["tag_object"])


def test_gitea_tag_object_conflict_blocks_record_creation(monkeypatch) -> None:
    def api(url, **kwargs):
        assert kwargs.get("method", "GET") == "GET"
        assert url.endswith("/tags/" + TAG)
        return {"commit": {"sha": SHA}}

    monkeypatch.setattr(r, "api", api)
    monkeypatch.setattr(r, "command", lambda *_: "d" * 40 + "\trefs/tags/" + TAG)
    with pytest.raises(r.ReleaseError, match="tag object identity conflict"):
        r.release_record(
            RELEASE, {}, "gitea", "https://example.invalid/api/v1", "org/repo", apply=True
        )


def test_real_quality_failure_stops_before_network_or_build(
    repository: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tools = tmp_path / "bin"
    tools.mkdir()
    (tools / "just").write_text("#!/bin/sh\nexit 19\n")
    (tools / "just").chmod(0o755)
    (tools / "uv").write_text("#!/bin/sh\ntouch unexpected-build\nexit 0\n")
    (tools / "uv").chmod(0o755)
    monkeypatch.setenv("PATH", f"{tools}:{os.defpath}")
    with pytest.raises(r.ReleaseError, match="just failed \\(exit 19\\)"):
        r.build(r.identity(TAG))
    assert not (repository / "unexpected-build").exists()
    assert not (repository / "dist").exists()


def test_published_package_skips_build(repository: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    identity = r.identity(TAG)
    monkeypatch.setattr(r, "github_tag", lambda *_: identity["commit"])
    original = r.command
    actions = []

    def command(*args):
        if args[0] == "git":
            return original(*args)
        actions.append(args)
        return ""

    monkeypatch.setattr(r, "command", command)
    monkeypatch.setattr(r, "pypi_files", lambda _: {"existing": "hash"})
    assert r.build(identity) is False
    assert actions == [("just", "check")]


def artifacts(path: Path) -> dict[str, str]:
    path.mkdir()
    metadata = f"Name: {r.PACKAGE}\nVersion: 1.2.3\n".encode()
    wheel = path / f"{r.ARCHIVE}-1.2.3-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(f"{r.ARCHIVE}-1.2.3.dist-info/METADATA", metadata)
    source = path / f"{r.ARCHIVE}-1.2.3.tar.gz"
    with tarfile.open(source, "w:gz") as archive:
        member = tarfile.TarInfo(f"{r.ARCHIVE}-1.2.3/PKG-INFO")
        member.size = len(metadata)
        archive.addfile(member, io.BytesIO(metadata))
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in path.iterdir()}


def test_partial_upload_reuses_only_missing_original_file(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "dist"
    hashes = artifacts(source)
    wheel = next(name for name in hashes if name.endswith(".whl"))
    monkeypatch.setattr(r, "pypi_files", lambda *_, **__: {wheel: hashes[wheel]})
    output = tmp_path / "pending"
    pending = r.pending_dist(RELEASE, source, output)
    assert pending == [next(name for name in hashes if name.endswith(".tar.gz"))]
    assert {p.name for p in output.iterdir()} == set(pending)
    assert (output / pending[0]).read_bytes() == (source / pending[0]).read_bytes()
    monkeypatch.setattr(r, "pypi_files", lambda *_, **__: hashes)
    assert r.pending_dist(RELEASE, source, tmp_path / "retry") == []


def test_existing_file_conflict_stops_before_upload_selection(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "dist"
    hashes = artifacts(source)
    monkeypatch.setattr(r, "pypi_files", lambda *_, **__: dict.fromkeys(hashes, "0" * 64))
    with pytest.raises(r.ReleaseError, match="differs from original build"):
        r.pending_dist(RELEASE, source, tmp_path / "pending")
    assert not (tmp_path / "pending").exists()


def test_record_resume_after_post_succeeded_but_readback_failed(monkeypatch) -> None:
    hashes = {"wheel": "hash"}
    record = None
    posts = 0
    fail_readback = True
    monkeypatch.setattr(r, "github_tag", lambda *_: SHA)

    def api(url, **kwargs):
        nonlocal record, posts, fail_readback
        if kwargs.get("method") == "POST":
            posts += 1
            record = {**kwargs["data"], "id": 17, "html_url": "https://example.invalid/release"}
            return record
        if record and fail_readback:
            fail_readback = False
            raise r.ReleaseError("readback unavailable")
        return record

    monkeypatch.setattr(r, "api", api)
    with pytest.raises(r.ReleaseError, match="readback unavailable"):
        r.release_record(
            RELEASE,
            hashes,
            "github",
            r.GITHUB_API,
            r.PUBLIC_REPOSITORY,
            apply=True,
            token="fixture",
        )
    for _ in range(2):
        result = r.release_record(
            RELEASE,
            hashes,
            "github",
            r.GITHUB_API,
            r.PUBLIC_REPOSITORY,
            apply=True,
            token="fixture",
        )
        assert result["status"] == "PASS" and not result["created"]
    assert posts == 1


@pytest.mark.parametrize(
    "conflict", ["tag", "files", "tag_object", "draft", "commit", "target", "marker"]
)
def test_release_conflict_is_fail_closed_without_mutation(monkeypatch, conflict) -> None:
    hashes = {"wheel": "hash"}
    marker = r.record_identity(RELEASE, hashes)
    record = {
        "id": 1,
        "tag_name": TAG,
        "draft": False,
        "prerelease": False,
        "html_url": "https://example.invalid/release",
        "sha1": SHA,
    }
    if conflict == "files":
        marker["files"] = {"wheel": "different"}
    if conflict == "tag_object":
        marker["tag_object"] = "d" * 40
    if conflict == "draft":
        record["draft"] = True
    if conflict == "commit":
        record["sha1"] = "b" * 40
    if conflict == "target":
        record["target_commitish"] = "b" * 40
    record["body"] = r.MARKER + json.dumps(marker) + " -->"
    if conflict == "marker":
        record["body"] = "unverified release"
    monkeypatch.setattr(r, "github_tag", lambda *_: "b" * 40 if conflict == "tag" else SHA)

    def api(url, **kwargs):
        assert kwargs.get("method", "GET") == "GET"
        return record

    monkeypatch.setattr(r, "api", api)
    with pytest.raises(r.ReleaseError):
        r.release_record(RELEASE, hashes, "github", r.GITHUB_API, r.PUBLIC_REPOSITORY, apply=True)


def test_local_caller_cannot_backfill_tag_with_pat(monkeypatch) -> None:
    monkeypatch.delenv("GITEA_ACTIONS", raising=False)
    with pytest.raises(r.ReleaseError, match="Gitea Actions job token"):
        r.sync_gitea(TAG, "https://example.invalid/api/v1", "org/repo")


@pytest.mark.parametrize("conflicting_record", [False, True])
def test_gitea_backfill_preserves_tag_object_and_does_not_build(
    monkeypatch, conflicting_record
) -> None:
    monkeypatch.setenv("GITEA_ACTIONS", "true")
    monkeypatch.setenv("RELEASE_TOKEN", "private-fixture")
    monkeypatch.setattr(r, "github_tag", lambda *_: SHA)
    monkeypatch.setattr(r, "receipt_identity", lambda *_: RELEASE)
    monkeypatch.setattr(r, "pypi_files", lambda _: {"wheel": "hash"})

    def api(url, **kwargs):
        if r.GITHUB_API in url:
            return {"body": r.MARKER + json.dumps(r.record_identity(RELEASE, {})) + " -->"}
        if url.endswith("/org/repo"):
            return {}
        if "/releases/tags/" in url and conflicting_record:
            return {"tag_name": TAG, "draft": True, "prerelease": False}
        return None

    monkeypatch.setattr(r, "api", api)
    actions = []

    def command(*args):
        actions.append(args)
        if args[1] == "rev-parse":
            return "c" * 40
        if args[1] == "ls-remote":
            return "c" * 40 + "\trefs/tags/" + TAG
        return ""

    def record(*args, **kwargs):
        if args[2] == "github":
            assert "token" not in kwargs
        else:
            assert kwargs["token"] == "private-fixture"
        return {"status": "PASS"}

    monkeypatch.setattr(r, "command", command)
    monkeypatch.setattr(r, "release_record", record)
    if conflicting_record:
        with pytest.raises(r.ReleaseError, match="Release identity conflict"):
            r.sync_gitea(TAG, "https://example.invalid/api/v1", "org/repo")
        assert not any(action[1] == "push" for action in actions)
        return
    result = r.sync_gitea(TAG, "https://example.invalid/api/v1", "org/repo")
    assert result["tag_object"] == "c" * 40
    assert all(action[0] == "git" for action in actions)
    assert [a for a in actions if a[1] == "push"] == [
        ("git", "push", "--no-follow-tags", "origin", f"{RELEASE['tag_object']}:refs/tags/{TAG}")
    ]


@pytest.mark.parametrize("local_ref", ["annotated", "peeled", "missing"])
def test_remote_raw_tag_survives_detached_checkout_and_local_ref_changes(
    repository: Path, tmp_path: Path, monkeypatch, local_ref: str
) -> None:
    approved = r.identity(TAG)
    client = tmp_path / "checkout"
    subprocess.run(["git", "clone", "-q", str(repository), str(client)], check=True)
    monkeypatch.chdir(client)
    r.command("git", "checkout", "--detach", approved["commit"])
    if local_ref == "peeled":
        r.command("git", "update-ref", f"refs/tags/{TAG}", approved["commit"])
    elif local_ref == "missing":
        r.command("git", "update-ref", "-d", f"refs/tags/{TAG}")
    before = r.command("git", "for-each-ref", "--format=%(objectname)", f"refs/tags/{TAG}")
    original = r.command

    def command(*args):
        if args[:2] == ("git", "fetch"):
            assert args[2:] == (
                "--no-tags",
                f"https://github.com/{r.PUBLIC_REPOSITORY}.git",
                approved["tag_object"],
            )
            return original("git", "fetch", "--no-tags", str(repository), approved["tag_object"])
        return original(*args)

    monkeypatch.setattr(r, "command", command)
    monkeypatch.setattr(
        r, "github_identity", lambda *_: (approved["tag_object"], approved["commit"])
    )
    actual = r.public_identity(TAG, approved["commit"], approved["tag_object"])
    assert actual == approved
    assert (
        r.identity(TAG, approved["commit"], tag_object=approved["tag_object"], checkout=True)
        == approved
    )
    assert before == r.command("git", "for-each-ref", "--format=%(objectname)", f"refs/tags/{TAG}")
    assert r.command("git", "rev-parse", "HEAD") == approved["commit"]


def test_remote_target_conflict_blocks_before_fetch(monkeypatch) -> None:
    monkeypatch.setattr(r, "github_identity", lambda *_: (RELEASE["tag_object"], "d" * 40))
    monkeypatch.setattr(r, "command", lambda *_: pytest.fail("must not fetch conflicting identity"))
    with pytest.raises(r.ReleaseError, match="expected commit mismatch"):
        r.public_identity(TAG, SHA, RELEASE["tag_object"])


def test_master_control_cannot_be_built_as_tag_source(repository: Path, monkeypatch) -> None:
    release = r.identity(TAG)
    (repository / "control.txt").write_text("new control revision\n")
    r.command("git", "add", "control.txt")
    r.command(
        "git",
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-qm",
        "control only",
    )
    with pytest.raises(r.ReleaseError, match="exact release commit"):
        r.build(release)


def test_previous_artifact_blocks_a_second_build(repository: Path, monkeypatch) -> None:
    release = r.identity(TAG)
    original = r.command
    calls = []

    def command(*args):
        if args[0] == "git":
            return original(*args)
        calls.append(args)
        return ""

    monkeypatch.setattr(r, "command", command)
    monkeypatch.setattr(r, "github_tag", lambda *_: release["commit"])
    monkeypatch.setattr(r, "pypi_files", lambda *_: None)
    monkeypatch.setattr(r, "api", lambda *_, **__: {"total_count": 1})
    with pytest.raises(r.ReleaseError, match="resume its publish job"):
        r.build(release)
    assert calls == [("just", "check")]


@pytest.mark.parametrize("conflict", [None, "control", "source", "workflow", "ref", "unknown"])
def test_receipt_separates_control_and_source_provenance(monkeypatch, conflict) -> None:
    hashes = dict.fromkeys(r.filenames("1.2.3"), "e" * 64)
    receipt = r.record_identity(RELEASE, hashes)
    run = {
        "head_sha": RELEASE["control_commit"],
        "head_branch": "master",
        "path": ".github/workflows/publish-pypi.yml",
        "head_repository": {"full_name": r.PUBLIC_REPOSITORY},
        "event": "workflow_dispatch",
    }

    def public(tag, source, obj):
        assert (tag, obj) == (TAG, RELEASE["tag_object"])
        if source != SHA:
            raise r.ReleaseError("source conflict")
        return dict(RELEASE)

    monkeypatch.setattr(r, "public_identity", public)
    monkeypatch.setattr(r, "api", lambda *_, **__: run)
    if conflict == "control":
        receipt["release_control_commit"] = SHA
    if conflict == "source":
        receipt["package_source_commit"] = RELEASE["control_commit"]
    if conflict == "workflow":
        run["path"] = ".github/workflows/ci.yml"
    if conflict == "ref":
        run["head_branch"] = "other"
    if conflict == "unknown":
        receipt["unexpected"] = True
    if conflict:
        with pytest.raises(r.ReleaseError):
            r.receipt_identity(receipt)
    else:
        actual = r.receipt_identity(receipt)
        assert actual["control_commit"] != actual["commit"] == SHA
        assert actual["files"] == hashes


def test_receipt_file_mutation_blocks_before_upload(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "dist"
    hashes = artifacts(source)
    release = {**RELEASE, "files": dict.fromkeys(hashes, "0" * 64)}
    monkeypatch.setattr(r, "pypi_files", lambda *_: pytest.fail("must reject artifacts first"))
    with pytest.raises(r.ReleaseError, match="source-bound build receipt"):
        r.pending_dist(release, source, tmp_path / "pending")


@pytest.mark.parametrize("conflict", [None, "source-as-control", "ref", "file"])
def test_pypi_attestation_binds_control_not_package_source(monkeypatch, conflict) -> None:
    name = f"{r.ARCHIVE}-1.2.3-py3-none-any.whl"
    digest = "e" * 64
    statement = {"subject": [{"name": name, "digest": {"sha256": digest}}]}
    if conflict == "file":
        statement["subject"][0]["digest"]["sha256"] = "f" * 64
    provenance = {
        "attestation_bundles": [
            {
                "publisher": {
                    "kind": "GitHub",
                    "repository": r.PUBLIC_REPOSITORY,
                    "workflow": "publish-pypi.yml",
                    "environment": "pypi",
                },
                "attestations": [
                    {
                        "envelope": {
                            "statement": base64.b64encode(json.dumps(statement).encode()).decode()
                        },
                        "verification_material": {
                            "certificate": base64.b64encode(b"synthetic certificate").decode()
                        },
                    }
                ],
            }
        ]
    }
    commit = SHA if conflict == "source-as-control" else RELEASE["control_commit"]
    ref = f"refs/tags/{TAG}" if conflict == "ref" else RELEASE["control_ref"]
    certificate_text = f"1.3.6.1.4.1.57264.1.3:\n    {commit}\nURI:https://github.com/{r.PUBLIC_REPOSITORY}/.github/workflows/publish-pypi.yml@{ref}\n"
    monkeypatch.setattr(r, "api", lambda *_: provenance)
    monkeypatch.setattr(
        r.subprocess,
        "run",
        lambda *_, **__: subprocess.CompletedProcess([], 0, certificate_text.encode(), b""),
    )
    item = {"filename": name, "digests": {"sha256": digest}}
    if conflict:
        with pytest.raises(r.ReleaseError, match="provenance conflict"):
            r.check_provenance(item, RELEASE)
    else:
        r.check_provenance(item, RELEASE)
