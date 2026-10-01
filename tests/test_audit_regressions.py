"""Audit regressions: evidence counts, bounded capture and version-specific text reads."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from snapshot_runner import artifact, cli, collect, git, security, verifiers


def _git(repo: Path, *args: str) -> bytes:
    result = git.GitRunner(repo).run(args)
    assert result.returncode == 0 and not result.truncated, result.stderr
    return result.stdout


def _commit(repo: Path) -> None:
    _git(repo, "add", "-A")
    _git(
        repo,
        "-c",
        "user.name=Audit Test",
        "-c",
        "user.email=audit@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--quiet",
        "-m",
        "fixture",
    )


@pytest.fixture
def repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    _git(repo, "init", "--quiet", "--initial-branch=main")
    (repo / "sample.py").write_text("VALUE = 1\n", encoding="utf-8")
    _commit(repo)
    return repo


def _prepare(repo: Path, task: str = "diff-audit", base: str | None = None):
    path, name, runner_root = cli._validate_target_repository_path(os.fspath(repo))
    target = git._validate_target_repository_context(
        path, name, runner_root, artifact._state_home(path), "/usr/bin/git", task
    )
    return cli._prepare_snapshot(task, base, target, "/usr/bin/git")


def test_preview_and_summary_ignore_an_incomplete_status_record() -> None:
    data = {"status_short": " M sample.py\nM"}
    counts = artifact._summary_status_counts(data)
    assert counts == {
        "changed_files": 1,
        "tracked_modified": 1,
        "untracked": 0,
        "staged": 0,
        "unstaged": 1,
    }
    envelope = {
        "data": data,
        "task": "repo-status",
        "truncated": True,
        "evidence_gaps": [{"kind": "git_output_limit"}],
    }
    preview = artifact._build_preview_summary("a" * 64, envelope)
    assert "staged=0 unstaged=1 changed_files=1" in preview
    assert "truncated=yes" in preview


def test_hunk_payload_that_looks_like_a_header_is_counted() -> None:
    diff = (
        "diff --git a/sample.py b/sample.py\n"
        "--- a/sample.py\n+++ b/sample.py\n@@ -1 +1 @@\n--- old\n+++ new\n"
    )
    assert security.unified_diff_path_changes(diff, repository_root=None) == (
        ("sample.py", "sample.py"),
    )
    data = {"diff": diff}
    assert artifact._summary_diff_counts(data) == {
        "diff_files": 1,
        "additions": 1,
        "deletions": 1,
    }
    envelope = {"data": data, "task": "branch-review", "truncated": False, "evidence_gaps": []}
    assert "diff: additions=1 deletions=1" in artifact._build_preview_summary("a" * 64, envelope)


def test_repository_display_config_does_not_change_evidence(repository: Path) -> None:
    for key, value in (
        ("status.branch", "true"),
        ("status.showStash", "true"),
        ("diff.noprefix", "true"),
        ("diff.mnemonicPrefix", "true"),
        ("diff.srcPrefix", "old/"),
        ("diff.dstPrefix", "new/"),
        ("diff.outputIndicatorNew", ">"),
        ("diff.outputIndicatorOld", "<"),
    ):
        _git(repository, "config", key, value)
    status = _prepare(repository, "repo-status")
    assert status.envelope["data"]["status_short"] == ""
    assert artifact._summary_status_counts(status.envelope["data"])["changed_files"] == 0
    (repository / "sample.py").write_text("VALUE = 2\n", encoding="utf-8")
    audit = _prepare(repository)
    diff = audit.envelope["data"]["unstaged_diff"]
    assert diff.startswith("diff --git a/sample.py b/sample.py\n")
    assert "-VALUE = 1\n+VALUE = 2\n" in diff


@pytest.mark.parametrize("name", ["records.csv", ".gitattributes"])
@pytest.mark.parametrize("staged", [False, True])
def test_bounded_diff_text_deletion_uses_the_git_version(
    repository: Path,
    name: str,
    staged: bool,
) -> None:
    (repository / name).write_text("example\n", encoding="utf-8")
    _commit(repository)
    (repository / name).unlink()
    if staged:
        _git(repository, "add", "-A")
    snapshot = _prepare(repository)
    key = "staged_diff" if staged else "unstaged_diff"
    assert f"diff --git a/{name} b/{name}\n" in snapshot.envelope["data"][key]
    assert "+++ /dev/null\n" in snapshot.envelope["data"][key]
    loaded = artifact._load_snapshot(snapshot.snapshot_id, repository)
    assert loaded.snapshot_bytes == snapshot.snapshot_bytes


def test_branch_attributes_diff_does_not_read_dirty_worktree(repository: Path) -> None:
    (repository / ".gitattributes").write_text("*.py text\n", encoding="utf-8")
    _commit(repository)
    _git(repository, "branch", "base")
    (repository / ".gitattributes").write_text("*.py -text\n", encoding="utf-8")
    _commit(repository)
    (repository / ".gitattributes").unlink()
    snapshot = _prepare(repository, "branch-review", "base")
    assert "+*.py -text\n" in snapshot.envelope["data"]["diff"]


@pytest.mark.parametrize("body", [b"old\0body\n", b"x" * (64 * 1024 + 1), b"\xff\n"])
def test_deletion_does_not_bypass_bounded_git_content_validation(
    repository: Path,
    body: bytes,
) -> None:
    (repository / "records.csv").write_bytes(body)
    _commit(repository)
    (repository / "records.csv").unlink()
    with pytest.raises(security.RunnerError, match="bounded diff text Git version was refused"):
        _prepare(repository)


@pytest.mark.parametrize("recursive", [False, True])
def test_diff_collection_stops_before_reading_past_the_aggregate_quota(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    recursive: bool,
) -> None:
    paths = [f"f{i}.py" for i in range(20)]
    builder = collect.SnapshotBuilder("diff-audit", repository.name, repository)
    builder.content_bytes = collect.SNAPSHOT_CONTENT_BUDGET - 300
    observed: list[tuple[str, ...]] = []
    monkeypatch.setattr(collect, "MAX_GIT_OUTPUT_BYTES", 128)
    if not recursive:
        monkeypatch.setattr(collect, "_bounded_path_batches", lambda paths: [(p,) for p in paths])

    class FakeGit:
        def run(self, args: tuple[str, ...], *, maximum: int) -> git.GitResult:
            selected = tuple(arg for arg in args if arg.startswith(":(top,literal)"))
            observed.append(selected)
            raw = b"x" * (100 * len(selected))
            return git.GitResult(raw[:maximum], b"", 0, len(raw) > maximum, "diff")

    with pytest.raises(security.RunnerError, match="remaining snapshot content budget"):
        collect._workspace_unified_diff(FakeGit(), builder, "staged-diff", paths, cached=True)
    assert not any(":(top,literal)f19.py" in batch for batch in observed if len(batch) == 1)
    assert len(observed) <= 12


def test_generated_tree_stops_at_file_and_directory_quotas(repository: Path, monkeypatch) -> None:
    tree = repository / "generated"
    tree.mkdir()
    monkeypatch.setattr(collect, "MAX_GENERATED_TREE_FILES", 2)
    for i in range(4):
        (tree / f"{i}.json").write_text("{}", encoding="utf-8")
    with pytest.raises(security.RunnerError, match="file-count limit"):
        collect._enumerate_generated_tree(repository, "generated")
    for path in tree.iterdir():
        path.unlink()
    monkeypatch.setattr(collect, "MAX_GENERATED_TREE_DIRECTORIES", 2)
    for i in range(3):
        (tree / str(i)).mkdir()
    with pytest.raises(security.RunnerError, match="directory or depth limit"):
        collect._enumerate_generated_tree(repository, "generated")


def test_repo_status_accepts_yaml_metadata_without_reading_the_body(repository: Path) -> None:
    marker = "SYNTHETIC_YAML_BODY"
    (repository / "settings.yaml").write_text(f"value: {marker}\n", encoding="utf-8")
    snapshot = _prepare(repository, "repo-status")
    assert "settings.yaml" in snapshot.envelope["data"]["status_short"]
    assert marker.encode() not in snapshot.snapshot_bytes
    with pytest.raises(security.RunnerError, match=security.YAML_CONTENT_REFUSED):
        _prepare(repository)


@pytest.mark.parametrize("name", ["项目", "project with spaces", "中文 项目"])
def test_non_ascii_and_space_repository_names_support_collection_and_read(
    repository: Path,
    name: str,
    capsys,
) -> None:
    renamed = repository.with_name(name)
    repository.rename(renamed)
    (renamed / "sample.py").write_text("VALUE = 2\n", encoding="utf-8")
    snapshot = _prepare(renamed)
    display_name = security.repository_display_name(name)
    assert security.is_safe_repository_name(display_name)
    assert snapshot.envelope["repository"] == display_name
    assert (
        cli.main(
            [
                "read",
                snapshot.snapshot_id,
                "--repo",
                os.fspath(renamed),
                "--field",
                "unstaged_diff",
            ],
            neutral=True,
        )
        == 0
    )
    assert "VALUE = 2" in capsys.readouterr().out


@pytest.mark.parametrize("suffix", [".rs", ".go", ".c", ".cpp", ".java", ".cs", ".swift"])
def test_common_source_languages_are_text_under_the_new_era_only(
    repository: Path,
    suffix: str,
) -> None:
    name = "module" + suffix
    (repository / name).write_text("old\n", encoding="utf-8")
    _commit(repository)
    (repository / name).write_text("new\n", encoding="utf-8")
    snapshot = _prepare(repository)
    assert snapshot.verifier.producer_security_epoch == 5
    assert f"diff --git a/{name} b/{name}\n" in snapshot.envelope["data"]["unstaged_diff"]
    assert any(entry["path"] == name for entry in snapshot.envelope["data"]["file_context"])
    with (
        security.era_rules(verifiers.verifier_for(2, 4).rules),
        pytest.raises(security.SecurityError, match="not an approved text path"),
    ):
        security.classify_scan_mode(name)


def test_unknown_extensions_cannot_reuse_a_bounded_diff_proof() -> None:
    text = "diff --git a/unknown.dat b/unknown.dat\n--- a/unknown.dat\n+++ b/unknown.dat\n@@ -1 +1 @@\n-old\n+new\n"
    with (
        security.verified_bounded_diff_paths(frozenset({"unknown.dat"})),
        pytest.raises(security.SecurityError),
    ):
        security.sanitize_text(text, scan_mode=security.ScanMode.UNIFIED_DIFF)


def test_staged_and_unstaged_diffs_share_one_quota(repository: Path, monkeypatch) -> None:
    (repository / "sample.py").write_text("STAGED = 2\n" * 20, encoding="utf-8")
    _git(repository, "add", "sample.py")
    (repository / "sample.py").write_text("UNSTAGED = 3\n" * 20, encoding="utf-8")
    staged = _git(repository, "diff", "--cached", "--no-ext-diff", "--no-textconv", "--")
    unstaged = _git(repository, "diff", "--no-ext-diff", "--no-textconv", "--")
    each_size = max(len(json_bytes(staged)), len(json_bytes(unstaged)))
    monkeypatch.setattr(collect, "SNAPSHOT_CONTENT_BUDGET", each_size + 50)
    with pytest.raises(security.RunnerError, match="remaining snapshot content budget"):
        _prepare(repository)


def json_bytes(raw: bytes) -> bytes:
    return collect._json_bytes(raw.decode("utf-8"))


def test_generated_tree_depth_is_bounded(repository: Path, monkeypatch) -> None:
    (repository / "generated/a/b/c").mkdir(parents=True)
    monkeypatch.setattr(collect, "MAX_GENERATED_TREE_DEPTH", 2)
    with pytest.raises(security.RunnerError, match="directory or depth limit"):
        collect._enumerate_generated_tree(repository, "generated")
