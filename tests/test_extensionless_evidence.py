from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from snapshot_runner import artifact, collect, git
from snapshot_runner import cli as runner

GIT = "/usr/bin/git"


def _run_git(repo: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        [GIT, "-C", os.fspath(repo), *arguments],
        cwd="/",
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    return result


def _git_text(repo: Path, *arguments: str) -> str:
    return _run_git(repo, *arguments).stdout.decode("utf-8", errors="strict").strip()


def _commit(repo: Path, message: str, *paths: str) -> str:
    _run_git(repo, "add", "--", *paths)
    _run_git(
        repo,
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "user.name=Runner Test",
        "-c",
        "user.email=runner-test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--quiet",
        "-m",
        message,
    )
    return _git_text(repo, "rev-parse", "HEAD")


def _repository(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    _run_git(repo, "init", "--quiet", "--initial-branch=main")
    (repo / "baseline.py").write_text("BASELINE = True\n", encoding="utf-8")
    _commit(repo, "baseline", "baseline.py")
    return repo, state


def _prepare(
    repo: Path,
    task: str = "diff-audit",
    task_argument: str | None = None,
) -> artifact.SnapshotArtifact:
    target_path, target_name, runner_path = runner._validate_target_repository_path(os.fspath(repo))
    target = git._validate_target_repository_context(
        target_path,
        target_name,
        runner_path,
        artifact._state_home(target_path),
        GIT,
        task,
    )
    return runner._prepare_snapshot(task, task_argument, target, GIT)


def _payload(result: artifact.SnapshotArtifact) -> dict[str, object]:
    return json.loads(result.snapshot_bytes)


def _git_manifest(repo: Path) -> tuple[tuple[str, str, int, str], ...]:
    git_dir = Path(_git_text(repo, "rev-parse", "--absolute-git-dir"))
    entries: list[tuple[str, str, int, str]] = []
    for path in sorted(git_dir.rglob("*")):
        metadata = path.lstat()
        relative = path.relative_to(git_dir).as_posix()
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISDIR(metadata.st_mode):
            entries.append((relative, "directory", mode, ""))
        elif stat.S_ISREG(metadata.st_mode):
            entries.append(
                (relative, "regular", mode, hashlib.sha256(path.read_bytes()).hexdigest())
            )
        elif stat.S_ISLNK(metadata.st_mode):
            target = os.readlink(path).encode("utf-8", errors="surrogateescape")
            entries.append((relative, "symlink", mode, hashlib.sha256(target).hexdigest()))
    return tuple(entries)


def _readonly_state(repo: Path) -> tuple[bytes, tuple[tuple[str, str, int, str], ...]]:
    porcelain = _run_git(repo, "status", "--porcelain=v1", "--untracked-files=all").stdout
    return porcelain, _git_manifest(repo)


def _contexts(payload: dict[str, object]) -> list[dict[str, object]]:
    data = payload["data"]
    assert isinstance(data, dict)
    contexts = data["file_context"]
    assert isinstance(contexts, list)
    return contexts


def test_untracked_extensionless_text_shebang_modes_and_exact_limit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo, _state = _repository(monkeypatch, tmp_path)
    files = {
        "python-entry": "#!/usr/bin/env python3\nprint('python')\n",
        "shell-entry": "#!/usr/bin/env sh\nprintf 'shell\\n'\n",
        "NOTES": "plain UTF-8 说明\n",
        "context-entry": "#!/usr/bin/env python3\nprint('context')\n",
    }
    for name, content in files.items():
        (repo / name).write_text(content, encoding="utf-8")
    for name in ("python-entry", "shell-entry", "context-entry"):
        (repo / name).chmod(0o755)
    (repo / "EXACT").write_bytes(b"x\n" * (collect.MAX_EXTENSIONLESS_TEXT_BYTES // 2))
    (repo / "unknown.foo").write_text("must stay unsupported\n", encoding="utf-8")

    payload = _payload(_prepare(repo))
    contexts = {(item["path"], item["source"]): item for item in _contexts(payload)}

    for name in files:
        context = contexts[(name, "untracked")]
        if name == "NOTES":
            assert context["content"] == files[name]
        else:
            assert context["content"].endswith(files[name].split("\n", 1)[1])
        assert context["executable"] is (name != "NOTES")
    assert len(contexts[("EXACT", "untracked")]["content"].encode("utf-8")) == 64 * 1024
    assert contexts[("EXACT", "untracked")]["executable"] is False
    assert all(item["path"] != "unknown.foo" for item in _contexts(payload))
    assert any(
        gap["kind"] == "file_refused" and gap["subject"] == "unknown.foo"
        for gap in payload["evidence_gaps"]
    )


def test_extensionless_binary_encoding_limit_symlink_fifo_and_sensitive_are_refused(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo, _state = _repository(monkeypatch, tmp_path)
    outside = tmp_path / "outside"
    outside.write_text("OUTSIDE_BODY_MUST_NOT_BE_READ\n", encoding="utf-8")
    (repo / "nul-file").write_bytes(b"text\0binary\n")
    (repo / "bad-encoding").write_bytes(b"text-\xff\n")
    (repo / "too-large").write_bytes(b"x" * (collect.MAX_EXTENSIONLESS_TEXT_BYTES + 1))
    (repo / "outside-link").symlink_to(outside)
    (repo / "named-pipe").write_text("baseline pipe path\n", encoding="utf-8")
    _commit(repo, "add pipe path", "named-pipe")
    (repo / "named-pipe").unlink()
    os.mkfifo(repo / "named-pipe", 0o600)
    (repo / "credentials").write_text("SENSITIVE_BODY_MUST_NOT_BE_READ\n", encoding="utf-8")

    result = _prepare(repo)
    payload = _payload(result)
    gaps = {(gap["subject"], gap["kind"]) for gap in payload["evidence_gaps"]}

    assert _contexts(payload) == []
    assert ("too-large", "file_limit") in gaps
    for name in ("nul-file", "bad-encoding", "outside-link", "named-pipe", "credentials"):
        assert (name, "file_refused") in gaps
    assert payload["truncated"] is True
    assert b"OUTSIDE_BODY_MUST_NOT_BE_READ" not in result.snapshot_bytes
    assert b"SENSITIVE_BODY_MUST_NOT_BE_READ" not in result.snapshot_bytes


def test_staged_and_worktree_extensionless_versions_are_distinct_and_read_only(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo, _state = _repository(monkeypatch, tmp_path)
    launcher = repo / "launcher"
    launcher.write_text("baseline version\n", encoding="utf-8")
    _commit(repo, "add launcher", "launcher")
    launcher.write_text("index version\n", encoding="utf-8")
    launcher.chmod(0o755)
    _run_git(repo, "add", "--", "launcher")
    launcher.write_text("worktree version\n", encoding="utf-8")
    launcher.chmod(0o644)
    before = _readonly_state(repo)

    first = _prepare(repo)
    second = _prepare(repo)
    payload = _payload(first)
    contexts = [item for item in _contexts(payload) if item["path"] == "launcher"]

    assert contexts == [
        {
            "path": "launcher",
            "content": "index version\n",
            "source": "index",
            "executable": True,
        },
        {
            "path": "launcher",
            "content": "worktree version\n",
            "source": "worktree",
            "executable": False,
        },
    ]
    data = payload["data"]
    assert "index version" in data["staged_diff"]
    assert "worktree version" not in data["staged_diff"]
    assert "worktree version" in data["unstaged_diff"]
    assert first.snapshot_bytes == second.snapshot_bytes
    assert first.snapshot_id == second.snapshot_id
    assert hashlib.sha256(first.snapshot_bytes).hexdigest() == first.snapshot_id
    assert len(first.snapshot_bytes) <= collect.MAX_SNAPSHOT_BYTES
    assert stat.S_IMODE(first.directory.lstat().st_mode) == 0o700
    for name in artifact.SNAPSHOT_FILE_NAMES:
        assert stat.S_IMODE((first.directory / name).lstat().st_mode) == 0o600
    assert _readonly_state(repo) == before


def test_staged_text_survives_separate_refused_worktree_version(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo, _state = _repository(monkeypatch, tmp_path)
    launcher = repo / "launcher"
    launcher.write_text("baseline\n", encoding="utf-8")
    _commit(repo, "add launcher", "launcher")
    launcher.write_text("safe staged version\n", encoding="utf-8")
    _run_git(repo, "add", "--", "launcher")
    launcher.write_bytes(b"unsafe worktree\0version\n")
    before = _readonly_state(repo)

    payload = _payload(_prepare(repo))
    contexts = [item for item in _contexts(payload) if item["path"] == "launcher"]
    data = payload["data"]

    assert contexts == [
        {
            "path": "launcher",
            "content": "safe staged version\n",
            "source": "index",
            "executable": False,
        }
    ]
    assert "safe staged version" in data["staged_diff"]
    assert "launcher" not in data["unstaged_diff"]
    assert any(
        gap["kind"] == "file_refused"
        and gap["subject"] == "launcher"
        and "worktree" in gap["reason"]
        for gap in payload["evidence_gaps"]
    )
    assert _readonly_state(repo) == before


def test_staged_rename_and_deletion_keep_versions_separate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo, _state = _repository(monkeypatch, tmp_path)
    (repo / "oldtool").write_text("renamed body\n", encoding="utf-8")
    (repo / "removedtool").write_text("deleted body\n", encoding="utf-8")
    _commit(repo, "extensionless baseline", "oldtool", "removedtool")
    _run_git(repo, "mv", "oldtool", "newtool")
    (repo / "removedtool").unlink()
    _run_git(repo, "add", "-u", "--", "removedtool")

    payload = _payload(_prepare(repo))
    paths = [(item["path"], item["source"]) for item in _contexts(payload)]
    staged = payload["data"]["staged_diff"]

    assert paths == [("newtool", "index")]
    assert "diff --git a/oldtool b/oldtool" in staged
    assert "diff --git a/newtool b/newtool" in staged
    assert "diff --git a/removedtool b/removedtool" in staged
    assert payload["evidence_gaps"] == []


def test_branch_review_extensionless_rename_uses_sealed_target_blob(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo, _state = _repository(monkeypatch, tmp_path)
    (repo / "oldtool").write_text("sealed target body\n", encoding="utf-8")
    base = _commit(repo, "add old tool", "oldtool")
    _run_git(repo, "branch", "comparison-base", base)
    _run_git(repo, "mv", "oldtool", "newtool")
    (repo / "newtool").chmod(0o755)
    _commit(repo, "rename tool", "newtool")
    (repo / "newtool").write_text("dirty worktree body\n", encoding="utf-8")
    before = _readonly_state(repo)

    payload = _payload(_prepare(repo, "branch-review", "comparison-base"))
    contexts = _contexts(payload)

    assert contexts == [
        {
            "path": "newtool",
            "content": "sealed target body\n",
            "source": "target",
            "executable": True,
        }
    ]
    assert "rename from oldtool" in payload["data"]["diff"]
    assert "rename to newtool" in payload["data"]["diff"]
    assert "dirty worktree body" not in result_text(payload)
    assert _readonly_state(repo) == before


def result_text(payload: dict[str, object]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)
