from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from codex_snapshot_runner import cli as runner
from codex_snapshot_runner import collect

GIT = "/usr/bin/git"


def _git(repo: Path, *arguments: str) -> bytes:
    environment = os.environ.copy()
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    result = subprocess.run(
        [GIT, "-C", os.fspath(repo), *arguments],
        cwd="/",
        env=environment,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    return result.stdout


def _write(repo: Path, relative: str, content: bytes) -> None:
    path = repo / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def _commit(repo: Path, message: str) -> None:
    _git(
        repo,
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "user.name=Codex Test",
        "-c",
        "user.email=codex-test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--quiet",
        "-m",
        message,
    )


def _initialize(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    _git(repo, "init", "--quiet", "--initial-branch=main")
    (repo / "plain.txt").write_text("baseline\n", encoding="utf-8")
    _git(repo, "add", "--", "plain.txt")
    _commit(repo, "baseline")
    return repo, state


def _jpeg(marker: bytes, *, byte_size: int = 128) -> bytes:
    prefix = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00"
    suffix = b"\xff\xd9"
    payload_size = max(0, byte_size - len(prefix) - len(marker) - len(suffix))
    return prefix + marker + b"\x00" * payload_size + suffix


def _png(marker: bytes) -> bytes:
    return b"\x89PNG\r\n\x1a\n" + marker + b"\x00png-payload"


def _webp(marker: bytes) -> bytes:
    payload = marker + b"\x00webp-payload"
    return b"RIFF" + len(payload).to_bytes(4, "little") + b"WEBP" + payload


def _summary(media_type: str, content: bytes) -> str:
    return (
        "binary image evidence\n"
        f"media_type: {media_type}\n"
        f"byte_size: {len(content)}\n"
        f"sha256: {hashlib.sha256(content).hexdigest()}\n"
    )


def _cli_snapshot(
    repo: Path,
    capsys: pytest.CaptureFixture[str],
    task: str = "diff-audit",
    argument: str | None = None,
) -> bytes:
    arguments = ["prepare", task, "--repo", os.fspath(repo)]
    if argument is not None:
        arguments.append(argument)
    assert runner.main(arguments) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    fields = dict(
        line.split(": ", 1)
        for line in captured.out.splitlines()
        if line.startswith(("snapshot_id: ", "snapshot: "))
    )
    raw = Path(fields["snapshot"]).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == fields["snapshot_id"]
    return raw


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: os.fsencode(item.relative_to(root))):
        info = path.lstat()
        digest.update(
            os.fsencode(path.relative_to(root))
            + b"\0"
            + str(stat.S_IFMT(info.st_mode)).encode()
            + b"\0"
        )
        if path.is_file():
            digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def _fingerprint(repo: Path) -> dict[str, str]:
    git_dir = repo / ".git"
    packed_refs = git_dir / "packed-refs"
    return {
        "head": _git(repo, "rev-parse", "HEAD").decode().strip(),
        "index": hashlib.sha256((git_dir / "index").read_bytes()).hexdigest(),
        "refs": _tree_digest(git_dir / "refs"),
        "packed_refs": (
            hashlib.sha256(packed_refs.read_bytes()).hexdigest()
            if packed_refs.exists()
            else "missing"
        ),
        "status": hashlib.sha256(
            _git(repo, "status", "--porcelain=v1", "-z", "--untracked-files=all")
        ).hexdigest(),
        "config": hashlib.sha256((git_dir / "config").read_bytes()).hexdigest(),
        "objects": _tree_digest(git_dir / "objects"),
    }


def _contexts(payload: dict[str, object]) -> dict[tuple[str, str | None], str]:
    data = payload["data"]
    assert isinstance(data, dict)
    contexts = data["file_context"]
    assert isinstance(contexts, list)
    return {
        (str(context["path"]), context.get("source")): str(context["content"])
        for context in contexts
    }


def test_diff_audit_records_exact_image_versions_without_reading_target_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, _state = _initialize(monkeypatch, tmp_path)
    baseline = {
        "staged.jpeg": _jpeg(b"old-staged"),
        "unstaged.jpg": _jpeg(b"old-unstaged"),
        "both.jpg": _jpeg(b"old-both"),
    }
    for relative, content in baseline.items():
        _write(repo, relative, content)
    _git(repo, "add", "--", *baseline)
    _commit(repo, "image baseline")

    staged = _jpeg(b"STAGED_IMAGE_MARKER", byte_size=300 * 1024)
    unstaged = _jpeg(b"UNSTAGED_IMAGE_MARKER")
    index_version = _jpeg(b"INDEX_IMAGE_MARKER")
    worktree_version = _jpeg(b"WORKTREE_IMAGE_MARKER")
    png = _png(b"PNG_IMAGE_MARKER")
    webp = _webp(b"WEBP_IMAGE_MARKER")
    untracked = _jpeg(b"UNTRACKED_IMAGE_MARKER")
    _write(repo, "staged.jpeg", staged)
    _git(repo, "add", "--", "staged.jpeg")
    _write(repo, "unstaged.jpg", unstaged)
    _write(repo, "both.jpg", index_version)
    _git(repo, "add", "--", "both.jpg")
    _write(repo, "both.jpg", worktree_version)
    _write(repo, "图 像/新增 图片.png", png)
    _git(repo, "add", "--", "图 像/新增 图片.png")
    _write(repo, "网络 图.webp", webp)
    _write(repo, "记录/现场 照片.jpg", untracked)

    before = _fingerprint(repo)
    first = _cli_snapshot(repo, capsys)
    second = _cli_snapshot(repo, capsys)
    after = _fingerprint(repo)
    assert first == second
    assert before == after

    payload = json.loads(first)
    assert payload["evidence_gaps"] == []
    assert payload["truncated"] is False
    contexts = _contexts(payload)
    assert contexts[("staged.jpeg", "index")] == _summary("image/jpeg", staged)
    assert contexts[("unstaged.jpg", "worktree")] == _summary("image/jpeg", unstaged)
    assert contexts[("both.jpg", "index")] == _summary("image/jpeg", index_version)
    assert contexts[("both.jpg", "worktree")] == _summary("image/jpeg", worktree_version)
    assert contexts[("图 像/新增 图片.png", "index")] == _summary("image/png", png)
    assert contexts[("网络 图.webp", "untracked")] == _summary("image/webp", webp)
    assert contexts[("记录/现场 照片.jpg", "untracked")] == _summary("image/jpeg", untracked)
    assert contexts[("both.jpg", "index")] != contexts[("both.jpg", "worktree")]
    data = payload["data"]
    assert isinstance(data, dict)
    assert all(
        relative not in str(data["staged_diff"]) + str(data["unstaged_diff"])
        for relative in (
            "staged.jpeg",
            "unstaged.jpg",
            "both.jpg",
            "图 像/新增 图片.png",
        )
    )
    for marker in (
        b"STAGED_IMAGE_MARKER",
        b"UNSTAGED_IMAGE_MARKER",
        b"INDEX_IMAGE_MARKER",
        b"WORKTREE_IMAGE_MARKER",
        b"PNG_IMAGE_MARKER",
        b"WEBP_IMAGE_MARKER",
        b"UNTRACKED_IMAGE_MARKER",
    ):
        assert marker not in first


def test_branch_review_uses_the_sealed_target_image_blob(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, _state = _initialize(monkeypatch, tmp_path)
    _git(repo, "branch", "base")
    committed = _webp(b"SEALED_TARGET_IMAGE")
    dirty = _webp(b"DIRTY_WORKTREE_IMAGE")
    relative = "封存 图像/目标.webp"
    _write(repo, relative, committed)
    _git(repo, "add", "--", relative)
    _commit(repo, "add image")
    _write(repo, relative, dirty)

    payload = json.loads(_cli_snapshot(repo, capsys, "branch-review", "base"))
    assert payload["evidence_gaps"] == []
    assert payload["truncated"] is False
    contexts = _contexts(payload)
    assert contexts[(relative, "target")] == _summary("image/webp", committed)
    assert hashlib.sha256(dirty).hexdigest() not in json.dumps(payload)
    data = payload["data"]
    assert isinstance(data, dict)
    assert relative not in str(data["diff"])


def test_invalid_and_unsupported_images_keep_explicit_gaps_and_text_regressions(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, _state = _initialize(monkeypatch, tmp_path)
    valid = _jpeg(b"VALID_IMAGE")
    _write(repo, "valid.jpg", valid)
    _write(repo, "mismatch.png", _jpeg(b"WRONG_DECLARATION"))
    _write(repo, "broken.jpg", b"\xff\xd8")
    _write(
        repo,
        "too-large.jpg",
        b"\xff\xd8\xff" + b"\x00" * collect.IMAGE_EVIDENCE_MAX_BYTES,
    )
    _write(repo, "image.gif", b"GIF89a\x00binary")
    _write(repo, "document.pdf", b"%PDF-1.7\x00binary")
    _write(repo, "asset.bin", b"\x00binary")
    _git(repo, "add", "--", "image.gif", "document.pdf", "asset.bin")
    (repo / "plain.txt").write_text("changed text\n", encoding="utf-8")
    (repo / "NOTICE").write_text("extensionless text\n", encoding="utf-8")
    (repo / "link.jpg").symlink_to("valid.jpg")

    payload = json.loads(_cli_snapshot(repo, capsys))
    contexts = _contexts(payload)
    assert contexts[("valid.jpg", "untracked")] == _summary("image/jpeg", valid)
    assert contexts[("plain.txt", None)] == "changed text\n"
    assert contexts[("NOTICE", "untracked")] == "extensionless text\n"
    assert not any(
        path in contexts
        for path in {
            ("mismatch.png", "untracked"),
            ("broken.jpg", "untracked"),
            ("too-large.jpg", "untracked"),
            ("link.jpg", "untracked"),
        }
    )

    gaps = {(gap["subject"], gap["kind"]): gap["reason"] for gap in payload["evidence_gaps"]}
    assert ("mismatch.png", "file_refused") in gaps
    assert ("broken.jpg", "file_refused") in gaps
    assert ("link.jpg", "file_refused") in gaps
    assert ("too-large.jpg", "file_limit") in gaps
    assert ("image.gif", "file_refused") in gaps
    assert ("document.pdf", "file_refused") in gaps
    assert ("asset.bin", "file_refused") in gaps
    assert payload["truncated"] is True
