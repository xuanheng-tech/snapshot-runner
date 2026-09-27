"""One unsanitizable file body must cost that file, not the snapshot.

A body whose text the sanitizer cannot prove safe used to abort the whole prepare: a repository
with one pasted private key published no diff, no status and no other file context either. These
tests pin the replacement -- a per-file `file_refused` gap that drops exactly that body -- and,
just as importantly, the refusals that still have to abort: the unified-diff route, YAML and
sensitive-path classification, and every message outside the small allow-list of body-content
refusals.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from snapshot_runner import artifact, collect, git, security
from snapshot_runner import cli as runner

GIT = "/usr/bin/git"
PRIVATE_KEY = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABgAAAAgAAAA=\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)
KEY_MATERIAL = "b3BlbnNzaC1rZXktdjEAAAAABgAAAAgAAAA="
PEM_REASON = "file body could not be safely redacted: private key boundary could not be proven"
BOM_REASON = "file body could not be safely redacted: byte-order mark outside the start of the text"


def _git(repo: Path, *arguments: str) -> None:
    result = subprocess.run(
        [GIT, "-C", os.fspath(repo), *arguments],
        cwd="/",
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")


def _commit(repo: Path, message: str) -> None:
    _git(repo, "add", "--all")
    _git(
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


@pytest.fixture
def repository(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    state.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    _git(repo, "init", "--quiet", "--initial-branch=main")
    (repo / "baseline.py").write_text("BASELINE = True\n", encoding="utf-8")
    _commit(repo, "baseline")
    return repo


def _prepare(repo: Path) -> artifact.SnapshotArtifact:
    target_path, target_name, runner_path = runner._validate_target_repository_path(os.fspath(repo))
    target = git._validate_target_repository_context(
        target_path,
        target_name,
        runner_path,
        artifact._state_home(target_path),
        GIT,
        "diff-audit",
    )
    return runner._prepare_snapshot("diff-audit", None, target, GIT)


def _envelope(artifact_value: artifact.SnapshotArtifact) -> dict[str, object]:
    return json.loads(artifact_value.snapshot_bytes)


def _paths(envelope: dict[str, object]) -> list[str]:
    return [str(entry["path"]) for entry in envelope["data"]["file_context"]]


def _refused(envelope: dict[str, object]) -> dict[str, dict[str, object]]:
    return {
        str(gap["subject"]): gap
        for gap in envelope["evidence_gaps"]
        if isinstance(gap, dict) and gap.get("kind") == "file_refused"
    }


def test_unsafe_body_is_dropped_as_a_gap_while_the_rest_is_published(repository: Path) -> None:
    repo = repository
    (repo / "baseline.py").write_text("BASELINE = 42\n", encoding="utf-8")
    (repo / "key.txt").write_text(PRIVATE_KEY, encoding="utf-8")

    envelope = _envelope(_prepare(repo))

    assert _paths(envelope) == ["baseline.py"], "healthy evidence must survive"
    assert "BASELINE = 42" in envelope["data"]["unstaged_diff"]
    assert envelope["truncated"] is True
    gap = _refused(envelope)["key.txt"]
    assert gap["reason"] == PEM_REASON
    assert gap["omitted_bytes"] == len(PRIVATE_KEY.encode("utf-8"))


def test_several_unsafe_bodies_mixed_with_good_ones(repository: Path) -> None:
    repo = repository
    (repo / "baseline.py").write_text("BASELINE = 7\n", encoding="utf-8")
    (repo / "good.txt").write_text("plain note\n", encoding="utf-8")
    (repo / "key.txt").write_text(PRIVATE_KEY, encoding="utf-8")
    (repo / "bom.txt").write_bytes(b"first\xef\xbb\xbfsecond\n")

    envelope = _envelope(_prepare(repo))

    assert sorted(_paths(envelope)) == ["baseline.py", "good.txt"]
    assert _refused(envelope)["key.txt"]["reason"] == PEM_REASON
    assert _refused(envelope)["key.txt"]["omitted_bytes"] == len(PRIVATE_KEY.encode("utf-8"))
    assert _refused(envelope)["bom.txt"]["reason"] == BOM_REASON
    assert _refused(envelope)["bom.txt"]["omitted_bytes"] == 15
    good = next(entry for entry in envelope["data"]["file_context"] if entry["path"] == "good.txt")
    assert good["content"] == "plain note\n", "the refusal must not bleed into a neighbouring file"


def test_the_refused_body_is_absent_from_every_field(repository: Path) -> None:
    repo = repository
    (repo / "untracked_key.txt").write_text(PRIVATE_KEY, encoding="utf-8")

    published = _prepare(repo).snapshot_bytes

    assert KEY_MATERIAL.encode("utf-8") not in published
    assert b"untracked_key.txt" in published, "the gap still names the file it dropped"
    assert _envelope_from_bytes(published)["redactions"] == {}, (
        "dropping a body is not a redaction and must not inflate the count"
    )


def _envelope_from_bytes(published: bytes) -> dict[str, object]:
    return json.loads(published)


def test_the_same_text_reaching_the_diff_route_still_refuses_the_run(repository: Path) -> None:
    """Fail-soft is scoped to one field. A diff carrying the same unprovable text still aborts.

    The unified diff is one evidence value that cannot be published partially, so a run whose diff
    holds an unsafe body publishes nothing at all -- exactly as it did before this change.
    """
    repo = repository
    (repo / "tracked.txt").write_text("safe\n", encoding="utf-8")
    _commit(repo, "add tracked")
    (repo / "tracked.txt").write_text(PRIVATE_KEY, encoding="utf-8")

    store = artifact.snapshot_output_root()
    before = sorted(path.name for path in store.iterdir()) if store.is_dir() else []
    with pytest.raises(runner.RunnerError, match="unable to sanitize unstaged-diff"):
        _prepare(repo)
    after = sorted(path.name for path in store.iterdir()) if store.is_dir() else []
    assert after == before, "a refused run must publish nothing, not even a partial artifact"


@pytest.mark.parametrize(
    ("message", "reason"),
    [
        (
            "PEM credential boundary cannot be proven",
            "file body could not be safely redacted: private key boundary could not be proven",
        ),
        ("NUL byte in text", "file body could not be safely redacted: NUL byte inside the text"),
        (
            "UTF-8 BOM is allowed only once at the beginning",
            "file body could not be safely redacted: byte-order mark outside the start of the text",
        ),
        (
            "text contains a residual authorization credential",
            "file body could not be safely redacted: a credential survived redaction",
        ),
        (
            "text contains a residual bearer credential",
            "file body could not be safely redacted: a credential survived redaction",
        ),
        (
            "text contains a residual credential pattern",
            "file body could not be safely redacted: a credential survived redaction",
        ),
        ("unified diff hunk is truncated", None),
        ("scan mode manifest is missing a text path", None),
        ("artifact exceeds the recursive element limit", None),
    ],
)
def test_only_the_allowed_body_refusals_become_gaps(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    message: str,
    reason: str | None,
) -> None:
    """The catch is an allow-list, not a swallow.

    The patched sanitizer raises only for the body, so the gap bookkeeping still runs normally. A
    refusal outside the body-content list aborts the prepare, because that kind of failure says the
    artifact's shape is wrong and cannot be downgraded into one omitted file.
    """
    repo = repository
    (repo / "untracked.txt").write_text("body text\n", encoding="utf-8")
    real = security.sanitize_text

    def selective(text: str, **keyword: object) -> security.SanitizedText:
        if text == "body text\n":
            raise security.SecurityError(message)
        return real(text, **keyword)

    monkeypatch.setattr(collect, "sanitize_text", selective)

    if reason is None:
        with pytest.raises(runner.RunnerError, match="unable to sanitize file context"):
            _prepare(repo)
        return
    published = _prepare(repo).snapshot_bytes
    gap = _refused(json.loads(published))["untracked.txt"]
    # The reason is asserted as it comes back out of the artifact, not as it was built: a gap reason
    # is sanitized like any other evidence text, and one parametrised case exists precisely because
    # quoting the raw exception sentence made the redactor rewrite it into "[REDACTED_BEARER]".
    assert gap["reason"] == reason
    assert reason.encode("utf-8") in published
    assert gap["omitted_bytes"] == len(b"body text\n")


def test_yaml_and_sensitive_path_hard_refusals_are_unchanged(repository: Path) -> None:
    """Requirement: the existing refusal semantics around file contexts stay as they were."""
    repo = repository
    (repo / "secret.pem").write_text("material\n", encoding="utf-8")
    (repo / "baseline.py").write_text("BASELINE = 2\n", encoding="utf-8")

    envelope = _envelope(_prepare(repo))
    assert _refused(envelope)["secret.pem"]["reason"] == (
        "sensitive or unsupported file type refused"
    )

    yaml_repo = repo / "sub"
    yaml_repo.mkdir()
    (yaml_repo / "rules.yaml").write_text("key: value\n", encoding="utf-8")
    with pytest.raises(runner.RunnerError, match="yaml_content_refused"):
        _prepare(repo)


def test_read_path_attributes_the_refused_file(repository: Path) -> None:
    repo = repository
    (repo / "baseline.py").write_text("BASELINE = 9\n", encoding="utf-8")
    (repo / "key.txt").write_text(PRIVATE_KEY, encoding="utf-8")
    (repo / "ok.txt").write_text("fine\n", encoding="utf-8")
    loaded = artifact._load_snapshot(_prepare(repo).snapshot_id, repo)

    refused = json.loads(
        artifact._build_evidence_output(loaded, "0.0.0", repository_root=repo, path="key.txt")
    )
    assert refused["found"] is True, "the artifact does know about this path"
    assert refused["evidence"]["file_context"] == []
    assert [gap["kind"] for gap in refused["evidence"]["evidence_gaps"]] == ["file_refused"]
    assert refused["evidence"]["evidence_gaps"][0]["reason"] == PEM_REASON

    accepted = json.loads(
        artifact._build_evidence_output(loaded, "0.0.0", repository_root=repo, path="ok.txt")
    )
    assert accepted["evidence"]["file_context"] == [{"path": "ok.txt", "content": "fine\n"}]
    assert accepted["evidence"]["evidence_gaps"] == []


def test_a_fail_soft_artifact_round_trips_and_tampering_is_still_refused(
    repository: Path,
) -> None:
    repo = repository
    (repo / "key.txt").write_text(PRIVATE_KEY, encoding="utf-8")
    published = _prepare(repo)

    reloaded = artifact._load_snapshot(published.snapshot_id, repo)
    assert reloaded.snapshot_id == published.snapshot_id
    assert reloaded.snapshot_bytes == published.snapshot_bytes
    assert _refused(_envelope(reloaded))["key.txt"]

    original = published.directory / "snapshot.json"
    raw = bytearray(original.read_bytes())
    raw[raw.index(b"file_refused") + len(b"file_refused") - 1] ^= 0x20
    original.write_bytes(bytes(raw))
    original.chmod(0o600)
    with pytest.raises(runner.RunnerError):
        artifact._load_snapshot(published.snapshot_id, repo)
