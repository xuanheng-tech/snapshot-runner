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


def _prepare(
    repo: Path, task: str = "diff-audit", argument: str | None = None
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
    return runner._prepare_snapshot(task, argument, target, GIT)


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


def test_the_source_tagged_extensionless_route_fails_soft_too(repository: Path) -> None:
    """A body reached through the versioned (source-carrying) entries is treated the same way.

    That branch of `_append_context` is a separate call path with its own metadata checks, so
    sharing the helper does not by itself prove it behaves alike.
    """
    repo = repository
    (repo / "justfile").write_text(f"check:\n\t@echo hi\nkey:\n\t{PRIVATE_KEY}", encoding="utf-8")

    envelope = _envelope(_prepare(repo))

    assert _refused(envelope)["justfile"]["reason"].endswith(
        "private key boundary could not be proven"
    )
    assert KEY_MATERIAL not in json.dumps(envelope)


def test_the_branch_review_blob_route_fails_soft_the_same_way(repository: Path) -> None:
    """Branch review reads a blob for context even when the change carries no content lines.

    A mode-only change yields a diff holding nothing but `old mode` / `new mode`, so the refusal
    cannot be attributed to the diff route: the run must still publish and name the dropped file.
    """
    repo = repository
    (repo / "key.txt").write_text(PRIVATE_KEY, encoding="utf-8")
    _commit(repo, "key on main")
    _git(repo, "checkout", "--quiet", "-b", "feature")
    os.chmod(repo / "key.txt", 0o755)
    _commit(repo, "mode only")

    envelope = _envelope(_prepare(repo, "branch-review", "main"))

    assert envelope["truncated"] is True
    assert "old mode" in envelope["data"]["diff"], "this must really exercise the blob route"
    assert _refused(envelope)["key.txt"]["reason"].endswith(
        "private key boundary could not be proven"
    )
    assert KEY_MATERIAL not in json.dumps(envelope)


def test_a_refused_file_above_the_read_cap_reports_both_losses_separately(
    repository: Path,
) -> None:
    """The bytes never read and the bytes read-then-dropped are two facts, not one number.

    Folding them together would overstate one and hide the other: the per-file cap is a truncation
    event a reviewer has to see, while the refusal concerns the part actually in hand.
    """
    repo = repository
    body = PRIVATE_KEY + "filler line\n" * 30_000
    (repo / "big.txt").write_text(body, encoding="utf-8")

    envelope = _envelope(_prepare(repo))

    gaps = {str(gap["kind"]): gap for gap in envelope["evidence_gaps"]}
    assert gaps["file_refused"]["subject"] == "big.txt"
    assert gaps["file_refused"]["omitted_bytes"] == 256 * 1024
    assert gaps["file_limit"]["subject"] == "big.txt"
    assert gaps["file_limit"]["omitted_bytes"] == len(body.encode("utf-8")) - 256 * 1024
    assert int(gaps["file_refused"]["omitted_bytes"]) + int(
        gaps["file_limit"]["omitted_bytes"]
    ) == len(body.encode("utf-8")), (
        "the two counts must partition the file without double-counting it"
    )


class _GapCarrier:
    """Just enough of a builder to exercise the pure gap-selection policy."""

    evidence_gaps: list[collect.EvidenceGap]


def test_the_gap_cap_never_evicts_a_body_refusal_first() -> None:
    """A mass of other refusals must not bury the fact that bodies were dropped.

    Branch review records its per-file diff refusals before it reads any blob, so insertion order
    alone would let a long run push the body refusals past the hard cap and publish evidence that
    looks complete while files had quietly vanished.
    """
    refusals = [
        collect.EvidenceGap(
            "file_refused",
            f"key{index}.txt",
            f"{collect.BODY_REFUSED_REASON_PREFIX}: private key boundary could not be proven",
        )
        for index in range(10)
    ]
    noise = [
        collect.EvidenceGap("diff_file_refused", f"old{index}.bin", "unsupported")
        for index in range(collect.MAX_EVIDENCE_GAPS)
    ]
    carrier = _GapCarrier()
    carrier.evidence_gaps = [*noise, *refusals]

    kept = collect.Snapshot._gaps_within_cap(carrier)

    assert len(kept) == collect.MAX_EVIDENCE_GAPS
    assert all(refusal in kept for refusal in refusals)
    assert kept[-1].subject == "key9.txt", "kept gaps stay in recording order"


def test_the_allow_list_and_the_reason_table_cannot_drift() -> None:
    """One mapping is both the allow-list and the reason text, and the reason must survive output.

    Two parallel tables would let a message be allowed with no reason, turning a deliberate refusal
    into an unexpected KeyError mid-collection. And a reason the sanitizer itself rewrites would
    publish an unreadable explanation -- exactly why the vocabulary is controlled rather than quoted
    from the exception.
    """
    assert frozenset(collect.BODY_REFUSAL_REASONS) == collect.BODY_SANITIZER_REFUSALS
    assert all(collect.BODY_REFUSAL_REASONS.values())
    for message in sorted(collect.BODY_SANITIZER_REFUSALS):
        reason = f"{collect.BODY_REFUSED_REASON_PREFIX}: {collect.BODY_REFUSAL_REASONS[message]}"
        stable = security.sanitize_text(
            reason, scan_mode=security.ScanMode.PLAIN_TEXT, repository_root=Path("/tmp")
        )
        assert stable.text == reason
        assert stable.redactions == {}


def _carrier(*gaps: collect.EvidenceGap) -> _GapCarrier:
    carrier = _GapCarrier()
    carrier.evidence_gaps = list(gaps)
    return carrier


def _body(index: int) -> collect.EvidenceGap:
    return collect.EvidenceGap(
        "file_refused",
        f"key{index}.txt",
        f"{collect.BODY_REFUSED_REASON_PREFIX}: private key boundary could not be proven",
    )


def _other(kind: str, index: int) -> collect.EvidenceGap:
    return collect.EvidenceGap(kind, f"{kind}{index}.txt", "recorded elsewhere")


def test_the_free_slots_fill_from_the_earliest_remaining_gap() -> None:
    """Which non-refusal gaps survive is a decision, not a side effect of the loop.

    Filling from the newest backwards would keep the same number of gaps and still satisfy every
    other assertion here, so the order is pinned directly.
    """
    cap = collect.MAX_EVIDENCE_GAPS
    refusals = [_body(index) for index in range(4)]
    noise = [_other("diff_file_refused", index) for index in range(cap)]

    kept = collect.Snapshot._gaps_within_cap(_carrier(*noise, *refusals))

    # Four refusals claim four slots, so only the 124 earliest other gaps keep one each, and the
    # published list stays in recording order rather than grouping refusals at the front.
    assert [gap.subject for gap in kept] == [
        *[gap.subject for gap in noise[: cap - 4]],
        *[gap.subject for gap in refusals],
    ]


def test_only_body_refusals_are_shielded_from_the_cap() -> None:
    """The shield is scoped to bodies, and that boundary is asserted rather than assumed.

    Every other per-file loss keeps first-in-first-out behaviour: widening the predicate to all
    `file_refused` entries would displace the per-file diff refusals that dominate a large branch
    review, which is a different trade-off and deliberately not taken here.
    """
    cap = collect.MAX_EVIDENCE_GAPS
    path_losses = [
        collect.EvidenceGap(
            "file_refused", f"rewritten{index}.txt", collect.REDACTION_REWRITTEN_PATH_REASON
        )
        for index in range(20)
    ]
    limits = [_other("file_limit", index) for index in range(20)]
    refusals = [_body(index) for index in range(3)]
    # The branch-review shape: per-file diff refusals already fill the list before any blob is read,
    # so everything recorded after them competes for the last slots.
    noise = [_other("diff_file_refused", index) for index in range(cap - 3)]

    kept = collect.Snapshot._gaps_within_cap(_carrier(*noise, *path_losses, *limits, *refusals))

    assert all(refusal in kept for refusal in refusals)
    assert not any(gap in kept for gap in [*path_losses, *limits])
    assert len(kept) == cap
    assert [gap.subject for gap in kept[: cap - 3]] == [gap.subject for gap in noise]
