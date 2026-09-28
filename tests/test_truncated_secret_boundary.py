"""A read that runs out of budget must not publish the slice it happened to keep.

The collector cuts a body to its per-file budget *before* the sanitizer sees it. The rules that
refuse a private key only recognise a block they can see end to end, so a key whose closing marker
fell past the cut read as ordinary text and the artifact published up to 256 KiB of key material
under a benign-looking `file_limit` gap. These tests pin the withheld body, the gap that replaces it,
and the cases that must keep their old behaviour: a complete block, an ordinary large file, and a
credential the redactor already handles.
"""

from __future__ import annotations

import itertools
import json
import os
import random
import re
import subprocess
import time
from pathlib import Path

import pytest

from snapshot_runner import artifact, collect, git, security
from snapshot_runner import cli as runner

GIT = "/usr/bin/git"
CAP = collect.MAX_FILE_BYTES
BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
END = "-----END OPENSSH PRIVATE KEY-----\n"
KEY_LINE = "b3BlbnNzaC1rZXktdjEAAAAABgAAAAgAAAA=\n"
# JSON escapes the newline, so a byte-level search has to use a marker without one.
KEY_MATERIAL = KEY_LINE.rstrip("\n")
PEM_REASON = "file body could not be safely redacted: private key boundary could not be proven"
CUTOFF_REASON = collect.TRUNCATED_BODY_REFUSAL_REASONS[security.SECRET_BOUNDARY_CUTOFF]
CREDENTIAL_REASON = collect.TRUNCATED_BODY_REFUSAL_REASONS[security.CREDENTIAL_CUTOFF]


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


def _envelope(published: artifact.SnapshotArtifact) -> dict[str, object]:
    return json.loads(published.snapshot_bytes)


def _paths(envelope: dict[str, object]) -> list[str]:
    return [str(entry["path"]) for entry in envelope["data"]["file_context"]]


def _gaps(envelope: dict[str, object], kind: str) -> dict[str, dict[str, object]]:
    return {
        str(gap["subject"]): gap
        for gap in envelope["evidence_gaps"]
        if isinstance(gap, dict) and gap.get("kind") == kind
    }


def _cut_at_cap(tail: str) -> str:
    """Text whose retained prefix is exactly the budget and ends inside ``tail``.

    The filler stops at a newline so the marker on the last line is preceded by a word boundary, the
    way a real config line would be.
    """
    return "y" * (CAP - len(tail) - 1) + "\n" + tail + "\nrest of the file\n"


def test_a_key_ending_past_the_cap_is_withheld_whole(repository: Path) -> None:
    repo = repository
    body = BEGIN + KEY_LINE * 4_000 + END
    content = "filler line\n" * 20_000 + body
    assert len(content) > CAP, "the closing marker has to fall outside the budget to be a straddle"
    (repo / "straddle.txt").write_text(content, encoding="utf-8")

    published = _prepare(repo)
    envelope = _envelope(published)

    assert "straddle.txt" not in _paths(envelope)
    gap = _gaps(envelope, "file_refused")["straddle.txt"]
    assert gap["reason"] == CUTOFF_REASON
    assert gap["omitted_bytes"] == len(content.encode("utf-8")), (
        "withholding the body loses all of it, so that is the number a reviewer needs"
    )
    assert KEY_MATERIAL.encode("utf-8") not in published.snapshot_bytes


def test_a_pem_closed_before_the_cap_still_takes_the_existing_rule(repository: Path) -> None:
    """A block the retained prefix shows end to end is not a straddle and must not be relabelled.

    The refusal here comes from the sanitizer one step later, so the two losses stay separately
    counted exactly as they were before this change.
    """
    repo = repository
    block = BEGIN + KEY_LINE * 40 + END
    content = block + "filler line\n" * 30_000
    (repo / "closed.txt").write_text(content, encoding="utf-8")

    envelope = _envelope(_prepare(repo))

    assert _gaps(envelope, "file_refused")["closed.txt"]["reason"] == PEM_REASON
    limits = _gaps(envelope, "file_limit")["closed.txt"]
    assert limits["omitted_bytes"] == len(content.encode("utf-8")) - CAP
    assert int(_gaps(envelope, "file_refused")["closed.txt"]["omitted_bytes"]) + int(
        limits["omitted_bytes"]
    ) == len(content.encode("utf-8"))


@pytest.mark.parametrize(
    "tail",
    [
        "token=ghp_A1b2C3d4E5f6G7h8I9",
        "key: sk-proj-QQQQQQQQQQQQQQQQQQQQQQ",
        "aws AKIAabcdefghijklmnop",
        "credential: Bearer abcde",
        "api AIzaAbcdefghijkl",
    ],
    ids=["github", "openai", "aws-key-id", "bearer", "google"],
)
def test_a_credential_cut_by_the_cap_is_withheld(repository: Path, tail: str) -> None:
    """Each marker is caught short of its own rule's minimum by exactly the bytes the cut removed.

    The AWS case is the one no length floor could reason about: ``AKIA[A-Z0-9]{16}\\b`` cannot match a
    20-character run that never ends, so the retained slice would have been published raw.
    """
    repo = repository
    content = _cut_at_cap(tail)
    (repo / "secrets.txt").write_text(content, encoding="utf-8")

    published = _prepare(repo)
    envelope = _envelope(published)

    assert _gaps(envelope, "file_refused")["secrets.txt"]["reason"] == CREDENTIAL_REASON
    assert "secrets.txt" not in _paths(envelope)
    assert tail.encode("utf-8") not in published.snapshot_bytes


def test_a_credential_fully_inside_the_cap_is_redacted_not_withheld(repository: Path) -> None:
    """The probe is about a slice, not about secrets in general: a whole value keeps its old path.

    Nothing of this file is dropped, so the evidence still arrives -- with the token replaced by the
    marker the sanitizer has always used.
    """
    repo = repository
    (repo / "config.txt").write_text(
        "token = ghp_A1b2C3d4E5f6G7h8I9J0K1L2M3N4\nowner = someone\n", encoding="utf-8"
    )

    envelope = _envelope(_prepare(repo))

    context = next(
        entry for entry in envelope["data"]["file_context"] if entry["path"] == "config.txt"
    )
    assert "A1b2C3d4E5f6G7h8I9J0K1L2M3N4" not in str(context["content"])
    assert envelope["redactions"].get("GITHUB_TOKEN") == 1
    assert "config.txt" not in _gaps(envelope, "file_refused")


def test_an_ordinary_large_file_still_publishes_its_truncated_prefix(repository: Path) -> None:
    """The requirement that the fix not simply widen the budget: normal big files stay normal."""
    repo = repository
    content = "notes line\n" * 30_000 + "the last complete line\n"
    assert len(content) > CAP
    (repo / "notes.txt").write_text(content, encoding="utf-8")

    envelope = _envelope(_prepare(repo))

    context = next(
        entry for entry in envelope["data"]["file_context"] if entry["path"] == "notes.txt"
    )
    assert len(str(context["content"])) == CAP
    gap = _gaps(envelope, "file_limit")["notes.txt"]
    assert gap["reason"] == "file context truncated at 256 KiB"
    assert gap["omitted_bytes"] == len(content.encode("utf-8")) - CAP
    assert "notes.txt" not in _gaps(envelope, "file_refused")


def test_a_withheld_straddle_costs_only_its_own_file(repository: Path) -> None:
    """One cut-through key must not take the snapshot, or a neighbour, down with it."""
    repo = repository
    (repo / "baseline.py").write_text("BASELINE = 42\n", encoding="utf-8")
    (repo / "straddle.txt").write_text(
        "filler line\n" * 20_000 + BEGIN + KEY_LINE * 4_000, encoding="utf-8"
    )
    (repo / "good.txt").write_text("plain note\n", encoding="utf-8")

    envelope = _envelope(_prepare(repo))

    assert sorted(_paths(envelope)) == ["baseline.py", "good.txt"]
    assert _gaps(envelope, "file_refused")["straddle.txt"]["reason"] == CUTOFF_REASON
    assert envelope["truncated"] is True
    assert "BASELINE = 42" in str(envelope["data"]["unstaged_diff"])


def test_no_body_bytes_survive_in_any_artifact_file(repository: Path) -> None:
    repo = repository
    marker = "SUPERSECRETLINE000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    body = "filler line\n" * 20_000 + BEGIN + marker + KEY_LINE * 4_000 + END
    (repo / "straddle.txt").write_text(body, encoding="utf-8")

    published = _prepare(repo)

    for stored in published.directory.iterdir():
        assert marker.encode("utf-8") not in stored.read_bytes(), (
            f"{stored.name} carries body material that was supposed to be withheld"
        )


def test_read_path_attributes_the_truncation_refusal(repository: Path) -> None:
    repo = repository
    (repo / "baseline.py").write_text("BASELINE = 9\n", encoding="utf-8")
    body = "filler line\n" * 20_000 + BEGIN + KEY_LINE * 4_000
    (repo / "straddle.txt").write_text(body, encoding="utf-8")
    loaded = artifact._load_snapshot(_prepare(repo).snapshot_id, repo)

    refused = json.loads(
        artifact._build_evidence_output(loaded, "0.0.0", repository_root=repo, path="straddle.txt")
    )
    assert refused["found"] is True, "the artifact does know about this path"
    assert refused["evidence"]["file_context"] == []
    assert [gap["kind"] for gap in refused["evidence"]["evidence_gaps"]] == ["file_refused"]
    assert refused["evidence"]["evidence_gaps"][0]["reason"] == CUTOFF_REASON
    assert refused["evidence"]["evidence_gaps"][0]["subject"] == "straddle.txt"

    healthy = json.loads(
        artifact._build_evidence_output(loaded, "0.0.0", repository_root=repo, path="baseline.py")
    )
    assert [item["content"] for item in healthy["evidence"]["file_context"]] == ["BASELINE = 9\n"]
    assert healthy["evidence"]["evidence_gaps"] == []


def test_a_body_written_before_the_guard_is_still_read(
    repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """History: the guard is a write-time decision, so an artifact already holding the slice reads.

    The guard is switched off only to *write* the shape the previous release produced, then restored
    before the read. A read that consulted the new predicate would refuse an artifact its own store
    wrote, which is the failure mode this repository's versioning work exists to prevent. The guard is
    restored by name rather than with ``monkeypatch.undo()``, which would also drop the state
    directory this test's artifact lives in.
    """
    repo = repository
    body = "filler line\n" * 20_000 + BEGIN + KEY_LINE * 4_000
    (repo / "straddle.txt").write_text(body, encoding="utf-8")
    guard = collect._truncated_body_reason
    monkeypatch.setattr(collect, "_truncated_body_reason", lambda text: None)
    try:
        published = _prepare(repo)
    finally:
        monkeypatch.setattr(collect, "_truncated_body_reason", guard)

    assert KEY_MATERIAL.encode("utf-8") in published.snapshot_bytes, (
        "this fixture must really be the artifact the old collector published"
    )
    loaded = artifact._load_snapshot(published.snapshot_id, repo)
    assert loaded.snapshot_bytes == published.snapshot_bytes
    assert loaded.snapshot_id == published.snapshot_id


def test_the_sealed_target_blob_route_withholds_a_straddling_blob(repository: Path) -> None:
    """Branch review reads the target blob through a second reader, which needs the same guard.

    A mode-only change keeps the diff free of content lines, so a refusal here can only have come
    from the blob prefix reader.
    """
    repo = repository
    body = "filler line\n" * 20_000 + BEGIN + KEY_LINE * 4_000
    (repo / "straddle.txt").write_text(body, encoding="utf-8")
    _commit(repo, "straddle on main")
    _git(repo, "checkout", "--quiet", "-b", "feature")
    os.chmod(repo / "straddle.txt", 0o755)
    _commit(repo, "mode only")

    published = _prepare(repo, "branch-review", "main")
    envelope = _envelope(published)

    assert "old mode" in str(envelope["data"]["diff"]), "this must really exercise the blob route"
    assert _gaps(envelope, "file_refused")["straddle.txt"]["reason"] == CUTOFF_REASON
    assert KEY_MATERIAL.encode("utf-8") not in published.snapshot_bytes


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (BEGIN + KEY_LINE, security.SECRET_BOUNDARY_CUTOFF),
        (BEGIN + KEY_LINE + END, None),
        (BEGIN + KEY_LINE + END + BEGIN + KEY_LINE, security.SECRET_BOUNDARY_CUTOFF),
        (BEGIN + BEGIN + KEY_LINE + END, security.SECRET_BOUNDARY_CUTOFF),
        (KEY_LINE + END, None),
        ("-----BEGIN RSA PRIVATE KEY-----\n" + KEY_LINE, security.SECRET_BOUNDARY_CUTOFF),
        ("-----BEGIN CERTIFICATE-----\n" + KEY_LINE, None),
        ("ghp_" + "A" * 17, security.CREDENTIAL_CUTOFF),
        ("ghp_" + "A" * 17 + "\n", None),
        ("Authorization: Bearer abc", security.CREDENTIAL_CUTOFF),
        ("Authorization: Bearer abc def\n", None),
        ("tasks-skylark\n", None),
        ("prefixghp_" + "A" * 17, None),
        ("xAIzaAbcdefghijkl", None),
        ("ghp_" + "A" * 17 + "." + "B" * 30, security.CREDENTIAL_CUTOFF),
        ("token: ghp_A1b2C3d4E5f6\nG7h8I9J0K1L2M3N4O5P6Q7R8", None),
        ("x" * 100 + ".ghp_" + "Q" * 50, security.CREDENTIAL_CUTOFF),
        ("token=ghp_", security.CREDENTIAL_CUTOFF),
        ("ghp_" + "A" * 14 + " " * 60 + "G7h8I9J0K1", None),
        ("Authorization: Bearer ", None),
        ("the file ends normally\n", None),
    ],
)
def test_the_probe_names_only_a_structure_the_cut_went_through(
    text: str, expected: str | None
) -> None:
    """What counts as a straddle is a decided list, including the shapes that deliberately do not.

    A close-only marker names nothing the reader was mid-way through, and a label outside the private
    key vocabulary is not a private key: both must leave the body publishable. A token the file itself
    split with a newline is not a cut either -- the sanitizer's token patterns miss that shape in a
    three-line file as well, which is a rule-coverage question recorded in the CHANGELOG, not this one.
    """
    assert security.truncated_secret_boundary(text) == expected


def test_the_probe_answers_a_prefix_full_of_marker_candidates_quickly() -> None:
    """This runs over whatever the audited repository contains, so its cost is a security property.

    One expression combining a marker with an unbounded character run before an end anchor costs a
    backtracking pass per marker candidate: measured at 27 s for a 300 201-character prefix holding
    60 000 of them and 170 s at 750 201, against 0.02 s for the sanitizer reading the same bytes. The
    bound below is deliberately loose -- the shapes that used to cost minutes answer in milliseconds
    now, and a regression to the backtracking form is what this is watching for.
    """
    text = "=AKIA" * 60_000 + "Q" * 200 + "!"
    assert len(text) == 300_201

    started = time.monotonic()
    result = security.truncated_secret_boundary(text)
    elapsed = time.monotonic() - started

    assert result is None, "no marker's value reaches the end here, so nothing is withheld"
    assert elapsed < 2.0, f"the probe took {elapsed:.3f}s on a {len(text)}-character prefix"


def test_a_prefix_cut_through_both_shapes_is_named_as_the_key_it_opens() -> None:
    """Order matters once both shapes are present, because the published reason says which one it saw.

    Measured: an unclosed key opener followed by a credential run reaching the cut is a key straddle,
    and naming it a credential would tell a reviewer the wrong thing about what was withheld.
    """
    text = BEGIN + KEY_LINE * 40 + "token=ghp_A1b2C3d4E5f6G7h8I9"

    assert security.truncated_secret_boundary(text) == security.SECRET_BOUNDARY_CUTOFF


def test_the_truncation_reasons_are_named_by_the_probe_and_survive_publication() -> None:
    """A drifted label would raise KeyError inside collection, and a rewritten reason reads as noise.

    The two sets are pinned against each other so adding a third cutoff without a reason fails here
    rather than on a user's repository, and each reason is round-tripped through the sanitizer
    because a gap reason is evidence text like any other.
    """
    assert frozenset(collect.TRUNCATED_BODY_REFUSAL_REASONS) == frozenset(
        security.SECRET_CUTOFF_KINDS
    )
    for reason in collect.TRUNCATED_BODY_REFUSAL_REASONS.values():
        stable = security.sanitize_text(
            reason, scan_mode=security.ScanMode.PLAIN_TEXT, repository_root=Path("/tmp")
        )
        assert stable.text == reason
        assert stable.redactions == {}
        assert len(reason) <= 256


class _GapCarrier:
    """Just enough of a builder to exercise the pure gap-selection policy."""

    evidence_gaps: list[collect.EvidenceGap]


def test_the_published_reasons_are_these_exact_words() -> None:
    """Pinned as literals, the way every other published gap reason is pinned here.

    Reading the wording out of the production table would let any rewording pass, and the sentence is
    what a reviewer of an artifact actually sees -- it has to survive the sanitizer on the way in, so
    it is worth freezing rather than deriving.
    """
    assert CUTOFF_REASON == (
        "file body could not be safely redacted: a private key boundary was cut off by the read limit"
    )
    assert CREDENTIAL_REASON == (
        "file body could not be safely redacted: a credential was cut off by the read limit"
    )


def test_the_guard_is_asked_only_of_a_body_the_reader_cut(repository: Path) -> None:
    """The gate is a decision, so it is asserted rather than left to the shape of the code.

    An untruncated body is handed to the sanitizer whole, and what it refuses -- a block it can see
    closed -- is the existing rule's business. A key opened and never closed in a small file, and a
    short token that simply ends the file, are therefore published today; both are rule-coverage
    questions the CHANGELOG records as remaining work, not consequences of the cut. Widening the
    guard to every body would also make this repository's own documentation, which quotes an opening
    marker with no closing one, refuse to appear in its evidence.
    """
    repo = repository
    (repo / "opened.txt").write_text(BEGIN + KEY_LINE * 40, encoding="utf-8")
    (repo / "short_token.txt").write_text("token=ghp_A1b2C3d4E5f6G7h8I9", encoding="utf-8")

    envelope = _envelope(_prepare(repo))

    assert "opened.txt" not in _gaps(envelope, "file_refused")
    assert "short_token.txt" not in _gaps(envelope, "file_refused")
    published = {str(c["path"]): str(c["content"]) for c in envelope["data"]["file_context"]}
    assert KEY_MATERIAL in published["opened.txt"]
    assert "ghp_A1b2C3d4E5f6G7h8I9" in published["short_token.txt"]
    assert security.truncated_secret_boundary(BEGIN + KEY_LINE * 40) is not None, (
        "the withheld shape is identical; only the absence of a cut separates the two"
    )


def test_a_truncation_refusal_is_shielded_from_the_gap_count_cap() -> None:
    """Filed under the body-refusal prefix, so a mass of other gaps cannot bury it.

    The cap protects bodies precisely because a dropped body is invisible in every other field; a
    truncation refusal that used its own wording would fall out of that protection silently.
    """
    cap = collect.MAX_EVIDENCE_GAPS
    refusals = [
        collect.EvidenceGap("file_refused", f"straddle{index}.txt", CUTOFF_REASON)
        for index in range(4)
    ]
    noise = [
        collect.EvidenceGap("diff_file_refused", f"old{index}.bin", "unsupported")
        for index in range(cap)
    ]
    carrier = _GapCarrier()
    carrier.evidence_gaps = [*noise, *refusals]

    kept = collect.Snapshot._gaps_within_cap(carrier)

    assert len(kept) == cap
    assert all(refusal in kept for refusal in refusals)
    assert collect._is_body_refusal(refusals[0])


# The single expression the linear probe replaced, kept here and only here as an oracle. It is right
# about every shape and costs a backtracking pass per marker candidate in the text, which is why the
# version that shipped first could not stay.
_LEGACY_CREDENTIAL_RE = re.compile(
    r"\b(?:sk-(?:proj-)?|gh[pousr]_|AIza|(?:AKIA|ASIA)|(?i:bearer)\s)[A-Za-z0-9._~+/=-]+\Z"
)
_CREDENTIAL_MARKERS = (
    "sk-proj-",
    "sk-",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "AIza",
    "AKIA",
    "ASIA",
    "Bearer ",
    "bearer\t",
)


@pytest.mark.parametrize("seed", [7, 11, 23])
def test_the_linear_probe_withholds_everything_the_expression_it_replaced_did(seed: int) -> None:
    """A rewrite that buys milliseconds may not spend them on a wider leak.

    Compared over every arrangement of prefix, marker, separator and tail below, plus a seeded fuzz of
    short strings drawn from the token alphabet and the punctuation that breaks a value. The probe is
    allowed to withhold *more*: it does, on text ending exactly on a marker with no value characters
    after it, where the expression needed at least one. It is never allowed to publish one the
    expression withheld -- which is what the shape of the difference cannot guarantee on its own.
    """
    separators = ["", " ", "\n", "=", ":", ".", ",", '"', "'", "/", "  ", "\n\n", "->", "\t"]
    tails = ["", "Q", "Q1W2", "a" * 20, "A" * 60, "a.b=c-d_e/f+g", "sk-QQ", "ghp_Q"]
    prefixes = ["", "\n", "x\n", "config:", BEGIN, "=" * 70, "a" * 300, "z" * 100 + "."]
    inputs = [
        prefix + marker + separator + tail
        for prefix, marker, separator, tail in itertools.product(
            prefixes, (*_CREDENTIAL_MARKERS, "prefixghp_", "xsk-"), separators, tails
        )
    ]
    rng = random.Random(seed)
    alphabet = "aBK9_-.:/=\n \tAKIAAIzask-ghp_Bearer"
    inputs += [
        "".join(rng.choice(alphabet) for _ in range(size))
        for size in (0, 3, 12, 40, 200)
        for _ in range(800)
    ]

    def withheld_by_probe(text: str) -> bool:
        return security._ends_in_truncated_credential(text)

    leaked = [
        text
        for text in inputs
        if _LEGACY_CREDENTIAL_RE.search(text) and not withheld_by_probe(text)
    ]
    assert leaked == [], [text[:60] for text in leaked[:5]]

    extra = [
        text
        for text in inputs
        if withheld_by_probe(text) and not _LEGACY_CREDENTIAL_RE.search(text)
    ]
    assert all(any(text.endswith(marker) for marker in _CREDENTIAL_MARKERS) for text in extra), [
        text[:60]
        for text in extra
        if not any(text.endswith(marker) for marker in _CREDENTIAL_MARKERS)
    ][:5]


class _ChunkedRead:
    """An ``os`` proxy whose ``read`` hands back at most ``chunk`` bytes, and may claim EOF early.

    A filesystem is free to return a short read, and the reader under test used to trust exactly one
    call. Everything else still goes to the real module.
    """

    def __init__(self, chunk: int, stop_early: int | None = None) -> None:
        self.chunk = chunk
        self.stop_early = stop_early
        self.per_descriptor: dict[int, int] = {}

    def __getattr__(self, name: str) -> object:
        return getattr(os, name)

    def read(self, descriptor: int, size: int) -> bytes:
        seen = self.per_descriptor.setdefault(descriptor, 0)
        if self.stop_early is not None and seen >= self.stop_early:
            return b""
        data = os.read(descriptor, min(size, self.chunk))
        self.per_descriptor[descriptor] = seen + len(data)
        return data


def test_a_short_read_still_publishes_the_whole_retained_prefix(
    repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Chunked reads are not a licence to publish half a file and call it complete."""
    repo = repository
    content = "notes line\n" * 30_000
    (repo / "notes.txt").write_text(content, encoding="utf-8")
    monkeypatch.setattr(collect, "os", _ChunkedRead(4096))

    envelope = _envelope(_prepare(repo))

    context = next(
        entry for entry in envelope["data"]["file_context"] if entry["path"] == "notes.txt"
    )
    assert len(str(context["content"])) == CAP
    gap = _gaps(envelope, "file_limit")["notes.txt"]
    assert gap["omitted_bytes"] == len(content.encode("utf-8")) - CAP


def test_a_straddle_reaching_the_cap_in_pieces_is_still_withheld(
    repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The gate's precondition is that the retained prefix really is the first CAP bytes."""
    repo = repository
    body = "filler line\n" * 20_000 + BEGIN + KEY_LINE * 4_000
    (repo / "straddle.txt").write_text(body, encoding="utf-8")
    monkeypatch.setattr(collect, "os", _ChunkedRead(8192))

    published = _prepare(repo)

    assert "straddle.txt" not in _paths(_envelope(published))
    assert _gaps(_envelope(published), "file_refused")["straddle.txt"]["reason"] == CUTOFF_REASON
    assert KEY_MATERIAL.encode("utf-8") not in published.snapshot_bytes


def test_a_read_that_stops_short_of_the_stated_size_is_refused(
    repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fewer bytes than the file claims, with no error, is a changed file -- not a whole one.

    Refusing is the only honest answer: the retained text is neither the cap nor the file, so it could
    end anywhere inside a secret while the artifact reported no gap at all.
    """
    repo = repository
    body = "filler line\n" * 20_000 + BEGIN + KEY_LINE * 4_000
    (repo / "big.txt").write_text(body, encoding="utf-8")
    monkeypatch.setattr(collect, "os", _ChunkedRead(8192, stop_early=100_000))

    envelope = _envelope(_prepare(repo))

    assert "big.txt" not in _paths(envelope)
    gap = _gaps(envelope, "file_refused")["big.txt"]
    assert gap["reason"] == "file changed while reading"
    assert gap["omitted_bytes"] == len(body.encode("utf-8")), (
        "a body this reader cannot vouch for is lost whole, and the gap says so"
    )
