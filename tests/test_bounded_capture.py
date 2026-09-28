"""Bounded test-log and Git-output capture across truncation boundaries."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from test_truncated_secret_boundary import BEGIN, END, KEY_LINE, _prepare
from test_truncated_secret_boundary import repository as repository

from snapshot_runner import collect, git, security


@pytest.mark.parametrize("shape", ["tail_closer", "hidden_both"])
def test_test_log_cut_cannot_hide_private_key_boundaries(
    repository: Path, monkeypatch: pytest.MonkeyPatch, shape: str
) -> None:
    monkeypatch.setattr(collect, "MAX_TEST_LOG_BYTES", 256)
    body = "ordinary\n" * 40 + BEGIN + KEY_LINE * (4 if shape == "tail_closer" else 60)
    if shape == "tail_closer":
        body += END
    (repository / "large.log").write_text(body)
    with pytest.raises(security.RunnerError):
        _prepare(repository, "test-triage", "large.log")


def test_test_log_redacts_a_credential_with_an_omitted_prefix(
    repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(collect, "MAX_TEST_LOG_BYTES", 256)
    token = "sk-" + "proj-" + "z" * 500
    (repository / "large.log").write_text("ordinary\n" * 40 + token + "\n")
    prepared = _prepare(repository, "test-triage", "large.log")
    envelope = json.loads((prepared.directory / "snapshot.json").read_text())
    assert "z" * 40 not in envelope["data"]["log"]
    assert envelope["redactions"]["OPENAI_TOKEN"] == 1


def test_test_log_utf8_is_validated_before_the_head_tail_cut(
    repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(collect, "MAX_TEST_LOG_BYTES", 256)
    (repository / "unicode.log").write_text("中" * 1_000 + "tail\n")
    prepared = _prepare(repository, "test-triage", "unicode.log")
    envelope = json.loads((prepared.directory / "snapshot.json").read_text())
    assert envelope["data"]["log"].endswith("tail\n")
    assert len(envelope["data"]["log"].encode()) <= collect.MAX_TEST_LOG_BYTES
    assert envelope["evidence_gaps"]


def test_test_log_short_reads_do_not_publish_an_unreported_prefix(
    repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = "ordinary output\n" * 40
    (repository / "short-read.log").write_text(body)
    original = os.read
    monkeypatch.setattr(
        collect.os, "read", lambda descriptor, size: original(descriptor, min(size, 7))
    )
    text, omitted, _, redactions = collect._read_test_log(repository, "short-read.log")
    assert text == body
    assert omitted == 0
    assert redactions == {}


def test_test_log_scan_has_a_separate_hard_bound(
    repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(collect, "MAX_TEST_LOG_SCAN_BYTES", 64)
    (repository / "too-large.log").write_text("ordinary\n" * 20)
    with pytest.raises(security.RunnerError, match="validation hard limit"):
        _prepare(repository, "test-triage", "too-large.log")


@pytest.mark.parametrize("prefix", [BEGIN + KEY_LINE * 40, "sk-" + "proj-" + "z" * 100])
def test_truncated_git_log_withholds_an_unredactable_prefix(
    repository: Path, monkeypatch: pytest.MonkeyPatch, prefix: str
) -> None:
    original = git.GitRunner.run

    def run(self: git.GitRunner, arguments: tuple[str, ...], **kwargs) -> git.GitResult:
        if "log" in arguments:
            return git.GitResult(prefix.encode(), b"", -9, True, "log")
        return original(self, arguments, **kwargs)

    monkeypatch.setattr(git.GitRunner, "run", run)
    prepared = _prepare(repository, "repo-status")
    envelope = json.loads((prepared.directory / "snapshot.json").read_text())
    assert envelope["data"]["recent_commits"] == ""
    assert {gap["kind"] for gap in envelope["evidence_gaps"]} >= {
        "git_output_limit",
        "git_output_refused",
    }
    assert prefix not in (prepared.directory / "snapshot.json").read_text()


def test_truncated_benign_git_log_keeps_its_prefix(tmp_path: Path) -> None:
    builder = collect.SnapshotBuilder("repo-status", "target", tmp_path)
    text = "ordinary commit\n" * 40
    assert (
        collect._decode_git(
            git.GitResult(text.encode(), b"", -9, True, "log"), "recent-commits", builder
        )
        == text
    )
    assert [gap.kind for gap in builder.gaps] == ["git_output_limit"]
