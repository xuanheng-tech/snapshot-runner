"""Regression and feature tests for Snapshot Runner 2.7.0 (contract 5, epoch 7)."""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from snapshot_runner import artifact as artifact_module
from snapshot_runner import cli, collect, security, verifiers


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["/usr/bin/git", "-C", os.fspath(repo), *args],
        cwd="/",
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def _commit(repo: Path, message: str = "fixture") -> str:
    _git(repo, "add", "-A")
    _git(
        repo,
        "-c",
        "user.name=Friction Test",
        "-c",
        "user.email=friction@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--quiet",
        "-m",
        message,
    )
    return _git(repo, "rev-parse", "HEAD").strip()


@pytest.fixture
def isolated_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    repo = tmp_path / "target-repo"
    repo.mkdir()
    _git(repo, "init", "--quiet", "--initial-branch=main")
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    _commit(repo, "initial")
    return repo, state


def test_epoch_7_is_current_and_earlier_epochs_remain_frozen() -> None:
    assert collect.PRODUCER_SECURITY_EPOCH == 7
    assert verifiers.CURRENT_VERIFIER.producer_security_epoch == 7
    assert verifiers.CURRENT_VERIFIER.is_current is True
    for epoch in (4, 5, 6):
        historical = verifiers.verifier_for(2, epoch)
        assert historical.is_current is False
        with (
            security.era_rules(historical.rules),
            pytest.raises(security.SecurityError, match=f"^{security.YAML_CONTENT_REFUSED}$"),
        ):
            security.classify_scan_mode(".github/workflows/ci.yml")
    assert verifiers.verifier_for(2, 7) is verifiers.CURRENT_VERIFIER
    assert security.classify_scan_mode(".github/workflows/ci.yml") is security.ScanMode.PLAIN_TEXT


def test_benign_yaml_audited_with_secret_redaction_and_branch_review(
    isolated_repo: tuple[Path, Path],
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, _state = isolated_repo
    workflow_dir = repo / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1"
    (workflow_dir / "ci.yml").write_text(
        "name: CI\n"
        "on: [push]\n"
        "env:\n"
        f"  TOKEN: {token}\n"
        "  LOCAL: /Users/alice/private.txt\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n",
        encoding="utf-8",
    )
    assert cli.main(["diff-audit", "--repo", os.fspath(repo), "--summary"], neutral=True) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["status"] == "complete"
    assert summary["evidence_gap"] is False
    snap_bytes = Path(summary["artifact"]).read_bytes()
    assert token.encode() not in snap_bytes
    assert b"/Users/alice/private.txt" not in snap_bytes
    envelope = json.loads(snap_bytes)
    assert envelope["producer_security_epoch"] == 7
    assert envelope["redactions"]["GITHUB_TOKEN"] >= 1
    assert envelope["redactions"]["ABSOLUTE_PATH"] >= 1
    assert any(
        entry["path"] == ".github/workflows/ci.yml"
        and "[REDACTED_GITHUB_TOKEN]" in entry["content"]
        for entry in envelope["data"]["file_context"]
    )

    # Read round-trip validates the epoch-7 YAML artifact cleanly.
    assert (
        cli.main(
            [
                "read",
                summary["snapshot_id"],
                "--repo",
                os.fspath(repo),
                "--path",
                ".github/workflows/ci.yml",
            ],
            neutral=True,
        )
        == 0
    )
    read_out = json.loads(capsys.readouterr().out)
    assert read_out["found"] is True

    # Branch review also audits benign YAML changes without yaml_content_refused.
    _git(repo, "switch", "-qc", "yaml-change")
    _commit(repo, "add workflow")
    assert (
        cli.main(["branch-review", "--repo", os.fspath(repo), "--summary", "main"], neutral=True)
        == 0
    )
    branch_summary = json.loads(capsys.readouterr().out)
    assert branch_summary["status"] == "complete"
    branch_bytes = Path(branch_summary["artifact"]).read_bytes()
    assert token.encode() not in branch_bytes


def test_benign_yaml_with_pem_private_key_fails_soft_without_leaking_key(
    isolated_repo: tuple[Path, Path],
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, _state = isolated_repo
    pem = (
        "-----BEGIN "
        + "PRIVATE KEY-----\n"
        + "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA\n"
        + "-----END "
        + "PRIVATE KEY-----\n"
    )
    (repo / "config.yaml").write_text(f"cert: |\n  {pem}", encoding="utf-8")
    assert cli.main(["diff-audit", "--repo", os.fspath(repo), "--summary"], neutral=True) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["status"] == "partial"
    assert summary["evidence_gap"] is True
    snap_bytes = Path(summary["artifact"]).read_bytes()
    assert b"MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA" not in snap_bytes


@pytest.mark.parametrize(
    "sensitive_path",
    [
        "secrets.yml",
        "secrets.yaml",
        "secret.yml",
        "secret.yaml",
        "credentials.yml",
        "credentials.yaml",
        "credential.yml",
        "credential.yaml",
        "vault.yml",
        "vault.yaml",
        ".secrets.yml",
        ".credentials.yaml",
        "config/secrets.prod.yml",
        "deploy/prod.credentials.yaml",
        ".env.yml",
        ".env.yaml",
        "secrets/app.yaml",
        "credentials/db.yml",
    ],
)
def test_secret_named_yaml_files_remain_blocked_everywhere(
    isolated_repo: tuple[Path, Path],
    capsys: pytest.CaptureFixture[str],
    sensitive_path: str,
) -> None:
    assert security.is_sensitive_repository_path(sensitive_path) is True
    assert security.is_relevant_text_path(sensitive_path) is False
    with pytest.raises(security.SecurityError, match="not an approved text path"):
        security.classify_scan_mode(sensitive_path)

    repo, _state = isolated_repo
    target = repo / sensitive_path
    target.parent.mkdir(parents=True, exist_ok=True)
    marker = "SENSITIVE_YAML_BODY_CANARY_9911"
    target.write_text(f"api_key: {marker}\n", encoding="utf-8")

    assert cli.main(["diff-audit", "--repo", os.fspath(repo), "--summary"], neutral=True) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["status"] == "partial"
    assert summary["evidence_gap"] is True
    snap_bytes = Path(summary["artifact"]).read_bytes()
    assert marker.encode() not in snap_bytes
    envelope = json.loads(snap_bytes)
    assert any(
        gap["kind"] == "file_refused" and gap["subject"] == sensitive_path
        for gap in envelope["evidence_gaps"]
    )


@pytest.mark.parametrize(
    "suffix",
    [
        ".astro",
        ".ps1",
        ".psd1",
        ".psm1",
        ".service",
        ".timer",
        ".policy",
        ".nft",
        ".svg",
        ".mod",
        ".sum",
        ".jsonc",
        ".in",
        ".lark",
        ".patch",
        ".proto",
        ".vue",
        ".svelte",
        ".scss",
        ".less",
        ".zsh",
        ".fish",
        ".cmake",
        ".mk",
    ],
)
def test_epoch_7_allowlist_accepts_benign_source_and_config_extensions(
    isolated_repo: tuple[Path, Path],
    capsys: pytest.CaptureFixture[str],
    suffix: str,
) -> None:
    repo, _state = isolated_repo
    name = f"sample{suffix}"
    (repo / name).write_text("hello world\n", encoding="utf-8")
    assert cli.main(["diff-audit", "--repo", os.fspath(repo), "--summary"], neutral=True) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["status"] == "complete"
    assert summary["evidence_gap"] is False
    envelope = json.loads(Path(summary["artifact"]).read_bytes())
    assert any(entry["path"] == name for entry in envelope["data"]["file_context"])

    # Frozen Epoch 6 still rejects the new extension.
    with (
        security.era_rules(verifiers.verifier_for(2, 6).rules),
        pytest.raises(security.SecurityError, match="not an approved text path"),
    ):
        security.classify_scan_mode(name)


@pytest.mark.parametrize(
    "blocked_name",
    ["doc.pdf", "sheet.docx", "font.ttf", "module.pyc", "raw.bin", "cert.pem", ".npmrc", ".env"],
)
def test_binary_and_secret_exclusions_stay_strict(blocked_name: str) -> None:
    assert security.is_relevant_text_path(blocked_name) is False


def _make_fake_snapshot(
    store: Path, snapshot_id: str, age_days: float, payload_bytes: int = 128
) -> Path:
    snap_dir = store / snapshot_id
    snap_dir.mkdir(mode=0o700)
    (snap_dir / "meta.json").write_bytes(b"{}\n")
    (snap_dir / "preview.txt").write_bytes(b"preview\n")
    (snap_dir / "snapshot.json").write_bytes(b"x" * payload_bytes)
    mtime = time.time() - age_days * 86400.0
    for child in snap_dir.iterdir():
        child.chmod(0o600)
        os.utime(child, (mtime, mtime))
    os.utime(snap_dir, (mtime, mtime))
    return snap_dir


def test_prune_dry_run_keep_ids_keep_file_keep_latest_and_safety(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))

    # Missing store succeeds cleanly with zero counts and does not create directories.
    assert cli.main(["prune", "--older-than-days", "14", "--dry-run"], neutral=True) == 0
    empty_report = json.loads(capsys.readouterr().out)
    assert empty_report["status"] == "complete"
    assert empty_report["scanned"] == 0
    assert empty_report["pruned"] == 0
    assert not (state / "snapshot-runner").exists()

    store = state / "snapshot-runner" / "snapshots"
    store.parent.mkdir(mode=0o700)
    store.mkdir(mode=0o700)

    id_recent = "a" * 64
    id_old_keep_cli = "b" * 64
    id_old_keep_file = "c" * 64
    id_old_latest = "d" * 64
    id_old_prune_1 = "e" * 64
    id_old_prune_2 = "f" * 64

    _make_fake_snapshot(store, id_recent, age_days=2.0, payload_bytes=100)
    _make_fake_snapshot(store, id_old_keep_cli, age_days=45.0, payload_bytes=200)
    _make_fake_snapshot(store, id_old_keep_file, age_days=50.0, payload_bytes=300)
    _make_fake_snapshot(store, id_old_latest, age_days=20.0, payload_bytes=400)
    _make_fake_snapshot(store, id_old_prune_1, age_days=60.0, payload_bytes=500)
    _make_fake_snapshot(store, id_old_prune_2, age_days=90.0, payload_bytes=600)

    # Unexpected entries, staging dirs, and directories with foreign files must never be removed.
    staging = store / ".staging-snapshot-1234"
    staging.mkdir(mode=0o700)
    straggler = store / "not-a-snapshot-id"
    straggler.mkdir(mode=0o700)
    foreign_snap = _make_fake_snapshot(store, "1" * 64, age_days=100.0, payload_bytes=50)
    (foreign_snap / "unexpected.txt").write_text("keep me\n", encoding="utf-8")
    outside = tmp_path / "outside-target"
    outside.mkdir(mode=0o700)
    symlink_snap = store / ("2" * 64)
    symlink_snap.symlink_to(outside)

    keep_file = tmp_path / "keep.txt"
    keep_file.write_text(f"# referenced snapshots\n\n{id_old_keep_file}\n", encoding="utf-8")

    # Dry-run: keeps recent (1), keep_cli (1), keep_file (1), and keep_latest=2 covers recent+old_latest;
    # only old_prune_1 and old_prune_2 are candidates!
    assert (
        cli.main(
            [
                "prune",
                "--older-than-days",
                "14",
                "--keep",
                id_old_keep_cli,
                "--keep-file",
                os.fspath(keep_file),
                "--keep-latest",
                "2",
                "--dry-run",
            ],
            neutral=True,
        )
        == 0
    )
    dry = json.loads(capsys.readouterr().out)
    assert dry["dry_run"] is True
    assert dry["scanned"] == 6
    assert dry["would_prune"] == 2
    assert dry["pruned"] == 0
    assert dry["kept"] == 4
    assert dry["skipped_unexpected"] == 3  # straggler, foreign_snap, symlink_snap
    assert dry["reclaimed_bytes"] == (500 + 600 + 2 * (3 + 8))
    assert (store / id_old_prune_1).is_dir()
    assert (store / id_old_prune_2).is_dir()

    # Live prune deletes ONLY the two unreferenced old snapshots.
    assert (
        cli.main(
            [
                "prune",
                "--older-than-days",
                "14",
                "--keep",
                id_old_keep_cli,
                "--keep-file",
                os.fspath(keep_file),
                "--keep-latest",
                "2",
            ],
            neutral=True,
        )
        == 0
    )
    live = json.loads(capsys.readouterr().out)
    assert live["dry_run"] is False
    assert live["pruned"] == 2
    assert live["would_prune"] == 2
    assert live["reclaimed_bytes"] == dry["reclaimed_bytes"]
    assert not (store / id_old_prune_1).exists()
    assert not (store / id_old_prune_2).exists()
    assert (store / id_recent).is_dir()
    assert (store / id_old_keep_cli).is_dir()
    assert (store / id_old_keep_file).is_dir()
    assert (store / id_old_latest).is_dir()
    assert staging.is_dir()
    assert straggler.is_dir()
    assert foreign_snap.is_dir()
    assert symlink_snap.is_symlink() and outside.is_dir()


@pytest.mark.parametrize(
    "argv",
    [
        ["prune"],
        ["prune", "--older-than-days", "-1"],
        ["prune", "--older-than-days", "14", "--keep-latest", "-2"],
        ["prune", "--older-than-days", "14", "--keep", "SYNTHETIC_BAD_ID"],
    ],
)
def test_prune_rejects_invalid_arguments_safely(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    argv: list[str],
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    assert cli.main(argv, neutral=True) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert f"workflow_failed: {cli.ARGUMENT_ERROR}" in captured.err
    assert "SYNTHETIC_BAD_ID" not in captured.err


def test_prune_rejects_invalid_keep_file_without_deleting_anything(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    store = state / "snapshot-runner" / "snapshots"
    store.parent.mkdir(mode=0o700)
    store.mkdir(mode=0o700)
    snap_id = "a" * 64
    _make_fake_snapshot(store, snap_id, age_days=60.0)

    bad_file = tmp_path / "bad-keep.txt"
    bad_file.write_text("NOT_A_VALID_HEX_ID_SECRET\n", encoding="utf-8")
    assert (
        cli.main(
            ["prune", "--older-than-days", "0", "--keep-file", os.fspath(bad_file)], neutral=True
        )
        == 2
    )
    err = capsys.readouterr().err
    assert cli.ARGUMENT_ERROR in err
    assert "NOT_A_VALID_HEX_ID_SECRET" not in err
    assert (store / snap_id).is_dir()

    # Non-neutral CLI entry (`python -m snapshot_runner.cli prune`) also works.
    assert cli.main(["prune", "--older-than-days", "30", "--dry-run"], neutral=False) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["would_prune"] == 1
    assert out["prune_schema_version"] == artifact_module.PRUNE_SCHEMA_VERSION
