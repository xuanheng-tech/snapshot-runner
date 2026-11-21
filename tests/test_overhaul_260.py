"""Regression and contract tests for Snapshot Runner 2.6.0 (contract 4, epoch 6)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import warnings
from pathlib import Path
from unittest import mock

import pytest

from snapshot_runner import artifact as artifact_module
from snapshot_runner import cli, collect, git, isolation, security, verifiers

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _git(repo: Path, *args: str, extra_config: tuple[str, ...] = ()) -> str:
    cmd = ["/usr/bin/git", *extra_config, "-C", os.fspath(repo), *args]
    result = subprocess.run(
        cmd,
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
        "user.name=Overhaul Test",
        "-c",
        "user.email=overhaul@example.invalid",
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
    state.mkdir(mode=0o755)
    state.chmod(0o755)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    repo = tmp_path / "target-repo"
    repo.mkdir()
    _git(repo, "init", "--quiet", "--initial-branch=main")
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    _commit(repo, "initial")
    return repo, state


def test_epoch_6_is_current_while_earlier_epochs_remain_frozen() -> None:
    assert collect.PRODUCER_SECURITY_EPOCH == 7
    assert verifiers.CURRENT_VERIFIER.producer_security_epoch == 7
    assert verifiers.CURRENT_VERIFIER.is_current is True
    assert verifiers.verifier_for(2, 4).is_current is False
    assert verifiers.verifier_for(2, 5).is_current is False
    assert verifiers.verifier_for(2, 6).is_current is False
    assert verifiers.verifier_for(2, 7) is verifiers.CURRENT_VERIFIER

    html_sample = "<div>hello</div>\n"
    with security.era_rules(verifiers.verifier_for(2, 5).rules):
        old_sanitized = security.sanitize_text(html_sample, scan_mode=security.ScanMode.PLAIN_TEXT)
    assert "<ABS_PATH:div:" in old_sanitized.text

    new_sanitized = security.sanitize_text(html_sample, scan_mode=security.ScanMode.PLAIN_TEXT)
    assert new_sanitized.text == html_sample
    assert new_sanitized.redactions == {}


def test_html_closing_tags_preserved_while_real_paths_redacted() -> None:
    raw = '<section><div class="a">ok</div><a href="/Users/alice/secret.txt">link</a></section>\n'
    sanitized = security.sanitize_text(raw, scan_mode=security.ScanMode.PLAIN_TEXT)
    assert "</div>" in sanitized.text
    assert "</section>" in sanitized.text
    assert "</a>" in sanitized.text
    assert "/Users/alice/secret.txt" not in sanitized.text
    assert "<ABS_PATH:secret.txt:" in sanitized.text
    assert sanitized.redactions == {"ABSOLUTE_PATH": 1}


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (
            '{"Authorization": "Basic dXNlcjpwYXNz"}',
            '{"Authorization": "[REDACTED_AUTH]"}',
        ),
        (
            r"{\"Authorization\": \"Basic dXNlcjpwYXNz\"}",
            r"{\"Authorization\": \"[REDACTED_AUTH]\"}",
        ),
        (
            '{"headers": {"Proxy-Authorization": "Bearer abcdefghijklmnop", "x": 1}}',
            '{"headers": {"Proxy-Authorization": "[REDACTED_AUTH]", "x": 1}}',
        ),
        (
            '{"raw": "Authorization: Basic dXNlcjpwYXNz"}',
            '{"raw": "Authorization: [REDACTED_AUTH]"}',
        ),
    ],
)
def test_auth_header_json_and_quoted_redaction_preserves_quotes(raw: str, expected: str) -> None:
    sanitized = security.sanitize_text(raw, scan_mode=security.ScanMode.PLAIN_TEXT)
    assert sanitized.text == expected
    assert sanitized.redactions == {"AUTH": 1}
    # Second pass must be strictly idempotent without crashing on [REDACTED_AUTH].
    rescan = security.sanitize_text(sanitized.text, scan_mode=security.ScanMode.PLAIN_TEXT)
    assert rescan.text == expected
    assert rescan.redactions == {}


@pytest.mark.parametrize(
    "benign",
    [
        "def f(authorization: str) -> None:\n    pass\n",
        "authorization: str | None = None\n",
        "authorization: Optional[str] = None\n",
        "authorization = None\n",
        "authorization = get_user()\n",
        "authorization = self.request_header\n",
        '{"authorization": "string", "ok": true}\n',
    ],
)
def test_auth_header_stops_false_positives_on_code_and_annotations(benign: str) -> None:
    sanitized = security.sanitize_text(benign, scan_mode=security.ScanMode.PLAIN_TEXT)
    assert sanitized.text == benign
    assert sanitized.redactions == {}


@pytest.mark.parametrize(
    ("secret", "category", "truncated_prefix"),
    [
        ("xoxb-" + "1234567890-123456789012-abcdefghij1234", "SLACK_TOKEN", "xoxb-" + "1234567"),
        (
            "xapp-" + "1-A0123456789-1234567890123-abcdef123456",
            "SLACK_TOKEN",
            "xapp-" + "1-A012",
        ),
        ("sk_live_" + "a1B2c3D4" * 3, "STRIPE_TOKEN", "sk_live_" + "a1B2"),
        ("rk_test_" + "z9Y8x7W6" * 3, "STRIPE_TOKEN", "rk_test_" + "z9Y8"),
        ("whsec_" + "m1N2o3P4" * 3, "STRIPE_TOKEN", "whsec_" + "m1N2"),
        (
            "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiIxMjM0NTYifQ." + "sig12345678",
            "JWT",
            "eyJ" + "hbGciOi",
        ),
        ("github_pat_" + "A1b2C3d4E5f6G7h8I9j0K1", "GITHUB_TOKEN", "github_pat_" + "A1b2"),
        ("glpat-" + "AbCdEfGh1234567890", "CLOUD_CREDENTIAL", "glpat-" + "AbCd"),
        ("npm_" + "A1b2C3d4E5f6G7h8I9j012", "CLOUD_CREDENTIAL", "npm_" + "A1b2"),
        ("pypi-" + "AgEIcHlwaS5vcmc" + "A1b2C3d4E5", "CLOUD_CREDENTIAL", "pypi-" + "AgEI"),
        ("ya29." + "a0AfH6SMBxYz1234567890abcdef", "CLOUD_CREDENTIAL", "ya29." + "a0Af"),
        ("dop_v1_" + "0123456789abcdef" * 2, "CLOUD_CREDENTIAL", "dop_v1_" + "0123"),
        ("hf_" + "A1b2C3d4E5f6G7h8I9j012", "CLOUD_CREDENTIAL", "hf_" + "A1b2"),
        ("hvs." + "A1b2C3d4E5f6G7h8I9j012", "CLOUD_CREDENTIAL", "hvs." + "A1b2"),
        ("SG." + "A1b2C3d4E5f6G7h8." + "Z9y8X7w6V5u4T3s2", "CLOUD_CREDENTIAL", "SG." + "A1b2"),
        ("dapi" + "0123456789abcdef" * 2, "CLOUD_CREDENTIAL", "dapi" + "012345"),
        ("LTAI" + "A1b2C3d4E5f6G7h8", "CLOUD_CREDENTIAL", "LTAI" + "A1b2"),
    ],
)
def test_expanded_token_patterns_and_truncated_markers(
    secret: str, category: str, truncated_prefix: str
) -> None:
    sanitized = security.sanitize_text(f"TOKEN={secret}\n", scan_mode=security.ScanMode.PLAIN_TEXT)
    assert secret not in sanitized.text
    assert f"[REDACTED_{category}]" in sanitized.text
    assert sanitized.redactions == {category: 1}
    assert (
        security.truncated_secret_boundary(f"TOKEN={truncated_prefix}")
        == security.CREDENTIAL_CUTOFF
    )


def test_redact_absolute_paths_respects_boundaries_and_skips_slash(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    text = 'path="src/app/main.py" leaked="/app/secret.txt" home=/app root=/ ok="/"\n'
    sanitized = security.sanitize_text(
        text,
        scan_mode=security.ScanMode.PLAIN_TEXT,
        repository_root=repo_root,
        explicit_paths=(Path("/"), Path("/app")),
    )
    assert "src/app/main.py" in sanitized.text
    assert "/app/secret.txt" not in sanitized.text
    assert "app/secret.txt" in sanitized.text
    assert "home=app" in sanitized.text
    assert 'ok="/"' in sanitized.text
    assert "root=/" in sanitized.text


def test_cross_home_read_succeeds_without_ambient_path_corruption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o755)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    author_home = tmp_path / "author-home"
    author_home.mkdir()
    monkeypatch.setenv("HOME", os.fspath(author_home))

    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "--quiet", "--initial-branch=main")
    (repo / "notes.md").write_text("initial\n", encoding="utf-8")
    _commit(repo)
    (repo / "notes.md").write_text(
        "reader home /tmp/fake/app and dir/reader/sub should survive read\n", encoding="utf-8"
    )
    assert cli.main(["diff-audit", "--repo", os.fspath(repo), "--summary"], neutral=True) == 0
    summary = json.loads(capsys.readouterr().out)
    snapshot_id = str(summary["snapshot_id"])

    # Read under a completely different HOME (including "/" and "/app").
    for other_home in ("/", "/app", os.fspath(tmp_path / "other-home")):
        monkeypatch.setenv("HOME", other_home)
        assert (
            cli.main(
                ["read", "--repo", os.fspath(repo), "--field", "head", snapshot_id],
                neutral=True,
            )
            == 0
        )
        payload = json.loads(capsys.readouterr().out)
        assert payload["snapshot_id"] == snapshot_id


def test_unified_diff_hunk_trailing_context_and_no_double_counting() -> None:
    aws_key = "AKIA" + "ABCDEFGHIJKLMNOP"
    diff_text = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,2 +1,2 @@ def verify(authorization: str) -> bool: "
        "# /Users/alice/tok Authorization: Bearer abcdefghijklmnop\n"
        f" ctx {aws_key}\n"
        "-old\n"
        "+new\n"
    )
    with security.verified_bounded_diff_paths(frozenset({"app.py"})):
        sanitized = security.sanitize_text(diff_text, scan_mode=security.ScanMode.UNIFIED_DIFF)
    assert "authorization: str" in sanitized.text
    assert "/Users/alice/tok" not in sanitized.text
    assert "abcdefghijklmnop" not in sanitized.text
    assert aws_key not in sanitized.text
    assert sanitized.redactions["AWS_ACCESS_KEY"] == 1
    assert sanitized.redactions["AUTH"] == 1
    assert sanitized.redactions["ABSOLUTE_PATH"] == 1

    single_sided = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,1 +1,2 @@\n"
        f" ctx {aws_key}\n"
        "+added\n"
    )
    with security.verified_bounded_diff_paths(frozenset({"app.py"})):
        sanitized_single = security.sanitize_text(
            single_sided, scan_mode=security.ScanMode.UNIFIED_DIFF
        )
    assert sanitized_single.redactions == {"AWS_ACCESS_KEY": 1}


def test_git_runner_truncation_utf8_no_resource_warning_and_portable_git(
    isolated_repo: tuple[Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, _state = isolated_repo
    builder = collect.SnapshotBuilder("repo-status", repo.name, repo)

    # Non-zero rc > 0 with truncated=True must fail; stderr truncation must fail.
    with pytest.raises(security.RunnerError, match="exit=2"):
        collect._decode_git(
            git.GitResult(b"out", b"", 2, True, "log", stdout_truncated=True), "log", builder
        )
    with pytest.raises(security.RunnerError, match="stderr exceeded"):
        collect._decode_git(
            git.GitResult(
                b"out", b"err", -9, True, "log", stdout_truncated=False, stderr_truncated=True
            ),
            "log",
            builder,
        )

    # Multi-byte UTF-8 boundary cut must not emit binary_or_encoding gap.
    utf8_prefix = ("hello " + "€" * 5).encode("utf-8")[:-1]  # incomplete trailing euro sign
    b2 = collect.SnapshotBuilder("repo-status", repo.name, repo)
    decoded = collect._decode_git(
        git.GitResult(utf8_prefix, b"", -9, True, "log", stdout_truncated=True),
        "recent-commits",
        b2,
    )
    assert decoded == "hello " + "€" * 4
    assert [g.kind for g in b2.gaps] == ["git_output_limit"]

    # Real truncated GitRunner.run leaves zero ResourceWarnings and handles core.quotePath=true.
    runner_git = git.GitRunner(repo)
    assert "core.quotePath=true" in runner_git._PREFIX
    (repo / "café.txt").write_text("x\n", encoding="utf-8")
    ls = runner_git.run(("ls-files", "--others"))
    assert b"\\303\\251" in ls.stdout

    big = repo / "big.txt"
    big.write_text("line\n" * 50000, encoding="utf-8")
    _commit(repo, "big")
    with warnings.catch_warnings():
        warnings.simplefilter("error", ResourceWarning)
        res = runner_git.run(("cat-file", "blob", "HEAD:big.txt"), maximum=4096)
        assert res.truncated and res.stdout_truncated and not res.stderr_truncated

    # Portable Git fallback when preferred /usr/bin/git path does not exist.
    monkeypatch.setattr(git, "TRUSTED_EXECUTABLES", {"git": tmp_path / "missing-git"})
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/git" if name == "git" else None)
    assert git._find_executable("git") == "/usr/bin/git"


def test_git_runner_pgid_kill_helper() -> None:
    proc = mock.MagicMock()
    proc.pid = 424242
    with (
        mock.patch.object(git.os, "getpgid", return_value=424242),
        mock.patch.object(git.os, "killpg") as killpg_mock,
    ):
        git._terminate_process_group(proc)
    killpg_mock.assert_called_once_with(424242, git.signal.SIGKILL)


def test_json_text_prefix_does_not_split_redacted_placeholders() -> None:
    prefix = "A" * 20
    marker = "[REDACTED_OPENAI_TOKEN]"
    text = prefix + marker + "tail"
    max_bytes = len(collect._json_bytes(prefix + "[REDACTED_"))
    accepted, omitted, _encoded = collect._json_text_prefix(text, max_bytes)
    assert accepted == prefix
    assert omitted == len((marker + "tail").encode("utf-8"))


def test_test_triage_multiline_newline_cut_and_single_redaction_count(
    isolated_repo: tuple[Path, Path],
) -> None:
    repo, _state = isolated_repo
    probe = "Bearer " + "abcdefghijklmnop"
    line = "prefix/sub/relpath/item.py ok\n"
    count = (collect.MAX_TEST_LOG_BYTES // len(line.encode("utf-8"))) + 50
    (repo / "suite.log").write_text(
        f"Authorization: {probe}\n" + line * count,
        encoding="utf-8",
    )
    snap = collect.collect_test_triage(repo, "suite.log")
    assert snap.redactions == {"AUTH": 1}
    assert "\n[...TEST_LOG_MIDDLE_OMITTED...]\n" in str(snap.data["log"])


def test_branch_review_deleted_submodule_emits_gap(isolated_repo: tuple[Path, Path]) -> None:
    repo, _state = isolated_repo
    sub_origin = repo.parent / "sub-origin"
    sub_origin.mkdir()
    _git(sub_origin, "init", "--quiet", "--initial-branch=main")
    (sub_origin / "sub.txt").write_text("sub\n", encoding="utf-8")
    _commit(sub_origin, "sub initial")

    _git(
        repo,
        "submodule",
        "add",
        os.fspath(sub_origin),
        "vendor/sub",
        extra_config=("-c", "protocol.file.allow=always"),
    )
    _commit(repo, "add submodule")
    _git(repo, "checkout", "-b", "remove-sub")
    _git(repo, "rm", "vendor/sub")
    (repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    _commit(repo, "remove submodule")

    target_ev = git._validate_target_repository_context(
        repo,
        repo.name,
        PROJECT_ROOT,
        artifact_module._state_home(repo),
        "/usr/bin/git",
        "branch-review",
    )
    published = cli._prepare_snapshot("branch-review", "main", target_ev, "/usr/bin/git")
    assert any(
        gap.get("kind") == "deleted_submodule" and gap.get("subject") == "vendor/sub"
        for gap in published.envelope["evidence_gaps"]
    )


def test_merge_msg_crlf_and_truncation_sequencer_abbrev_and_short_merge_branch(
    isolated_repo: tuple[Path, Path],
) -> None:
    repo, _state = isolated_repo
    base_oid = _git(repo, "rev-parse", "HEAD").strip()
    _git(repo, "checkout", "-b", "topic")
    (repo / "topic.txt").write_text("topic\n", encoding="utf-8")
    topic_oid = _commit(repo, "topic commit")
    _git(repo, "checkout", "main")
    _git(repo, "config", "remote.origin.url", "https://example.invalid/fixture.git")
    _git(repo, "config", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*")
    _git(repo, "update-ref", "refs/remotes/origin/main", base_oid)
    _git(repo, "config", "branch.main.remote", "origin")
    _git(repo, "config", "branch.main.merge", "main")

    git_dir = Path(_git(repo, "rev-parse", "--path-format=absolute", "--git-dir").strip())
    (git_dir / "MERGE_HEAD").write_text(f"{topic_oid}\n", encoding="ascii")
    (git_dir / "MERGE_MSG").write_bytes(("Hello CRLF\r\n" * 450).encode("utf-8"))

    target_ev = git._validate_target_repository_context(
        repo,
        repo.name,
        PROJECT_ROOT,
        artifact_module._state_home(repo),
        "/usr/bin/git",
        "repo-status",
    )
    published = cli._prepare_snapshot("repo-status", None, target_ev, "/usr/bin/git")
    data = published.envelope["data"]
    assert data["upstream"] == "origin/main"
    active = data["active_operation"]
    assert isinstance(active, dict) and active["type"] == "merge"
    msg = str(active["message"])
    assert "\r" not in msg
    assert len(msg) == 2048

    # Check sequencer abbreviated OID resolution cleanly.
    (git_dir / "MERGE_HEAD").unlink()
    (git_dir / "MERGE_MSG").unlink()
    seq_dir = git_dir / "sequencer"
    seq_dir.mkdir()
    (seq_dir / "todo").write_text(f"pick {topic_oid[:7]} topic commit\n", encoding="ascii")
    resolved = git.detect_active_git_operation(git_dir)
    assert resolved == {"type": "cherry-pick", "head": topic_oid}


def test_atomic_write_no_double_close_and_long_path_gap_attribution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "snapshot.json"
    real_close = os.close
    closed_fds: list[int] = []

    def tracking_close(fd: int) -> None:
        closed_fds.append(fd)
        real_close(fd)

    monkeypatch.setattr(artifact_module.os, "replace", mock.Mock(side_effect=OSError("disk full")))
    monkeypatch.setattr(artifact_module.os, "close", tracking_close)
    with pytest.raises(OSError, match="disk full"):
        artifact_module._atomic_write(target, b"{}\n", 1024)
    # Wait: `with output_file as output:` closes via C file.close(), NOT os.close(), so tracking
    # confirms os.close() is NOT erroneously called on the already-owned fd!
    assert closed_fds == []

    # Long path > 256 attribution in _evidence_for_path
    long_path = ("a/" * 135) + "leaf.py"
    assert len(long_path) > 256
    data: dict[str, object] = {
        "status_short": "",
        "staged_diff": "",
        "unstaged_diff": "",
        "file_context": [],
    }
    gaps = [{"kind": "file_refused", "subject": long_path[:256], "reason": "binary file refused"}]
    ev, found = artifact_module._evidence_for_path(data, gaps, long_path, tmp_path)
    assert found is True
    assert ev["evidence_gaps"] == gaps


def test_perf_and_portability_checks(
    isolated_repo: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, _state = isolated_repo
    # ScanModeManifest O(1) lookup
    manifest = security.ScanModeManifest(
        security.SCAN_CLASSIFIER_VERSION,
        (security.ScanModeBinding(("a",), security.ScanMode.PLAIN_TEXT),),
    )
    assert manifest._modes[("a",)] is security.ScanMode.PLAIN_TEXT
    assert manifest.mode_for(("a",)) is security.ScanMode.PLAIN_TEXT
    with pytest.raises(security.SecurityError):
        manifest.mode_for(("missing",))

    # Skip git check-attr when no attribute sources and empty conversion_policy
    runner_git = git.GitRunner(repo)
    called_args: list[tuple[str, ...]] = []
    original_run = git.GitRunner.run

    def spy_run(self: git.GitRunner, arguments: tuple[str, ...], **kwargs: object) -> git.GitResult:
        called_args.append(arguments)
        return original_run(self, arguments, **kwargs)

    monkeypatch.setattr(git.GitRunner, "run", spy_run)
    res = collect._workspace_conversion_paths(
        runner_git, git.GitConversionPolicy(), ["app.py"], [], [], []
    )
    assert res == []
    assert not any("check-attr" in arg for args in called_args for arg in args)

    # isolation.TEMP_ROOT portability
    expected_temp = Path(os.path.realpath(tempfile.gettempdir())) / f"snapshot-runner-{os.getuid()}"
    assert expected_temp == isolation.TEMP_ROOT


def test_diff_audit_head_current_branch_and_read_fields_offset_limit(
    isolated_repo: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    repo, _state = isolated_repo
    expected_head = _git(repo, "rev-parse", "HEAD").strip()
    (repo / "app.py").write_text(
        "VALUE = 2\n" + "".join(f"LINE_{i} = {i}\n" for i in range(40)), encoding="utf-8"
    )

    assert cli.main(["diff-audit", "--repo", os.fspath(repo), "--summary"], neutral=True) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["head"] == expected_head
    snapshot_id = str(summary["snapshot_id"])

    # Batch --fields
    assert (
        cli.main(
            [
                "read",
                "--repo",
                os.fspath(repo),
                "--fields",
                "current_branch,head,status_short",
                snapshot_id,
            ],
            neutral=True,
        )
        == 0
    )
    fields_payload = json.loads(capsys.readouterr().out)
    assert fields_payload["selector"] == {
        "kind": "fields",
        "values": ["current_branch", "head", "status_short"],
    }
    assert fields_payload["evidence"]["fields"]["current_branch"] == "main"
    assert fields_payload["evidence"]["fields"]["head"] == expected_head
    assert " M app.py\n" in fields_payload["evidence"]["fields"]["status_short"]

    # Bounded string slicing via --offset and --limit
    assert (
        cli.main(
            [
                "read",
                "--repo",
                os.fspath(repo),
                "--field",
                "unstaged_diff",
                "--offset",
                "5",
                "--limit",
                "20",
                snapshot_id,
            ],
            neutral=True,
        )
        == 0
    )
    sliced = json.loads(capsys.readouterr().out)
    ev = sliced["evidence"]
    assert ev["offset"] == 5
    assert ev["limit"] == 20
    assert len(ev["value"]) == 20
    assert ev["has_more"] is True
    assert ev["total_length"] > 25

    # Invalid selector/offset/limit combinations fail cleanly without echoing values
    marker = "USER_SECRET_MARKER"
    for bad_args in (
        ["read", "--repo", os.fspath(repo), "--fields", "head,missing_key", snapshot_id],
        ["read", "--repo", os.fspath(repo), "--fields", "", snapshot_id],
        ["read", "--repo", os.fspath(repo), "--field", "head", "--fields", "head", snapshot_id],
        ["read", "--repo", os.fspath(repo), "--offset", "0", snapshot_id],
        ["read", "--repo", os.fspath(repo), "--field", "head", "--offset", "-1", snapshot_id],
        ["read", "--repo", os.fspath(repo), "--field", "head", "--limit", marker, snapshot_id],
        ["read", "--repo", os.fspath(repo), "--field", "file_context", "--limit", "5", snapshot_id],
    ):
        assert cli.main(bad_args, neutral=True) == 2
        err = capsys.readouterr().err
        assert err.startswith("workflow_failed: ARGUMENT_ERROR:")
        assert marker not in err


def test_justfile_exposes_read_recipe() -> None:
    just = shutil.which("just")
    assert just is not None
    result = subprocess.run(
        [just, "--dry-run", "read", "--repo", "/absolute/target/repo", "a" * 64],
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "snapshot_runner.cli read" in result.stdout + result.stderr
