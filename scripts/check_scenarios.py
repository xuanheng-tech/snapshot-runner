"""Measure a small, offline scenario baseline through an installed public CLI."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import stat
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = (
    ("clean", "repo-status", "complete"),
    ("workspace", "diff-audit", "complete"),
    ("quoted-path", "diff-audit", "complete"),
    ("scoped", "diff-audit", "complete"),
    ("unborn", "diff-audit", "complete"),
    ("long-branch", "repo-status", "complete"),
    ("custom-upstream", "repo-status", "complete"),
    ("unborn-upstream", "repo-status", "complete"),
    ("branch-rename", "branch-review", "complete"),
    ("unstaged-type-change", "diff-audit", "partial"),
    ("staged-type-change", "diff-audit", "partial"),
    ("branch-type-change", "branch-review", "complete"),
    ("extensionless", "diff-audit", "complete"),
    ("binary", "diff-audit", "partial"),
    ("large-context", "diff-audit", "partial"),
    ("yaml-boundary", "diff-audit", "refused"),
    ("test-log", "test-triage", "complete"),
    ("large-test-log", "test-triage", "partial"),
)


def run(args: list[str], env: dict[str, str], cwd: Path) -> subprocess.CompletedProcess[bytes]:
    with subprocess.Popen(
        args,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    ) as process:
        try:
            stdout, stderr = process.communicate(timeout=45)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise RuntimeError("scenario command timed out") from None
        return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)


def git(repo: Path, env: dict[str, str], *args: str) -> str:
    result = run(
        [
            "/usr/bin/git",
            "-C",
            str(repo),
            "-c",
            "init.templateDir=",
            "-c",
            "user.name=Scenario Fixture",
            "-c",
            "user.email=scenario@example.invalid",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=false",
            *args,
        ],
        env,
        repo.parent,
    )
    if result.returncode:
        raise RuntimeError("synthetic repository setup failed")
    return result.stdout.decode("utf-8").strip()


def manifest(repo: Path) -> dict[str, tuple[object, ...]]:
    entries = {}
    for path in repo.rglob("*"):
        metadata = path.lstat()
        content = (
            os.readlink(path).encode("utf-8")
            if stat.S_ISLNK(metadata.st_mode)
            else path.read_bytes()
            if stat.S_ISREG(metadata.st_mode)
            else b""
        )
        entries[path.relative_to(repo).as_posix()] = (
            metadata.st_mode,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
            hashlib.sha256(content).hexdigest(),
        )
    return entries


def setup(name: str, root: Path, env: dict[str, str]) -> tuple[Path, list[str]]:
    repo = root / "repo"
    repo.mkdir()
    git(repo, env, "init", "-q", "-b", "main")
    value = repo / "safe.py"
    value.write_text("VALUE = 1\n", encoding="utf-8")
    git(repo, env, "add", "safe.py")
    git(repo, env, "commit", "-qm", "baseline")
    git(repo, env, "branch", "base")
    extra = []
    if name in {"unborn", "unborn-upstream"}:
        git(repo, env, "update-ref", "-d", "refs/heads/main")
    if name in {"workspace", "scoped"}:
        value.write_text("VALUE = 2\n", encoding="utf-8")
        git(repo, env, "add", "safe.py")
        value.write_text("VALUE = 3\n", encoding="utf-8")
        (repo / "untracked.py").write_text("ADDED = True\n", encoding="utf-8")
        if name == "scoped":
            extra = ["--scope-path", "safe.py"]
    elif name == "quoted-path":
        (repo / "模型 [test]*?.py").write_text("UNICODE = True\n", encoding="utf-8")
    elif name in {"custom-upstream", "unborn-upstream", "long-branch"}:
        branch = "main"
        if name == "long-branch":
            branch = "feature/" + "x" * 120 + "/" + "y" * 135
            git(repo, env, "branch", "-m", branch)
        git(repo, env, "config", "remote.origin.url", "https://example.invalid/fixture.git")
        git(
            repo,
            env,
            "config",
            "remote.origin.fetch",
            "+refs/heads/main:refs/remotes/tracking/stable",
        )
        git(repo, env, "config", f"branch.{branch}.remote", "origin")
        git(repo, env, "config", f"branch.{branch}.merge", "refs/heads/main")
        git(repo, env, "update-ref", "refs/remotes/tracking/stable", "refs/heads/base")
    elif name == "branch-rename":
        git(repo, env, "mv", "safe.py", "renamed.py")
        git(repo, env, "commit", "-qm", "rename")
    elif name in {"unstaged-type-change", "staged-type-change", "branch-type-change"}:
        outside = root / "outside.py"
        outside.write_text("OUTSIDE_BODY_CANARY\n", encoding="utf-8")
        value.unlink()
        value.symlink_to(outside)
        if name == "branch-type-change":
            git(repo, env, "add", "safe.py")
            git(repo, env, "commit", "-qm", "link baseline")
            git(repo, env, "branch", "-f", "base", "HEAD")
            value.unlink()
            value.write_text("VALUE = 42\n", encoding="utf-8")
        if name != "unstaged-type-change":
            git(repo, env, "add", "safe.py")
        if name == "branch-type-change":
            git(repo, env, "commit", "-qm", "regular file")
    elif name == "extensionless":
        (repo / "project-entry").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    elif name == "binary":
        (repo / "unknown.bin").write_bytes(b"\x00\xff\x01")
    elif name == "large-context":
        (repo / "large.txt").write_text("line\n" * (60 * 1024), encoding="utf-8")
    elif name == "yaml-boundary":
        (repo / "config.yaml").write_text("enabled: true\n", encoding="utf-8")
    elif name in {"test-log", "large-test-log"}:
        count = 250_000 if name == "large-test-log" else 1
        (repo / "failed.log").write_text("fixture failed\n" * count, encoding="utf-8")
    return repo, extra


def check_case(
    executable: Path, name: str, task: str, expected: str, root: Path, repeat: int
) -> dict:
    root.mkdir(mode=0o700)
    home, state, temporary = (root / entry for entry in ("home", "state", "tmp"))
    for directory in (home, state, temporary):
        directory.mkdir(mode=0o700)
    env = {
        "PATH": os.defpath,
        "HOME": str(home),
        "XDG_STATE_HOME": str(state),
        "TMPDIR": str(temporary),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "LANG": "C.UTF-8",
        "GIT_AUTHOR_DATE": "2026-01-01T00:00:00+00:00",
        "GIT_COMMITTER_DATE": "2026-01-01T00:00:00+00:00",
    }
    repo, extra = setup(name, root, env)
    if task == "branch-review":
        extra += ["base"]
    if task == "test-triage":
        extra += ["failed.log"]
    before = manifest(repo)
    durations, rss, snapshot_ids = [], [], set()
    errors = []
    summary = {}
    snapshot_bytes = b""
    output_bytes = 0
    for index in range(repeat):
        command = [str(executable), task, "--repo", str(repo), "--summary", *extra]
        measurement = root / f"rss-{index}.txt"
        if Path("/usr/bin/time").is_file():
            command = ["/usr/bin/time", "-f", "%M", "-o", str(measurement), "--", *command]
        started = time.monotonic()
        result = run(command, env, root)
        durations.append(time.monotonic() - started)
        output_bytes = len(result.stdout)
        if measurement.exists():
            rss.append(int(measurement.read_text().splitlines()[-1]))
        if expected == "refused":
            if (
                result.returncode != 2
                or b"yaml_content_refused" not in result.stderr
                or result.stdout
            ):
                errors.append("expected YAML boundary refusal")
            if list(state.rglob("snapshot.json")):
                errors.append("refused collection published evidence")
            continue
        if result.returncode:
            errors.append("collection failed")
            continue
        summary = json.loads(result.stdout)
        if summary["status"] != expected:
            errors.append("unexpected evidence completeness")
        if (
            name in {"custom-upstream", "unborn-upstream", "long-branch"}
            and summary["result"]["upstream"] != "tracking/stable"
        ):
            errors.append("incorrect upstream mapping")
        snapshot_bytes = Path(summary["artifact"]).read_bytes()
        if b"OUTSIDE_BODY_CANARY" in snapshot_bytes:
            errors.append("symlink target body was collected")
        if "type-change" in name:
            data = json.loads(snapshot_bytes)["data"]
            patch = (
                data["diff"]
                if task == "branch-review"
                else data["staged_diff" if name == "staged-type-change" else "unstaged_diff"]
            )
            if "deleted file mode" not in patch or "new file mode" not in patch:
                errors.append("type-change patch is incomplete")
        snapshot_ids.add(summary["snapshot_id"])
    read_bytes = None
    if summary:
        if task == "repo-status":
            selector = ["--field", "head"]
        elif task == "test-triage":
            selector = ["--field", "log"]
        else:
            path = {
                "branch-rename": "renamed.py",
                "quoted-path": "模型 [test]*?.py",
                "extensionless": "project-entry",
                "binary": "unknown.bin",
                "large-context": "large.txt",
            }.get(name, "safe.py")
            selector = ["--path", path]
        read = run(
            [
                str(executable),
                "read",
                summary["snapshot_id"],
                "--repo",
                str(repo),
                *selector,
            ],
            env,
            root,
        )
        if read.returncode or not json.loads(read.stdout)["found"]:
            errors.append("targeted read failed")
        read_bytes = len(read.stdout)
    if len(snapshot_ids) > 1:
        errors.append("repeated collection changed snapshot identity")
    if manifest(repo) != before:
        errors.append("collection modified the target repository")
    return {
        "case": name,
        "command": task,
        "expected": expected,
        "status": "FAIL" if errors else "PASS",
        "errors": sorted(set(errors)),
        "samples": repeat,
        "seconds_median": round(statistics.median(durations), 4),
        "seconds_max": round(max(durations), 4),
        "max_rss_kib": max(rss) if rss else None,
        "summary_bytes": output_bytes,
        "targeted_read_bytes": read_bytes,
        "snapshot_bytes": len(snapshot_bytes),
        "snapshot_store_bytes": sum(p.stat().st_size for p in state.rglob("*") if p.is_file()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--executable", required=True, type=Path, help="installed snapshot-runner entry"
    )
    parser.add_argument("--repeat", type=int, choices=range(1, 11), default=3)
    args = parser.parse_args()
    executable = args.executable.resolve(strict=True)
    if executable.is_relative_to(ROOT):
        parser.error("use an installed CLI outside the source checkout")
    with tempfile.TemporaryDirectory(prefix="snapshot-runner-scenarios-") as directory:
        root = Path(directory).resolve()
        if root.is_relative_to(ROOT):
            parser.error("TMPDIR must be outside the source checkout")
        rows = [
            check_case(executable, name, task, expected, root / name, args.repeat)
            for name, task, expected in CASES
        ]
        version = run([str(executable), "--version"], {"PATH": os.defpath}, root)
        result = {
            "status": "PASS" if all(row["status"] == "PASS" for row in rows) else "FAIL",
            "runner": version.stdout.decode().strip(),
            "scenarios": rows,
        }
        print(json.dumps(result, sort_keys=True))
        return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
