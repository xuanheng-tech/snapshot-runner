"""Exercise wheel and sdist installations outside the source checkout."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
TASKS = ("repo-status", "diff-audit", "branch-review", "test-triage")
COMMANDS = (*TASKS, "read")


class PackageCheckError(ValueError):
    """The installed distribution did not satisfy an acceptance check."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PackageCheckError(message)


def run(
    args: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    phase: str,
    expected_exit: int = 0,
    timeout: int = 30,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            args, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        raise PackageCheckError(f"{phase} timed out") from None
    require(result.returncode == expected_exit, f"{phase} failed (exit {result.returncode})")
    return result


def repository_files(repo: Path) -> dict[str, tuple[int, str]]:
    return {
        path.relative_to(repo).as_posix(): (
            stat.S_IMODE(path.stat().st_mode),
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        for path in repo.rglob("*")
        if path.is_file()
    }


def extract_sdist(sdist: Path, version: str, destination: Path) -> Path:
    """Validate the source archive before extracting regular files into a private tree."""
    prefix = PurePosixPath(f"snapshot_runner-{version}")
    required = {
        "pyproject.toml",
        "PKG-INFO",
        "LICENSE",
        "README.md",
        "snapshot_runner/__init__.py",
        "snapshot_runner/cli.py",
        "tool_cli_contract.json",
    }
    try:
        with tarfile.open(sdist, "r:gz") as archive:
            files = {}
            seen = set()
            for member in archive.getmembers():
                path = PurePosixPath(member.name)
                require(
                    not path.is_absolute()
                    and (
                        member.name == path.as_posix()
                        or member.isdir()
                        and member.name.rstrip("/") == path.as_posix()
                    )
                    and ".." not in path.parts
                    and "\\" not in member.name
                    and path.is_relative_to(prefix),
                    "sdist archive contains a non-canonical source path",
                )
                require(member.isfile() or member.isdir(), "sdist archive contains a special entry")
                require(path != prefix or member.isdir(), "sdist source root is not a directory")
                relative = path.relative_to(prefix).as_posix()
                require(relative not in seen, "sdist archive contains a duplicate path")
                require(".git" not in path.parts, "sdist archive contains Git metadata")
                seen.add(relative)
                if member.isfile():
                    files[relative] = member
            require(required <= files.keys(), "sdist is missing required source files")
            require(
                all(files[name].size > 0 for name in required),
                "sdist contains an empty required source file",
            )

            def read(name: str) -> bytes:
                stream = archive.extractfile(files[name])
                if stream is None:
                    raise PackageCheckError("sdist source file could not be read")
                with stream:
                    return stream.read()

            metadata = BytesParser().parsebytes(read("PKG-INFO"))
            require(
                metadata.get_all("Name") == ["snapshot-runner"]
                and metadata.get_all("Version") == [version],
                "sdist package metadata mismatch",
            )
            project = tomllib.loads(read("pyproject.toml").decode("utf-8"))
            project_identity = project.get("project")
            require(
                isinstance(project_identity, dict)
                and project_identity.get("name") == "snapshot-runner"
                and project_identity.get("version") == version,
                "sdist project identity mismatch",
            )
            build_system = project.get("build-system")
            require(
                isinstance(build_system, dict)
                and isinstance(build_system.get("build-backend"), str)
                and bool(build_system["build-backend"].strip())
                and isinstance(build_system.get("requires"), list)
                and bool(build_system["requires"])
                and all(
                    isinstance(item, str) and item.strip() for item in build_system["requires"]
                ),
                "sdist build configuration is incomplete",
            )
            destination.mkdir(mode=0o700)
            archive.extractall(destination, filter="data")
    except (tarfile.TarError, tomllib.TOMLDecodeError, UnicodeError):
        raise PackageCheckError("sdist archive or configuration could not be read") from None
    return destination / prefix.name


def check_sdist(sdist: Path, version: str, root: Path) -> dict[str, object]:
    require(not root.is_relative_to(ROOT), "TMPDIR must be outside the source checkout")
    sdist = sdist.resolve(strict=True)
    require(
        sdist.is_file() and sdist.name.endswith(".tar.gz"), "acceptance requires a source archive"
    )
    source_hash = hashlib.sha256(sdist.read_bytes()).hexdigest()
    source = extract_sdist(sdist, version, root / "source")
    uv = shutil.which("uv")
    if uv is None:
        raise PackageCheckError("uv is required for package acceptance")
    run(
        [
            uv,
            "build",
            "--wheel",
            "--force-pep517",
            "--no-config",
            "--no-sources",
            "--out-dir",
            str(root / "dist"),
            "--python",
            sys.executable,
            str(source),
        ],
        cwd=root,
        env=dict(os.environ),
        phase="sdist wheel build",
        timeout=180,
    )
    wheels = list((root / "dist").glob("*.whl"))
    require(len(wheels) == 1, "sdist build must produce exactly one wheel")
    installed = root / "installed"
    installed.mkdir(mode=0o700)
    result = check(wheels[0], version, installed)
    require(
        hashlib.sha256(sdist.read_bytes()).hexdigest() == source_hash,
        "package acceptance modified the sdist",
    )
    result["sdist_sha256"] = source_hash
    return result


def check(wheel: Path, version: str, root: Path) -> dict[str, object]:
    require(not root.is_relative_to(ROOT), "TMPDIR must be outside the source checkout")
    uv = shutil.which("uv")
    if uv is None:
        raise PackageCheckError("uv is required for package acceptance")
    build_env = dict(os.environ)
    wheel = wheel.resolve(strict=True)
    require(wheel.is_file() and wheel.suffix == ".whl", "acceptance requires a wheel file")
    wheel_hash = hashlib.sha256(wheel.read_bytes()).hexdigest()
    venv = root / "venv"
    run(
        [uv, "venv", "--python", sys.executable, str(venv)],
        cwd=root,
        env=build_env,
        phase="isolated environment creation",
        timeout=60,
    )
    python = venv / "bin/python"
    run(
        [
            uv,
            "pip",
            "install",
            "--no-config",
            "--no-index",
            "--no-deps",
            "--python",
            str(python),
            str(wheel),
        ],
        cwd=root,
        env=build_env,
        phase="offline wheel installation",
        timeout=60,
    )
    outside, home, state, repo = (root / name for name in ("outside", "home", "state", "target"))
    for directory in (outside, home, state, repo):
        directory.mkdir(mode=0o700)
    env = {
        "PATH": os.defpath,
        "HOME": str(home),
        "XDG_STATE_HOME": str(state),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "LANG": "C.UTF-8",
    }
    metadata = json.loads(
        run(
            [
                str(python),
                "-I",
                "-c",
                "import importlib.metadata as m, json, snapshot_runner as r, sys; "
                "d = m.distribution('snapshot-runner'); "
                "print(json.dumps({'version': d.version, 'module_version': r.__version__, "
                "'module': r.__file__, 'prefix': sys.prefix, "
                "'scripts': {e.name: e.value for e in d.entry_points "
                "if e.group == 'console_scripts'}}))",
            ],
            cwd=outside,
            env=env,
            phase="installed package import",
        ).stdout
    )
    require(
        metadata["version"] == metadata["module_version"] == version, "installed version mismatch"
    )
    require(Path(metadata["prefix"]) == venv, "installed import must use the isolated environment")
    require(
        Path(metadata["module"]).is_relative_to(venv),
        "installed import resolved outside the environment",
    )
    require(
        metadata["scripts"] == {"snapshot-runner": "snapshot_runner.cli:snapshot_runner_main"},
        "installed console scripts differ from the public interface",
    )

    def git(*args: str) -> str:
        return run(
            [
                "/usr/bin/git",
                "-C",
                str(repo),
                "-c",
                "user.name=Package Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
                *args,
            ],
            cwd=outside,
            env=env,
            phase="synthetic repository setup",
        ).stdout

    git("-c", "init.templateDir=", "init", "-q", "-b", "main")
    value = repo / "value.py"
    value.write_text("value = 1\n", encoding="utf-8")
    (repo / ".gitignore").write_text("failed.log\n", encoding="utf-8")
    git("add", "value.py", ".gitignore")
    git("commit", "-qm", "baseline")
    git("switch", "-qc", "feature")
    value.write_text("value = 2\n", encoding="utf-8")
    git("add", "value.py")
    git("commit", "-qm", "feature")
    value.write_text("value = 3\n", encoding="utf-8")
    git("add", "value.py")
    value.write_text("value = 4\n", encoding="utf-8")
    (repo / "untracked.py").write_text("untracked = True\n", encoding="utf-8")
    (repo / "failed.log").write_text("FAILED package_fixture\n1 failed\n", encoding="utf-8")
    before = repository_files(repo)
    executable = str(venv / "bin/snapshot-runner")

    def cli(*args: str) -> str:
        result = run(
            [executable, *args], cwd=outside, env=env, phase=f"installed {args[0]} acceptance"
        )
        require(result.stderr == "", "successful installed CLI emitted stderr")
        return result.stdout

    for command in (None, *COMMANDS):
        prefix = [] if command is None else [command]
        require(
            cli(*prefix, "--version").strip() == f"snapshot-runner {version}",
            "CLI version mismatch",
        )
        require("usage: snapshot-runner" in cli(*prefix, "--help"), "installed CLI help missing")

    snapshots = {}
    for task in TASKS:
        positional = (
            ["main"] if task == "branch-review" else ["failed.log"] if task == "test-triage" else []
        )
        summary = json.loads(cli(task, "--repo", str(repo), "--summary", *positional))
        require(
            summary["status"] == "complete" and not summary["evidence_gap"],
            f"{task} evidence incomplete",
        )
        artifact = Path(summary["artifact"])
        require(artifact.is_relative_to(state), "artifact escaped the private state directory")
        require(
            hashlib.sha256(artifact.read_bytes()).hexdigest() == summary["snapshot_id"],
            "artifact identity mismatch",
        )
        require(stat.S_IMODE(artifact.stat().st_mode) == 0o600, "artifact file mode mismatch")
        require(
            stat.S_IMODE(artifact.parent.stat().st_mode) == 0o700,
            "artifact directory mode mismatch",
        )
        snapshots[task] = summary
    require(snapshots["branch-review"]["result"]["commits"] == 1, "sealed branch range mismatch")
    require(
        snapshots["test-triage"]["next_action"] == "open_artifact",
        "test log collection must require review",
    )
    snapshot_id = snapshots["diff-audit"]["snapshot_id"]
    for selector in ([], ["--path", "value.py"], ["--field", "status_short"]):
        read = json.loads(cli("read", snapshot_id, "--repo", str(repo), *selector))
        require(
            read["found"] and read["runner_version"] == version,
            "installed evidence reader mismatch",
        )
        require(read["snapshot_id"] == snapshot_id, "evidence reader selected another snapshot")
        if selector == ["--path", "value.py"]:
            require(
                "value = 4" in json.dumps(read["evidence"]),
                "installed evidence reader omitted changed content",
            )
    rejected = run(
        [executable, "repo-status", "--PACKAGE_CHECK_MARKER"],
        cwd=outside,
        env=env,
        phase="installed argument rejection",
        expected_exit=2,
    )
    require(
        rejected.stdout == "" and "ARGUMENT_ERROR" in rejected.stderr,
        "installed argument error mismatch",
    )
    require(
        "PACKAGE_CHECK_MARKER" not in rejected.stderr, "installed argument error echoed its input"
    )
    require(repository_files(repo) == before, "installed CLI modified the target repository")
    require(
        hashlib.sha256(wheel.read_bytes()).hexdigest() == wheel_hash,
        "package acceptance modified the wheel",
    )
    return {
        "status": "PASS",
        "version": version,
        "python": sys.version.split()[0],
        "commands": COMMANDS,
        "wheel_sha256": wheel_hash,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--wheel", type=Path, help="check an existing wheel; may be combined with --sdist"
    )
    parser.add_argument("--sdist", type=Path, help="build and check an existing source archive")
    parser.add_argument("--expected-version", help="defaults to the source project version")
    args = parser.parse_args(argv)
    try:
        with (ROOT / "pyproject.toml").open("rb") as stream:
            version = args.expected_version or tomllib.load(stream)["project"]["version"]
        with tempfile.TemporaryDirectory(prefix="snapshot-runner-package-check-") as temporary:
            root = Path(temporary).resolve()
            require(not root.is_relative_to(ROOT), "TMPDIR must be outside the source checkout")
            wheel, sdist = args.wheel, args.sdist
            if wheel is None and sdist is None:
                uv = shutil.which("uv")
                if uv is None:
                    raise PackageCheckError("uv is required for package acceptance")
                run(
                    [uv, "build", "--out-dir", str(root / "dist"), "--python", sys.executable],
                    cwd=ROOT,
                    env=dict(os.environ),
                    phase="distribution build",
                    timeout=180,
                )
                wheels = list((root / "dist").glob("*.whl"))
                sdists = list((root / "dist").glob("*.tar.gz"))
                require(
                    len(wheels) == len(sdists) == 1, "build must produce one wheel and one sdist"
                )
                wheel, sdist = wheels[0], sdists[0]
            result = {}
            if wheel is not None:
                installed = root / "wheel-check"
                installed.mkdir(mode=0o700)
                result = check(wheel, version, installed)
            if sdist is not None:
                source = root / "sdist-check"
                source.mkdir(mode=0o700)
                source_result = check_sdist(sdist, version, source)
                if result:
                    result["sdist"] = source_result
                else:
                    result = source_result
            if wheel is not None:
                require(
                    hashlib.sha256(wheel.read_bytes()).hexdigest() == result["wheel_sha256"],
                    "package acceptance modified the original wheel",
                )
        print(json.dumps(result, sort_keys=True))
    except (PackageCheckError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"package_check_failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
