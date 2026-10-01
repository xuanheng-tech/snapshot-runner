"""Source distributions must work independently and remain immutable during acceptance."""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import tarfile
from pathlib import Path

import pytest

from scripts import check_package as p

VERSION = "1.2.3"
PREFIX = f"snapshot_runner-{VERSION}"
PROJECT = (
    '[project]\nname = "snapshot-runner"\nversion = "1.2.3"\n'
    '[build-system]\nrequires = ["uv_build>=0.12.1,<0.13"]\nbuild-backend = "uv_build"\n'
)
SOURCE_FILES = {
    "pyproject.toml": PROJECT.encode(),
    "PKG-INFO": b"Metadata-Version: 2.4\nName: snapshot-runner\nVersion: 1.2.3\n",
    "LICENSE": b"Fixture license text\n",
    "README.md": b"Fixture package\n",
    "snapshot_runner/__init__.py": b'__version__ = "1.2.3"\n',
    "snapshot_runner/cli.py": b"def snapshot_runner_main(): pass\n",
    "tool_cli_contract.json": b"{}\n",
}


def write_sdist(
    tmp_path: Path,
    files: dict[str, bytes] | None = None,
    extra: tuple[tarfile.TarInfo, bytes | None] | None = None,
) -> Path:
    target = tmp_path / f"{PREFIX}.tar.gz"
    with tarfile.open(target, "w:gz") as archive:
        for name, content in (SOURCE_FILES if files is None else files).items():
            member = tarfile.TarInfo(f"{PREFIX}/{name}")
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        if extra is not None:
            member, content = extra
            if content is not None:
                member.size = len(content)
            archive.addfile(member, None if content is None else io.BytesIO(content))
    return target


def test_source_archive_extracts_complete_tree_without_git(tmp_path: Path) -> None:
    archive = write_sdist(tmp_path)
    before = archive.read_bytes()
    source = p.extract_sdist(archive, VERSION, tmp_path / "source")
    assert source == tmp_path / "source" / PREFIX
    assert not (source / ".git").exists()
    assert {
        path.relative_to(source).as_posix(): path.read_bytes()
        for path in source.rglob("*")
        if path.is_file()
    } == SOURCE_FILES
    assert archive.read_bytes() == before


@pytest.mark.parametrize("missing", SOURCE_FILES)
def test_source_archive_requires_complete_distribution(tmp_path: Path, missing: str) -> None:
    files = dict(SOURCE_FILES)
    del files[missing]
    archive = write_sdist(tmp_path, files)
    destination = tmp_path / "source"
    with pytest.raises(p.PackageCheckError, match="missing required source files"):
        p.extract_sdist(archive, VERSION, destination)
    assert not destination.exists()


@pytest.mark.parametrize("empty", SOURCE_FILES)
def test_empty_required_source_files_are_refused(tmp_path: Path, empty: str) -> None:
    files = {**SOURCE_FILES, empty: b""}
    with pytest.raises(p.PackageCheckError, match="empty required source file"):
        p.extract_sdist(write_sdist(tmp_path, files), VERSION, tmp_path / "source")


@pytest.mark.parametrize(
    "name",
    [
        "../escape",
        f"{PREFIX}/../escape",
        f"/{PREFIX}/escape",
        f"{PREFIX}/./escape",
        f"{PREFIX}//escape",
        f"{PREFIX}\\escape",
        "different-root/escape",
    ],
)
def test_source_archive_refuses_noncanonical_paths(tmp_path: Path, name: str) -> None:
    archive = write_sdist(tmp_path, extra=(tarfile.TarInfo(name), b"untrusted\n"))
    destination = tmp_path / "source"
    with pytest.raises(p.PackageCheckError, match="non-canonical source path"):
        p.extract_sdist(archive, VERSION, destination)
    assert not destination.exists() and not (tmp_path / "escape").exists()


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE])
def test_source_archive_refuses_links_and_special_files(tmp_path: Path, kind: bytes) -> None:
    member = tarfile.TarInfo(f"{PREFIX}/extra")
    member.type = kind
    member.linkname = "../../escape"
    archive = write_sdist(tmp_path, extra=(member, None))
    destination = tmp_path / "source"
    with pytest.raises(p.PackageCheckError, match="special entry"):
        p.extract_sdist(archive, VERSION, destination)
    assert not destination.exists() and not (tmp_path / "escape").exists()


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        (f"{PREFIX}/README.md", "duplicate path"),
        (f"{PREFIX}/.git/config", "Git metadata"),
        (PREFIX, "source root is not a directory"),
    ],
)
def test_ambiguous_or_git_dependent_source_layouts_are_refused(
    tmp_path: Path, name: str, reason: str
) -> None:
    archive = write_sdist(tmp_path, extra=(tarfile.TarInfo(name), b"untrusted\n"))
    with pytest.raises(p.PackageCheckError, match=reason):
        p.extract_sdist(archive, VERSION, tmp_path / "source")


@pytest.mark.parametrize(
    ("name", "content", "reason"),
    [
        ("PKG-INFO", b"Name: another-package\nVersion: 1.2.3\n", "package metadata mismatch"),
        ("PKG-INFO", b"Name: snapshot-runner\nVersion: 9.9.9\n", "package metadata mismatch"),
        (
            "PKG-INFO",
            b"Name: snapshot-runner\nVersion: 1.2.3\nVersion: 9.9.9\n",
            "package metadata mismatch",
        ),
        (
            "pyproject.toml",
            PROJECT.replace("snapshot-runner", "another").encode(),
            "project identity",
        ),
        ("pyproject.toml", PROJECT.replace("1.2.3", "9.9.9").encode(), "project identity"),
        ("pyproject.toml", b"project = 42\n", "project identity"),
        (
            "pyproject.toml",
            b'[project]\nname="snapshot-runner"\nversion="1.2.3"\n',
            "build configuration",
        ),
        (
            "pyproject.toml",
            PROJECT.replace('["uv_build>=0.12.1,<0.13"]', "[]").encode(),
            "build configuration",
        ),
        ("pyproject.toml", b"invalid = [", "archive or configuration"),
    ],
)
def test_source_identity_and_build_configuration_are_validated(
    tmp_path: Path, name: str, content: bytes, reason: str
) -> None:
    files = {**SOURCE_FILES, name: content}
    destination = tmp_path / "source"
    with pytest.raises(p.PackageCheckError, match=reason):
        p.extract_sdist(write_sdist(tmp_path, files), VERSION, destination)
    assert not destination.exists()


def test_invalid_archive_has_a_controlled_failure(tmp_path: Path) -> None:
    archive = tmp_path / "invalid.tar.gz"
    archive.write_bytes(b"not a tar archive")
    with pytest.raises(p.PackageCheckError, match="archive or configuration"):
        p.extract_sdist(archive, VERSION, tmp_path / "source")


@pytest.mark.parametrize(
    ("wheel_count", "mutate_sdist"), [(0, False), (1, False), (2, False), (1, True)]
)
def test_sdist_build_uses_independent_source_and_reuses_installed_acceptance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, wheel_count: int, mutate_sdist: bool
) -> None:
    archive = write_sdist(tmp_path)
    original = archive.read_bytes()
    root = tmp_path / "acceptance"
    root.mkdir()
    installed_calls = []
    monkeypatch.setattr(p.shutil, "which", lambda _: "/fixture/uv")

    def build(args, *, cwd, env, phase, timeout):
        assert cwd == root and timeout == 180 and phase == "sdist wheel build"
        assert args[:6] == [
            "/fixture/uv",
            "build",
            "--wheel",
            "--force-pep517",
            "--no-config",
            "--no-sources",
        ]
        source = Path(args[-1])
        assert source == root / "source" / PREFIX and not source.is_relative_to(p.ROOT)
        assert not (source / ".git").exists()
        assert (source / "LICENSE").read_bytes() == SOURCE_FILES["LICENSE"]
        (root / "dist").mkdir()
        for number in range(wheel_count):
            (root / "dist" / f"fixture-{number}.whl").write_bytes(b"fixture wheel")
        if mutate_sdist:
            archive.write_bytes(b"changed sdist")
        return subprocess.CompletedProcess(args, 0, "", "")

    def installed(wheel, version, work):
        installed_calls.append(wheel)
        assert version == VERSION and work == root / "installed"
        return {"status": "PASS", "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest()}

    monkeypatch.setattr(p, "run", build)
    monkeypatch.setattr(p, "check", installed)
    if mutate_sdist:
        with pytest.raises(p.PackageCheckError, match="modified the sdist"):
            p.check_sdist(archive, VERSION, root)
        assert installed_calls == [root / "dist" / "fixture-0.whl"]
    elif wheel_count == 1:
        result = p.check_sdist(archive, VERSION, root)
        assert result["status"] == "PASS"
        assert result["sdist_sha256"] == hashlib.sha256(original).hexdigest()
        assert installed_calls == [root / "dist" / "fixture-0.whl"]
    else:
        with pytest.raises(p.PackageCheckError, match="exactly one wheel"):
            p.check_sdist(archive, VERSION, root)
        assert not installed_calls
    assert archive.read_bytes() == (b"changed sdist" if mutate_sdist else original)


def test_sdist_failure_keeps_original_inputs_and_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    wheel = tmp_path / "original.whl"
    wheel.write_bytes(b"original wheel")
    files = dict(SOURCE_FILES)
    del files["LICENSE"]
    archive = write_sdist(tmp_path, files)
    original = (wheel.read_bytes(), archive.read_bytes())
    roots = []

    def installed(_wheel, _version, work):
        roots.append(work.parent)
        return {"status": "PASS", "wheel_sha256": hashlib.sha256(_wheel.read_bytes()).hexdigest()}

    monkeypatch.setattr(p, "check", installed)
    monkeypatch.setattr(p.tempfile, "tempdir", str(tmp_path))
    result = p.main(["--wheel", str(wheel), "--sdist", str(archive), "--expected-version", VERSION])
    captured = capsys.readouterr()
    assert result == 1 and captured.out == ""
    assert captured.err == "package_check_failed: sdist is missing required source files\n"
    assert roots and all(not root.exists() for root in roots)
    assert (wheel.read_bytes(), archive.read_bytes()) == original


def test_combined_acceptance_refuses_original_wheel_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    wheel = tmp_path / "original.whl"
    wheel.write_bytes(b"original wheel")
    archive = write_sdist(tmp_path)
    roots = []

    def installed(_wheel, _version, work):
        roots.append(work.parent)
        return {"status": "PASS", "wheel_sha256": hashlib.sha256(_wheel.read_bytes()).hexdigest()}

    def source(_archive, _version, _work):
        wheel.write_bytes(b"changed wheel")
        return {"status": "PASS"}

    monkeypatch.setattr(p, "check", installed)
    monkeypatch.setattr(p, "check_sdist", source)
    monkeypatch.setattr(p.tempfile, "tempdir", str(tmp_path))
    assert p.main(["--wheel", str(wheel), "--sdist", str(archive)]) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and "modified the original wheel" in captured.err
    assert roots and all(not root.exists() for root in roots)


def test_combined_acceptance_refuses_sdist_mutation_during_wheel_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    wheel = tmp_path / "original.whl"
    wheel.write_bytes(b"original wheel")
    archive = write_sdist(tmp_path)
    roots = []

    def installed(_wheel, _version, work):
        roots.append(work.parent)
        archive.write_bytes(archive.read_bytes() + b"\0")
        return {"status": "PASS", "wheel_sha256": hashlib.sha256(_wheel.read_bytes()).hexdigest()}

    def source(_archive, version, work):
        assert p.extract_sdist(_archive, version, work / "source").is_dir()
        return {"status": "PASS", "sdist_sha256": hashlib.sha256(_archive.read_bytes()).hexdigest()}

    monkeypatch.setattr(p, "check", installed)
    monkeypatch.setattr(p, "check_sdist", source)
    monkeypatch.setattr(p.tempfile, "tempdir", str(tmp_path))
    result = p.main(["--wheel", str(wheel), "--sdist", str(archive), "--expected-version", VERSION])
    captured = capsys.readouterr()
    assert result == 1 and captured.out == ""
    assert captured.err == "package_check_failed: package acceptance modified the original sdist\n"
    assert roots and all(not root.exists() for root in roots)


def test_sdist_only_mode_preserves_acceptance_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    archive = write_sdist(tmp_path)
    roots = []

    def source(sdist, version, work):
        assert sdist == archive and version == VERSION
        roots.append(work.parent)
        return {"status": "PASS", "sdist_sha256": hashlib.sha256(sdist.read_bytes()).hexdigest()}

    monkeypatch.setattr(p, "check_sdist", source)
    monkeypatch.setattr(p.tempfile, "tempdir", str(tmp_path))
    assert p.main(["--sdist", str(archive), "--expected-version", VERSION]) == 0
    captured = capsys.readouterr()
    assert captured.err == "" and json.loads(captured.out)["status"] == "PASS"
    assert roots and all(not root.exists() for root in roots)


@pytest.mark.parametrize("include_sdist", [False, True])
def test_default_gate_requires_and_checks_both_distributions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    include_sdist: bool,
) -> None:
    roots = []
    checked = []
    monkeypatch.setattr(p.shutil, "which", lambda _: "/fixture/uv")
    monkeypatch.setattr(p.tempfile, "tempdir", str(tmp_path))

    def build(args, *, cwd, env, phase, timeout):
        assert args[:2] == ["/fixture/uv", "build"] and "--wheel" not in args
        assert cwd == p.ROOT and phase == "distribution build" and timeout == 180
        dist = Path(args[args.index("--out-dir") + 1])
        roots.append(dist.parent)
        dist.mkdir()
        (dist / "original.whl").write_bytes(b"original wheel")
        if include_sdist:
            write_sdist(dist)
        return subprocess.CompletedProcess(args, 0, "", "")

    def installed(wheel, version, work):
        assert version == VERSION and work.parent == roots[0]
        checked.append("wheel")
        return {"status": "PASS", "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest()}

    def source(sdist, version, work):
        assert version == VERSION and work.parent == roots[0]
        checked.append("sdist")
        return {"status": "PASS", "sdist_sha256": hashlib.sha256(sdist.read_bytes()).hexdigest()}

    monkeypatch.setattr(p, "run", build)
    monkeypatch.setattr(p, "check", installed)
    monkeypatch.setattr(p, "check_sdist", source)
    result = p.main(["--expected-version", VERSION])
    captured = capsys.readouterr()
    if include_sdist:
        report = json.loads(captured.out)
        assert result == 0 and captured.err == ""
        assert checked == ["wheel", "sdist"]
        assert report["status"] == report["sdist"]["status"] == "PASS"
    else:
        assert result == 1 and captured.out == "" and checked == []
        assert "build must produce one wheel and one sdist" in captured.err
    assert roots and all(not root.exists() for root in roots)
