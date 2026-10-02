"""Close release records without rebuilding or republishing an existing package.

Git publication remains separate. This script consumes existing exact tags and the
existing changelog; only the GitHub workflow may build/upload packages.
"""

from __future__ import annotations

import argparse
import base64
import errno
import hashlib
import http.client
import io
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from email.parser import BytesParser
from pathlib import Path

try:
    from scripts.changelog import extract_tag
except ModuleNotFoundError:
    from changelog import extract_tag

PUBLIC_REPOSITORY = "xuanheng-tech/snapshot-runner"
PACKAGE = "snapshot-runner"
ARCHIVE = PACKAGE.replace("-", "_")
GITHUB_API = "https://api.github.com"
TAG_RE = re.compile(r"v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)")
MARKER = "<!-- snapshot-runner-release "
# PyPI needs a short, bounded moment to expose a just-published version. Release-record
# closure runs seconds after upload, so it waits; build and pending-upload paths must not.
PROPAGATION_ATTEMPTS = 12
PROPAGATION_DELAY_SECONDS = 15
PUBLIC_GIT_ATTEMPTS = 3
PUBLIC_GIT_DELAY_SECONDS = 2
PUBLIC_GIT_TIMEOUT_SECONDS = 60
HTTP_GET_ATTEMPTS = 2
HTTP_GET_DELAY_SECONDS = 2


class ReleaseError(ValueError):
    """Missing evidence or conflicting immutable publication identity."""


class ReleaseIdentityError(ReleaseError):
    """Observed source, tag, file, or provenance identities disagree."""


def command(*args: str) -> str:
    operation = args[0]
    if operation == "git":
        offset = 3 if args[1:2] == ("-C",) else 1
        if args[offset : offset + 1] and args[offset] in {
            "cat-file",
            "diff",
            "fetch",
            "ls-remote",
            "push",
            "rev-parse",
            "show",
        }:
            operation += f" {args[offset]}"
    public_read = (
        len(args) == 5
        and args[:3] in (("git", "fetch", "--no-tags"), ("git", "ls-remote", "--tags"))
        and args[3] == f"https://github.com/{PUBLIC_REPOSITORY}.git"
    )
    attempts = PUBLIC_GIT_ATTEMPTS if public_read else 1
    for attempt in range(attempts):
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                check=False,
                timeout=PUBLIC_GIT_TIMEOUT_SECONDS if public_read else None,
            )
        except subprocess.TimeoutExpired:
            if attempt + 1 == attempts:
                raise ReleaseError(f"{operation} timed out after {attempts} attempts") from None
        else:
            if args[0] in ("just", "uv"):
                print(result.stdout, end="", flush=True)
                print(result.stderr, end="", file=sys.stderr, flush=True)
            if not result.returncode:
                return result.stdout.strip()
            if attempt + 1 == attempts or not _transient_git_transport(result.stderr):
                suffix = f" after {attempt + 1} attempts" if attempt else ""
                raise ReleaseError(f"{operation} failed (exit {result.returncode}){suffix}")
        time.sleep(PUBLIC_GIT_DELAY_SECONDS)
    raise AssertionError("unreachable public Git retry state")


def _transient_git_transport(stderr: str) -> bool:
    """Classify transport errors internally; never echo credential-bearing Git diagnostics."""
    message = stderr.lower()
    if any(
        marker in message
        for marker in (
            "authentication failed",
            "permission denied",
            "could not read username",
            "repository not found",
            "couldn't find remote ref",
            "not our ref",
            "certificate",
        )
    ):
        return False
    return any(
        marker in message
        for marker in (
            "could not resolve host:",
            "failed to connect to",
            "connection timed out",
            "operation timed out",
            "connection reset by peer",
            "recv failure:",
            "send failure:",
            "http/2 stream",
            "http/2 framing layer",
            "the requested url returned error: 502",
            "the requested url returned error: 503",
            "the requested url returned error: 504",
        )
    )


def check_readme_version(readme: str, version: str, package: str = PACKAGE) -> None:
    """Fail when README current-stable or install pins disagree with the release version.

    Only the current-stable declaration and ``package==X.Y.Z`` install pins are checked.
    Historical changelog or prose version mentions are ignored.
    """
    stables = re.findall(
        r"^Current stable release:\s*\*\*(\d+\.\d+\.\d+)\*\*",
        readme,
        flags=re.MULTILINE,
    )
    if not stables:
        raise ReleaseError("README missing current stable release declaration")
    if any(item != version for item in stables):
        raise ReleaseError("README current stable release does not match package version")
    pins = re.findall(rf"{re.escape(package)}==(\d+\.\d+\.\d+)", readme)
    if not pins:
        raise ReleaseError("README missing package install version pin")
    if any(item != version for item in pins):
        raise ReleaseError("README install version pin does not match package version")


def identity(
    tag: str,
    expected_sha: str | None = None,
    *,
    tag_object: str | None = None,
    checkout: bool = False,
) -> dict:
    if TAG_RE.fullmatch(tag) is None:
        raise ReleaseError("invalid formal release tag")
    # A checkout action can replace its local tag ref with the peeled commit.
    # Release workflows supply the authoritative remote object, never that ref.
    tag_object = tag_object or command("git", "rev-parse", f"refs/tags/{tag}")
    if re.fullmatch(r"[0-9a-f]{40}", tag_object) is None:
        raise ReleaseError("invalid annotated tag object")
    if command("git", "cat-file", "-t", tag_object) != "tag":
        raise ReleaseError("formal release requires an annotated tag")
    header = command("git", "cat-file", "tag", tag_object).split("\n\n", 1)[0]
    commit = command("git", "rev-parse", f"{tag_object}^{{commit}}")
    lines = header.splitlines()
    if (
        len(lines) != 4
        or lines[:3] != [f"object {commit}", "type commit", f"tag {tag}"]
        or re.fullmatch(r"tagger [^\x00\r\n]+", lines[3]) is None
    ):
        raise ReleaseIdentityError("raw annotated tag name/target conflict")
    if expected_sha is not None and commit != expected_sha:
        raise ReleaseIdentityError("tag/expected commit mismatch")
    if checkout and command("git", "rev-parse", "HEAD") != commit:
        raise ReleaseError("build checkout is not the exact release commit")
    project = tomllib.loads(command("git", "show", f"{commit}:pyproject.toml"))["project"]
    package = command("git", "show", f"{commit}:snapshot_runner/__init__.py")
    version = tag[1:]
    if project["name"] != PACKAGE or project["version"] != version:
        raise ReleaseIdentityError("tag/project version mismatch")
    if re.search(rf'^__version__ = "{re.escape(version)}"$', package, re.MULTILINE) is None:
        raise ReleaseIdentityError("package version declarations disagree")
    check_readme_version(command("git", "show", f"{commit}:README.md"), version)
    notes = extract_tag(command("git", "show", f"{commit}:CHANGELOG.md"), tag)
    return {
        "tag": tag,
        "tag_object": tag_object,
        "version": version,
        "commit": commit,
        "notes": notes,
    }


def _http_failure(error: urllib.error.HTTPError) -> ReleaseError:
    # A bare 403 does not distinguish API permissions, a proxy refusal, and rate limiting.
    remaining = error.headers.get("x-ratelimit-remaining", "") if error.headers else ""
    retry_after = error.headers.get("retry-after", "") if error.headers else ""
    rate_limited = error.code == 429 or (
        error.code == 403
        and (remaining.strip() == "0" or re.fullmatch(r"[0-9]{1,10}", retry_after.strip()))
    )
    if rate_limited:
        code, recovery = "HTTP_RATE_LIMITED", "wait for the API retry window before rerunning"
    elif error.code == 401:
        code, recovery = "HTTP_UNAUTHORIZED", "check the existing API client's authorization"
    elif error.code == 403:
        code, recovery = (
            "HTTP_FORBIDDEN_UNKNOWN",
            "check API permissions and the configured proxy route; cause is unknown",
        )
    elif error.code == 407:
        code, recovery = (
            "HTTP_PROXY_AUTH_REQUIRED",
            "check the configured proxy's existing authorization",
        )
    elif error.code in (409, 412):
        code, recovery = (
            "HTTP_STATE_CONFLICT",
            "verify remote state and the original receipt before any mutation",
        )
    elif 500 <= error.code <= 599:
        code, recovery = (
            "HTTP_SERVER_ERROR",
            "check service availability and the configured route before rerunning",
        )
    else:
        code, recovery = "HTTP_REQUEST_REJECTED", "check the request and existing API authorization"
    return ReleaseError(
        f"{code}: release HTTP request failed (status {error.code}); recovery: {recovery}"
    )


def _network_failure(error: OSError | http.client.HTTPException) -> ReleaseError:
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(reason, TimeoutError):
        code, recovery = (
            "NETWORK_TIMEOUT",
            "check service availability and the configured network route",
        )
    elif isinstance(reason, socket.gaierror):
        code, recovery = "NETWORK_DNS_FAILED", "check name resolution for the configured route"
    elif isinstance(reason, ssl.SSLCertVerificationError):
        code, recovery = (
            "NETWORK_TLS_VERIFICATION_FAILED",
            "check the clock and certificate trust for the configured route",
        )
    elif isinstance(reason, ssl.SSLError):
        code, recovery = "NETWORK_TLS_FAILED", "check TLS support for the configured route"
    elif isinstance(reason, ConnectionError) or (
        isinstance(reason, OSError)
        and reason.errno in {errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ENETDOWN}
    ):
        code, recovery = (
            "NETWORK_CONNECTION_FAILED",
            "check service availability and the configured proxy route",
        )
    elif isinstance(reason, http.client.IncompleteRead):
        code, recovery = (
            "NETWORK_RESPONSE_INCOMPLETE",
            "check service availability before rerunning the read",
        )
    elif isinstance(reason, http.client.HTTPException):
        code, recovery = (
            "NETWORK_HTTP_PROTOCOL_FAILED",
            "check HTTP support for the configured route; cause is unknown",
        )
    else:
        code, recovery = (
            "NETWORK_CAUSE_UNKNOWN",
            "check the configured route with the existing client; cause is unknown",
        )
    return ReleaseError(f"{code}: release HTTP request unavailable; recovery: {recovery}")


def request(url: str, *, token: str = "", method: str = "GET", data: dict | None = None):
    headers = {"Accept": "application/json", "User-Agent": "snapshot-runner-release"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = None if data is None else json.dumps(data).encode()
    if body is not None:
        headers["Content-Type"] = "application/json"
    attempts = HTTP_GET_ATTEMPTS if method == "GET" and data is None else 1
    for attempt in range(attempts):
        try:
            operation = urllib.request.Request(url, data=body, headers=headers, method=method)
            with urllib.request.urlopen(operation, timeout=30) as response:
                raw = response.read(8 * 1024 * 1024 + 1)
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and method == "GET":
                return None
            raise _http_failure(exc) from None
        except (OSError, http.client.HTTPException) as exc:
            reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
            if attempt + 1 == attempts or not isinstance(
                reason, (TimeoutError, ConnectionResetError, http.client.IncompleteRead)
            ):
                raise _network_failure(exc) from None
        except ValueError:
            raise ReleaseError(
                "HTTP_REQUEST_INVALID: release HTTP request configuration invalid; "
                "recovery: check the API URL and the existing client's authorization configuration"
            ) from None
        else:
            if len(raw) > 8 * 1024 * 1024:
                raise ReleaseError("release response exceeds 8 MiB")
            return raw
        time.sleep(HTTP_GET_DELAY_SECONDS)
    raise AssertionError("unreachable release HTTP retry state")


def api(url: str, **kwargs):
    raw = request(url, **kwargs)
    return None if raw is None else json.loads(raw)


def poll(load):
    """Repeat one bounded PyPI read while the published version is still propagating.

    Only a missing document (``None``) is retried. Any other failure, including a
    conflicting identity or a non-404 HTTP status, propagates immediately so a real
    provenance error is never masked by a retry.
    """
    for remaining in range(PROPAGATION_ATTEMPTS - 1, -1, -1):
        value = load()
        if value is not None or not remaining:
            return value
        time.sleep(PROPAGATION_DELAY_SECONDS)
    return None


def github_tag(tag: str, expected_object: str | None = None) -> str | None:
    result = github_identity(tag, expected_object)
    return None if result is None else result[1]


def github_identity(tag: str, expected_object: str | None = None) -> tuple[str, str] | None:
    if TAG_RE.fullmatch(tag) is None:
        raise ReleaseError("invalid formal release tag")
    token = os.environ.get("PUBLIC_GITHUB_TOKEN", "")
    ref = api(f"{GITHUB_API}/repos/{PUBLIC_REPOSITORY}/git/ref/tags/{tag}", token=token)
    if ref is None:
        return None
    obj = ref["object"]
    if obj["type"] != "tag" or (expected_object is not None and obj["sha"] != expected_object):
        raise ReleaseIdentityError("GitHub annotated tag object identity conflict")
    tag_object = obj["sha"]
    obj = api(f"{GITHUB_API}/repos/{PUBLIC_REPOSITORY}/git/tags/{tag_object}", token=token)[
        "object"
    ]
    if obj["type"] != "commit":
        raise ReleaseError("public tag does not resolve to a commit")
    return tag_object, obj["sha"]


def public_identity(tag: str, expected_sha: str | None, expected_object: str | None) -> dict:
    remote = github_identity(tag, expected_object)
    if remote is None:
        raise ReleaseError("GitHub formal tag missing")
    tag_object, commit = remote
    if expected_sha is not None and commit != expected_sha:
        raise ReleaseIdentityError("tag/expected commit mismatch")
    # Fetch the immutable object into the object database, without updating any
    # local tag. This also works with a detached HEAD or a shallow checkout.
    command("git", "fetch", "--no-tags", f"https://github.com/{PUBLIC_REPOSITORY}.git", tag_object)
    return identity(tag, commit, tag_object=tag_object)


def filenames(version: str) -> set[str]:
    return {f"{ARCHIVE}-{version}-py3-none-any.whl", f"{ARCHIVE}-{version}.tar.gz"}


def control_identity() -> dict:
    commit = os.environ.get("GITHUB_SHA", "")
    ref = os.environ.get("GITHUB_REF", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    root = str(Path(__file__).resolve().parents[1])
    workflow = f"{PUBLIC_REPOSITORY}/.github/workflows/publish-pypi.yml@{ref}"
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("GITHUB_REPOSITORY") != PUBLIC_REPOSITORY
        or os.environ.get("GITHUB_WORKFLOW_REF") != workflow
        or re.fullmatch(r"[0-9a-f]{40}", commit) is None
        or re.fullmatch(r"[1-9]\d*", run_id) is None
        or command("git", "-C", root, "rev-parse", "HEAD") != commit
    ):
        raise ReleaseError("build/publish requires the exact GitHub release-control checkout")
    return {"control_commit": commit, "control_ref": ref, "build_run_id": run_id}


def _valid_notes(notes: object) -> bool:
    return isinstance(notes, str) and 1 <= len(notes) <= 8192


def receipt_identity(receipt: dict) -> dict:
    release = public_identity(
        receipt["tag"], receipt["package_source_commit"], receipt["tag_object"]
    )
    release.update(
        control_commit=receipt["release_control_commit"],
        control_ref=receipt["release_control_ref"],
        build_run_id=receipt["build_run_id"],
        notes=receipt["notes"],
    )
    hashes = receipt["files"]
    if (
        receipt != record_identity(release, hashes)
        or set(hashes) != filenames(release["version"])
        or any(re.fullmatch(r"[0-9a-f]{64}", value) is None for value in hashes.values())
        or re.fullmatch(r"[0-9a-f]{40}", release["control_commit"]) is None
        or re.fullmatch(r"[1-9]\d*", release["build_run_id"]) is None
        or release["control_ref"] not in ("refs/heads/master", f"refs/tags/{release['tag']}")
        or not _valid_notes(release["notes"])
    ):
        raise ReleaseError("malformed release receipt")
    run = api(
        f"{GITHUB_API}/repos/{PUBLIC_REPOSITORY}/actions/runs/{release['build_run_id']}",
        token=os.environ.get("PUBLIC_GITHUB_TOKEN", ""),
    )
    if (
        run is None
        or run["head_sha"] != release["control_commit"]
        or run["path"] != ".github/workflows/publish-pypi.yml"
        or run["head_repository"]["full_name"] != PUBLIC_REPOSITORY
        or run["event"] not in ("push", "workflow_dispatch")
        or run["head_branch"] != release["control_ref"].split("/", 2)[2]
    ):
        raise ReleaseIdentityError("release-control run provenance conflict")
    release["files"] = hashes
    return release


def artifact_hashes(source: Path, version: str) -> dict[str, str]:
    paths = {p.name: p for p in source.iterdir() if p.name != ".gitignore"}
    if set(paths) != filenames(version) or any(
        not p.is_file() or p.is_symlink() for p in paths.values()
    ):
        raise ReleaseError("expected original wheel and sdist only")
    hashes = {}
    for name, path in sorted(paths.items()):
        raw = path.read_bytes()
        check_artifact(name, raw, version)
        hashes[name] = hashlib.sha256(raw).hexdigest()
    return hashes


def check_artifact(name: str, raw: bytes, version: str) -> None:
    if name.endswith(".whl"):
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            paths = [p for p in archive.namelist() if p.endswith(".dist-info/METADATA")]
            if len(paths) != 1:
                raise ReleaseError("ambiguous wheel metadata")
            metadata = archive.read(paths[0])
    else:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            paths = [p for p in archive.getmembers() if p.name.endswith("/PKG-INFO")]
            if len(paths) != 1 or not paths[0].isfile():
                raise ReleaseError("ambiguous source metadata")
            metadata = archive.extractfile(paths[0]).read()
    parsed = BytesParser().parsebytes(metadata)
    if parsed["Name"] != PACKAGE or parsed["Version"] != version:
        raise ReleaseIdentityError("package artifact identity mismatch")


def check_provenance(item: dict, release: dict, *, wait: bool = False) -> None:
    name = item["filename"]
    url = f"https://pypi.org/integrity/{PACKAGE}/{release['version']}/{name}/provenance"
    provenance = poll(lambda: api(url)) if wait else api(url)
    if provenance is None:
        raise ReleaseError("PyPI provenance missing; do not rebuild or upload")
    for bundle in provenance["attestation_bundles"]:
        publisher = bundle["publisher"]
        if publisher != {
            "kind": "GitHub",
            "repository": PUBLIC_REPOSITORY,
            "workflow": "publish-pypi.yml",
            "environment": "pypi",
        }:
            continue
        for attestation in bundle["attestations"]:
            statement = json.loads(base64.b64decode(attestation["envelope"]["statement"]))
            if statement["subject"] != [
                {"name": name, "digest": {"sha256": item["digests"]["sha256"]}}
            ]:
                continue
            certificate = base64.b64decode(attestation["verification_material"]["certificate"])
            result = subprocess.run(
                ["openssl", "x509", "-inform", "DER", "-noout", "-text"],
                input=certificate,
                capture_output=True,
                check=False,
            )
            text = result.stdout.decode("utf-8")
            # Compare PyPI's HTTPS-served provenance claims; this is not a new
            # cryptographic verifier or a substitute for Sigstore verification.
            sha = re.search(r"1\.3\.6\.1\.4\.1\.57264\.1\.3:\s*\n\s*([0-9a-f]{40})\s*\n", text)
            uri = f"URI:https://github.com/{PUBLIC_REPOSITORY}/.github/workflows/publish-pypi.yml@{release['control_ref']}"
            if (
                result.returncode == 0
                and sha
                and sha[1] == release["control_commit"]
                and uri + "\n" in text
            ):
                return
    raise ReleaseIdentityError("PyPI publisher/commit/file provenance conflict")


def pypi_files(
    release: dict, *, complete: bool = True, wait: bool = False
) -> dict[str, str] | None:
    url = f"https://pypi.org/pypi/{PACKAGE}/{release['version']}/json"
    doc = poll(lambda: api(url)) if wait else api(url)
    if doc is None:
        return None
    if doc["info"]["name"] != PACKAGE or doc["info"]["version"] != release["version"]:
        raise ReleaseIdentityError("PyPI project/version conflict")
    items = doc["urls"]
    names = {item["filename"] for item in items}
    expected = filenames(release["version"])
    if len(names) != len(items) or not names <= expected or (complete and names != expected):
        raise ReleaseError("PyPI file set incomplete/conflicting; resume the original publish job")
    hashes = {}
    for item in items:
        url = urllib.parse.urlsplit(item["url"])
        if url.scheme != "https" or url.hostname != "files.pythonhosted.org" or item["yanked"]:
            raise ReleaseError("unexpected PyPI file origin or yanked file")
        raw = request(item["url"])
        digest = hashlib.sha256(raw).hexdigest()
        if digest != item["digests"]["sha256"] or len(raw) != item["size"]:
            raise ReleaseIdentityError("PyPI downloaded file digest/size conflict")
        check_artifact(item["filename"], raw, release["version"])
        check_provenance(item, release, wait=wait)
        hashes[item["filename"]] = digest
        if "files" in release and release["files"].get(item["filename"]) != digest:
            raise ReleaseIdentityError("PyPI file differs from the source-bound build receipt")
    return hashes


def build(release: dict, dist: Path = Path("dist")) -> bool:
    identity(release["tag"], release["commit"], tag_object=release["tag_object"], checkout=True)
    if command("git", "rev-parse", "--is-shallow-repository") != "false":
        raise ReleaseError("source checkout must include complete Git history before quality/build")
    command("git", "diff", "--exit-code", "HEAD", "--")
    command("just", "check")
    command("git", "diff", "--exit-code", "HEAD", "--")
    if github_tag(release["tag"], release["tag_object"]) != release["commit"]:
        raise ReleaseIdentityError("GitHub tag identity conflict")
    if pypi_files(release) is not None:
        return False
    previous = api(
        f"{GITHUB_API}/repos/{PUBLIC_REPOSITORY}/actions/artifacts?name=publication-{release['tag']}",
        token=os.environ.get("PUBLIC_GITHUB_TOKEN", ""),
    )
    if previous is None or previous["total_count"]:
        raise ReleaseError("original build artifact exists or is unknown; resume its publish job")
    command("uv", "build", "--out-dir", str(dist))
    command(
        "uv",
        "run",
        "--frozen",
        "python",
        str(Path(__file__).resolve().with_name("check_package.py")),
        "--wheel",
        str(dist / f"{ARCHIVE}-{release['version']}-py3-none-any.whl"),
        "--sdist",
        str(dist / f"{ARCHIVE}-{release['version']}.tar.gz"),
        "--expected-version",
        release["version"],
    )
    return True


def pending_dist(release: dict, source: Path, output: Path) -> list[str]:
    hashes = artifact_hashes(source, release["version"])
    if "files" in release and hashes != release["files"]:
        raise ReleaseError("downloaded artifacts differ from the source-bound build receipt")
    existing = pypi_files(release, complete=False) or {}
    pending = []
    for name, digest in hashes.items():
        if name in existing:
            if existing[name] != digest:
                raise ReleaseError(
                    "existing PyPI file differs from original build; refusing upload"
                )
        else:
            pending.append(name)
    output.mkdir()  # A fresh job-owned directory; never clean or overwrite caller data.
    for name in pending:
        shutil.copyfile(source / name, output / name)
    return pending


def check_record(record: dict, release: dict, hashes: dict, platform: str) -> None:
    if record["tag_name"] != release["tag"] or record["draft"] or record["prerelease"]:
        raise ReleaseIdentityError(f"{platform} Release identity conflict")
    if record.get("sha1", release["commit"]) != release["commit"]:
        raise ReleaseIdentityError(f"{platform} Release commit conflict")
    target = record.get("target_commitish", "")
    if re.fullmatch(r"[0-9a-f]{40}", target) and target != release["commit"]:
        raise ReleaseIdentityError(f"{platform} Release target commit conflict")
    body = record.get("body") or ""
    if body.count(MARKER) != 1:
        raise ReleaseError(f"{platform} Release identity marker missing or ambiguous")
    marker = body.split(MARKER, 1)[1].split(" -->", 1)[0]
    if json.loads(marker) != record_identity(release, hashes):
        raise ReleaseIdentityError(f"{platform} Release file/tag object identity conflict")


def record_identity(release: dict, hashes: dict) -> dict:
    return {
        "tag": release["tag"],
        "tag_object": release["tag_object"],
        "package_source_commit": release["commit"],
        "release_control_commit": release["control_commit"],
        "release_control_ref": release["control_ref"],
        "build_run_id": release["build_run_id"],
        "notes": release["notes"],
        "files": hashes,
    }


def release_record(
    release: dict,
    hashes: dict,
    platform: str,
    base: str,
    repository: str,
    *,
    apply: bool = False,
    token: str = "",
) -> dict:
    root = f"{base.rstrip('/')}/repos/{repository}"
    if platform == "github":
        if base != GITHUB_API or repository != PUBLIC_REPOSITORY:
            raise ReleaseError("unexpected GitHub release authority")
        target = github_tag(release["tag"], release["tag_object"])
    else:
        tag = api(f"{root}/tags/{release['tag']}", token=token)
        target = None if tag is None else tag["commit"]["sha"]
        if target is not None:
            remote = command("git", "ls-remote", "--refs", "origin", f"refs/tags/{release['tag']}")
            if remote.split() != [release["tag_object"], f"refs/tags/{release['tag']}"]:
                raise ReleaseIdentityError("Gitea tag object identity conflict")
    if target != release["commit"]:
        raise ReleaseError(f"{platform} tag missing or conflicting")
    expected = record_identity(release, hashes)
    endpoint = f"{root}/releases/tags/{release['tag']}"
    record = api(endpoint, token=token)
    created = False
    if record is None and apply:
        if not token:
            raise ReleaseError("RELEASE_TOKEN is missing")
        body = (
            release["notes"]
            + f"\n\nPackage: https://pypi.org/project/{PACKAGE}/{release['version']}/"
            + f"\n\nPackage source commit: `{release['commit']}`"
            + f"\n\nRelease-control commit: `{release['control_commit']}`"
            + f"\n\nBuild receipt: https://github.com/{PUBLIC_REPOSITORY}/actions/runs/{release['build_run_id']}\n\n"
            + MARKER
            + json.dumps(expected, sort_keys=True)
            + " -->"
        )
        payload = {
            "tag_name": release["tag"],
            "name": f"Snapshot Runner {release['tag']}" if platform == "github" else release["tag"],
            "body": body,
            "draft": False,
            "prerelease": False,
        }
        # GitHub's existing tag is authoritative. Supplying its historical
        # commit unnecessarily triggers the workflow-write permission check.
        if platform != "github":
            payload["target_commitish"] = release["commit"]
        record = api(
            f"{root}/releases",
            token=token,
            method="POST",
            data=payload,
        )
        created = True
        record = api(endpoint, token=token)
    if record is None:
        raise ReleaseError(f"{platform} Release missing")
    check_record(record, release, hashes, platform)
    # target_commitish can be a historical branch name. For an existing tag,
    # GitHub identifies the release through tag_name, not today's branch HEAD.
    return {"status": "PASS", "created": created, "id": record["id"], "url": record["html_url"]}


def sync_gitea(tag: str, base: str, repository: str) -> dict:
    # Only the built-in Actions actor suppresses recursive tag workflows on
    # Gitea. A PAT/local caller must never use this old-tag backfill route.
    if os.environ.get("GITEA_ACTIONS") != "true" or base == GITHUB_API:
        raise ReleaseError("tag synchronization requires the Gitea Actions job token")
    if TAG_RE.fullmatch(tag) is None:
        raise ReleaseError("invalid formal release tag")
    token = os.environ.get("RELEASE_TOKEN", "")
    if not token:
        raise ReleaseError("RELEASE_TOKEN is missing")
    public_commit = github_tag(tag)
    if public_commit is None:
        return {"status": "SKIP", "reason": "version has no public tag"}
    public_record = api(f"{GITHUB_API}/repos/{PUBLIC_REPOSITORY}/releases/tags/{tag}")
    if public_record is None:
        return {"status": "SKIP", "reason": "rerun after GitHub package and Release publication"}
    body = public_record.get("body") or ""
    if body.count(MARKER) != 1:
        raise ReleaseError("GitHub Release identity marker missing or ambiguous")
    receipt = json.loads(body.split(MARKER, 1)[1].split(" -->", 1)[0])
    release = receipt_identity(receipt)
    if release["tag"] != tag or release["commit"] != public_commit:
        raise ReleaseIdentityError("GitHub Release source identity conflict")
    hashes = pypi_files(release, wait=True)
    if hashes is None:
        return {
            "status": "SKIP",
            "reason": "package not yet published; rerun after GitHub publication",
        }
    public = release_record(release, hashes, "github", GITHUB_API, PUBLIC_REPOSITORY)
    root = f"{base.rstrip('/')}/repos/{repository}"
    if api(root, token=token) is None:
        raise ReleaseError("Gitea repository is unavailable to the job token")
    existing_record = api(f"{root}/releases/tags/{tag}", token=token)
    if existing_record is not None:
        check_record(existing_record, release, hashes, "gitea")
    endpoint = f"{root}/tags/{tag}"
    existing = api(endpoint, token=token)
    if existing is None:
        # Push the fetched raw object, never a potentially rewritten checkout ref.
        command(
            "git", "push", "--no-follow-tags", "origin", f"{release['tag_object']}:refs/tags/{tag}"
        )
    elif existing["commit"]["sha"] != public_commit:
        raise ReleaseIdentityError("Gitea formal tag identity conflict")
    raw_tag = release["tag_object"]
    remote = command("git", "ls-remote", "--refs", "origin", f"refs/tags/{tag}")
    if remote.split() != [raw_tag, f"refs/tags/{tag}"]:
        raise ReleaseIdentityError("Gitea tag object identity conflict")
    private = release_record(release, hashes, "gitea", base, repository, apply=True, token=token)
    return {
        "tag": tag,
        "commit": public_commit,
        "tag_object": raw_tag,
        "package_verification": "PASS",
        "github_release": public,
        "gitea_release": private,
        "files": hashes,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=(
            "gate",
            "build",
            "package-state",
            "pending-dist",
            "record",
            "verify",
            "sync-gitea",
        ),
    )
    parser.add_argument("tag", nargs="?")
    parser.add_argument("--expected-sha")
    parser.add_argument("--expected-tag-object")
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--platform", choices=("github", "gitea"), default="github")
    parser.add_argument("--api-url", default=GITHUB_API)
    parser.add_argument("--repository", default=PUBLIC_REPOSITORY)
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument("--output", type=Path, default=Path("pending-dist"))
    args = parser.parse_args(argv)
    try:
        if args.command == "sync-gitea":
            print(json.dumps(sync_gitea(args.tag, args.api_url, args.repository), sort_keys=True))
            return 0
        if args.command == "build":
            if not args.expected_sha or args.receipt is None:
                raise ReleaseError("build requires expected source commit and receipt output")
            release = public_identity(args.tag, args.expected_sha, args.expected_tag_object or None)
            release.update(control_identity())
            release["notes"] = os.environ.get("RELEASE_NOTES") or release["notes"]
            if not _valid_notes(release["notes"]):
                raise ReleaseError("release notes must contain 1 to 8192 characters")
        elif args.receipt is not None:
            release = receipt_identity(json.loads(args.receipt.read_text(encoding="utf-8")))
            if args.tag is not None and args.tag != release["tag"]:
                raise ReleaseIdentityError("requested tag/receipt conflict")
            if args.expected_sha is not None and args.expected_sha != release["commit"]:
                raise ReleaseIdentityError("expected source commit/receipt conflict")
            if (
                args.expected_tag_object is not None
                and args.expected_tag_object != release["tag_object"]
            ):
                raise ReleaseIdentityError("expected tag object/receipt conflict")
        elif args.command == "gate":
            release = public_identity(args.tag, args.expected_sha, args.expected_tag_object)
        else:
            raise ReleaseError(
                "package and Release verification require the original build receipt"
            )
        result = {
            "tag": release["tag"],
            "tag_object": release["tag_object"],
            "package_source_commit": release["commit"],
            "release_control_commit": release.get("control_commit"),
        }
        outputs = {}
        if args.command == "build":
            built = build(release, args.dist)
            outputs["built"] = str(built).lower()
            if built:
                receipt = record_identity(release, artifact_hashes(args.dist, release["version"]))
                with args.receipt.open("x", encoding="utf-8") as stream:
                    stream.write(json.dumps(receipt, sort_keys=True) + "\n")
                result["receipt"] = receipt
        elif args.command == "pending-dist":
            if control_identity() != {
                key: release[key] for key in ("control_commit", "control_ref", "build_run_id")
            }:
                raise ReleaseError("publish must resume the original release-control run")
            result["pending"] = pending_dist(release, args.dist, args.output)
            outputs["pending"] = str(bool(result["pending"])).lower()
        elif args.command != "gate":
            if github_tag(release["tag"], release["tag_object"]) != release["commit"]:
                raise ReleaseIdentityError("GitHub tag identity conflict")
            hashes = pypi_files(release, wait=args.command in ("record", "verify"))
            result["package_verification"] = "MISSING" if hashes is None else "PASS"
            result["files"] = hashes
            if args.command in ("record", "verify"):
                if hashes is None:
                    raise ReleaseError(
                        "PyPI package missing; record closure cannot publish packages"
                    )
                result["release_verification"] = release_record(
                    release,
                    hashes,
                    args.platform,
                    args.api_url,
                    args.repository,
                    apply=args.command == "record",
                    token=os.environ.get("RELEASE_TOKEN", ""),
                )
        result.update(outputs)
        if outputs and os.environ.get("GITHUB_OUTPUT"):
            with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as stream:
                for key, value in outputs.items():
                    stream.write(f"{key}={value}\n")
        print(json.dumps(result, sort_keys=True))
    except (ReleaseError, OSError, ValueError, KeyError, TypeError) as exc:
        message = f"release_failed: {type(exc).__name__}: {exc}"
        if isinstance(exc, ReleaseIdentityError):
            message += "; recovery: verify remote identities against the original build receipt and exact tag"
        print(message, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
