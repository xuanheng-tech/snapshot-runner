from __future__ import annotations

import base64
import errno
import hashlib
import io
import json
import os
import socket
import ssl
import subprocess
import tarfile
import zipfile
from email.message import Message
from pathlib import Path

import pytest

from scripts import release as r

ROOT = Path(__file__).resolve().parents[1]
TAG = "v1.2.3"
SHA = "a" * 40
RELEASE = {
    "tag": TAG,
    "tag_object": "c" * 40,
    "version": "1.2.3",
    "commit": SHA,
    "notes": "- Release notes",
    "control_commit": "b" * 40,
    "control_ref": "refs/heads/master",
    "build_run_id": "123",
}


def _http_wire(body: bytes, headers: bytes = b"", status: str = "200 OK") -> bytes:
    return f"HTTP/1.1 {status}\r\n".encode() + headers + b"\r\n" + body


@pytest.fixture
def memory_http(monkeypatch: pytest.MonkeyPatch):
    """Use the real HTTP parser and reader without opening a network connection."""

    class MemorySocket:
        def __init__(self, raw: bytes):
            self.stream = io.BytesIO(raw)

        def makefile(self, mode: str):
            assert mode == "rb"
            return self.stream

    def serve(*messages: bytes):
        pending = iter(messages)
        calls = []
        responses = []
        streams = []
        slept = []

        def open_request(operation, **kwargs):
            assert all(stream.closed for stream in streams)
            calls.append((operation.get_method(), operation.data, kwargs["timeout"]))
            source = MemorySocket(next(pending))
            response = r.http.client.HTTPResponse(source, method=operation.get_method())
            response.begin()
            streams.append(source.stream)
            responses.append(response)
            return response

        monkeypatch.setattr(r.urllib.request, "urlopen", open_request)
        monkeypatch.setattr(r.time, "sleep", slept.append)
        return calls, responses, streams, slept

    return serve


@pytest.mark.parametrize(
    ("status", "header_values", "category"),
    [
        (401, {}, "HTTP_UNAUTHORIZED"),
        (403, {}, "HTTP_FORBIDDEN_UNKNOWN"),
        (403, {"X-RateLimit-Remaining": "0"}, "HTTP_RATE_LIMITED"),
        (403, {"X-RateLimit-Remaining": "1"}, "HTTP_FORBIDDEN_UNKNOWN"),
        (403, {"Retry-After": "12"}, "HTTP_RATE_LIMITED"),
        (403, {"Retry-After": "SYNTHETIC_RELEASE_MARKER"}, "HTTP_FORBIDDEN_UNKNOWN"),
        (403, {"X-RateLimit-Remaining": "SYNTHETIC_RELEASE_MARKER"}, "HTTP_FORBIDDEN_UNKNOWN"),
        (407, {}, "HTTP_PROXY_AUTH_REQUIRED"),
        (409, {}, "HTTP_STATE_CONFLICT"),
        (412, {}, "HTTP_STATE_CONFLICT"),
        (429, {}, "HTTP_RATE_LIMITED"),
        (502, {}, "HTTP_SERVER_ERROR"),
        (503, {}, "HTTP_SERVER_ERROR"),
        (422, {}, "HTTP_REQUEST_REJECTED"),
    ],
)
def test_http_failure_uses_evidence_and_safe_recovery_without_replay(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    status: int,
    header_values: dict[str, str],
    category: str,
) -> None:
    marker = "SYNTHETIC_RELEASE_MARKER"
    url = f"https://{marker}@example.invalid/{marker}"
    headers = Message()
    for name, value in {**header_values, "Set-Cookie": marker}.items():
        headers[name] = value
    body = io.BytesIO(marker.encode())
    failure = r.urllib.error.HTTPError(url, status, marker, headers, body)
    calls = []

    def open_request(request, **kwargs):
        calls.append((request.get_method(), kwargs["timeout"]))
        raise failure

    monkeypatch.setattr(r.urllib.request, "urlopen", open_request)
    monkeypatch.setattr(r.time, "sleep", lambda _: pytest.fail("HTTP errors must not replay"))
    with pytest.raises(r.ReleaseError) as raised:
        r.request(url, token=marker)
    message = str(raised.value)
    assert message.startswith(category + ":")
    assert f"status {status}" in message and "recovery:" in message
    assert marker not in message and "example.invalid" not in message
    assert calls == [("GET", 30)]
    assert body.tell() == 0
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_only_get_404_is_missing_evidence(monkeypatch: pytest.MonkeyPatch, method: str) -> None:
    calls = []

    def open_request(*_args, **_kwargs):
        calls.append("request")
        raise r.urllib.error.HTTPError("https://example.invalid", 404, "fixture", None, None)

    monkeypatch.setattr(r.urllib.request, "urlopen", open_request)
    monkeypatch.setattr(r.time, "sleep", lambda _: pytest.fail("404 must not replay here"))
    if method == "GET":
        assert r.request("https://example.invalid", method=method) is None
    else:
        with pytest.raises(r.ReleaseError, match="HTTP_REQUEST_REJECTED.*status 404"):
            r.request("https://example.invalid", method=method)
    assert calls == ["request"]


@pytest.mark.parametrize(
    ("failure", "category", "attempts"),
    [
        (r.urllib.error.URLError(TimeoutError("SYNTHETIC_RELEASE_MARKER")), "NETWORK_TIMEOUT", 2),
        (TimeoutError("SYNTHETIC_RELEASE_MARKER"), "NETWORK_TIMEOUT", 2),
        (
            r.urllib.error.URLError(socket.gaierror(-2, "SYNTHETIC_RELEASE_MARKER")),
            "NETWORK_DNS_FAILED",
            1,
        ),
        (
            r.urllib.error.URLError(ssl.SSLCertVerificationError(1, "SYNTHETIC_RELEASE_MARKER")),
            "NETWORK_TLS_VERIFICATION_FAILED",
            1,
        ),
        (ssl.SSLError(1, "SYNTHETIC_RELEASE_MARKER"), "NETWORK_TLS_FAILED", 1),
        (
            r.urllib.error.URLError(ConnectionRefusedError("SYNTHETIC_RELEASE_MARKER")),
            "NETWORK_CONNECTION_FAILED",
            1,
        ),
        (ConnectionResetError("SYNTHETIC_RELEASE_MARKER"), "NETWORK_CONNECTION_FAILED", 2),
        (
            r.urllib.error.URLError(ConnectionResetError("SYNTHETIC_RELEASE_MARKER")),
            "NETWORK_CONNECTION_FAILED",
            2,
        ),
        (OSError(errno.ENETUNREACH, "SYNTHETIC_RELEASE_MARKER"), "NETWORK_CONNECTION_FAILED", 1),
        (r.urllib.error.URLError("SYNTHETIC_RELEASE_MARKER"), "NETWORK_CAUSE_UNKNOWN", 1),
        (OSError(errno.EIO, "SYNTHETIC_RELEASE_MARKER"), "NETWORK_CAUSE_UNKNOWN", 1),
        (
            r.http.client.IncompleteRead(b"SYNTHETIC_RELEASE_MARKER"),
            "NETWORK_RESPONSE_INCOMPLETE",
            2,
        ),
        (
            r.urllib.error.URLError(r.http.client.IncompleteRead(b"SYNTHETIC_RELEASE_MARKER")),
            "NETWORK_RESPONSE_INCOMPLETE",
            2,
        ),
        (
            r.urllib.error.URLError(
                r.urllib.error.URLError(TimeoutError("SYNTHETIC_RELEASE_MARKER"))
            ),
            "NETWORK_CAUSE_UNKNOWN",
            1,
        ),
        (
            r.http.client.BadStatusLine("SYNTHETIC_RELEASE_MARKER"),
            "NETWORK_HTTP_PROTOCOL_FAILED",
            1,
        ),
    ],
)
def test_network_failure_uses_typed_evidence_and_bounded_safe_recovery(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure: OSError | r.http.client.HTTPException,
    category: str,
    attempts: int,
) -> None:
    calls = []
    slept = []

    def open_request(*_args, **_kwargs):
        calls.append("request")
        raise failure

    monkeypatch.setattr(r.urllib.request, "urlopen", open_request)
    monkeypatch.setattr(r.time, "sleep", slept.append)
    with pytest.raises(r.ReleaseError) as raised:
        r.request("https://example.invalid/SYNTHETIC_RELEASE_MARKER")
    assert str(raised.value).startswith(category + ":")
    assert "recovery:" in str(raised.value)
    assert "SYNTHETIC_RELEASE_MARKER" not in str(raised.value)
    assert calls == ["request"] * attempts
    assert slept == [2] * (attempts - 1)
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("stage", ["open", "read"])
@pytest.mark.parametrize(
    "failure",
    [
        TimeoutError("SYNTHETIC_RELEASE_MARKER"),
        r.urllib.error.URLError(TimeoutError("SYNTHETIC_RELEASE_MARKER")),
        ConnectionResetError("SYNTHETIC_RELEASE_MARKER"),
        r.urllib.error.URLError(ConnectionResetError("SYNTHETIC_RELEASE_MARKER")),
        r.http.client.IncompleteRead(b"SYNTHETIC_RELEASE_MARKER"),
        r.urllib.error.URLError(r.http.client.IncompleteRead(b"SYNTHETIC_RELEASE_MARKER")),
    ],
)
def test_bodyless_get_recovers_from_one_transient_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    stage: str,
    failure: OSError | r.http.client.HTTPException,
) -> None:
    payload = b"complete response"
    calls = []
    slept = []
    limits = []
    responses = []

    class Body(io.BytesIO):
        def read(self, limit: int) -> bytes:
            limits.append(limit)
            if stage == "read" and len(calls) == 1:
                raise failure
            return super().read(limit)

    def open_request(operation, **kwargs):
        assert all(response.closed for response in responses)
        calls.append(
            (operation.get_method(), operation.full_url, operation.data, kwargs["timeout"])
        )
        if stage == "open" and len(calls) == 1:
            raise failure
        response = Body(b"discarded partial" if len(calls) == 1 else payload)
        responses.append(response)
        return response

    monkeypatch.setattr(r.urllib.request, "urlopen", open_request)
    monkeypatch.setattr(r.time, "sleep", slept.append)
    url = "https://example.invalid/SYNTHETIC_RELEASE_MARKER"
    assert r.request(url) == payload
    assert calls == [("GET", url, None, 30)] * 2
    assert slept == [2]
    assert limits == [8 * 1024 * 1024 + 1] * (1 if stage == "open" else 2)
    assert all(response.closed for response in responses)
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize(
    ("method", "data"), [("POST", {"fixture": True}), ("PATCH", None), ("GET", {})]
)
@pytest.mark.parametrize(
    "failure",
    [
        r.urllib.error.URLError(TimeoutError("SYNTHETIC_RELEASE_MARKER")),
        ConnectionResetError("SYNTHETIC_RELEASE_MARKER"),
        r.http.client.IncompleteRead(b"SYNTHETIC_RELEASE_MARKER"),
    ],
)
def test_transient_failure_does_not_replay_writes_or_get_with_a_body(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    data: dict | None,
    failure: OSError | r.http.client.HTTPException,
) -> None:
    calls = []

    def open_request(operation, **_kwargs):
        calls.append((operation.get_method(), operation.data))
        raise failure

    monkeypatch.setattr(r.urllib.request, "urlopen", open_request)
    monkeypatch.setattr(r.time, "sleep", lambda _: pytest.fail("must not replay this request"))
    with pytest.raises(r.ReleaseError, match="^NETWORK_"):
        r.request("https://example.invalid", method=method, data=data)
    assert calls == [(method, None if data is None else json.dumps(data).encode())]


def test_invalid_json_is_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = []

    def open_request(*_args, **_kwargs):
        response = io.BytesIO(b"{invalid JSON")
        responses.append(response)
        return response

    monkeypatch.setattr(r.urllib.request, "urlopen", open_request)
    monkeypatch.setattr(r.time, "sleep", lambda _: pytest.fail("invalid JSON must not retry"))
    with pytest.raises(json.JSONDecodeError):
        r.api("https://example.invalid")
    assert len(responses) == 1 and responses[0].closed


def test_invalid_http_configuration_withholds_private_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def open_request(*_args, **_kwargs):
        raise ValueError("SYNTHETIC_RELEASE_MARKER")

    monkeypatch.setattr(r.urllib.request, "urlopen", open_request)
    monkeypatch.setattr(
        r.time, "sleep", lambda _: pytest.fail("invalid configuration must not retry")
    )
    with pytest.raises(r.ReleaseError) as raised:
        r.request("https://example.invalid/SYNTHETIC_RELEASE_MARKER")
    assert str(raised.value).startswith("HTTP_REQUEST_INVALID:")
    assert "SYNTHETIC_RELEASE_MARKER" not in str(raised.value)


@pytest.mark.parametrize(
    ("failure", "category"),
    [
        (TimeoutError("SYNTHETIC_RELEASE_MARKER"), "NETWORK_TIMEOUT"),
        (ConnectionResetError("SYNTHETIC_RELEASE_MARKER"), "NETWORK_CONNECTION_FAILED"),
        (r.http.client.IncompleteRead(b"SYNTHETIC_RELEASE_MARKER"), "NETWORK_RESPONSE_INCOMPLETE"),
    ],
)
def test_response_read_exhaustion_has_the_same_safe_network_boundary(
    monkeypatch: pytest.MonkeyPatch,
    failure: OSError | r.http.client.HTTPException,
    category: str,
) -> None:
    responses = []
    slept = []

    class InterruptedBody(io.BytesIO):
        def read(self, _limit: int) -> bytes:
            raise failure

    def open_request(*_args, **_kwargs):
        response = InterruptedBody()
        responses.append(response)
        return response

    monkeypatch.setattr(r.urllib.request, "urlopen", open_request)
    monkeypatch.setattr(r.time, "sleep", slept.append)
    with pytest.raises(r.ReleaseError) as raised:
        r.request("https://example.invalid")
    assert str(raised.value).startswith(category + ":")
    assert "SYNTHETIC_RELEASE_MARKER" not in str(raised.value)
    assert len(responses) == 2 and all(response.closed for response in responses)
    assert slept == [2]


@pytest.mark.parametrize(
    ("interrupted", "size"),
    [(True, 8 * 1024 * 1024), (True, 8 * 1024 * 1024 + 1), (False, 8 * 1024 * 1024 + 1)],
)
def test_get_retry_preserves_the_response_size_limit(
    monkeypatch: pytest.MonkeyPatch, interrupted: bool, size: int
) -> None:
    payload = b"x" * size
    responses = []
    slept = []

    class InterruptedBody(io.BytesIO):
        def read(self, _limit: int) -> bytes:
            raise r.http.client.IncompleteRead(b"discarded partial")

    def open_request(*_args, **_kwargs):
        response = InterruptedBody() if interrupted and not responses else io.BytesIO(payload)
        responses.append(response)
        return response

    monkeypatch.setattr(r.urllib.request, "urlopen", open_request)
    monkeypatch.setattr(r.time, "sleep", slept.append)
    if size == 8 * 1024 * 1024:
        assert r.request("https://example.invalid") == payload
    else:
        with pytest.raises(r.ReleaseError, match="response exceeds 8 MiB"):
            r.request("https://example.invalid")
    assert len(responses) == (2 if interrupted else 1)
    assert all(response.closed for response in responses)
    assert slept == ([2] if interrupted else [])


@pytest.mark.parametrize("json_api", [False, True])
def test_content_length_premature_eof_recovers_without_accepting_partial_json(
    memory_http, json_api: bool
) -> None:
    partial = b'{"partial":true}'
    complete = b'{"complete":true}'
    headers = f"Content-Length: {len(complete)}\r\n".encode()
    calls, responses, streams, slept = memory_http(
        _http_wire(partial, headers), _http_wire(complete, headers)
    )
    url = "https://example.invalid"
    if json_api:
        assert r.api(url) == {"complete": True}
    else:
        assert r.request(url) == complete
    assert calls == [("GET", None, 30)] * 2
    assert slept == [2]
    assert all(response.isclosed() for response in responses)
    assert all(stream.closed for stream in streams)


def test_content_length_premature_eof_exhaustion_has_safe_bounded_diagnostics(
    memory_http, capsys: pytest.CaptureFixture[str]
) -> None:
    partial = b"SYNTHETIC_RELEASE_MARKER"
    message = _http_wire(partial, b"Content-Length: 200\r\n")
    calls, responses, streams, slept = memory_http(message, message)
    with pytest.raises(r.ReleaseError, match="^NETWORK_RESPONSE_INCOMPLETE:") as raised:
        r.request("https://example.invalid/SYNTHETIC_RELEASE_MARKER")
    assert "recovery:" in str(raised.value)
    assert "SYNTHETIC_RELEASE_MARKER" not in str(raised.value)
    assert "example.invalid" not in str(raised.value)
    assert calls == [("GET", None, 30)] * 2
    assert slept == [2]
    assert all(response.isclosed() for response in responses)
    assert all(stream.closed for stream in streams)
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize(
    ("method", "data"), [("POST", {"fixture": True}), ("PATCH", None), ("GET", {})]
)
def test_content_length_premature_eof_does_not_replay_writes_or_get_with_body(
    memory_http, method: str, data: dict | None
) -> None:
    calls, responses, streams, slept = memory_http(_http_wire(b"short", b"Content-Length: 20\r\n"))
    with pytest.raises(r.ReleaseError, match="^NETWORK_RESPONSE_INCOMPLETE:"):
        r.request("https://example.invalid", method=method, data=data)
    assert calls == [(method, None if data is None else json.dumps(data).encode(), 30)]
    assert slept == []
    assert responses[0].isclosed() and streams[0].closed


@pytest.mark.parametrize(
    ("method", "status", "headers", "body", "expected"),
    [
        ("GET", "200 OK", b"Content-Length: 4\r\n", b"data", b"data"),
        ("GET", "200 OK", b"Content-Length: 0\r\n", b"ignored", b""),
        ("GET", "200 OK", b"", b"data", b"data"),
        ("GET", "200 OK", b"Content-Length: invalid\r\n", b"data", b"data"),
        ("GET", "200 OK", b"Content-Length: -1\r\n", b"data", b"data"),
        ("HEAD", "200 OK", b"Content-Length: 200\r\n", b"", b""),
        ("GET", "101 Switching Protocols", b"Content-Length: 200\r\n", b"", b""),
        ("GET", "204 No Content", b"Content-Length: 200\r\n", b"", b""),
        ("GET", "304 Not Modified", b"Content-Length: 200\r\n", b"", b""),
        (
            "GET",
            "200 OK",
            b"Transfer-Encoding: chunked\r\nContent-Length: 200\r\n",
            b"4\r\ndata\r\n0\r\n\r\n",
            b"data",
        ),
    ],
)
def test_http_effective_framing_keeps_existing_success_semantics(
    memory_http, method: str, status: str, headers: bytes, body: bytes, expected: bytes
) -> None:
    calls, responses, streams, slept = memory_http(_http_wire(body, headers, status))
    assert r.request("https://example.invalid", method=method) == expected
    assert calls == [(method, None, 30)]
    assert slept == []
    assert responses[0].isclosed() and streams[0].closed


def test_chunked_premature_eof_still_recovers_through_the_existing_retry(memory_http) -> None:
    headers = b"Transfer-Encoding: chunked\r\nContent-Length: 200\r\n"
    calls, responses, streams, slept = memory_http(
        _http_wire(b"4\r\nda", headers), _http_wire(b"4\r\ndata\r\n0\r\n\r\n", headers)
    )
    assert r.request("https://example.invalid") == b"data"
    assert calls == [("GET", None, 30)] * 2
    assert slept == [2]
    assert all(response.isclosed() for response in responses)
    assert all(stream.closed for stream in streams)


@pytest.mark.parametrize(
    ("declared", "actual"),
    [
        (8 * 1024 * 1024, 8 * 1024 * 1024),
        (8 * 1024 * 1024 + 1, 8 * 1024 * 1024 + 1),
        (16 * 1024 * 1024, 8 * 1024 * 1024 + 1),
    ],
)
def test_http_content_length_preserves_the_size_limit_before_incomplete_detection(
    memory_http, declared: int, actual: int
) -> None:
    payload = b"x" * actual
    calls, responses, streams, slept = memory_http(
        _http_wire(payload, f"Content-Length: {declared}\r\n".encode())
    )
    if actual == 8 * 1024 * 1024:
        assert r.request("https://example.invalid") == payload
    else:
        with pytest.raises(r.ReleaseError, match="response exceeds 8 MiB"):
            r.request("https://example.invalid")
    assert calls == [("GET", None, 30)]
    assert slept == []
    assert responses[0].isclosed() and streams[0].closed


@pytest.mark.parametrize("actual", [5, 8 * 1024 * 1024])
def test_short_body_with_large_content_length_is_still_an_incomplete_response(
    memory_http, actual: int
) -> None:
    message = _http_wire(b"x" * actual, b"Content-Length: 16777216\r\n")
    calls, responses, streams, slept = memory_http(message, message)
    with pytest.raises(r.ReleaseError, match="^NETWORK_RESPONSE_INCOMPLETE:"):
        r.request("https://example.invalid")
    assert calls == [("GET", None, 30)] * 2
    assert slept == [2]
    assert all(response.isclosed() for response in responses)
    assert all(stream.closed for stream in streams)


def test_complete_http_response_with_malformed_json_is_not_retried(memory_http) -> None:
    payload = b"{invalid JSON"
    calls, responses, streams, slept = memory_http(
        _http_wire(payload, f"Content-Length: {len(payload)}\r\n".encode())
    )
    with pytest.raises(json.JSONDecodeError):
        r.api("https://example.invalid")
    assert calls == [("GET", None, 30)]
    assert slept == []
    assert responses[0].isclosed() and streams[0].closed


@pytest.mark.parametrize("conflict", ["digest", "size"])
def test_complete_http_artifact_conflict_stops_without_transport_retry(
    monkeypatch: pytest.MonkeyPatch, memory_http, conflict: str
) -> None:
    payload = b"fixture artifact"
    calls, responses, streams, slept = memory_http(
        _http_wire(payload, f"Content-Length: {len(payload)}\r\n".encode())
    )
    item = {
        "filename": "snapshot_runner-1.2.3-py3-none-any.whl",
        "url": "https://files.pythonhosted.org/fixture.whl",
        "yanked": False,
        "digests": {"sha256": hashlib.sha256(payload).hexdigest()},
        "size": len(payload),
    }
    if conflict == "digest":
        item["digests"]["sha256"] = "f" * 64
    else:
        item["size"] += 1
    monkeypatch.setattr(
        r, "api", lambda _: {"info": {"name": r.PACKAGE, "version": "1.2.3"}, "urls": [item]}
    )
    monkeypatch.setattr(
        r, "check_provenance", lambda *_: pytest.fail("must stop before provenance")
    )
    with pytest.raises(r.ReleaseIdentityError, match="downloaded file digest/size conflict"):
        r.pypi_files(RELEASE, complete=False)
    assert calls == [("GET", None, 30)]
    assert slept == []
    assert responses[0].isclosed() and streams[0].closed


def test_identity_failure_has_its_own_recovery_entry_before_mutation(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def conflict(*_args):
        raise r.ReleaseIdentityError("GitHub annotated tag object identity conflict")

    monkeypatch.setattr(r, "public_identity", conflict)
    monkeypatch.setattr(
        r, "command", lambda *_: pytest.fail("must not mutate on identity conflict")
    )
    assert r.main(["gate", TAG]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("release_failed: ReleaseIdentityError:")
    assert "original build receipt and exact tag" in captured.err


@pytest.mark.parametrize(
    "extra_header", ["object " + SHA, "type tree", "tag v9.9.9", "encoding UTF-8"]
)
def test_release_identity_rejects_extra_or_duplicate_tag_headers(
    repository: Path, extra_header: str
) -> None:
    raw = subprocess.check_output(["git", "cat-file", "tag", TAG]).decode()
    header, message = raw.split("\n\n", 1)
    ambiguous = header + "\n" + extra_header + "\n\n" + message
    result = subprocess.run(
        ["git", "hash-object", "-t", "tag", "--literally", "--stdin", "-w"],
        input=ambiguous.encode(),
        capture_output=True,
        check=True,
    )
    with pytest.raises(r.ReleaseError, match="raw annotated tag"):
        r.identity(TAG, tag_object=result.stdout.decode().strip())


@pytest.mark.parametrize(
    ("arguments", "operation"),
    [
        (("git", "fetch", "origin"), "git fetch"),
        (("git", "ls-remote", "origin"), "git ls-remote"),
        (("git", "push", "origin", "HEAD"), "git push"),
        (("git", "-C", "/fixture-private-path", "rev-parse", "HEAD"), "git rev-parse"),
    ],
)
def test_git_failure_identifies_operation_without_echoing_inputs(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    arguments: tuple[str, ...],
    operation: str,
) -> None:
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(
            args, 128, "fixture-private-stdout", "fixture-private-stderr"
        )

    monkeypatch.setattr(r.subprocess, "run", run)
    monkeypatch.setattr(r.time, "sleep", lambda _: pytest.fail("must not retry"))
    with pytest.raises(r.ReleaseError) as failure:
        r.command(*arguments)
    assert str(failure.value) == f"{operation} failed (exit 128)"
    assert calls == [arguments]
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("verb", ["fetch", "ls-remote"])
def test_public_git_read_recovers_from_transient_transport(
    monkeypatch: pytest.MonkeyPatch, verb: str
) -> None:
    arguments = (
        "git",
        verb,
        "--no-tags" if verb == "fetch" else "--tags",
        f"https://github.com/{r.PUBLIC_REPOSITORY}.git",
        f"refs/tags/{TAG}",
    )
    calls, waits = [], []

    def run(args, **kwargs):
        calls.append((args, kwargs["timeout"]))
        return subprocess.CompletedProcess(
            args,
            128 if len(calls) == 1 else 0,
            "resolved\n",
            "fatal: the requested URL returned error: 502",
        )

    monkeypatch.setattr(r.subprocess, "run", run)
    monkeypatch.setattr(r.time, "sleep", waits.append)
    assert r.command(*arguments) == "resolved"
    assert calls == [(arguments, r.PUBLIC_GIT_TIMEOUT_SECONDS)] * 2
    assert waits == [r.PUBLIC_GIT_DELAY_SECONDS]


@pytest.mark.parametrize("timeout", [False, True])
def test_public_git_transport_failure_has_a_finite_budget(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    timeout: bool,
) -> None:
    arguments = ("git", "fetch", "--no-tags", f"https://github.com/{r.PUBLIC_REPOSITORY}.git", SHA)
    calls, waits = [], []

    def run(args, **kwargs):
        calls.append(args)
        if timeout:
            raise subprocess.TimeoutExpired(
                args, kwargs["timeout"], stderr="fixture-private-stderr"
            )
        return subprocess.CompletedProcess(args, 128, "", "fatal: connection reset by peer")

    monkeypatch.setattr(r.subprocess, "run", run)
    monkeypatch.setattr(r.time, "sleep", waits.append)
    with pytest.raises(r.ReleaseError) as failure:
        r.command(*arguments)
    assert len(calls) == r.PUBLIC_GIT_ATTEMPTS
    assert waits == [r.PUBLIC_GIT_DELAY_SECONDS] * (r.PUBLIC_GIT_ATTEMPTS - 1)
    assert f"after {r.PUBLIC_GIT_ATTEMPTS} attempts" in str(failure.value)
    assert "fixture-private" not in str(failure.value)
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize(
    "diagnostic",
    [
        "authentication failed; the requested URL returned error: 502",
        "permission denied",
        "repository not found",
        "couldn't find remote ref",
        "not our ref",
        "SSL certificate problem",
        "local tag would be clobbered",
    ],
)
def test_public_git_identity_and_permission_failures_are_not_retried(
    monkeypatch: pytest.MonkeyPatch, diagnostic: str
) -> None:
    arguments = ("git", "fetch", "--no-tags", f"https://github.com/{r.PUBLIC_REPOSITORY}.git", SHA)
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 128, "", diagnostic)

    monkeypatch.setattr(r.subprocess, "run", run)
    monkeypatch.setattr(r.time, "sleep", lambda _: pytest.fail("must not retry"))
    with pytest.raises(r.ReleaseError):
        r.command(*arguments)
    assert calls == [arguments]


@pytest.mark.parametrize(
    "arguments",
    [
        ("git", "push", "--no-follow-tags", "origin", "HEAD:refs/heads/main"),
        ("git", "push", "--no-tags", "https://github.com/{repo}.git", "HEAD"),
        ("git", "fetch", "--no-tags", "origin", SHA),
        ("git", "fetch", "--no-tags", "https://github.com/other/repository.git", SHA),
        ("git", "ls-remote", "--refs", "origin", f"refs/tags/{TAG}"),
    ],
)
def test_external_writes_and_nonpublic_reads_are_never_replayed(
    monkeypatch: pytest.MonkeyPatch, arguments: tuple[str, ...]
) -> None:
    arguments = tuple(arg.replace("{repo}", r.PUBLIC_REPOSITORY) for arg in arguments)
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(
            args, 128, "", "fatal: the requested URL returned error: 502"
        )

    monkeypatch.setattr(r.subprocess, "run", run)
    monkeypatch.setattr(r.time, "sleep", lambda _: pytest.fail("must not retry"))
    with pytest.raises(r.ReleaseError):
        r.command(*arguments)
    assert calls == [arguments]


@pytest.fixture
def repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.chdir(repo)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    subprocess.run(["git", "init", "-q", "-b", "main"], check=True)
    (repo / "snapshot_runner").mkdir()
    (repo / "pyproject.toml").write_text(f'[project]\nname = "{r.PACKAGE}"\nversion = "1.2.3"\n')
    (repo / "snapshot_runner/__init__.py").write_text('__version__ = "1.2.3"\n')
    (repo / "CHANGELOG.md").write_text("# Changelog\n\n## Unreleased\n\n## 1.2.3\n\n- Notes\n")
    (repo / "README.md").write_text(
        "Current stable release: **1.2.3**.\n\npip install 'snapshot-runner==1.2.3'\n"
    )
    subprocess.run(
        ["git", "add", "pyproject.toml", "snapshot_runner", "CHANGELOG.md", "README.md"], check=True
    )
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "fixture",
        ],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "tag",
            "-a",
            TAG,
            "-m",
            "Fixture release",
        ],
        check=True,
    )
    return repo


@pytest.mark.parametrize("tag", ["v1.2.4", "v01.2.3", "archive-v1.2.3"])
def test_tag_version_mismatch_blocks_before_quality_or_build(repository: Path, tag: str) -> None:
    if tag == "v1.2.4":
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "tag",
                "-a",
                tag,
                "-m",
                "Mismatched version",
            ],
            check=True,
        )
    with pytest.raises(r.ReleaseError):
        r.identity(tag)


def test_exact_commit_is_required(repository: Path) -> None:
    with pytest.raises(r.ReleaseError, match="tag/expected commit mismatch"):
        r.identity(TAG, SHA)


def test_lightweight_tag_is_not_a_formal_release(repository: Path) -> None:
    subprocess.run(["git", "tag", "v1.2.4"], check=True)
    with pytest.raises(r.ReleaseError, match="annotated tag"):
        r.identity("v1.2.4")


@pytest.mark.parametrize("kind,object_id", [("commit", SHA), ("tag", "d" * 40)])
def test_public_tag_object_conflict_fails_even_at_same_commit(monkeypatch, kind, object_id) -> None:
    monkeypatch.setattr(r, "api", lambda *_, **__: {"object": {"type": kind, "sha": object_id}})
    with pytest.raises(r.ReleaseIdentityError, match="tag object identity conflict"):
        r.github_tag(TAG, RELEASE["tag_object"])


def test_gitea_tag_object_conflict_blocks_record_creation(monkeypatch) -> None:
    def api(url, **kwargs):
        assert kwargs.get("method", "GET") == "GET"
        assert url.endswith("/tags/" + TAG)
        return {"commit": {"sha": SHA}}

    monkeypatch.setattr(r, "api", api)
    monkeypatch.setattr(r, "command", lambda *_: "d" * 40 + "\trefs/tags/" + TAG)
    with pytest.raises(r.ReleaseIdentityError, match="tag object identity conflict"):
        r.release_record(
            RELEASE, {}, "gitea", "https://example.invalid/api/v1", "org/repo", apply=True
        )


def test_real_quality_failure_stops_before_network_or_build(
    repository: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tools = tmp_path / "bin"
    tools.mkdir()
    (tools / "just").write_text("#!/bin/sh\nexit 19\n")
    (tools / "just").chmod(0o755)
    (tools / "uv").write_text("#!/bin/sh\ntouch unexpected-build\nexit 0\n")
    (tools / "uv").chmod(0o755)
    monkeypatch.setenv("PATH", f"{tools}:{os.defpath}")
    with pytest.raises(r.ReleaseError, match="just failed \\(exit 19\\)"):
        r.build(r.identity(TAG))
    assert not (repository / "unexpected-build").exists()
    assert not (repository / "dist").exists()


def test_published_package_skips_build(repository: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    identity = r.identity(TAG)
    monkeypatch.setattr(r, "github_tag", lambda *_: identity["commit"])
    original = r.command
    actions = []

    def command(*args):
        if args[0] == "git":
            return original(*args)
        actions.append(args)
        return ""

    monkeypatch.setattr(r, "command", command)
    monkeypatch.setattr(r, "pypi_files", lambda *_, **__: {"existing": "hash"})
    assert r.build(identity) is False
    assert actions == [("just", "check")]


def artifacts(path: Path) -> dict[str, str]:
    path.mkdir()
    metadata = f"Name: {r.PACKAGE}\nVersion: 1.2.3\n".encode()
    wheel = path / f"{r.ARCHIVE}-1.2.3-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(f"{r.ARCHIVE}-1.2.3.dist-info/METADATA", metadata)
    source = path / f"{r.ARCHIVE}-1.2.3.tar.gz"
    with tarfile.open(source, "w:gz") as archive:
        member = tarfile.TarInfo(f"{r.ARCHIVE}-1.2.3/PKG-INFO")
        member.size = len(metadata)
        archive.addfile(member, io.BytesIO(metadata))
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in path.iterdir()}


def test_partial_upload_reuses_only_missing_original_file(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "dist"
    hashes = artifacts(source)
    wheel = next(name for name in hashes if name.endswith(".whl"))
    monkeypatch.setattr(r, "pypi_files", lambda *_, **__: {wheel: hashes[wheel]})
    output = tmp_path / "pending"
    pending = r.pending_dist(RELEASE, source, output)
    assert pending == [next(name for name in hashes if name.endswith(".tar.gz"))]
    assert {p.name for p in output.iterdir()} == set(pending)
    assert (output / pending[0]).read_bytes() == (source / pending[0]).read_bytes()
    monkeypatch.setattr(r, "pypi_files", lambda *_, **__: hashes)
    assert r.pending_dist(RELEASE, source, tmp_path / "retry") == []


def test_existing_file_conflict_stops_before_upload_selection(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "dist"
    hashes = artifacts(source)
    monkeypatch.setattr(r, "pypi_files", lambda *_, **__: dict.fromkeys(hashes, "0" * 64))
    with pytest.raises(r.ReleaseError, match="differs from original build"):
        r.pending_dist(RELEASE, source, tmp_path / "pending")
    assert not (tmp_path / "pending").exists()


@pytest.mark.parametrize("platform", ["github", "gitea"])
def test_record_resume_after_post_succeeded_but_readback_failed(monkeypatch, platform) -> None:
    hashes = {"wheel": "hash"}
    record = None
    posts = 0
    fail_readback = True
    monkeypatch.setattr(r, "github_tag", lambda *_: SHA)
    monkeypatch.setattr(r, "command", lambda *_: f"{RELEASE['tag_object']}\trefs/tags/{TAG}")
    base = r.GITHUB_API if platform == "github" else "https://example.invalid/api/v1"

    def api(url, **kwargs):
        nonlocal record, posts, fail_readback
        if url.endswith(f"/tags/{TAG}") and "/releases/" not in url:
            return {"commit": {"sha": SHA}}
        if kwargs.get("method") == "POST":
            if platform == "github":
                # The job token cannot request a historical workflow target;
                # the already-verified annotated tag supplies package identity.
                assert "target_commitish" not in kwargs["data"]
            else:
                assert kwargs["data"]["target_commitish"] == SHA
            posts += 1
            record = {**kwargs["data"], "id": 17, "html_url": "https://example.invalid/release"}
            if platform == "github":
                record["target_commitish"] = "master"
            return record
        if record and fail_readback:
            fail_readback = False
            raise r.ReleaseError("readback unavailable")
        return record

    monkeypatch.setattr(r, "api", api)
    with pytest.raises(r.ReleaseError, match="readback unavailable"):
        r.release_record(
            RELEASE,
            hashes,
            platform,
            base,
            r.PUBLIC_REPOSITORY,
            apply=True,
            token="fixture",
        )
    for _ in range(2):
        result = r.release_record(
            RELEASE,
            hashes,
            platform,
            base,
            r.PUBLIC_REPOSITORY,
            apply=True,
            token="fixture",
        )
        assert result["status"] == "PASS" and not result["created"]
    assert posts == 1


@pytest.mark.parametrize(
    "conflict", ["tag", "files", "tag_object", "draft", "commit", "target", "marker"]
)
def test_release_conflict_is_fail_closed_without_mutation(monkeypatch, conflict) -> None:
    hashes = {"wheel": "hash"}
    marker = r.record_identity(RELEASE, hashes)
    record = {
        "id": 1,
        "tag_name": TAG,
        "draft": False,
        "prerelease": False,
        "html_url": "https://example.invalid/release",
        "sha1": SHA,
    }
    if conflict == "files":
        marker["files"] = {"wheel": "different"}
    if conflict == "tag_object":
        marker["tag_object"] = "d" * 40
    if conflict == "draft":
        record["draft"] = True
    if conflict == "commit":
        record["sha1"] = "b" * 40
    if conflict == "target":
        record["target_commitish"] = "b" * 40
    record["body"] = r.MARKER + json.dumps(marker) + " -->"
    if conflict == "marker":
        record["body"] = "unverified release"
    monkeypatch.setattr(r, "github_tag", lambda *_: "b" * 40 if conflict == "tag" else SHA)

    def api(url, **kwargs):
        assert kwargs.get("method", "GET") == "GET"
        return record

    monkeypatch.setattr(r, "api", api)
    with pytest.raises(r.ReleaseError):
        r.release_record(RELEASE, hashes, "github", r.GITHUB_API, r.PUBLIC_REPOSITORY, apply=True)


def test_local_caller_cannot_backfill_tag_with_pat(monkeypatch) -> None:
    monkeypatch.delenv("GITEA_ACTIONS", raising=False)
    with pytest.raises(r.ReleaseError, match="Gitea Actions job token"):
        r.sync_gitea(TAG, "https://example.invalid/api/v1", "org/repo")


@pytest.mark.parametrize("conflicting_record", [False, True])
def test_gitea_backfill_preserves_tag_object_and_does_not_build(
    monkeypatch, conflicting_record
) -> None:
    monkeypatch.setenv("GITEA_ACTIONS", "true")
    monkeypatch.setenv("RELEASE_TOKEN", "private-fixture")
    monkeypatch.setattr(r, "github_tag", lambda *_: SHA)
    monkeypatch.setattr(r, "receipt_identity", lambda *_: RELEASE)
    monkeypatch.setattr(r, "pypi_files", lambda *_, **__: {"wheel": "hash"})

    def api(url, **kwargs):
        if r.GITHUB_API in url:
            return {"body": r.MARKER + json.dumps(r.record_identity(RELEASE, {})) + " -->"}
        if url.endswith("/org/repo"):
            return {}
        if "/releases/tags/" in url and conflicting_record:
            return {"tag_name": TAG, "draft": True, "prerelease": False}
        return None

    monkeypatch.setattr(r, "api", api)
    actions = []

    def command(*args):
        actions.append(args)
        if args[1] == "rev-parse":
            return "c" * 40
        if args[1] == "ls-remote":
            return "c" * 40 + "\trefs/tags/" + TAG
        return ""

    def record(*args, **kwargs):
        if args[2] == "github":
            assert "token" not in kwargs
        else:
            assert kwargs["token"] == "private-fixture"
        return {"status": "PASS"}

    monkeypatch.setattr(r, "command", command)
    monkeypatch.setattr(r, "release_record", record)
    if conflicting_record:
        with pytest.raises(r.ReleaseError, match="Release identity conflict"):
            r.sync_gitea(TAG, "https://example.invalid/api/v1", "org/repo")
        assert not any(action[1] == "push" for action in actions)
        return
    result = r.sync_gitea(TAG, "https://example.invalid/api/v1", "org/repo")
    assert result["tag_object"] == "c" * 40
    assert all(action[0] == "git" for action in actions)
    assert [a for a in actions if a[1] == "push"] == [
        ("git", "push", "--no-follow-tags", "origin", f"{RELEASE['tag_object']}:refs/tags/{TAG}")
    ]


@pytest.mark.parametrize("local_ref", ["annotated", "peeled", "missing"])
def test_remote_raw_tag_survives_detached_checkout_and_local_ref_changes(
    repository: Path, tmp_path: Path, monkeypatch, local_ref: str
) -> None:
    approved = r.identity(TAG)
    client = tmp_path / "checkout"
    subprocess.run(["git", "clone", "-q", str(repository), str(client)], check=True)
    monkeypatch.chdir(client)
    r.command("git", "checkout", "--detach", approved["commit"])
    if local_ref == "peeled":
        r.command("git", "update-ref", f"refs/tags/{TAG}", approved["commit"])
    elif local_ref == "missing":
        r.command("git", "update-ref", "-d", f"refs/tags/{TAG}")
    before = r.command("git", "for-each-ref", "--format=%(objectname)", f"refs/tags/{TAG}")
    original = r.command

    def command(*args):
        if args[:2] == ("git", "fetch"):
            assert args[2:] == (
                "--no-tags",
                f"https://github.com/{r.PUBLIC_REPOSITORY}.git",
                approved["tag_object"],
            )
            return original("git", "fetch", "--no-tags", str(repository), approved["tag_object"])
        return original(*args)

    monkeypatch.setattr(r, "command", command)
    monkeypatch.setattr(
        r, "github_identity", lambda *_: (approved["tag_object"], approved["commit"])
    )
    actual = r.public_identity(TAG, approved["commit"], approved["tag_object"])
    assert actual == approved
    assert (
        r.identity(TAG, approved["commit"], tag_object=approved["tag_object"], checkout=True)
        == approved
    )
    assert before == r.command("git", "for-each-ref", "--format=%(objectname)", f"refs/tags/{TAG}")
    assert r.command("git", "rev-parse", "HEAD") == approved["commit"]


def test_remote_target_conflict_blocks_before_fetch(monkeypatch) -> None:
    monkeypatch.setattr(r, "github_identity", lambda *_: (RELEASE["tag_object"], "d" * 40))
    monkeypatch.setattr(r, "command", lambda *_: pytest.fail("must not fetch conflicting identity"))
    with pytest.raises(r.ReleaseError, match="expected commit mismatch"):
        r.public_identity(TAG, SHA, RELEASE["tag_object"])


def test_master_control_cannot_be_built_as_tag_source(repository: Path, monkeypatch) -> None:
    release = r.identity(TAG)
    (repository / "control.txt").write_text("new control revision\n")
    r.command("git", "add", "control.txt")
    r.command(
        "git",
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-qm",
        "control only",
    )
    with pytest.raises(r.ReleaseError, match="exact release commit"):
        r.build(release)


def test_shallow_source_is_rejected_before_quality_or_build(
    repository: Path, tmp_path: Path, monkeypatch
) -> None:
    release = r.identity(TAG)
    checkout = tmp_path / "shallow"
    r.command("git", "clone", "--depth", "1", repository.as_uri(), str(checkout))
    monkeypatch.chdir(checkout)
    with pytest.raises(r.ReleaseError, match="complete Git history"):
        r.build(release)


def test_previous_artifact_blocks_a_second_build(repository: Path, monkeypatch) -> None:
    release = r.identity(TAG)
    original = r.command
    calls = []

    def command(*args):
        if args[0] == "git":
            return original(*args)
        calls.append(args)
        return ""

    monkeypatch.setattr(r, "command", command)
    monkeypatch.setattr(r, "github_tag", lambda *_: release["commit"])
    monkeypatch.setattr(r, "pypi_files", lambda *_, **__: None)
    monkeypatch.setattr(r, "api", lambda *_, **__: {"total_count": 1})
    with pytest.raises(r.ReleaseError, match="resume its publish job"):
        r.build(release)
    assert calls == [("just", "check")]


@pytest.mark.parametrize("acceptance_failed", [False, True])
def test_original_distribution_acceptance_gates_receipt_and_upload_outputs(
    repository: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    acceptance_failed: bool,
) -> None:
    release = r.identity(TAG)
    dist, receipt, output = (tmp_path / name for name in ("dist", "receipt.json", "outputs"))
    calls = []
    original = r.command

    def command(*args):
        if args[0] == "git":
            return original(*args)
        calls.append(args)
        if args[:4] == ("uv", "run", "--frozen", "python") and acceptance_failed:
            raise r.ReleaseError("original distribution acceptance failed")
        return ""

    hashes = {name: "e" * 64 for name in r.filenames(release["version"])}

    def artifact_hashes(*_args):
        assert not acceptance_failed, "receipt hashes must follow successful acceptance"
        return hashes

    monkeypatch.setattr(r, "command", command)
    monkeypatch.setattr(r, "public_identity", lambda *_: dict(release))
    monkeypatch.setattr(
        r,
        "control_identity",
        lambda: {key: RELEASE[key] for key in ("control_commit", "control_ref", "build_run_id")},
    )
    monkeypatch.setattr(r, "github_tag", lambda *_: release["commit"])
    monkeypatch.setattr(r, "pypi_files", lambda *_: None)
    monkeypatch.setattr(r, "api", lambda *_, **__: {"total_count": 0})
    monkeypatch.setattr(r, "artifact_hashes", artifact_hashes)
    monkeypatch.delenv("RELEASE_NOTES", raising=False)
    monkeypatch.delenv("PUBLIC_GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    result = r.main(
        [
            "build",
            TAG,
            "--expected-sha",
            release["commit"],
            "--dist",
            str(dist),
            "--receipt",
            str(receipt),
        ]
    )
    assert calls == [
        ("just", "check"),
        ("uv", "build", "--out-dir", str(dist)),
        (
            "uv",
            "run",
            "--frozen",
            "python",
            str(ROOT / "scripts/check_package.py"),
            "--wheel",
            str(dist / "snapshot_runner-1.2.3-py3-none-any.whl"),
            "--sdist",
            str(dist / "snapshot_runner-1.2.3.tar.gz"),
            "--expected-version",
            "1.2.3",
        ),
    ]
    captured = capsys.readouterr()
    if acceptance_failed:
        assert result == 1 and captured.out == ""
        assert "original distribution acceptance failed" in captured.err
        assert not receipt.exists() and not output.exists()
    else:
        assert result == 0 and captured.err == ""
        recorded = json.loads(receipt.read_text())
        assert recorded["package_source_commit"] == release["commit"]
        assert recorded["release_control_commit"] == RELEASE["control_commit"]
        assert recorded["files"] == hashes
        assert "built=true" in output.read_text()


@pytest.mark.parametrize(
    ("default_notes", "override", "valid"),
    [
        pytest.param("n", None, True, id="default-minimum"),
        pytest.param("n" * 8192, None, True, id="default-maximum"),
        pytest.param("source notes", "n" * 8192, True, id="override-maximum"),
        pytest.param("n" * 8192, "", True, id="empty-override-fallback"),
        pytest.param("n" * 8193, None, False, id="default-too-long"),
        pytest.param("source notes", "n" * 8193, False, id="override-too-long"),
        pytest.param("", None, False, id="empty-default"),
        pytest.param(None, "", False, id="invalid-default-fallback"),
    ],
)
def test_build_notes_are_validated_before_publication_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    default_notes: str | None,
    override: str | None,
    valid: bool,
) -> None:
    release = {**RELEASE, "notes": default_notes}
    dist, receipt, output = (tmp_path / name for name in ("dist", "receipt.json", "outputs"))
    hashes = dict.fromkeys(r.filenames(release["version"]), "e" * 64)
    built_notes, hashed_paths = [], []

    def build(actual, destination):
        assert destination == dist
        built_notes.append(actual["notes"])
        return True

    def artifact_hashes(destination, version):
        assert version == release["version"]
        hashed_paths.append(destination)
        return hashes

    monkeypatch.setattr(r, "public_identity", lambda *_: dict(release))
    monkeypatch.setattr(
        r,
        "control_identity",
        lambda: {key: RELEASE[key] for key in ("control_commit", "control_ref", "build_run_id")},
    )
    monkeypatch.setattr(r, "build", build)
    monkeypatch.setattr(r, "artifact_hashes", artifact_hashes)
    if override is None:
        monkeypatch.delenv("RELEASE_NOTES", raising=False)
    else:
        monkeypatch.setenv("RELEASE_NOTES", override)
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    result = r.main(
        ["build", TAG, "--expected-sha", SHA, "--dist", str(dist), "--receipt", str(receipt)]
    )
    captured = capsys.readouterr()
    assert result == (0 if valid else 1)
    if not valid:
        assert captured.out == "" and "release notes" in captured.err
        assert built_notes == hashed_paths == []
        assert not dist.exists() and not receipt.exists() and not output.exists()
        return
    assert captured.err == ""
    assert built_notes == [override or default_notes]
    assert hashed_paths == [dist]
    assert output.read_text() == "built=true\n"
    recorded = json.loads(receipt.read_text())
    assert recorded["notes"] == (override or default_notes)
    monkeypatch.setattr(
        r,
        "api",
        lambda *_, **__: {
            "head_sha": RELEASE["control_commit"],
            "head_branch": "master",
            "path": ".github/workflows/publish-pypi.yml",
            "head_repository": {"full_name": r.PUBLIC_REPOSITORY},
            "event": "workflow_dispatch",
        },
    )
    monkeypatch.delenv("PUBLIC_GITHUB_TOKEN", raising=False)
    assert r.receipt_identity(recorded)["notes"] == recorded["notes"]


@pytest.mark.parametrize("notes", ["", "n" * 8193, None], ids=["empty", "too-long", "non-string"])
def test_receipt_notes_are_rejected_before_provenance_read(monkeypatch, notes) -> None:
    receipt = r.record_identity(
        {**RELEASE, "notes": notes}, dict.fromkeys(r.filenames("1.2.3"), "e" * 64)
    )
    monkeypatch.setattr(r, "public_identity", lambda *_: dict(RELEASE))
    monkeypatch.setattr(r, "api", lambda *_, **__: pytest.fail("must reject receipt before API"))
    with pytest.raises(r.ReleaseError, match="malformed release receipt"):
        r.receipt_identity(receipt)


@pytest.mark.parametrize("conflict", [None, "control", "source", "workflow", "ref", "unknown"])
def test_receipt_separates_control_and_source_provenance(monkeypatch, conflict) -> None:
    hashes = dict.fromkeys(r.filenames("1.2.3"), "e" * 64)
    receipt = r.record_identity(RELEASE, hashes)
    run = {
        "head_sha": RELEASE["control_commit"],
        "head_branch": "master",
        "path": ".github/workflows/publish-pypi.yml",
        "head_repository": {"full_name": r.PUBLIC_REPOSITORY},
        "event": "workflow_dispatch",
    }

    def public(tag, source, obj):
        assert (tag, obj) == (TAG, RELEASE["tag_object"])
        if source != SHA:
            raise r.ReleaseError("source conflict")
        return dict(RELEASE)

    monkeypatch.setattr(r, "public_identity", public)
    monkeypatch.setattr(r, "api", lambda *_, **__: run)
    if conflict == "control":
        receipt["release_control_commit"] = SHA
    if conflict == "source":
        receipt["package_source_commit"] = RELEASE["control_commit"]
    if conflict == "workflow":
        run["path"] = ".github/workflows/ci.yml"
    if conflict == "ref":
        run["head_branch"] = "other"
    if conflict == "unknown":
        receipt["unexpected"] = True
    if conflict:
        with pytest.raises(r.ReleaseError):
            r.receipt_identity(receipt)
    else:
        actual = r.receipt_identity(receipt)
        assert actual["control_commit"] != actual["commit"] == SHA
        assert actual["files"] == hashes


def test_receipt_file_mutation_blocks_before_upload(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "dist"
    hashes = artifacts(source)
    release = {**RELEASE, "files": dict.fromkeys(hashes, "0" * 64)}
    monkeypatch.setattr(
        r, "pypi_files", lambda *_, **__: pytest.fail("must reject artifacts first")
    )
    with pytest.raises(r.ReleaseError, match="source-bound build receipt"):
        r.pending_dist(release, source, tmp_path / "pending")


@pytest.mark.parametrize("conflict", [None, "source-as-control", "ref", "file"])
def test_pypi_attestation_binds_control_not_package_source(monkeypatch, conflict) -> None:
    name = f"{r.ARCHIVE}-1.2.3-py3-none-any.whl"
    digest = "e" * 64
    statement = {"subject": [{"name": name, "digest": {"sha256": digest}}]}
    if conflict == "file":
        statement["subject"][0]["digest"]["sha256"] = "f" * 64
    provenance = {
        "attestation_bundles": [
            {
                "publisher": {
                    "kind": "GitHub",
                    "repository": r.PUBLIC_REPOSITORY,
                    "workflow": "publish-pypi.yml",
                    "environment": "pypi",
                },
                "attestations": [
                    {
                        "envelope": {
                            "statement": base64.b64encode(json.dumps(statement).encode()).decode()
                        },
                        "verification_material": {
                            "certificate": base64.b64encode(b"synthetic certificate").decode()
                        },
                    }
                ],
            }
        ]
    }
    commit = SHA if conflict == "source-as-control" else RELEASE["control_commit"]
    ref = f"refs/tags/{TAG}" if conflict == "ref" else RELEASE["control_ref"]
    certificate_text = f"1.3.6.1.4.1.57264.1.3:\n    {commit}\nURI:https://github.com/{r.PUBLIC_REPOSITORY}/.github/workflows/publish-pypi.yml@{ref}\n"
    monkeypatch.setattr(r, "api", lambda *_: provenance)
    monkeypatch.setattr(
        r.subprocess,
        "run",
        lambda *_, **__: subprocess.CompletedProcess([], 0, certificate_text.encode(), b""),
    )
    item = {"filename": name, "digests": {"sha256": digest}}
    if conflict:
        with pytest.raises(r.ReleaseError, match="provenance conflict"):
            r.check_provenance(item, RELEASE)
    else:
        r.check_provenance(item, RELEASE)


def test_release_closure_waits_out_pypi_propagation(monkeypatch: pytest.MonkeyPatch) -> None:
    """A version that appears after a short delay must still close successfully."""
    slept: list[float] = []
    monkeypatch.setattr(r.time, "sleep", lambda seconds: slept.append(seconds))
    calls = 0

    def load() -> str | None:
        nonlocal calls
        calls += 1
        return None if calls < 3 else "published"

    assert r.poll(load) == "published"
    assert calls == 3
    assert slept == [r.PROPAGATION_DELAY_SECONDS, r.PROPAGATION_DELAY_SECONDS]


def test_release_closure_gives_up_after_bounded_propagation_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retry is bounded: exhaustion returns None so the caller fails closed."""
    slept: list[float] = []
    monkeypatch.setattr(r.time, "sleep", lambda seconds: slept.append(seconds))
    calls = 0

    def load() -> None:
        nonlocal calls
        calls += 1
        return None

    assert r.poll(load) is None
    assert calls == r.PROPAGATION_ATTEMPTS
    assert len(slept) == r.PROPAGATION_ATTEMPTS - 1


@pytest.mark.parametrize(
    "failure",
    [
        r.ReleaseError("PyPI project/version conflict"),
        r.ReleaseIdentityError("PyPI provenance conflict"),
    ],
)
def test_propagation_polling_does_not_retry_api_errors(
    monkeypatch: pytest.MonkeyPatch,
    failure: r.ReleaseError,
) -> None:
    """Only a missing document is retried; a real failure surfaces immediately."""
    slept: list[float] = []
    monkeypatch.setattr(r.time, "sleep", lambda seconds: slept.append(seconds))
    calls = 0

    def load() -> None:
        nonlocal calls
        calls += 1
        raise failure

    with pytest.raises(r.ReleaseError, match="conflict"):
        r.poll(load)
    assert calls == 1
    assert slept == []


def test_propagation_http_attempts_are_bounded_and_each_get_has_its_own_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    slept = []

    def open_request(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        if calls % 2:
            raise TimeoutError("SYNTHETIC_RELEASE_MARKER")
        if calls <= 24:
            raise r.urllib.error.HTTPError("https://example.invalid", 404, "fixture", None, None)
        return io.BytesIO(b'{"published": true}')

    monkeypatch.setattr(r.urllib.request, "urlopen", open_request)
    monkeypatch.setattr(r.time, "sleep", slept.append)

    def load():
        return r.api("https://example.invalid")

    assert r.poll(load) is None
    assert calls == 24
    assert slept == [2, 15] * 11 + [2]
    assert load() == {"published": True}
    assert calls == 26
    assert slept == [2, 15] * 11 + [2, 2]


def test_propagation_stops_after_get_transport_retries_are_exhausted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    slept = []

    def open_request(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise TimeoutError("SYNTHETIC_RELEASE_MARKER")

    monkeypatch.setattr(r.urllib.request, "urlopen", open_request)
    monkeypatch.setattr(r.time, "sleep", slept.append)
    with pytest.raises(r.ReleaseError, match="^NETWORK_TIMEOUT:"):
        r.poll(lambda: r.api("https://example.invalid"))
    assert calls == 2
    assert slept == [2]


def test_record_closure_waits_but_build_and_pending_do_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Closure paths poll; build and pending-upload paths read once and move on."""
    observed: list[bool] = []
    monkeypatch.setattr(r.time, "sleep", lambda seconds: None)

    def fake_api(url: str, **kwargs):
        return None

    monkeypatch.setattr(r, "api", fake_api)

    monkeypatch.setattr(
        r,
        "poll",
        lambda load: (observed.append(True), load())[1],
    )
    # Build path: a single read, no polling.
    assert r.pypi_files(RELEASE) is None
    assert observed == []
    # Pending-upload path: a single read, no polling.
    assert r.pypi_files(RELEASE, complete=False) is None
    assert observed == []
    # Closure path: polls.
    assert r.pypi_files(RELEASE, wait=True) is None
    assert observed == [True]


def test_check_readme_version_accepts_matching_stable_and_pins() -> None:
    readme = (
        "Current stable release: **1.2.3**.\n\n"
        "pip install 'snapshot-runner==1.2.3'\n"
        "Older note about 1.0.0 remains historical prose.\n"
    )
    r.check_readme_version(readme, "1.2.3")


def test_check_readme_version_rejects_stable_mismatch() -> None:
    readme = "Current stable release: **1.2.0**.\n\npip install 'snapshot-runner==1.2.3'\n"
    with pytest.raises(r.ReleaseError, match="current stable release"):
        r.check_readme_version(readme, "1.2.3")


def test_check_readme_version_rejects_install_pin_mismatch() -> None:
    readme = "Current stable release: **1.2.3**.\n\npip install 'snapshot-runner==1.2.0'\n"
    with pytest.raises(r.ReleaseError, match="install version pin"):
        r.check_readme_version(readme, "1.2.3")


def test_identity_rejects_readme_install_pin_mismatch(repository: Path) -> None:
    (repository / "README.md").write_text(
        "Current stable release: **1.2.3**.\n\npip install 'snapshot-runner==1.2.0'\n"
    )
    subprocess.run(["git", "add", "README.md"], check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "stale readme pin",
        ],
        check=True,
    )
    subprocess.run(["git", "tag", "-d", TAG], check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "tag",
            "-a",
            TAG,
            "-m",
            "Fixture release",
        ],
        check=True,
    )
    with pytest.raises(r.ReleaseError, match="install version pin"):
        r.identity(TAG)
