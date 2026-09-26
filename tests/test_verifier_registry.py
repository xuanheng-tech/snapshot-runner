"""Artifact reads resolve a verifier from the artifact's own declared versions.

The registry is the seam between "what this release writes" and "what a stored snapshot was
written under". These tests pin three things: the current row still describes exactly what this
release produces, an unregistered version is refused before any content is trusted, and the
envelope validator follows the row it is given rather than the live producer constants.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from snapshot_runner import artifact as artifact_module
from snapshot_runner import collect as collect_module
from snapshot_runner import security as security_module
from snapshot_runner import verifiers

SNAPSHOT_ID = "1da3b7c99b425b2a087554fc9ccb0b372fc0aaae40eda09b00c352f780642869"
_MINIMAL_ENVELOPE = {
    "schema_version": 2,
    "producer_security_epoch": 4,
    "task": "test-triage",
    "repository": "target-repo",
    "data": {"log": "", "log_display_name": "pytest.log"},
    "truncated": False,
    "evidence_gaps": [],
    "redactions": {},
    "trust_boundary": verifiers.CURRENT_VERIFIER.trust_boundary,
    "security_notice": verifiers.CURRENT_VERIFIER.security_notice,
}


def _store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    store = state / "snapshot-runner" / "snapshots"
    for level in (store.parent, store):
        level.mkdir(mode=0o700)
    return store


def _write_snapshot_directory(store: Path, meta: dict[str, object]) -> Path:
    directory = store / SNAPSHOT_ID
    directory.mkdir(mode=0o700)
    payloads = {
        "meta.json": artifact_module._serialize_snapshot_meta(meta),
        "snapshot.json": b"{}\n",
        "preview.txt": b"MANUAL REVIEW REQUIRED BEFORE UPLOAD\n",
    }
    for name, payload in payloads.items():
        artifact_file = directory / name
        artifact_file.write_bytes(payload)
        artifact_file.chmod(0o600)
    return directory


def _meta(**overrides: object) -> dict[str, object]:
    meta: dict[str, object] = {
        "schema_version": 2,
        "producer_security_epoch": 4,
        "snapshot_id": SNAPSHOT_ID,
        "task": "repo-status",
        "repository": "target-repo",
        "snapshot_sha256": SNAPSHOT_ID,
        "snapshot_bytes": 3,
        "preview_sha256": "0" * 64,
        "preview_bytes": 38,
    }
    meta.update(overrides)
    return meta


def test_the_current_row_is_exactly_what_this_release_writes() -> None:
    """Raising a producer constant must register a new era instead of orphaning the old one.

    This assertion is the forcing function: it fails the moment ``collect`` or ``security``
    changes a declaration without a matching ``verifiers`` row, which is the point where
    historical reads would otherwise silently break.
    """
    current = verifiers.CURRENT_VERIFIER

    assert current.schema_version == collect_module.SNAPSHOT_SCHEMA_VERSION
    assert current.meta_schema_version == artifact_module.SNAPSHOT_META_SCHEMA_VERSION
    assert current.producer_security_epoch == collect_module.PRODUCER_SECURITY_EPOCH
    assert current.scan_classifier_version == security_module.SCAN_CLASSIFIER_VERSION
    assert current.trust_boundary == collect_module.TRUST_BOUNDARY
    assert current.security_notice == collect_module.SECURITY_NOTICE
    assert current.is_current is True
    assert [row for row in verifiers._VERIFIERS.values() if row.is_current] == [current]


def test_a_registered_classifier_version_is_one_the_sanitizer_accepts() -> None:
    assert {row.scan_classifier_version for row in verifiers._VERIFIERS.values()} == (
        security_module.SUPPORTED_SCAN_CLASSIFIER_VERSIONS
    )


def test_verifier_for_resolves_the_registered_era() -> None:
    assert verifiers.verifier_for(2, 4) is verifiers.CURRENT_VERIFIER


@pytest.mark.parametrize(
    ("meta_schema_version", "producer_security_epoch"),
    [(2, 3), (2, 5), (1, 4), (3, 4), (0, 4), (None, 4), ("2", 4), (2, [4])],
)
def test_an_unregistered_or_malformed_version_is_refused(
    meta_schema_version: object, producer_security_epoch: object
) -> None:
    with pytest.raises(artifact_module.RunnerError) as refused:
        verifiers.verifier_for(meta_schema_version, producer_security_epoch)
    assert str(refused.value) == verifiers.UNSUPPORTED_ARTIFACT_VERSION_ERROR
    assert refused.value.code == artifact_module.ARTIFACT_PUBLISH_FAILED


def test_loading_an_unregistered_era_refuses_before_trusting_any_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The version gate runs first, so an unknown era never reaches hashing or sanitization."""
    store = _store(tmp_path, monkeypatch)
    _write_snapshot_directory(store, _meta(producer_security_epoch=3))

    with pytest.raises(artifact_module.RunnerError) as refused:
        artifact_module._load_snapshot_directory(SNAPSHOT_ID, store / SNAPSHOT_ID)
    assert str(refused.value) == verifiers.UNSUPPORTED_ARTIFACT_VERSION_ERROR


def test_the_envelope_validator_follows_the_row_it_is_given(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Declarations are compared per era, never against whatever this release now emits."""
    legacy = verifiers.ArtifactVerifier(
        schema_version=2,
        meta_schema_version=2,
        producer_security_epoch=4,
        scan_classifier_version=2,
        trust_boundary=verifiers.CURRENT_VERIFIER.trust_boundary,
        security_notice="Superseded notice from the release that wrote this artifact.",
        is_current=False,
    )
    superseded = {**_MINIMAL_ENVELOPE, "security_notice": legacy.security_notice}

    assert artifact_module._validate_snapshot_envelope(superseded, legacy) is superseded
    with pytest.raises(artifact_module.RunnerError):
        artifact_module._validate_snapshot_envelope(superseded, verifiers.CURRENT_VERIFIER)
    with pytest.raises(artifact_module.RunnerError):
        artifact_module._validate_snapshot_envelope(_MINIMAL_ENVELOPE, legacy)

    bumped = collect_module.SECURITY_NOTICE.replace("version: 2.", "version: 3.")
    monkeypatch.setattr(artifact_module, "SECURITY_NOTICE", bumped)
    assert artifact_module._validate_snapshot_envelope(
        dict(_MINIMAL_ENVELOPE), verifiers.CURRENT_VERIFIER
    )


def test_a_scanned_manifest_still_rejects_an_unregistered_classifier_version() -> None:
    with pytest.raises(security_module.SecurityError):
        security_module.ScanModeManifest(999, ())
    assert security_module.ScanModeManifest(
        verifiers.CURRENT_VERIFIER.scan_classifier_version, ()
    ).classifier_version == json.loads(json.dumps(2))
