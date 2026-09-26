"""Artifact reads resolve a verifier from the artifact's own declared versions.

The registry is the seam between "what this release writes" and "what a stored snapshot was
written under". These tests pin three things: the current row still describes exactly what this
release produces, an unregistered version is refused before any content is trusted, and the
envelope validator follows the row it is given rather than the live producer constants.
"""

from __future__ import annotations

import ast
import inspect
import os
import re
from dataclasses import replace
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


def test_the_current_rules_are_exactly_the_sanitizer_s_live_constants() -> None:
    """The forcing check for a rule edit, as distinct from a declaration edit.

    The era row and the live sanitizer constants are written independently, and this compares them
    by value: two equal compiled patterns are not one object, so identity checks would prove
    nothing. Tightening a pattern, a suffix set or a limit without registering the era that replaces
    it fails here -- which is the only thing standing between a rule edit and two different silent
    failures: every older artifact failing its canonical re-serialization, or new artifacts being
    written under superseded rules.
    """
    current = verifiers.CURRENT_VERIFIER.rules

    assert current is security_module.CURRENT_RULES or current.descriptor() == (
        security_module.CURRENT_RULES.descriptor()
    )
    assert security_module.SCAN_RULES_V2.descriptor() == current.descriptor(), (
        "the live sanitizer rules moved but no era was registered for them"
    )


def test_a_frozen_era_does_not_read_the_live_constants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Editing a rule in place must not move an era, at import time or afterwards.

    The shape of the failure this pins was measured: adding one token pattern to
    ``KNOWN_TOKEN_PATTERNS`` makes every stored artifact containing matching text fail its own
    canonical re-serialization, while the test suite stays green -- unless the era's rule data is
    its own copy.
    """
    frozen = security_module.SCAN_RULES_V2
    assert frozen.token_patterns is not security_module.KNOWN_TOKEN_PATTERNS
    assert frozen.absolute_path_re.pattern == security_module.ABSOLUTE_PATH_RE.pattern
    assert frozen.yaml_text_suffixes is not security_module.YAML_TEXT_SUFFIXES

    monkeypatch.setattr(
        security_module,
        "KNOWN_TOKEN_PATTERNS",
        (*security_module.KNOWN_TOKEN_PATTERNS, ("X", re.compile("x"))),
    )
    monkeypatch.setattr(
        security_module,
        "ABSOLUTE_PATH_RE",
        re.compile(r"(?<![\w+.:/~-])/(?!/)(?:[^\s]+/)*[^\s]*"),
    )
    monkeypatch.setattr(
        security_module, "YAML_TEXT_SUFFIXES", frozenset({".yaml", ".yml", ".conf"})
    )
    assert security_module.SCAN_RULES_V2.descriptor() == frozen.descriptor()
    assert len(security_module.SCAN_RULES_V2.token_patterns) == 4
    assert len(security_module.SCAN_RULES_V2.yaml_text_suffixes) == 2


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
    # `rules` replaces the old standalone classifier-version field: an era's classifier version is
    # read from the frozen rules it sanitizes under, so the two cannot disagree.
    legacy = verifiers.ArtifactVerifier(
        schema_version=2,
        meta_schema_version=2,
        producer_security_epoch=4,
        trust_boundary=verifiers.CURRENT_VERIFIER.trust_boundary,
        security_notice="Superseded notice from the release that wrote this artifact.",
        rules=security_module.SCAN_RULES_V2,
        is_current=False,
    )
    assert legacy.scan_classifier_version == 2
    superseded = {**_MINIMAL_ENVELOPE, "security_notice": legacy.security_notice}

    assert artifact_module._validate_snapshot_envelope(superseded, legacy) is superseded
    with pytest.raises(artifact_module.RunnerError):
        artifact_module._validate_snapshot_envelope(superseded, verifiers.CURRENT_VERIFIER)
    with pytest.raises(artifact_module.RunnerError):
        artifact_module._validate_snapshot_envelope(_MINIMAL_ENVELOPE, legacy)

    # A release that reworded its notice no longer changes what a stored artifact must say.
    monkeypatch.setattr(
        collect_module,
        "SECURITY_NOTICE",
        collect_module.SECURITY_NOTICE.replace("version: 2.", "version: 3."),
    )
    assert artifact_module._validate_snapshot_envelope(
        dict(_MINIMAL_ENVELOPE), verifiers.CURRENT_VERIFIER
    )


def test_a_scanned_manifest_still_rejects_an_unregistered_classifier_version() -> None:
    with pytest.raises(security_module.SecurityError):
        security_module.ScanModeManifest(999, ())
    assert (
        security_module.ScanModeManifest(
            verifiers.CURRENT_VERIFIER.scan_classifier_version, ()
        ).classifier_version
        == security_module.SCAN_CLASSIFIER_VERSION
    )


def test_the_sanitizer_reuses_the_rules_of_the_era_being_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One stored body, two eras: the older reproduces its bytes, the newer redacts the text.

    This is what a future secret-pattern change depends on. Widening an existing redaction category
    is enough to make every artifact whose body already matches it fail its own canonical
    re-serialization, which under current-rule reading means it stops existing. The era's rules are
    what prevent that, and the newer era still redacts on write.
    """
    era_4 = verifiers.CURRENT_VERIFIER
    later_rules = replace(
        era_4.rules,
        classifier_version=3,
        token_patterns=(
            *era_4.rules.token_patterns,
            ("GITHUB_TOKEN", re.compile(r"\bPROBE_TOKEN\b")),
        ),
    )
    later = replace(
        era_4,
        producer_security_epoch=5,
        rules=later_rules,
        security_notice=era_4.security_notice.replace("version: 2.", "version: 3."),
    )
    assert later.security_notice != era_4.security_notice
    body = {"log": "PROBE_TOKEN = 1\n", "log_display_name": "pytest.log"}

    def round_trip(verifier: verifiers.ArtifactVerifier) -> tuple[bytes, bytes]:
        envelope = {
            **_MINIMAL_ENVELOPE,
            "data": dict(body),
            "producer_security_epoch": verifier.producer_security_epoch,
            "trust_boundary": verifier.trust_boundary,
            "security_notice": verifier.security_notice,
        }
        normalized = artifact_module._sanitize_validate_snapshot(
            envelope, Path("/tmp"), verifier=verifier
        )
        return (
            artifact_module._serialize_snapshot(envelope),
            artifact_module._serialize_snapshot(normalized),
        )

    # A registered era whose classifier the sanitizer will not run still fails closed, so a
    # half-finished bump cannot quietly scan historical bodies under the wrong rule set.
    with pytest.raises(artifact_module.RunnerError, match="classifier"):
        round_trip(later)
    monkeypatch.setattr(security_module, "SUPPORTED_SCAN_CLASSIFIER_VERSIONS", frozenset({2, 3}))

    published, under_era_4 = round_trip(era_4)
    assert under_era_4 == published, "the era that wrote it must reproduce its own bytes"

    _, under_later = round_trip(later)
    assert under_later != published, (
        "the later rules rewrite the body, so reading it under them is what refused the artifact"
    )


_TWO_FILE_DIFF = (
    "diff --git a/one.py b/one.py\n"
    "index 1111111..2222222 100644\n"
    "--- a/one.py\n+++ b/one.py\n@@ -1 +1 @@\n-a\n+b\n"
    "diff --git a/two.py b/two.py\n"
    "index 3333333..4444444 100644\n"
    "--- a/two.py\n+++ b/two.py\n@@ -1 +1 @@\n-c\n+d\n"
)
_PEM_BLOCK = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABgAAAAgAAAA=\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)


def _diff_audit_envelope(verifier: verifiers.ArtifactVerifier, content: str) -> dict[str, object]:
    return {
        "schema_version": 2,
        "producer_security_epoch": verifier.producer_security_epoch,
        "task": "diff-audit",
        "repository": "target-repo",
        "data": {
            "status_short": " M one.py\n",
            "staged_diff": "",
            "unstaged_diff": _TWO_FILE_DIFF,
            "file_context": [{"path": "one.py", "content": content}],
        },
        "truncated": False,
        "evidence_gaps": [],
        "redactions": {},
        "trust_boundary": verifier.trust_boundary,
        "security_notice": verifier.security_notice,
    }


@pytest.mark.parametrize(
    ("field", "replacement", "probe", "era_outcome"),
    [
        ("file_uri_re", r"(?!x)x", "see file:///srv/secrets/x for details\n", "accepted"),
        ("absolute_path_re", r"(?!x)x", "/srv/data/one.txt\n", "accepted"),
        # A complete key block is refused by the shipped rules; the inert pattern accepts it raw.
        ("pem_boundary_re", r"(?!x)x", _PEM_BLOCK, "refused"),
        ("allowed_text_suffixes", frozenset(), "value = 2\n", "accepted"),
        ("yaml_text_suffixes", frozenset({".yaml", ".yml", ".py"}), "value = 2\n", "accepted"),
        ("sensitive_file_suffixes", frozenset({".py"}), "value = 2\n", "accepted"),
        ("max_elements", 1, "value = 2\n", "accepted"),
    ],
)
def test_each_pinned_rule_field_is_actually_era_dependent(
    field: str, replacement: object, probe: str, era_outcome: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every site the era can change must consult the era, not the live constant.

    One inert pattern, one emptied eligibility set, one halved limit: wired to the era, the later
    rules answer differently from the rules that wrote the body. A site still reading a module global
    would pass for every other field and fail for its own, which is the gap that left ten of the read
    sites revertable to the live constant with a green suite.
    """
    era_4 = verifiers.CURRENT_VERIFIER
    # Admit the later classifier version first, so the only difference left between the two eras is
    # the field under test.
    monkeypatch.setattr(security_module, "SUPPORTED_SCAN_CLASSIFIER_VERSIONS", frozenset({2, 3}))
    value = re.compile(replacement) if isinstance(replacement, str) else replacement
    later_rules = replace(era_4.rules, classifier_version=3, **{field: value})
    later = replace(
        era_4,
        producer_security_epoch=5,
        rules=later_rules,
        security_notice=era_4.security_notice.replace("version: 2.", "version: 3."),
    )

    def outcome(verifier: verifiers.ArtifactVerifier) -> tuple[str, str]:
        try:
            normalized = artifact_module._sanitize_validate_snapshot(
                _diff_audit_envelope(verifier, probe), Path("/tmp"), verifier=verifier
            )
        except artifact_module.RunnerError as exc:
            return ("refused", str(exc))
        return ("accepted", str(normalized["data"]))

    under_era = outcome(era_4)
    assert under_era[0] == era_outcome, under_era[1]
    assert outcome(later) != under_era, f"{field} is not read from the era"


RULE_CONSTANT_NAMES = frozenset(
    {
        "KNOWN_TOKEN_PATTERNS",
        "AUTH_HEADER_RE",
        "BEARER_RE",
        "PEM_PRIVATE_KEY_BOUNDARY_RE",
        "FILE_URI_RE",
        "ABSOLUTE_PATH_RE",
        "SENSITIVE_FILE_SUFFIXES",
        "SENSITIVE_EXACT_FILE_NAMES",
        "ALLOWED_TEXT_SUFFIXES",
        "ALLOWED_EXTENSIONLESS_NAMES",
        "YAML_TEXT_SUFFIXES",
        "RASTER_IMAGE_MEDIA_TYPES",
        "RASTER_IMAGE_EVIDENCE_RE",
        "MAX_SANITIZE_DEPTH",
        "MAX_SANITIZE_ELEMENTS",
        "MAX_DIFF_PATH_CANDIDATES",
        "MAX_EXTENSIONLESS_TEXT_BYTES",
    }
)


def test_no_sanitizer_rule_is_read_bypassing_the_era_policy() -> None:
    """A rule reached without ``active_rules()`` is a rule a later release applies to history.

    Behavioural checks can only cover the fields a test happens to perturb; this covers all of them
    and every field added later, by reading the module. The constants above are the definition of the
    rule sets and may be named there, but no function body may consult one directly.
    """
    path = Path(inspect.getsourcefile(security_module) or "")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            continue
        for inner in ast.walk(node):
            if isinstance(inner, ast.Name) and inner.id in RULE_CONSTANT_NAMES:
                offenders.append(f"{node.name}:{inner.lineno} {inner.id}")
    assert offenders == []
