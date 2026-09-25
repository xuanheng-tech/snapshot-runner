from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..budget import _json_bytes, _json_text_prefix
from ..evidence import (
    _snapshot_security_error,
)
from ..git import (
    BranchReviewSeal,
)
from ..model import (
    MAX_EVIDENCE_GAPS,
    MAX_SNAPSHOT_BYTES,
    PRODUCER_SECURITY_EPOCH,
    SECURITY_NOTICE,
    SNAPSHOT_CONTENT_BUDGET,
    SNAPSHOT_SCHEMA_VERSION,
    TRUST_BOUNDARY,
    EvidenceGap,
)
from ..security import (
    SCAN_CLASSIFIER_VERSION,
    SNAPSHOT_COLLECTION_FAILED,
    RunnerError,
    ScanMode,
    ScanModeBinding,
    ScanModeManifest,
    SecurityError,
    sanitize_json_value,
    sanitize_text,
)


@dataclass(slots=True)
class Snapshot:
    task: str
    repository: str
    data: dict[str, object]
    scan_manifest: ScanModeManifest
    evidence_gaps: list[EvidenceGap] = field(default_factory=list)
    redactions: dict[str, int] = field(default_factory=dict)
    branch_review_seal: BranchReviewSeal | None = field(default=None, repr=False)

    def as_envelope(self) -> dict[str, object]:
        gaps = [gap.as_dict() for gap in self.evidence_gaps[:MAX_EVIDENCE_GAPS]]
        if len(self.evidence_gaps) > MAX_EVIDENCE_GAPS:
            gaps.append(
                EvidenceGap(
                    "gap_limit",
                    "snapshot",
                    "additional evidence gaps omitted after the hard gap-count limit",
                    len(self.evidence_gaps) - MAX_EVIDENCE_GAPS,
                ).as_dict()
            )
        envelope: dict[str, object] = {
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "producer_security_epoch": PRODUCER_SECURITY_EPOCH,
            "task": self.task,
            "repository": self.repository,
            "data": self.data,
            "truncated": bool(gaps),
            "evidence_gaps": gaps,
            "redactions": dict(sorted(self.redactions.items())),
            "trust_boundary": TRUST_BOUNDARY,
            "security_notice": SECURITY_NOTICE,
        }
        encoded = _json_bytes(envelope)
        if len(encoded) > MAX_SNAPSHOT_BYTES:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED, "bounded snapshot serialization exceeded 8 MiB"
            )
        return envelope


class SnapshotBuilder:
    def __init__(self, task: str, repository: str, repo_root: Path) -> None:
        self.task = task
        self.repository = repository
        self.repo_root = repo_root
        self.data: dict[str, object] = {}
        self.gaps: list[EvidenceGap] = []
        self.redactions: dict[str, int] = {}
        self.content_bytes = 0
        self._scan_modes: dict[tuple[str | int, ...], ScanMode] = {}

    def _bind_mode(self, path: tuple[str | int, ...], scan_mode: ScanMode) -> None:
        if not isinstance(scan_mode, ScanMode):
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED, "snapshot text requires a trusted scan mode"
            )
        existing = self._scan_modes.get(path)
        if existing is not None and existing is not scan_mode:
            raise RunnerError(SNAPSHOT_COLLECTION_FAILED, "snapshot scan mode binding conflicts")
        self._scan_modes[path] = scan_mode

    def _bind_value_modes(
        self,
        value: object,
        path: tuple[str | int, ...],
        scan_mode: ScanMode,
    ) -> None:
        if isinstance(value, str):
            self._bind_mode(path, scan_mode)
        elif isinstance(value, (list, tuple)):
            for index, item in enumerate(value):
                self._bind_value_modes(item, (*path, index), scan_mode)
        elif isinstance(value, dict):
            for key, item in value.items():
                if isinstance(key, str):
                    self._bind_value_modes(item, (*path, key), scan_mode)

    def _manifest(self) -> ScanModeManifest:
        bindings = tuple(
            ScanModeBinding(path, mode)
            for path, mode in sorted(self._scan_modes.items(), key=lambda item: repr(item[0]))
        )
        return ScanModeManifest(SCAN_CLASSIFIER_VERSION, bindings)

    def gap(
        self,
        kind: str,
        subject: str,
        reason: str,
        omitted_bytes: int | None = None,
    ) -> None:
        try:
            safe_kind = sanitize_text(
                kind, scan_mode=ScanMode.PLAIN_TEXT, repository_root=self.repo_root
            ).text
            safe_subject = sanitize_text(
                subject, scan_mode=ScanMode.PLAIN_TEXT, repository_root=self.repo_root
            ).text
            safe_reason = sanitize_text(
                reason, scan_mode=ScanMode.PLAIN_TEXT, repository_root=self.repo_root
            ).text
        except SecurityError as exc:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED, "unable to sanitize snapshot evidence metadata"
            ) from exc
        self.gaps.append(EvidenceGap(safe_kind, safe_subject, safe_reason, omitted_bytes))

    def add_text(
        self,
        key: str,
        raw_text: str,
        *,
        source: str,
        scan_mode: ScanMode,
    ) -> None:
        try:
            sanitized = sanitize_text(
                raw_text,
                scan_mode=scan_mode,
                repository_root=self.repo_root,
            )
        except SecurityError as exc:
            raise _snapshot_security_error(
                exc, f"unable to sanitize {source}; prepare refused"
            ) from exc
        for category, count in sanitized.redactions.items():
            self.redactions[category] = self.redactions.get(category, 0) + count
        remaining = max(0, SNAPSHOT_CONTENT_BUDGET - self.content_bytes)
        accepted, omitted, encoded_length = _json_text_prefix(sanitized.text, remaining)
        self.data[key] = accepted
        self._bind_mode((key,), scan_mode)
        self.content_bytes += encoded_length
        if omitted:
            self.gap(
                "snapshot_limit", source, "snapshot content truncated at 8 MiB budget", omitted
            )

    def add_value(self, key: str, value: object, *, scan_mode: ScanMode) -> None:
        try:
            sanitized = sanitize_json_value(
                value,
                scan_mode=scan_mode,
                repository_root=self.repo_root,
            )
        except SecurityError as exc:
            raise _snapshot_security_error(
                exc, f"unable to sanitize structured evidence {key}; prepare refused"
            ) from exc
        encoded = _json_bytes(sanitized)
        remaining = max(0, SNAPSHOT_CONTENT_BUDGET - self.content_bytes)
        if len(encoded) > remaining:
            self.data[key] = [] if isinstance(sanitized, list) else {}
            self._scan_modes = {
                path: mode for path, mode in self._scan_modes.items() if path[:1] != (key,)
            }
            self.gap(
                "snapshot_limit",
                key,
                "structured evidence omitted at the total snapshot hard limit",
                len(encoded),
            )
            return
        self.data[key] = sanitized
        self._bind_value_modes(sanitized, (key,), scan_mode)
        self.content_bytes += len(encoded)

    def finish(self, *, branch_review_seal: BranchReviewSeal | None = None) -> Snapshot:
        manifest = self._manifest()
        try:
            invariant_data = sanitize_json_value(
                self.data,
                scan_manifest=manifest,
                repository_root=self.repo_root,
            )
        except SecurityError as exc:
            raise _snapshot_security_error(exc, "snapshot builder invariant failed closed") from exc
        if invariant_data != self.data:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED,
                "snapshot builder data changed during final sanitization",
            )
        snapshot = Snapshot(
            task=self.task,
            repository=self.repository,
            data=self.data,
            scan_manifest=manifest,
            evidence_gaps=self.gaps,
            redactions=self.redactions,
            branch_review_seal=branch_review_seal,
        )
        snapshot.as_envelope()
        return snapshot
