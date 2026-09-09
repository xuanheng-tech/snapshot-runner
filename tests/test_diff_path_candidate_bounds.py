"""Diff header path classification must stay bounded on hostile path names."""

from __future__ import annotations

import contextlib
from pathlib import PurePosixPath

import pytest

from codex_snapshot_runner import security


def _hostile_header(components: int) -> str:
    path = "/".join(["a b"] * components) + "/f.py"
    return f"a/{path} b/{path}"


def test_component_suffix_matches_pathlib_semantics() -> None:
    cases = [
        "",
        ".",
        "..",
        "...",
        "a",
        "a.b",
        "a.b.c",
        ".env",
        ".env.local",
        "a.",
        "a..",
        "..a",
        ".pem",
        "x.PEM",
        "id_rsa",
        "a.b.",
        "....",
        "..pem",
        "foo.tar.gz",
    ]
    for case in cases:
        assert security._component_suffix(case) == PurePosixPath(case).suffix, case


def test_sensitive_component_detection_semantics_are_unchanged() -> None:
    for component in (".env", ".env.local", ".netrc", "id_rsa", "id_ed25519"):
        assert security._is_sensitive_path_component(component)
    for component in ("a.pem", "a.key", "a.p12", "a.pfx", "A.PEM"):
        assert security._is_sensitive_path_component(component)
    for component in ("module.py", "notes.md", "pemfile", "keyring", ".pem", "a.pemx"):
        assert not security._is_sensitive_path_component(component)


def test_candidate_expansion_is_bounded_and_fails_closed() -> None:
    header = _hostile_header(security.MAX_DIFF_PATH_CANDIDATES)
    with pytest.raises(security.SecurityError) as error:
        security._diff_git_path_candidates(header, None)
    assert "too many candidate paths" in str(error.value)


def test_candidate_expansion_accepts_paths_below_the_bound() -> None:
    candidates = security._diff_git_path_candidates(_hostile_header(4), None)
    expected = "/".join(["a b"] * 4) + "/f.py"
    assert (expected, expected) in candidates


def test_hostile_path_classification_work_stays_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Guard the quadratic blow-up structurally: count component classifications."""

    calls = 0
    original = security._is_sensitive_path_component

    def counting(component: str) -> bool:
        nonlocal calls
        calls += 1
        return original(component)

    monkeypatch.setattr(security, "_is_sensitive_path_component", counting)

    components = 60
    security._diff_git_path_candidates(_hostile_header(components), None)
    # Before the bound, this header produced ~4 * components candidate pairs, each
    # classified across every path component, i.e. quadratic growth. The bound keeps
    # the product below a fixed multiple of the candidate limit.
    assert calls <= 8 * security.MAX_DIFF_PATH_CANDIDATES * components


def test_evaluated_candidates_never_exceed_the_hard_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The candidate list is the quadratic factor; it must have a fixed ceiling."""

    original = security._diff_prefixed_path
    for components in (10, 60, 127, 200, 400):
        evaluated = 0

        def counting(raw: str, prefix: str, root, _original=original) -> str:
            nonlocal evaluated
            evaluated += 1
            return _original(raw, prefix, root)

        monkeypatch.setattr(security, "_diff_prefixed_path", counting)
        with contextlib.suppress(security.SecurityError):
            security._diff_git_path_candidates(_hostile_header(components), None)
        # Two prefixed paths are resolved per candidate pair, and pairs are capped.
        assert evaluated <= 2 * security.MAX_DIFF_PATH_CANDIDATES, components
