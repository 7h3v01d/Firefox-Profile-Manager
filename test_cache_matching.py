# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright 2026 Leon Priest <https://github.com/7h3v01d>
"""Regression tests for local-cache folder matching.

Pins the defect where clear_cache() matched LOCALAPPDATA cache folders by
the pre-dot prefix of the profile id, which could delete a neighbouring
profile's cache. Revert matching_local_cache_dirs() to the old
`startswith(name.split('.')[0])` behaviour and test_neighbouring_profile_
cache_is_not_matched must fail.
"""

import sys
from pathlib import Path

import pytest

import firefox_profile_manager as fpm


@pytest.fixture
def cache_root(tmp_path, monkeypatch):
    """A fake LOCALAPPDATA/.../Profiles containing several cache folders."""
    root = tmp_path / "LocalCache" / "Profiles"
    root.mkdir(parents=True)
    monkeypatch.setattr(fpm, "local_cache_root", lambda: root)
    return root


def make_cache(root: Path, name: str) -> Path:
    d = root / name
    (d / "cache2").mkdir(parents=True)
    return d


def test_exact_profile_cache_is_matched(cache_root, tmp_path):
    make_cache(cache_root, "abc.default")
    profile = tmp_path / "Profiles" / "abc.default"
    profile.mkdir(parents=True)

    matched = fpm.matching_local_cache_dirs(profile)

    assert [d.name for d in matched] == ["abc.default"]


def test_neighbouring_profile_cache_is_not_matched(cache_root, tmp_path):
    """The bug: 'abc.default' must not match 'abcdef.default-release'."""
    make_cache(cache_root, "abc.default")
    make_cache(cache_root, "abcdef.default-release")
    profile = tmp_path / "Profiles" / "abc.default"
    profile.mkdir(parents=True)

    matched = [d.name for d in fpm.matching_local_cache_dirs(profile)]

    assert "abcdef.default-release" not in matched
    assert matched == ["abc.default"]


def test_shared_prefix_before_dot_is_not_matched(cache_root, tmp_path):
    """Two profiles sharing a pre-dot token must stay isolated."""
    make_cache(cache_root, "w7x8y9.default")
    make_cache(cache_root, "w7x8y9.dev-edition")
    profile = tmp_path / "Profiles" / "w7x8y9.default"
    profile.mkdir(parents=True)

    matched = [d.name for d in fpm.matching_local_cache_dirs(profile)]

    assert matched == ["w7x8y9.default"]


def test_match_is_case_insensitive(cache_root, tmp_path):
    make_cache(cache_root, "ABC.Default-Release")
    profile = tmp_path / "Profiles" / "abc.default-release"
    profile.mkdir(parents=True)

    matched = fpm.matching_local_cache_dirs(profile)

    assert len(matched) == 1


def test_files_are_ignored_only_dirs_matched(cache_root, tmp_path):
    (cache_root / "abc.default").write_text("not a folder")
    profile = tmp_path / "Profiles" / "abc.default"
    profile.mkdir(parents=True)

    assert fpm.matching_local_cache_dirs(profile) == []


def test_missing_cache_root_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(fpm, "local_cache_root", lambda: None)
    profile = tmp_path / "abc.default"
    profile.mkdir()

    assert fpm.matching_local_cache_dirs(profile) == []


def test_nonexistent_cache_root_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(fpm, "local_cache_root", lambda: tmp_path / "nope")
    profile = tmp_path / "abc.default"
    profile.mkdir()

    assert fpm.matching_local_cache_dirs(profile) == []


def test_clear_cache_removes_only_own_cache(cache_root, tmp_path):
    """End-to-end: the neighbour's cache2 survives a clear_cache() run."""
    mine = make_cache(cache_root, "abc.default")
    neighbour = make_cache(cache_root, "abcdef.default-release")
    profile = tmp_path / "Profiles" / "abc.default"
    (profile / "cache2").mkdir(parents=True)

    fpm.clear_cache(profile, lambda msg: None)

    assert not (mine / "cache2").exists()
    assert (neighbour / "cache2").exists(), "neighbouring profile cache was destroyed"
