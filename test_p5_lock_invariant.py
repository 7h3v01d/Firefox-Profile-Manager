# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright 2026 Leon Priest <https://github.com/7h3v01d>
"""P5 regression tests: the lock invariant belongs to the primitives.

Pins a time-of-check/time-of-use race. The GUI checks the lock when the
button is clicked, but cleanup can run for minutes afterwards (a backup on
a large profile is slow) and Firefox may be started in that window. Every
destructive function must therefore re-establish the invariant itself
rather than trusting its caller.

Remove require_profile_writable() from clear_session_restore() or
clear_cache() and the corresponding tests fail.
"""

import sqlite3

import pytest

import firefox_profile_manager as fpm

from test_p0_safety import make_profile, make_perms_db
from test_p4_release import make_valid_backup


@pytest.fixture
def locked(monkeypatch):
    """Simulate Firefox holding the profile."""
    def apply(state=fpm.LockState.LOCKED):
        monkeypatch.setattr(fpm, "profile_lock_state", lambda p: state)
    return apply


class TestDestructivePrimitivesSelfGuard:
    """Every destructive primitive enforces the lock without being asked."""

    def test_clear_session_refuses_when_locked(self, tmp_path, locked):
        profile = make_profile(tmp_path)
        session = profile / "sessionstore.jsonlz4"
        session.write_bytes(b"session data")
        locked()

        with pytest.raises(RuntimeError, match="Close Firefox|close Firefox"):
            fpm.clear_session_restore(profile, lambda m: None)

        assert session.exists(), "session file deleted while profile was in use"

    def test_clear_cache_refuses_when_locked(self, tmp_path, locked):
        profile = make_profile(tmp_path)
        blob = profile / "cache2" / "entries" / "blob"
        blob.parent.mkdir(parents=True)
        blob.write_bytes(b"x" * 128)
        locked()

        with pytest.raises(RuntimeError):
            fpm.clear_cache(profile, lambda m: None)

        assert blob.exists(), "cache deleted while profile was in use"

    def test_clear_session_refuses_on_unknown(self, tmp_path, locked):
        """Ambiguity is refusal, not permission."""
        profile = make_profile(tmp_path)
        session = profile / "sessionstore.jsonlz4"
        session.write_bytes(b"data")
        locked(fpm.LockState.UNKNOWN)

        with pytest.raises(RuntimeError, match="Could not verify"):
            fpm.clear_session_restore(profile, lambda m: None)
        assert session.exists()

    def test_clear_cache_refuses_on_unknown(self, tmp_path, locked):
        profile = make_profile(tmp_path)
        blob = profile / "cache2" / "blob"
        blob.parent.mkdir(parents=True)
        blob.write_bytes(b"x")
        locked(fpm.LockState.UNKNOWN)

        with pytest.raises(RuntimeError):
            fpm.clear_cache(profile, lambda m: None)
        assert blob.exists()

    def test_primitives_proceed_when_free(self, tmp_path):
        profile = make_profile(tmp_path)
        (profile / "sessionstore.jsonlz4").write_bytes(b"data")
        blob = profile / "cache2" / "blob"
        blob.parent.mkdir(parents=True)
        blob.write_bytes(b"x")

        fpm.clear_session_restore(profile, lambda m: None)
        fpm.clear_cache(profile, lambda m: None)

        assert not (profile / "sessionstore.jsonlz4").exists()
        assert not (profile / "cache2").exists()

    @pytest.mark.parametrize("fn_name", [
        "delete_permission_rows", "clear_session_restore",
        "clear_cache", "restore_profile",
    ])
    def test_every_destructive_primitive_has_the_guard(self, fn_name):
        """Structural check: a new destructive function must opt in.

        Cheap insurance that the invariant is not quietly dropped from one
        function while the others keep it.
        """
        import ast
        import inspect

        src = inspect.getsource(fpm)
        tree = ast.parse(src)
        node = next(n for n in tree.body
                    if isinstance(n, ast.FunctionDef) and n.name == fn_name)
        calls = {n.func.id for n in ast.walk(node)
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        assert "require_profile_writable" in calls, \
            f"{fn_name} does not enforce the lock invariant"


class TestRaceWindowAfterSlowBackup:
    """The scenario that motivated this: Firefox starts mid-cleanup."""

    def test_firefox_started_during_backup_stops_cache_deletion(self, tmp_path):
        profile = make_profile(tmp_path)
        blob = profile / "cache2" / "blob"
        blob.parent.mkdir(parents=True)
        blob.write_bytes(b"x" * 64)

        # FREE for the initial check, then LOCKED once "the backup finishes"
        states = iter([fpm.LockState.FREE, fpm.LockState.LOCKED,
                       fpm.LockState.LOCKED, fpm.LockState.LOCKED])
        original = fpm.profile_lock_state
        fpm.profile_lock_state = lambda p: next(states, fpm.LockState.LOCKED)
        try:
            fpm.require_profile_writable(profile)     # T+0: click, all clear
            with pytest.raises(RuntimeError):         # T+36: cache deletion
                fpm.clear_cache(profile, lambda m: None)
        finally:
            fpm.profile_lock_state = original

        assert blob.exists()

    def test_no_permissions_selected_still_guards_session_and_cache(self, tmp_path, locked):
        """The worse variant: with nothing to delete, delete_permission_rows
        is skipped, so it cannot supply the second lock check."""
        profile = make_profile(tmp_path)
        make_perms_db(profile)
        (profile / "sessionstore.jsonlz4").write_bytes(b"data")
        locked()

        # delete_permission_rows is a no-op with an empty selection...
        assert fpm.delete_permission_rows(profile, [], lambda m: None) == 0
        # ...so the session clear must refuse on its own.
        with pytest.raises(RuntimeError):
            fpm.clear_session_restore(profile, lambda m: None)

    def test_restore_still_guarded(self, tmp_path, locked):
        profile = make_profile(tmp_path / "Profiles")
        (profile / "marker.txt").write_text("original")
        z = make_valid_backup(tmp_path / "b.zip", profile.name)
        locked()

        with pytest.raises(RuntimeError):
            fpm.restore_profile(z, profile, lambda m: None)
        assert (profile / "marker.txt").read_text() == "original"

    def test_permission_deletion_still_guarded(self, tmp_path, locked):
        profile = make_profile(tmp_path)
        make_perms_db(profile, [(1, "https://evil.co.in", "desktop-notification")])
        locked()

        with pytest.raises(RuntimeError):
            fpm.delete_permission_rows(profile, [1], lambda m: None)

        conn = sqlite3.connect(str(profile / "permissions.sqlite"))
        assert conn.execute("SELECT COUNT(*) FROM moz_perms").fetchone()[0] == 1
        conn.close()


class TestForensicTextReport:
    """Checks a claim from review that each extension is listed twice."""

    def test_extensions_are_listed_once_each(self, tmp_path):
        import json
        profile = make_profile(tmp_path)
        make_perms_db(profile)
        (profile / "extensions.json").write_text(json.dumps({"addons": [
            {"id": "a@x", "defaultLocale": {"name": "uBlock Origin"},
             "active": True, "signedState": 2},
            {"id": "b@x", "defaultLocale": {"name": "Something Else"},
             "active": True, "signedState": 2},
        ]}))

        snap = fpm.write_forensic_snapshot(
            profile, tmp_path / "out", [], [], lambda m: None)
        text = (snap / "snapshot.txt").read_text()

        assert text.count("uBlock Origin") == 1
        assert text.count("Something Else") == 1
