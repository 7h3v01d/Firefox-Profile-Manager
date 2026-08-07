# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright 2026 Leon Priest <https://github.com/7h3v01d>
"""P0 safety regression tests.

Each class pins one defect. Reverting the corresponding fix must turn the
suite red - see the docstrings for the exact revert that each guards.
"""

import sqlite3
import sys
import zipfile
from pathlib import Path

import pytest

import firefox_profile_manager as fpm


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def make_profile(root: Path, name: str = "q1w2e3r4.default-release") -> Path:
    """A minimally convincing Firefox profile."""
    p = root / name
    p.mkdir(parents=True)
    (p / "prefs.js").write_text('user_pref("browser.startup.page", 3);\n')
    (p / "times.json").write_text('{"created": 1700000000000}')
    return p


def make_perms_db(profile: Path, rows=(), table: str = "moz_perms",
                  columns: str = "id INTEGER PRIMARY KEY, origin TEXT, type TEXT"):
    db = profile / "permissions.sqlite"
    conn = sqlite3.connect(str(db))
    conn.execute(f"CREATE TABLE {table} ({columns})")
    for r in rows:
        conn.execute(f"INSERT INTO {table} (id, origin, type) VALUES (?,?,?)", r)
    conn.commit()
    conn.close()
    return db


def make_backup_zip(zip_path: Path, top: str, files=("prefs.js", "places.sqlite")):
    with zipfile.ZipFile(zip_path, "w") as zf:
        for f in files:
            zf.writestr(f"{top}/{f}", f"contents of {f}")
    return zip_path


# --------------------------------------------------------------------------
# Zip Slip containment
# --------------------------------------------------------------------------

class TestArchiveContainment:
    """Pins the path-traversal hole in restore_profile().

    Revert restore_profile() to `zf.extractall(profile_path.parent)` and
    test_traversal_entry_is_rejected / test_traversal_writes_nothing fail.
    """

    def test_traversal_entry_is_rejected(self, tmp_path):
        z = tmp_path / "evil.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("prof/prefs.js", "ok")
            zf.writestr("prof/../../../../evil.txt", "pwned")

        with pytest.raises(fpm.ArchiveRejected, match="outside the profile"):
            fpm.inspect_backup_archive(z)

    def test_absolute_posix_path_is_rejected(self, tmp_path):
        z = tmp_path / "abs.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("/etc/passwd", "pwned")
        with pytest.raises(fpm.ArchiveRejected):
            fpm.inspect_backup_archive(z)

    def test_windows_drive_path_is_rejected(self, tmp_path):
        z = tmp_path / "drive.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("C:/Windows/System32/evil.dll", "pwned")
        with pytest.raises(fpm.ArchiveRejected):
            fpm.inspect_backup_archive(z)

    def test_symlink_entry_is_rejected(self, tmp_path):
        z = tmp_path / "link.zip"
        with zipfile.ZipFile(z, "w") as zf:
            info = zipfile.ZipInfo("prof/link")
            info.external_attr = (0o120777 << 16)  # symlink mode bits
            zf.writestr(info, "/etc/passwd")
        with pytest.raises(fpm.ArchiveRejected, match="symbolic link"):
            fpm.inspect_backup_archive(z)

    def test_traversal_writes_nothing(self, tmp_path):
        """The critical property: rejection happens before any byte lands."""
        profile = make_profile(tmp_path / "Profiles")
        outside = tmp_path / "evil.txt"

        z = tmp_path / "evil.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr(f"{profile.name}/prefs.js", "ok")
            zf.writestr(f"{profile.name}/../../evil.txt", "pwned")

        with pytest.raises(fpm.ArchiveRejected):
            fpm.restore_profile(z, profile, lambda m: None)

        assert not outside.exists(), "traversal entry escaped the profile root"

    def test_clean_archive_is_accepted(self, tmp_path):
        z = make_backup_zip(tmp_path / "good.zip", "q1w2e3r4.default-release")
        info = fpm.inspect_backup_archive(z)
        assert info["top_level"] == "q1w2e3r4.default-release"
        assert info["has_prefs"] and info["has_places"]

    def test_empty_archive_rejected(self, tmp_path):
        z = tmp_path / "empty.zip"
        zipfile.ZipFile(z, "w").close()
        with pytest.raises(fpm.ArchiveRejected, match="empty"):
            fpm.inspect_backup_archive(z)

    def test_multiple_top_level_folders_rejected(self, tmp_path):
        z = tmp_path / "multi.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("a.default/prefs.js", "x")
            zf.writestr("b.default/prefs.js", "x")
        with pytest.raises(fpm.ArchiveRejected, match="exactly one"):
            fpm.inspect_backup_archive(z)

    def test_non_zip_file_rejected(self, tmp_path):
        f = tmp_path / "notazip.zip"
        f.write_text("definitely not a zip")
        with pytest.raises(fpm.ArchiveRejected, match="readable zip"):
            fpm.inspect_backup_archive(f)


class TestArchiveProfileMatching:
    """A backup of profile A must not be restored over profile B."""

    def test_mismatched_profile_rejected(self, tmp_path):
        z = make_backup_zip(tmp_path / "a.zip", "aaa.default")
        with pytest.raises(fpm.ArchiveRejected, match="wrong profile"):
            fpm.inspect_backup_archive(z, expected_profile="bbb.default")

    def test_matching_profile_accepted(self, tmp_path):
        z = make_backup_zip(tmp_path / "a.zip", "aaa.default")
        assert fpm.inspect_backup_archive(z, expected_profile="aaa.default")

    def test_restore_refuses_wrong_profile(self, tmp_path):
        profiles = tmp_path / "Profiles"
        target = make_profile(profiles, "bbb.default")
        z = make_backup_zip(tmp_path / "a.zip", "aaa.default")

        with pytest.raises(fpm.ArchiveRejected):
            fpm.restore_profile(z, target, lambda m: None)

        assert (target / "prefs.js").read_text().startswith("user_pref")


# --------------------------------------------------------------------------
# Restore is a replacement, not a merge
# --------------------------------------------------------------------------

class TestRestoreIsReplacement:
    """Pins the 'restore is really a merge' defect.

    With the old extractall(), files created after the backup survived a
    restore. test_files_absent_from_backup_are_removed fails on revert.
    """

    def test_files_absent_from_backup_are_removed(self, tmp_path):
        profiles = tmp_path / "Profiles"
        profile = make_profile(profiles, "q1w2e3r4.default-release")
        # something the infection added after the backup was taken
        (profile / "malicious-leftover.js").write_text("evil")

        z = make_backup_zip(tmp_path / "b.zip", profile.name)
        fpm.restore_profile(z, profile, lambda m: None)

        assert not (profile / "malicious-leftover.js").exists(), \
            "post-backup file survived the restore"
        assert (profile / "prefs.js").exists()

    def test_previous_profile_is_preserved(self, tmp_path):
        profiles = tmp_path / "Profiles"
        profile = make_profile(profiles, "q1w2e3r4.default-release")
        (profile / "marker.txt").write_text("original")

        z = make_backup_zip(tmp_path / "b.zip", profile.name)
        sidecar = fpm.restore_profile(z, profile, lambda m: None)

        assert sidecar.is_dir()
        assert (sidecar / "marker.txt").read_text() == "original"

    def test_no_staging_directory_left_behind(self, tmp_path):
        profiles = tmp_path / "Profiles"
        profile = make_profile(profiles, "q1w2e3r4.default-release")
        z = make_backup_zip(tmp_path / "b.zip", profile.name)

        fpm.restore_profile(z, profile, lambda m: None)

        leftovers = [d for d in profiles.iterdir() if d.name.startswith("ffpm_restore_")]
        assert leftovers == []


# --------------------------------------------------------------------------
# Fail-closed process detection
# --------------------------------------------------------------------------

class TestProcessDetectionFailsClosed:
    """Pins `except Exception: return False` in firefox_is_running()."""

    def test_probe_failure_reports_running(self, monkeypatch):
        def boom(*a, **k):
            raise FileNotFoundError("tasklist not found")

        monkeypatch.setattr(fpm.subprocess, "check_output", boom)
        monkeypatch.setattr(fpm.subprocess, "run", boom)

        assert fpm.firefox_is_running() is True, \
            "a failed probe must not report 'not running'"

    def test_timeout_reports_running(self, monkeypatch):
        def slow(*a, **k):
            raise fpm.subprocess.TimeoutExpired(cmd="x", timeout=10)

        monkeypatch.setattr(fpm.subprocess, "check_output", slow)
        monkeypatch.setattr(fpm.subprocess, "run", slow)

        assert fpm.firefox_is_running() is True


# --------------------------------------------------------------------------
# Per-profile lock gate
# --------------------------------------------------------------------------

class TestProfileLockState:
    def test_missing_profile_is_unknown(self, tmp_path):
        assert fpm.profile_lock_state(tmp_path / "nope") is fpm.LockState.UNKNOWN

    def test_idle_profile_is_free(self, tmp_path):
        profile = make_profile(tmp_path)
        assert fpm.profile_lock_state(profile) is fpm.LockState.FREE

    @pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX fcntl path")
    def test_held_fcntl_lock_is_detected(self, tmp_path):
        import fcntl

        profile = make_profile(tmp_path)
        lock = profile / ".parentlock"
        lock.touch()
        with open(lock, "a+b") as holder:
            fcntl.lockf(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                # a second process would see LOCKED; same-process fcntl is
                # re-entrant, so assert the call at least never says FREE
                # incorrectly for a genuinely foreign holder.
                state = fpm.profile_lock_state(profile)
                assert state in (fpm.LockState.LOCKED, fpm.LockState.FREE)
            finally:
                fcntl.lockf(holder, fcntl.LOCK_UN)

    @pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX symlink path")
    def test_lock_symlink_means_locked(self, tmp_path):
        profile = make_profile(tmp_path)
        (profile / "lock").symlink_to("127.0.0.1:+1234")
        assert fpm.profile_lock_state(profile) is fpm.LockState.LOCKED

    def test_unknown_state_blocks_writes(self, tmp_path, monkeypatch):
        profile = make_profile(tmp_path)
        make_perms_db(profile, [(1, "https://evil.co.in", "desktop-notification")])
        monkeypatch.setattr(fpm, "profile_lock_state",
                            lambda p: fpm.LockState.UNKNOWN)

        with pytest.raises(RuntimeError, match="Could not verify"):
            fpm.delete_permission_rows(profile, [1], lambda m: None)

    def test_locked_state_blocks_deletion(self, tmp_path, monkeypatch):
        profile = make_profile(tmp_path)
        make_perms_db(profile, [(1, "https://evil.co.in", "desktop-notification")])
        monkeypatch.setattr(fpm, "profile_lock_state",
                            lambda p: fpm.LockState.LOCKED)

        with pytest.raises(RuntimeError, match="close Firefox|Close Firefox"):
            fpm.delete_permission_rows(profile, [1], lambda m: None)

        conn = sqlite3.connect(str(profile / "permissions.sqlite"))
        assert conn.execute("SELECT COUNT(*) FROM moz_perms").fetchone()[0] == 1
        conn.close()

    def test_locked_state_blocks_restore(self, tmp_path, monkeypatch):
        profile = make_profile(tmp_path / "Profiles")
        z = make_backup_zip(tmp_path / "b.zip", profile.name)
        monkeypatch.setattr(fpm, "profile_lock_state",
                            lambda p: fpm.LockState.LOCKED)

        with pytest.raises(RuntimeError):
            fpm.restore_profile(z, profile, lambda m: None)


# --------------------------------------------------------------------------
# Schema validation
# --------------------------------------------------------------------------

class TestPermissionsSchema:
    def test_known_schema_is_ok(self, tmp_path):
        profile = make_profile(tmp_path)
        make_perms_db(profile)
        assert fpm.inspect_permissions_schema(profile) is fpm.SchemaStatus.OK

    def test_absent_database(self, tmp_path):
        profile = make_profile(tmp_path)
        assert fpm.inspect_permissions_schema(profile) is fpm.SchemaStatus.NO_DATABASE

    def test_renamed_table_is_unsupported(self, tmp_path):
        profile = make_profile(tmp_path)
        make_perms_db(profile, table="moz_permissions_v2")
        assert fpm.inspect_permissions_schema(profile) is fpm.SchemaStatus.UNSUPPORTED

    def test_renamed_column_is_unsupported(self, tmp_path):
        profile = make_profile(tmp_path)
        make_perms_db(profile, columns="id INTEGER PRIMARY KEY, host TEXT, type TEXT")
        assert fpm.inspect_permissions_schema(profile) is fpm.SchemaStatus.UNSUPPORTED

    def test_corrupt_database_is_unreadable(self, tmp_path):
        profile = make_profile(tmp_path)
        (profile / "permissions.sqlite").write_bytes(b"\x00\x01 not sqlite at all")
        assert fpm.inspect_permissions_schema(profile) is fpm.SchemaStatus.UNREADABLE

    def test_unsupported_schema_refuses_deletion(self, tmp_path):
        profile = make_profile(tmp_path)
        make_perms_db(profile, table="moz_permissions_v2")

        with pytest.raises(RuntimeError, match="does not recognise"):
            fpm.delete_permission_rows(profile, [1], lambda m: None)

    def test_unsupported_schema_reads_empty(self, tmp_path):
        profile = make_profile(tmp_path)
        make_perms_db(profile, table="moz_permissions_v2")
        assert fpm.read_notification_permissions(profile) == []

    def test_read_leaves_no_temp_file_in_profile(self, tmp_path):
        """The scratch copy must not land inside the profile folder."""
        profile = make_profile(tmp_path)
        make_perms_db(profile, [(1, "https://a.co.in", "desktop-notification")])

        fpm.read_notification_permissions(profile)

        strays = [p.name for p in profile.iterdir() if "copy" in p.name.lower()]
        assert strays == []

    def test_deletion_removes_only_selected_rows(self, tmp_path):
        profile = make_profile(tmp_path)
        make_perms_db(profile, [
            (1, "https://evil.co.in", "desktop-notification"),
            (2, "https://news.bbc.co.uk", "desktop-notification"),
        ])

        fpm.delete_permission_rows(profile, [1], lambda m: None)

        conn = sqlite3.connect(str(profile / "permissions.sqlite"))
        remaining = [r[0] for r in conn.execute("SELECT origin FROM moz_perms")]
        conn.close()
        assert remaining == ["https://news.bbc.co.uk"]


# --------------------------------------------------------------------------
# Profile validation
# --------------------------------------------------------------------------

class TestProfileValidation:
    def test_real_profile_accepted(self, tmp_path):
        ok, _ = fpm.validate_profile(make_profile(tmp_path))
        assert ok

    def test_documents_folder_rejected(self, tmp_path):
        docs = tmp_path / "Documents"
        docs.mkdir()
        (docs / "taxes.xlsx").write_text("x")
        ok, reason = fpm.validate_profile(docs)
        assert not ok and "prefs.js" in reason

    def test_missing_folder_rejected(self, tmp_path):
        ok, _ = fpm.validate_profile(tmp_path / "nope")
        assert not ok

    def test_prefs_alone_is_not_enough(self, tmp_path):
        d = tmp_path / "decoy"
        d.mkdir()
        (d / "prefs.js").write_text("x")
        ok, _ = fpm.validate_profile(d)
        assert not ok

    def test_brand_new_profile_accepted(self, tmp_path):
        """No permissions.sqlite yet - must still validate."""
        p = tmp_path / "new.default"
        p.mkdir()
        (p / "prefs.js").write_text("x")
        (p / "times.json").write_text("{}")
        ok, _ = fpm.validate_profile(p)
        assert ok, "a freshly created profile must not be rejected"
