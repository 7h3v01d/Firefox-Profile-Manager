# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright 2026 Leon Priest <https://github.com/7h3v01d>
"""Windows-only tests for profile lock detection.

These exist because nothing else in the suite can exercise the LOCKED branch
on Windows. Python's open() uses permissive share flags, so it cannot
reproduce the sharing violation Firefox creates by holding parent.lock with
dwShareMode=0. These tests emulate that with CreateFileW directly.

This is the gate that authorises every write operation - cleanup, restore,
and the incomplete-backup abort all depend on it - so it needs to be proven
on the platform it actually ships to.
"""

import sys

import pytest

import firefox_profile_manager as fpm

from test_p0_safety import make_profile

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("win"),
    reason="Windows-specific lock semantics",
)


class ExclusiveHandle:
    """Holds a file open the way Firefox holds parent.lock.

    dwShareMode=0 means no other process may open the file at all, which is
    what makes Python's open() raise PermissionError.
    """

    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x80
    INVALID_HANDLE_VALUE = -1

    def __init__(self, path):
        self.path = str(path)
        self.handle = None

    def __enter__(self):
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        kernel32.CreateFileW.restype = wintypes.HANDLE

        handle = kernel32.CreateFileW(
            self.path,
            self.GENERIC_READ | self.GENERIC_WRITE,
            0,                      # dwShareMode = 0: exclusive, like Firefox
            None,
            self.OPEN_EXISTING,
            self.FILE_ATTRIBUTE_NORMAL,
            None,
        )
        if handle == self.INVALID_HANDLE_VALUE or handle is None:
            err = ctypes.get_last_error()
            raise OSError(f"test setup: CreateFileW failed (error {err})")
        self.handle = handle
        self._kernel32 = kernel32
        return self

    def __exit__(self, *exc):
        if self.handle is not None:
            self._kernel32.CloseHandle(self.handle)
            self.handle = None


class TestWindowsLockDetection:
    def test_lock_file_absent_is_free(self, tmp_path):
        """A profile Firefox has never opened has no parent.lock."""
        profile = make_profile(tmp_path)
        assert not (profile / "parent.lock").exists()
        assert fpm.profile_lock_state(profile) is fpm.LockState.FREE

    def test_lock_file_present_but_unheld_is_free(self, tmp_path):
        """Windows leaves parent.lock on disk after Firefox exits.

        Presence must NOT be read as 'in use' - that would permanently block
        every profile Firefox has ever opened.
        """
        profile = make_profile(tmp_path)
        (profile / "parent.lock").write_bytes(b"")
        assert fpm.profile_lock_state(profile) is fpm.LockState.FREE

    def test_exclusively_held_lock_is_detected(self, tmp_path):
        """The critical case: Firefox has the profile open."""
        profile = make_profile(tmp_path)
        lock = profile / "parent.lock"
        lock.write_bytes(b"")

        with ExclusiveHandle(lock):
            assert fpm.profile_lock_state(profile) is fpm.LockState.LOCKED

        # and releases cleanly once the holder goes away
        assert fpm.profile_lock_state(profile) is fpm.LockState.FREE

    def test_held_lock_blocks_permission_deletion(self, tmp_path):
        from test_p0_safety import make_perms_db

        profile = make_profile(tmp_path)
        make_perms_db(profile, [(1, "https://evil.co.in", "desktop-notification")])
        lock = profile / "parent.lock"
        lock.write_bytes(b"")

        with ExclusiveHandle(lock):
            with pytest.raises(RuntimeError, match="Close Firefox|close Firefox"):
                fpm.delete_permission_rows(profile, [1], lambda m: None)

        import sqlite3
        conn = sqlite3.connect(str(profile / "permissions.sqlite"))
        remaining = conn.execute("SELECT COUNT(*) FROM moz_perms").fetchone()[0]
        conn.close()
        assert remaining == 1, "row was deleted despite the profile being locked"

    def test_held_lock_blocks_restore(self, tmp_path):
        from test_p4_release import make_valid_backup

        profile = make_profile(tmp_path / "Profiles")
        (profile / "marker.txt").write_text("original")
        z = make_valid_backup(tmp_path / "b.zip", profile.name)
        lock = profile / "parent.lock"
        lock.write_bytes(b"")

        with ExclusiveHandle(lock):
            with pytest.raises(RuntimeError):
                fpm.restore_profile(z, profile, lambda m: None)

        assert (profile / "marker.txt").read_text() == "original"

    def test_unreadable_profile_directory_is_unknown(self, tmp_path):
        """Ambiguity must fail closed, not report FREE."""
        assert fpm.profile_lock_state(tmp_path / "does-not-exist") \
            is fpm.LockState.UNKNOWN
