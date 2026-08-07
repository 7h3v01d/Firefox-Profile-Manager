# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright 2026 Leon Priest <https://github.com/7h3v01d>
"""P6 regression tests: archive root validation and verified deletion.

Two findings pinned here:

1. Profile artefacts were matched by suffix, so 'junk/prefs.js' satisfied
   the check even though Firefox requires prefs.js at the profile root.
2. rmtree(ignore_errors=True) meant a failed deletion was reported as a
   success - for session data that means telling the user the scam tab is
   gone when it is still on disk.
"""

import shutil
import zipfile

import pytest

import firefox_profile_manager as fpm

from test_p0_safety import make_profile


class TestArchiveRootValidation:
    """Revert has() to suffix matching and these fail."""

    def test_nested_prefs_is_rejected(self, tmp_path):
        z = tmp_path / "nested.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("p.default/junk/prefs.js", "x")
            zf.writestr("p.default/junk/places.sqlite", "x")

        with pytest.raises(fpm.ArchiveRejected, match="top level"):
            fpm.inspect_backup_archive(z)

    def test_nested_prefs_does_not_replace_profile(self, tmp_path):
        profile = make_profile(tmp_path / "Profiles")
        (profile / "marker.txt").write_text("original")
        z = tmp_path / "nested.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr(f"{profile.name}/junk/prefs.js", "x")
            zf.writestr(f"{profile.name}/junk/places.sqlite", "x")

        with pytest.raises(fpm.ArchiveRejected):
            fpm.restore_profile(z, profile, lambda m: None)

        assert (profile / "marker.txt").read_text() == "original"

    def test_root_prefs_with_nested_corroborating_is_rejected(self, tmp_path):
        """prefs.js at root but every corroborating file buried."""
        z = tmp_path / "half.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("p.default/prefs.js", "x")
            zf.writestr("p.default/deep/times.json", "{}")

        with pytest.raises(fpm.ArchiveRejected, match="does not look"):
            fpm.inspect_backup_archive(z)

    def test_lookalike_filename_is_not_accepted(self, tmp_path):
        """'notprefs.js' must not satisfy a prefs.js requirement."""
        z = tmp_path / "lookalike.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("p.default/notprefs.js", "x")
            zf.writestr("p.default/times.json", "{}")

        with pytest.raises(fpm.ArchiveRejected, match="top level"):
            fpm.inspect_backup_archive(z)

    def test_genuine_profile_still_accepted(self, tmp_path):
        z = tmp_path / "good.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("p.default/prefs.js", "x")
            zf.writestr("p.default/times.json", "{}")
            zf.writestr("p.default/storage/default/thing.db", "x")

        info = fpm.inspect_backup_archive(z)
        assert info["has_prefs"] is True

    def test_session_data_in_subfolder_still_detected(self, tmp_path):
        """sessionstore-backups is legitimately a subfolder."""
        z = tmp_path / "sess.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("p.default/prefs.js", "x")
            zf.writestr("p.default/times.json", "{}")
            zf.writestr("p.default/sessionstore-backups/recovery.jsonlz4", "x")

        assert fpm.inspect_backup_archive(z)["has_session"] is True

    def test_real_backup_roundtrips(self, tmp_path):
        profile = make_profile(tmp_path / "Profiles")
        (profile / "storage").mkdir()
        (profile / "storage" / "nested.db").write_text("x")
        result = fpm.backup_profile(profile, tmp_path / "b", lambda m: None)

        info = fpm.inspect_backup_archive(result.zip_path,
                                          expected_profile=profile.name)
        assert info["has_prefs"] and info["is_ours"]


class TestVerifiedSessionDeletion:
    """Revert to rmtree(ignore_errors=True) and these fail."""

    def test_successful_deletion_reports_accurately(self, tmp_path):
        profile = make_profile(tmp_path)
        (profile / "sessionstore.jsonlz4").write_bytes(b"data")
        backups = profile / "sessionstore-backups"
        backups.mkdir()
        (backups / "recovery.jsonlz4").write_bytes(b"data")

        removed = fpm.clear_session_restore(profile, lambda m: None)

        assert removed == 2
        assert not (profile / "sessionstore.jsonlz4").exists()
        assert not backups.exists()

    def test_failed_deletion_raises_rather_than_claiming_success(
            self, tmp_path, monkeypatch):
        """The scam tab surviving must never be reported as cleared."""
        profile = make_profile(tmp_path)
        backups = profile / "sessionstore-backups"
        backups.mkdir()
        (backups / "recovery.jsonlz4").write_bytes(b"data")

        def refuse(path, *a, **k):
            raise PermissionError("file in use by another process")

        monkeypatch.setattr(shutil, "rmtree", refuse)
        messages = []

        with pytest.raises(RuntimeError, match="may reopen"):
            fpm.clear_session_restore(profile, messages.append)

        assert backups.exists()
        assert not any("Cleared" in m for m in messages), \
            "reported success for a deletion that failed"

    def test_partial_failure_is_detected(self, tmp_path, monkeypatch):
        """rmtree can return without error yet leave the folder behind."""
        profile = make_profile(tmp_path)
        backups = profile / "sessionstore-backups"
        backups.mkdir()
        (backups / "recovery.jsonlz4").write_bytes(b"data")

        monkeypatch.setattr(shutil, "rmtree", lambda p, *a, **k: None)

        with pytest.raises(RuntimeError, match="still present"):
            fpm.clear_session_restore(profile, lambda m: None)

    def test_nothing_to_clear_is_not_an_error(self, tmp_path):
        profile = make_profile(tmp_path)
        assert fpm.clear_session_restore(profile, lambda m: None) == 0


class TestVerifiedCacheDeletion:
    """Cache failure warns rather than raises - it is not a security issue."""

    def test_successful_clear_counts_accurately(self, tmp_path):
        profile = make_profile(tmp_path)
        for name in ("cache2", "startupCache"):
            d = profile / name
            d.mkdir()
            (d / "blob").write_bytes(b"x")

        cleared, failed = fpm.clear_cache(profile, lambda m: None)

        assert cleared == 2 and failed == ()

    def test_failed_clear_is_not_counted_as_cleared(self, tmp_path, monkeypatch):
        profile = make_profile(tmp_path)
        d = profile / "cache2"
        d.mkdir()
        (d / "blob").write_bytes(b"x")

        def refuse(path, *a, **k):
            raise PermissionError("in use")

        monkeypatch.setattr(shutil, "rmtree", refuse)
        messages = []

        cleared, failed = fpm.clear_cache(profile, messages.append)

        assert cleared == 0, "counted a folder that was not removed"
        assert len(failed) == 1
        assert any("WARNING" in m for m in messages)

    def test_cache_failure_does_not_abort_cleanup(self, tmp_path, monkeypatch):
        """A stuck cache folder must not raise - it is only disk space."""
        profile = make_profile(tmp_path)
        (profile / "cache2").mkdir()
        monkeypatch.setattr(shutil, "rmtree", lambda p, *a, **k: None)

        cleared, failed = fpm.clear_cache(profile, lambda m: None)   # no raise
        assert cleared == 0 and len(failed) == 1


class TestDocumentedResidualRace:
    """The probe-then-act window is documented, not eliminated.

    require_profile_writable() releases its probe before the mutation, so
    Firefox could in principle start in the microseconds between. Closing
    that fully needs an interprocess lock held across the mutation with
    Firefox's own semantics. This test records the accepted boundary so the
    decision is visible rather than forgotten.
    """

    def test_guard_is_a_probe_not_a_held_lock(self, tmp_path):
        profile = make_profile(tmp_path)
        fpm.require_profile_writable(profile)
        # nothing is retained afterwards
        assert fpm.profile_lock_state(profile) is fpm.LockState.FREE

    def test_residual_race_is_documented_in_source(self):
        import inspect
        doc = inspect.getdoc(fpm.require_profile_writable) or ""
        assert "trusting the caller" in doc
