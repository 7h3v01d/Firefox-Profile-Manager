# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright 2026 Leon Priest <https://github.com/7h3v01d>
"""P4 regression tests: public-release blockers.

Covers backup completeness vs archive verification, semantic archive
validation, audit-expression drift, WAL-aware reads, tri-state lock
reporting, filename collisions, and the background worker.
"""

import json
import sqlite3
import zipfile
from pathlib import Path

import pytest

from PyQt6.QtCore import QCoreApplication, QThread, QTimer
from PyQt6.QtWidgets import QApplication

import firefox_profile_manager as fpm

from test_p0_safety import make_profile, make_perms_db


def make_valid_backup(zip_path: Path, top: str, extra=(), manifest=True):
    """An archive that passes semantic validation."""
    with zipfile.ZipFile(zip_path, "w") as zf:
        if manifest:
            zf.writestr(fpm.BACKUP_MANIFEST_NAME, json.dumps({
                "format": fpm.BACKUP_FORMAT,
                "format_version": fpm.BACKUP_FORMAT_VERSION,
                "profile": top,
            }))
        for f in ("prefs.js", "times.json") + tuple(extra):
            zf.writestr(f"{top}/{f}", f"contents of {f}")
    return zip_path


# --------------------------------------------------------------------------
# Backup completeness
# --------------------------------------------------------------------------

class TestBackupCompleteness:
    """Pins 'verified' being reported for a backup missing source files.

    Revert require_complete handling in backup_profile() and
    test_incomplete_safety_backup_raises fails.
    """

    def _profile_with_unreadable_file(self, tmp_path, monkeypatch):
        profile = make_profile(tmp_path / "Profiles")
        (profile / "key4.db").write_text("secret")
        real_write = zipfile.ZipFile.write

        def failing_write(self, filename, arcname=None, *a, **k):
            if str(filename).endswith("key4.db"):
                raise PermissionError("file in use")
            return real_write(self, filename, arcname, *a, **k)

        monkeypatch.setattr(zipfile.ZipFile, "write", failing_write)
        return profile

    def test_skipped_files_are_recorded(self, tmp_path, monkeypatch):
        profile = self._profile_with_unreadable_file(tmp_path, monkeypatch)
        result = fpm.backup_profile(profile, tmp_path / "b", lambda m: None)

        assert result.skipped == 1
        assert "key4.db" in result.skipped_files
        assert result.complete is False

    def test_incomplete_backup_is_not_reported_complete(self, tmp_path, monkeypatch):
        """The archive can be intact while the backup is not."""
        profile = self._profile_with_unreadable_file(tmp_path, monkeypatch)
        messages = []
        result = fpm.backup_profile(profile, tmp_path / "b", messages.append)

        joined = " ".join(messages)
        assert "ARCHIVE VERIFIED" in joined
        assert "BACKUP INCOMPLETE" in joined
        assert result.complete is False

    def test_incomplete_safety_backup_raises(self, tmp_path, monkeypatch):
        profile = self._profile_with_unreadable_file(tmp_path, monkeypatch)
        with pytest.raises(fpm.IncompleteBackupError, match="incomplete"):
            fpm.backup_profile(profile, tmp_path / "b", lambda m: None,
                               require_complete=True)

    def test_complete_backup_passes_require_complete(self, tmp_path):
        profile = make_profile(tmp_path / "Profiles")
        result = fpm.backup_profile(profile, tmp_path / "b", lambda m: None,
                                    require_complete=True)
        assert result.complete is True

    def test_incomplete_error_is_a_verification_error(self):
        assert issubclass(fpm.IncompleteBackupError, fpm.BackupVerificationError)


# --------------------------------------------------------------------------
# Filename collisions
# --------------------------------------------------------------------------

class TestUniquePaths:
    def test_unused_path_is_returned_unchanged(self, tmp_path):
        p = tmp_path / "a.zip"
        assert fpm.unique_path(p) == p

    def test_existing_path_gets_a_suffix(self, tmp_path):
        p = tmp_path / "a.zip"
        p.write_text("x")
        assert fpm.unique_path(p).name == "a-1.zip"

    def test_two_backups_in_same_second_do_not_collide(self, tmp_path, monkeypatch):
        """Pins the second-resolution timestamp overwrite."""
        profile = make_profile(tmp_path / "Profiles")

        class FrozenClock(fpm.datetime):
            @classmethod
            def now(cls, tz=None):
                return fpm.datetime(2026, 8, 7, 12, 0, 0, tzinfo=tz)

        monkeypatch.setattr(fpm, "datetime", FrozenClock)

        a = fpm.backup_profile(profile, tmp_path / "b", lambda m: None)
        b = fpm.backup_profile(profile, tmp_path / "b", lambda m: None)

        assert a.zip_path != b.zip_path
        assert a.zip_path.exists() and b.zip_path.exists()


# --------------------------------------------------------------------------
# Semantic archive validation
# --------------------------------------------------------------------------

class TestArchiveIsAProfile:
    """Pins 'structurally safe but semantically nonsense' archives.

    An archive holding only hello.txt is perfectly contained and would have
    replaced a working profile.
    """

    def test_non_profile_archive_is_rejected(self, tmp_path):
        z = tmp_path / "fake.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("q1w2e3r4.default-release/hello.txt", "hi")

        with pytest.raises(fpm.ArchiveRejected, match="prefs.js"):
            fpm.inspect_backup_archive(z)

    def test_corroborating_files_without_prefs_are_rejected(self, tmp_path):
        """Discriminates the prefs.js check from the corroborating check.

        This archive has places.sqlite and times.json but no prefs.js, so it
        satisfies corroboration while still not being a profile. Remove the
        PROFILE_MARKER requirement and this is accepted.
        """
        z = tmp_path / "noprefs.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("p.default/places.sqlite", "x")
            zf.writestr("p.default/times.json", "{}")

        with pytest.raises(fpm.ArchiveRejected, match="does not appear"):
            fpm.inspect_backup_archive(z)

    def test_prefs_alone_is_not_enough(self, tmp_path):
        z = tmp_path / "thin.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("p.default/prefs.js", "x")

        with pytest.raises(fpm.ArchiveRejected, match="does not look"):
            fpm.inspect_backup_archive(z)

    def test_valid_archive_accepted(self, tmp_path):
        z = make_valid_backup(tmp_path / "good.zip", "p.default")
        info = fpm.inspect_backup_archive(z)
        assert info["has_prefs"] and info["is_ours"]

    def test_non_profile_archive_does_not_replace_profile(self, tmp_path):
        profile = make_profile(tmp_path / "Profiles")
        (profile / "marker.txt").write_text("original")
        z = tmp_path / "fake.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr(f"{profile.name}/hello.txt", "hi")

        with pytest.raises(fpm.ArchiveRejected):
            fpm.restore_profile(z, profile, lambda m: None)

        assert (profile / "marker.txt").read_text() == "original"

    def test_our_backups_carry_a_manifest(self, tmp_path):
        profile = make_profile(tmp_path / "Profiles")
        result = fpm.backup_profile(profile, tmp_path / "b", lambda m: None)
        info = fpm.inspect_backup_archive(result.zip_path)

        assert info["is_ours"] is True
        assert info["manifest"]["format"] == fpm.BACKUP_FORMAT
        assert info["manifest"]["profile"] == profile.name

    def test_third_party_archive_flagged_as_not_ours(self, tmp_path):
        z = make_valid_backup(tmp_path / "x.zip", "p.default", manifest=False)
        info = fpm.inspect_backup_archive(z)
        assert info["is_ours"] is False
        assert "NOT created by this tool" in fpm.describe_backup_archive(info)

    def test_manifest_is_not_extracted_into_the_profile(self, tmp_path):
        profile = make_profile(tmp_path / "Profiles")
        result = fpm.backup_profile(profile, tmp_path / "b", lambda m: None)

        fpm.restore_profile(result.zip_path, profile, lambda m: None)

        assert not (profile / fpm.BACKUP_MANIFEST_NAME).exists()
        assert (profile / "prefs.js").exists()

    def test_roundtrip_backup_then_restore(self, tmp_path):
        profile = make_profile(tmp_path / "Profiles")
        (profile / "places.sqlite").write_text("bookmarks")
        result = fpm.backup_profile(profile, tmp_path / "b", lambda m: None)
        (profile / "infection.js").write_text("evil")

        fpm.restore_profile(result.zip_path, profile, lambda m: None)

        assert (profile / "places.sqlite").read_text() == "bookmarks"
        assert not (profile / "infection.js").exists()


# --------------------------------------------------------------------------
# Audit expression drift
# --------------------------------------------------------------------------

class TestAuditExpressionIntegrity:
    """Pins the drift where H-05 recorded 3.0 while the code used 2.5.

    A forensic snapshot must not state a rule other than the one that
    produced the decision.
    """

    def test_entropy_expression_matches_live_constants(self):
        h = {x.id: x for x in fpm.HEURISTICS}["H-05"]
        assert str(fpm.ENTROPY_MIN_BITS) in h.expression
        assert str(fpm.ENTROPY_MIN_LABEL_LEN) in h.expression
        assert str(fpm.ENTROPY_MIN_DIGIT_RATIO) in h.expression
        assert str(fpm.ENTROPY_MAX_VOWEL_RATIO) in h.expression

    def test_expression_is_derived_not_hardcoded(self):
        """Rebuild the expression from the constants and require an exact match.

        Hardcoding the string again passes test_entropy_expression_matches_
        live_constants only by coincidence of the current values; this fails
        the moment the text and the constants disagree.
        """
        h = {x.id: x for x in fpm.HEURISTICS}["H-05"]
        expected = (
            f"label length >= {fpm.ENTROPY_MIN_LABEL_LEN} "
            f"AND shannon entropy >= {fpm.ENTROPY_MIN_BITS} bits/char "
            f"AND (digit ratio >= {fpm.ENTROPY_MIN_DIGIT_RATIO} "
            f"OR vowel ratio <= {fpm.ENTROPY_MAX_VOWEL_RATIO}), "
            "excluding known CDN/hosting suffixes"
        )
        assert h.expression == expected

    def test_no_heuristic_expression_contains_a_stale_literal(self):
        """The specific drift that occurred: 3.0 left behind after retuning."""
        live = {str(fpm.ENTROPY_MIN_BITS), str(fpm.ENTROPY_MIN_LABEL_LEN)}
        for h in fpm.HEURISTICS:
            if "shannon entropy" not in h.expression:
                continue
            assert "3.0" not in h.expression or "3.0" in live

    def test_snapshot_records_the_live_expression(self, tmp_path):
        profile = make_profile(tmp_path / "Profiles")
        make_perms_db(profile, [(1, "https://a.co.in", "desktop-notification")])
        snap = fpm.write_forensic_snapshot(
            profile, tmp_path / "out", [(1, "https://a.co.in", "desktop-notification")],
            [1], lambda m: None)

        data = json.loads((snap / "snapshot.json").read_text())
        h05 = next(h for h in data["heuristics"] if h["id"] == "H-05")
        assert str(fpm.ENTROPY_MIN_BITS) in h05["pattern"]


# --------------------------------------------------------------------------
# WAL awareness
# --------------------------------------------------------------------------

class TestWalAwareReads:
    """Pins stale reads from WAL-mode databases."""

    def _wal_profile(self, tmp_path):
        profile = make_profile(tmp_path / "Profiles")
        db = profile / "permissions.sqlite"
        conn = sqlite3.connect(str(db))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE moz_perms (id INTEGER PRIMARY KEY, origin TEXT, type TEXT)")
        conn.commit()
        # Leave this row uncheckpointed, i.e. living in the -wal file.
        conn.execute("INSERT INTO moz_perms VALUES (1, 'https://evil.co.in', 'desktop-notification')")
        conn.commit()
        return profile, conn

    def test_uncheckpointed_row_is_visible(self, tmp_path):
        profile, conn = self._wal_profile(tmp_path)
        try:
            assert (profile / "permissions.sqlite-wal").exists(), "test setup: no WAL"
            perms = fpm.read_notification_permissions(profile)
            assert [p[1] for p in perms] == ["https://evil.co.in"], \
                "WAL contents were not seen - stale read"
        finally:
            conn.close()

    def test_live_wal_is_detected(self, tmp_path):
        profile, conn = self._wal_profile(tmp_path)
        try:
            assert fpm.has_live_wal(profile / "permissions.sqlite") is True
        finally:
            conn.close()

    def test_no_wal_when_absent(self, tmp_path):
        profile = make_profile(tmp_path / "Profiles")
        make_perms_db(profile)
        assert fpm.has_live_wal(profile / "permissions.sqlite") is False

    def test_health_report_warns_about_pending_writes(self, tmp_path):
        profile, conn = self._wal_profile(tmp_path)
        try:
            report = fpm.build_health_report(profile, 1)
            assert report["live_wal"] is True
            assert any("Close Firefox" in r for r in report["recommendations"])
        finally:
            conn.close()

    def test_forensic_snapshot_captures_sidecars(self, tmp_path):
        profile, conn = self._wal_profile(tmp_path)
        try:
            snap = fpm.write_forensic_snapshot(
                profile, tmp_path / "out", [], [], lambda m: None)
            assert (snap / "permissions.sqlite").exists()
            assert (snap / "permissions.sqlite-wal").exists(), \
                "evidence copy omitted the write-ahead log"
        finally:
            conn.close()


# --------------------------------------------------------------------------
# Tri-state lock reporting
# --------------------------------------------------------------------------

class TestLockReporting:
    def test_unknown_is_not_reported_as_running(self, tmp_path, monkeypatch):
        """Pins UNKNOWN rendering as a factual 'yes'."""
        profile = make_profile(tmp_path / "Profiles")
        make_perms_db(profile)
        monkeypatch.setattr(fpm, "profile_lock_state", lambda p: fpm.LockState.UNKNOWN)

        text = fpm.format_health_report(fpm.build_health_report(profile, 1))

        assert "UNKNOWN" in text
        assert "Profile in use:     yes" not in text

    @pytest.mark.parametrize("state,expected", [
        (fpm.LockState.FREE, "no"),
        (fpm.LockState.LOCKED, "yes"),
    ])
    def test_definite_states_render_plainly(self, tmp_path, monkeypatch, state, expected):
        profile = make_profile(tmp_path / "Profiles")
        make_perms_db(profile)
        monkeypatch.setattr(fpm, "profile_lock_state", lambda p: state)
        text = fpm.format_health_report(fpm.build_health_report(profile, 1))
        assert f"Profile in use:     {expected}" in text


# --------------------------------------------------------------------------
# Background worker
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


def run_worker(qapp, fn, timeout_ms=5000):
    """Run a Worker on a real QThread and pump the event loop until done."""
    thread = QThread()
    worker = fpm.Worker(fn)
    worker.moveToThread(thread)
    captured = {"result": None, "error": None, "progress": [], "done": False}

    def on_finished(result):
        captured["result"] = result
        captured["done"] = True

    def on_failed(message, exc_name):
        captured["error"] = (message, exc_name)
        captured["done"] = True

    worker.progress.connect(captured["progress"].append)
    worker.finished.connect(on_finished)
    worker.failed.connect(on_failed)
    thread.started.connect(worker.run)
    thread.start()

    timer = QTimer()
    timer.setSingleShot(True)
    timer.start(timeout_ms)
    while not captured["done"] and timer.isActive():
        QCoreApplication.processEvents()
    thread.quit()
    thread.wait()
    return captured


class TestWorker:
    def test_result_is_delivered(self, qapp):
        out = run_worker(qapp, lambda log: 42)
        assert out["result"] == 42
        assert out["error"] is None

    def test_progress_is_forwarded(self, qapp):
        def work(log):
            log("step one")
            log("step two")
            return None

        out = run_worker(qapp, work)
        assert out["progress"] == ["step one", "step two"]

    def test_exception_is_reported_not_swallowed(self, qapp):
        def work(log):
            raise fpm.IncompleteBackupError("safety backup incomplete")

        out = run_worker(qapp, work)
        assert out["result"] is None
        assert out["error"][1] == "IncompleteBackupError"
        assert "incomplete" in out["error"][0]

    def test_exception_type_survives_for_ui_branching(self, qapp):
        """run_clean branches on the class name, so it must be exact."""
        def work(log):
            raise fpm.ArchiveRejected("nope")

        assert run_worker(qapp, work)["error"][1] == "ArchiveRejected"

    def test_work_runs_off_the_calling_thread(self, qapp):
        main_thread = QThread.currentThread()
        out = run_worker(qapp, lambda log: QThread.currentThread() is not main_thread)
        assert out["result"] is True, "work executed on the UI thread"

    def test_real_backup_through_worker(self, qapp, tmp_path):
        profile = make_profile(tmp_path / "Profiles")
        out = run_worker(
            qapp, lambda log: fpm.backup_profile(profile, tmp_path / "b", log))

        assert out["error"] is None
        assert out["result"].complete is True
        assert any("Backing up" in m for m in out["progress"])
