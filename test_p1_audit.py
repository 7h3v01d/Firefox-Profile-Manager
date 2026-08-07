# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright 2026 Leon Priest <https://github.com/7h3v01d>
"""P1 regression tests: backup verification, heuristic IDs, permission diff,
restore dry-run, and forensic snapshots.

Each class notes the revert that turns it red.
"""

import json
import sqlite3
import zipfile
from pathlib import Path

import pytest

import firefox_profile_manager as fpm

from test_p0_safety import make_profile, make_perms_db, make_backup_zip


# --------------------------------------------------------------------------
# Backup verification
# --------------------------------------------------------------------------

class TestBackupVerification:
    """Pins 'zip created' being treated as 'backup succeeded'.

    Drop the verify_backup() call from backup_profile() and
    test_truncated_archive_is_caught fails.
    """

    def test_good_backup_verifies(self, tmp_path):
        profile = make_profile(tmp_path / "Profiles")
        result = fpm.backup_profile(profile, tmp_path / "backups", lambda m: None)

        assert result.zip_path.exists()
        assert result.written >= 2
        assert result.uncompressed > 0

    def test_truncated_archive_is_caught(self, tmp_path):
        z = tmp_path / "b.zip"
        make_backup_zip(z, "p.default", files=("prefs.js", "places.sqlite"))

        with pytest.raises(fpm.BackupVerificationError, match="missing"):
            fpm.verify_backup(z, ["p.default/prefs.js",
                                  "p.default/places.sqlite",
                                  "p.default/key4.db"])

    def test_corrupt_archive_is_caught(self, tmp_path):
        z = tmp_path / "b.zip"
        make_backup_zip(z, "p.default")

        # Corrupt the stored payload itself. Flipping a byte at an arbitrary
        # offset is not enough: much of a small zip is central-directory
        # metadata, and mangling that does not break any member's CRC.
        raw = bytearray(z.read_bytes())
        payload = b"contents of prefs.js"
        offset = raw.find(payload)
        assert offset != -1, "test setup: payload not found in archive"
        raw[offset + 3] ^= 0xFF
        z.write_bytes(bytes(raw))

        with pytest.raises(fpm.BackupVerificationError, match="Corrupt entry"):
            fpm.verify_backup(z, [])

    def test_non_zip_is_caught(self, tmp_path):
        f = tmp_path / "b.zip"
        f.write_text("not a zip")
        with pytest.raises(fpm.BackupVerificationError, match="readable zip"):
            fpm.verify_backup(f, [])

    def test_empty_profile_refuses_to_produce_backup(self, tmp_path):
        """An empty archive must not be presented as a safety net."""
        empty = tmp_path / "empty.default"
        empty.mkdir()
        with pytest.raises(fpm.BackupVerificationError, match="Nothing was backed up"):
            fpm.backup_profile(empty, tmp_path / "backups", lambda m: None)

    def test_backup_profile_actually_verifies_its_output(self, tmp_path, monkeypatch):
        """Integration: backup_profile must verify, not just be verifiable.

        Simulates a write that silently fails to land, so the manifest and
        the archive disagree. Remove the verify_backup() call from
        backup_profile() and this passes a broken backup as good.
        """
        profile = make_profile(tmp_path / "Profiles")
        real_write = zipfile.ZipFile.write
        dropped = {"done": False}

        def flaky_write(self, filename, arcname=None, *a, **k):
            if not dropped["done"] and str(filename).endswith("prefs.js"):
                dropped["done"] = True
                return  # pretend it worked; write nothing
            return real_write(self, filename, arcname, *a, **k)

        monkeypatch.setattr(zipfile.ZipFile, "write", flaky_write)

        with pytest.raises(fpm.BackupVerificationError, match="missing"):
            fpm.backup_profile(profile, tmp_path / "backups", lambda m: None)

    def test_verification_does_not_require_optional_files(self, tmp_path):
        """A profile with no saved logins must still verify cleanly.

        Guards against regressing to a hardcoded logins.json/key4.db check,
        which would false-alarm on a healthy profile.
        """
        profile = make_profile(tmp_path / "Profiles")
        assert not (profile / "logins.json").exists()

        result = fpm.backup_profile(profile, tmp_path / "backups", lambda m: None)
        assert result.written >= 2

    def test_unreadable_file_is_skipped_not_fatal(self, tmp_path):
        profile = make_profile(tmp_path / "Profiles")
        (profile / "places.sqlite").write_text("data")
        result = fpm.backup_profile(profile, tmp_path / "backups", lambda m: None)
        assert result.skipped == 0
        assert result.written >= 3


# --------------------------------------------------------------------------
# Heuristic identity
# --------------------------------------------------------------------------

class TestHeuristics:
    def test_ids_are_unique(self):
        ids = [h.id for h in fpm.HEURISTICS]
        assert len(ids) == len(set(ids))

    def test_every_heuristic_has_a_description(self):
        assert all(h.description.strip() for h in fpm.HEURISTICS)

    @pytest.mark.parametrize("origin,expected", [
        ("https://secure-updates.co.in", "H-01"),
        ("https://a3f9c1e0b2.example.com", "H-02"),
        ("https://gisbotnetwork-cdn.example", "H-03"),
        ("https://push-alerts.xyz", "H-04"),
    ])
    def test_known_scam_shapes_match_expected_id(self, origin, expected):
        ids = [h.id for h in fpm.match_heuristics(origin)]
        assert expected in ids

    @pytest.mark.parametrize("origin", [
        "https://news.bbc.co.uk",
        "https://mail.google.com",
        "https://github.com",
    ])
    def test_ordinary_sites_do_not_match(self, origin):
        assert fpm.match_heuristics(origin) == []

    def test_is_suspicious_agrees_with_match_heuristics(self):
        for origin in ["https://a.co.in", "https://bbc.co.uk"]:
            assert fpm.is_suspicious(origin) == bool(fpm.match_heuristics(origin))

    def test_empty_origin_is_safe(self):
        assert fpm.match_heuristics("") == []
        assert fpm.match_heuristics(None) == []


# --------------------------------------------------------------------------
# Permission diff
# --------------------------------------------------------------------------

class TestPermissionDiff:
    """Pins 'Deleted 6 entries' as the only record of a destructive action."""

    def test_diff_records_action_per_row(self):
        rows = [
            (1, "https://evil.co.in", "desktop-notification"),
            (2, "https://news.bbc.co.uk", "desktop-notification"),
        ]
        diff = fpm.build_permission_diff(rows, [1])

        by_id = {d["id"]: d for d in diff}
        assert by_id[1]["action"] == "remove"
        assert by_id[2]["action"] == "keep"

    def test_diff_records_why_it_was_flagged(self):
        rows = [(1, "https://evil.co.in", "desktop-notification")]
        diff = fpm.build_permission_diff(rows, [1])

        assert diff[0]["flagged"] is True
        assert [h["id"] for h in diff[0]["heuristics"]] == ["H-01"]
        assert diff[0]["heuristics"][0]["description"]

    def test_manual_selection_of_unflagged_row_is_recorded(self):
        rows = [(1, "https://news.bbc.co.uk", "desktop-notification")]
        diff = fpm.build_permission_diff(rows, [1])

        assert diff[0]["action"] == "remove"
        assert diff[0]["flagged"] is False
        assert diff[0]["heuristics"] == []

    def test_formatted_diff_names_origins_and_reasons(self):
        rows = [
            (1, "https://evil.co.in", "desktop-notification"),
            (2, "https://news.bbc.co.uk", "desktop-notification"),
        ]
        text = fpm.format_permission_diff(fpm.build_permission_diff(rows, [1]))

        assert "evil.co.in" in text
        assert "H-01" in text
        assert "Keeping 1" in text

    def test_manual_selection_labelled_in_text(self):
        rows = [(1, "https://news.bbc.co.uk", "desktop-notification")]
        text = fpm.format_permission_diff(fpm.build_permission_diff(rows, [1]))
        assert "manually selected" in text

    def test_nothing_selected_is_stated_plainly(self):
        rows = [(1, "https://evil.co.in", "desktop-notification")]
        text = fpm.format_permission_diff(fpm.build_permission_diff(rows, []))
        assert "No notification permissions selected" in text


# --------------------------------------------------------------------------
# Restore dry-run
# --------------------------------------------------------------------------

class TestRestoreDryRun:
    def test_summary_reports_contents(self, tmp_path):
        z = tmp_path / "b.zip"
        make_backup_zip(z, "p.default",
                        files=("prefs.js", "places.sqlite", "logins.json",
                               "extensions.json", "sessionstore.jsonlz4"))
        info = fpm.inspect_backup_archive(z)

        assert info["has_prefs"] and info["has_places"]
        assert info["has_logins"] and info["has_extensions"]
        assert info["has_session"]
        assert info["has_cookies"] is False

    def test_key4db_counts_as_logins(self, tmp_path):
        z = tmp_path / "b.zip"
        make_backup_zip(z, "p.default", files=("prefs.js", "times.json", "key4.db"))
        assert fpm.inspect_backup_archive(z)["has_logins"] is True

    def test_description_is_human_readable(self, tmp_path):
        z = tmp_path / "b.zip"
        make_backup_zip(z, "p.default", files=("prefs.js", "places.sqlite"))
        text = fpm.describe_backup_archive(fpm.inspect_backup_archive(z))

        assert "p.default" in text
        assert "Bookmarks & history:   yes" in text
        assert "Saved logins:          not in this backup" in text

    def test_dry_run_does_not_touch_the_profile(self, tmp_path):
        profile = make_profile(tmp_path / "Profiles")
        (profile / "marker.txt").write_text("untouched")
        z = tmp_path / "b.zip"
        make_backup_zip(z, profile.name)

        fpm.inspect_backup_archive(z, expected_profile=profile.name)

        assert (profile / "marker.txt").read_text() == "untouched"


# --------------------------------------------------------------------------
# Forensic snapshot
# --------------------------------------------------------------------------

class TestForensicSnapshot:
    """Pins evidence capture. Deleting write_forensic_snapshot's JSON output
    or moving it after deletion turns these red."""

    def _profile_with_perms(self, tmp_path):
        profile = make_profile(tmp_path / "Profiles")
        rows = [
            (1, "https://secure-updates.co.in", "desktop-notification"),
            (2, "https://news.bbc.co.uk", "desktop-notification"),
        ]
        make_perms_db(profile, rows)
        return profile, rows

    def test_snapshot_files_are_written(self, tmp_path):
        profile, rows = self._profile_with_perms(tmp_path)
        snap = fpm.write_forensic_snapshot(
            profile, tmp_path / "out", rows, [1], lambda m: None)

        assert (snap / "snapshot.json").is_file()
        assert (snap / "snapshot.txt").is_file()
        assert (snap / "permissions.sqlite").is_file()

    def test_snapshot_records_heuristics_and_actions(self, tmp_path):
        profile, rows = self._profile_with_perms(tmp_path)
        snap = fpm.write_forensic_snapshot(
            profile, tmp_path / "out", rows, [1], lambda m: None)

        data = json.loads((snap / "snapshot.json").read_text())
        by_id = {d["id"]: d for d in data["notification_permissions"]}

        assert by_id[1]["action"] == "remove"
        assert [h["id"] for h in by_id[1]["heuristics"]] == ["H-01"]
        assert by_id[2]["action"] == "keep"
        assert data["summary"]["permissions_to_remove"] == 1
        assert data["summary"]["permissions_flagged"] == 1

    def test_snapshot_records_profile_metadata(self, tmp_path):
        profile, rows = self._profile_with_perms(tmp_path)
        (profile / "compatibility.ini").write_text(
            "[Compatibility]\nLastVersion=141.0_20260701120000/20260701120000\n")

        snap = fpm.write_forensic_snapshot(
            profile, tmp_path / "out", rows, [], lambda m: None)
        data = json.loads((snap / "snapshot.json").read_text())

        assert data["profile"]["name"] == profile.name
        assert data["profile"]["firefox_version"].startswith("141.0")
        assert data["profile"]["permissions_schema"] == "ok"

    def test_snapshot_embeds_heuristic_definitions(self, tmp_path):
        """A snapshot must be interpretable years later, so it carries the
        rule definitions rather than just the IDs."""
        profile, rows = self._profile_with_perms(tmp_path)
        snap = fpm.write_forensic_snapshot(
            profile, tmp_path / "out", rows, [1], lambda m: None)

        data = json.loads((snap / "snapshot.json").read_text())
        ids = {h["id"] for h in data["heuristics"]}
        assert "H-01" in ids
        assert all(h["description"] and h["pattern"] for h in data["heuristics"])

    def test_snapshot_is_written_before_deletion(self, tmp_path):
        """The captured database must still contain the rows being removed."""
        profile, rows = self._profile_with_perms(tmp_path)
        snap = fpm.write_forensic_snapshot(
            profile, tmp_path / "out", rows, [1], lambda m: None)

        fpm.delete_permission_rows(profile, [1], lambda m: None)

        conn = sqlite3.connect(str(snap / "permissions.sqlite"))
        preserved = [r[0] for r in conn.execute("SELECT origin FROM moz_perms")]
        conn.close()
        assert "https://secure-updates.co.in" in preserved, \
            "evidence was captured after deletion"

    def test_snapshot_does_not_modify_the_profile(self, tmp_path):
        profile, rows = self._profile_with_perms(tmp_path)
        before = sorted(p.name for p in profile.iterdir())

        fpm.write_forensic_snapshot(profile, tmp_path / "out", rows, [1], lambda m: None)

        assert sorted(p.name for p in profile.iterdir()) == before

    def test_text_report_is_readable(self, tmp_path):
        profile, rows = self._profile_with_perms(tmp_path)
        snap = fpm.write_forensic_snapshot(
            profile, tmp_path / "out", rows, [1], lambda m: None)

        text = (snap / "snapshot.txt").read_text()
        assert "secure-updates.co.in" in text
        assert "H-01" in text

    def test_missing_compatibility_ini_is_unknown_not_fatal(self, tmp_path):
        profile, rows = self._profile_with_perms(tmp_path)
        snap = fpm.write_forensic_snapshot(
            profile, tmp_path / "out", rows, [], lambda m: None)
        data = json.loads((snap / "snapshot.json").read_text())
        assert data["profile"]["firefox_version"] == "unknown"
