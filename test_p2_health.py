# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright 2026 Leon Priest <https://github.com/7h3v01d>
"""P2 regression tests: extension inventory detail, prefs reading, the
health report, and the troubleshooting launcher."""

import json

import pytest

import firefox_profile_manager as fpm

from test_p0_safety import make_profile, make_perms_db


def write_extensions(profile, addons):
    (profile / "extensions.json").write_text(json.dumps({"addons": addons}))


UBLOCK = {
    "id": "uBlock0@raymondhill.net",
    "defaultLocale": {"name": "uBlock Origin"},
    "active": True,
    "signedState": 2,
    "installDate": 1700000000000,
    "userPermissions": {"permissions": ["storage", "webRequest"]},
}
ROGUE = {
    "id": "rogue@example.com",
    "defaultLocale": {"name": "Totally Safe Toolbar"},
    "active": True,
    "signedState": 0,
    "installDate": 1750000000000,
}
SYSTEM_ADDON = {
    "id": "system@mozilla.org",
    "defaultLocale": {"name": "System Feature"},
    "active": True,
    "signedState": 3,
}


class TestExtensionDetail:
    def test_signing_state_is_reported(self, tmp_path):
        profile = make_profile(tmp_path)
        write_extensions(profile, [UBLOCK, ROGUE])

        by_name = {e["name"]: e for e in fpm.list_extensions(profile)}
        assert by_name["uBlock Origin"]["signed_label"] == "signed"
        assert by_name["uBlock Origin"]["is_unsigned"] is False
        assert by_name["Totally Safe Toolbar"]["is_unsigned"] is True

    def test_system_addons_are_not_flagged_unsigned(self, tmp_path):
        profile = make_profile(tmp_path)
        write_extensions(profile, [SYSTEM_ADDON])
        ext = fpm.list_extensions(profile)[0]
        assert ext["is_system"] is True
        assert ext["is_unsigned"] is False

    def test_install_date_is_formatted(self, tmp_path):
        profile = make_profile(tmp_path)
        write_extensions(profile, [UBLOCK])
        assert fpm.list_extensions(profile)[0]["installed"].count("-") == 2

    def test_missing_install_date_is_blank_not_fatal(self, tmp_path):
        profile = make_profile(tmp_path)
        write_extensions(profile, [SYSTEM_ADDON])
        assert fpm.list_extensions(profile)[0]["installed"] == ""

    def test_permissions_are_captured(self, tmp_path):
        profile = make_profile(tmp_path)
        write_extensions(profile, [UBLOCK])
        assert "webRequest" in fpm.list_extensions(profile)[0]["permissions"]

    def test_corrupt_extensions_json_is_not_fatal(self, tmp_path):
        profile = make_profile(tmp_path)
        (profile / "extensions.json").write_text("{ not json")
        assert fpm.list_extensions(profile) == []

    def test_absent_extensions_json(self, tmp_path):
        assert fpm.list_extensions(make_profile(tmp_path)) == []


class TestPrefsReading:
    def test_reads_int_bool_and_string(self, tmp_path):
        profile = make_profile(tmp_path)
        (profile / "prefs.js").write_text(
            'user_pref("browser.startup.page", 3);\n'
            'user_pref("browser.thing.enabled", true);\n'
            'user_pref("browser.name", "hello");\n'
        )
        assert fpm.read_pref(profile, "browser.startup.page") == 3
        assert fpm.read_pref(profile, "browser.thing.enabled") is True
        assert fpm.read_pref(profile, "browser.name") == "hello"

    def test_absent_pref_is_none(self, tmp_path):
        profile = make_profile(tmp_path)
        assert fpm.read_pref(profile, "no.such.pref") is None

    def test_prefix_collision_does_not_match(self, tmp_path):
        """'browser.startup.page' must not be matched by a longer key."""
        profile = make_profile(tmp_path)
        (profile / "prefs.js").write_text(
            'user_pref("browser.startup.pagecount", 9);\n')
        assert fpm.read_pref(profile, "browser.startup.page") is None

    def test_session_restore_detection(self, tmp_path):
        profile = make_profile(tmp_path)
        (profile / "prefs.js").write_text('user_pref("browser.startup.page", 3);\n')
        assert fpm.session_restore_enabled(profile) is True

        (profile / "prefs.js").write_text('user_pref("browser.startup.page", 1);\n')
        assert fpm.session_restore_enabled(profile) is False


class TestHumanSize:
    @pytest.mark.parametrize("n,expected", [
        (0, "0 B"),
        (512, "512 B"),
        (2048, "2.0 KB"),
        (5 * 1024 * 1024, "5.0 MB"),
        (int(1.8 * 1024 ** 3), "1.8 GB"),
    ])
    def test_formatting(self, n, expected):
        assert fpm.human_size(n) == expected


class TestHealthReport:
    def _sick_profile(self, tmp_path):
        profile = make_profile(tmp_path / "Profiles")
        make_perms_db(profile, [
            (1, "https://secure-updates.co.in", "desktop-notification"),
            (2, "https://news.bbc.co.uk", "desktop-notification"),
        ])
        write_extensions(profile, [UBLOCK, ROGUE])
        (profile / "prefs.js").write_text('user_pref("browser.startup.page", 3);\n')
        return profile

    def test_counts_are_reported(self, tmp_path):
        report = fpm.build_health_report(self._sick_profile(tmp_path), 2)

        assert report["permissions_total"] == 2
        assert report["permissions_flagged"] == 1
        assert report["extensions_total"] == 2
        assert report["extensions_unsigned"] == 1
        assert report["session_restore"] is True
        assert report["profile_count"] == 2

    def test_recommendations_cover_each_problem(self, tmp_path):
        report = fpm.build_health_report(self._sick_profile(tmp_path), 1)
        joined = " ".join(report["recommendations"]).lower()

        assert "notification permission" in joined
        assert "restore previous session" in joined
        assert "unsigned" in joined

    def test_system_addons_do_not_trigger_unsigned_warning(self, tmp_path):
        """Health report must not nag about Mozilla's own system add-ons.

        A warning that fires on every healthy machine trains the user to
        ignore warnings. Revert the is_system exemption in
        build_health_report() and this fails.
        """
        profile = make_profile(tmp_path / "Profiles")
        make_perms_db(profile, [(1, "https://news.bbc.co.uk", "desktop-notification")])
        write_extensions(profile, [UBLOCK, SYSTEM_ADDON])
        (profile / "prefs.js").write_text('user_pref("browser.startup.page", 1);\n')

        report = fpm.build_health_report(profile, 1)

        assert report["extensions_unsigned"] == 0
        assert not any("unsigned" in r.lower() for r in report["recommendations"])

    def test_healthy_profile_gets_all_clear(self, tmp_path):
        profile = make_profile(tmp_path / "Profiles")
        make_perms_db(profile, [(1, "https://news.bbc.co.uk", "desktop-notification")])
        write_extensions(profile, [UBLOCK])
        (profile / "prefs.js").write_text('user_pref("browser.startup.page", 1);\n')

        report = fpm.build_health_report(profile, 1)
        assert report["recommendations"] == ["Nothing obviously wrong with this profile."]

    def test_flagged_origins_carry_heuristic_ids(self, tmp_path):
        report = fpm.build_health_report(self._sick_profile(tmp_path), 1)
        assert report["flagged_origins"][0]["heuristics"] == "H-01"

    def test_report_is_readable(self, tmp_path):
        report = fpm.build_health_report(self._sick_profile(tmp_path), 2)
        text = fpm.format_health_report(report)

        assert "secure-updates.co.in" in text
        assert "Totally Safe Toolbar" in text
        assert "Restore session:    ENABLED" in text
        assert "Recommendations" in text

    def test_scan_does_not_modify_the_profile(self, tmp_path):
        profile = self._sick_profile(tmp_path)
        before = sorted(p.name for p in profile.iterdir())

        fpm.build_health_report(profile, 1)

        assert sorted(p.name for p in profile.iterdir()) == before

    def test_unsupported_schema_is_surfaced(self, tmp_path):
        profile = make_profile(tmp_path / "Profiles")
        make_perms_db(profile, table="moz_permissions_v2")
        report = fpm.build_health_report(profile, 1)

        assert report["schema"] is fpm.SchemaStatus.UNSUPPORTED
        assert any("manually" in r for r in report["recommendations"])

    def test_cache_size_is_measured(self, tmp_path):
        profile = make_profile(tmp_path / "Profiles")
        cache = profile / "cache2" / "entries"
        cache.mkdir(parents=True)
        (cache / "blob").write_bytes(b"x" * 4096)

        assert fpm.build_health_report(profile, 1)["cache_bytes"] >= 4096


class TestTroubleshootLauncher:
    def test_missing_binary_raises_actionable_error(self, monkeypatch):
        monkeypatch.setattr(fpm.shutil, "which", lambda n: None)
        monkeypatch.setattr(fpm, "find_firefox_binary", lambda: None)

        with pytest.raises(RuntimeError, match="Troubleshoot Mode"):
            fpm.launch_troubleshoot_mode(lambda m: None)

    def test_launches_with_safe_mode_flag(self, monkeypatch, tmp_path):
        fake = tmp_path / "firefox"
        fake.write_text("#!/bin/sh\n")
        monkeypatch.setattr(fpm, "find_firefox_binary", lambda: fake)

        calls = []
        monkeypatch.setattr(fpm.subprocess, "Popen", lambda args, **k: calls.append(args))

        fpm.launch_troubleshoot_mode(lambda m: None)

        assert calls == [[str(fake), "-safe-mode"]]

    def test_binary_discovery_prefers_path(self, monkeypatch, tmp_path):
        fake = tmp_path / "firefox"
        fake.write_text("x")
        monkeypatch.setattr(fpm.shutil, "which", lambda n: str(fake))
        assert fpm.find_firefox_binary() == fake
