# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright 2026 Leon Priest <https://github.com/7h3v01d>
"""P3 regression tests: statistical hostname analysis (H-05).

The corpus tests are the point of this module. An entropy heuristic is only
as good as its false-positive rate, so the legitimate-hostname corpus is a
hard gate: any tuning change that flags a real site fails the suite.
"""

import pytest

import firefox_profile_manager as fpm


# Machine-generated hostnames of the kind scam push networks issue.
SCAM_CORPUS = [
    "https://d9mp99u07b.co.in",
    "https://a3f9c1e0b2.example.com",
    "https://x7k2m9q1w8.top",
    "https://kj3h4kj2h34.push-alerts.xyz",
    "https://zqxjw8vn2p.notif.online",
    "https://8fh39dks02.badsite.com",
    "https://bzkrvhxqmn.site",
    "https://news-4k2j9x.icu",
    "https://q7w8e9r0t1y2.club",
]

# Real hostnames that must never be flagged. Includes deliberately awkward
# cases: CDN hosts that are genuinely random, and long single-word domains.
LEGIT_CORPUS = [
    # CDN / cloud - random by design
    "https://d2k1ftgv7pobq7.cloudfront.net",
    "https://s3.amazonaws.com",
    "https://cdn.jsdelivr.net",
    "https://fonts.gstatic.com",
    "https://scontent-syd2-1.xx.fbcdn.net",
    "https://abc123def456.b-cdn.net",
    "https://myapp-prod-7f3k.herokuapp.com",
    # long real words - high entropy, but words
    "https://stackoverflow.com",
    "https://developer.mozilla.org",
    "https://openstreetmap.org",
    "https://www.theguardian.com",
    "https://login.microsoftonline.com",
    # everyday sites
    "https://news.bbc.co.uk",
    "https://mail.google.com",
    "https://github.com",
    "https://www.reddit.com",
    "https://en.wikipedia.org",
    "https://calendar.google.com",
    "https://outlook.office.com",
    "https://web.whatsapp.com",
    "https://music.youtube.com",
    "https://accounts.spotify.com",
    "https://myaccount.google.com",
    "https://teams.microsoft.com",
    "https://www.commbank.com.au",
    "https://my.telstra.com.au",
    "https://www.woolworths.com.au",
    "https://www.bunnings.com.au",
]


class TestShannonEntropy:
    def test_empty_string(self):
        assert fpm.shannon_entropy("") == 0.0

    def test_uniform_string_is_zero(self):
        assert fpm.shannon_entropy("aaaaaaaa") == 0.0

    def test_random_scores_higher_than_word(self):
        assert fpm.shannon_entropy("x7k2m9q1w8") > fpm.shannon_entropy("calendar")

    def test_all_distinct_is_log2_n(self):
        assert fpm.shannon_entropy("abcd") == pytest.approx(2.0)


class TestHostnameParsing:
    @pytest.mark.parametrize("origin,expected", [
        ("https://example.com", "example.com"),
        ("http://example.com/path/here", "example.com"),
        ("https://example.com:8443", "example.com"),
        ("https://example.com^privateBrowsingId=1", "example.com"),
        ("EXAMPLE.COM", "example.com"),
        ("https://example.com.", "example.com"),
        ("", ""),
    ])
    def test_normalisation(self, origin, expected):
        assert fpm.hostname_from_origin(origin) == expected


class TestEntropyCorpus:
    """The false-positive gate. Loosening the thresholds breaks this."""

    @pytest.mark.parametrize("origin", SCAM_CORPUS)
    def test_scam_hostnames_are_flagged(self, origin):
        assert fpm.is_high_entropy_host(origin) is True

    @pytest.mark.parametrize("origin", LEGIT_CORPUS)
    def test_legitimate_hostnames_are_not_flagged(self, origin):
        assert fpm.is_high_entropy_host(origin) is False, \
            f"false positive on {origin}"

    def test_cdn_exemption_applies_to_subdomains(self):
        assert fpm.is_exempt_host("d2k1ftgv7pobq7.cloudfront.net")
        assert fpm.is_exempt_host("cloudfront.net")

    def test_exemption_is_suffix_not_substring(self):
        """'evil-cloudfront.net.attacker.com' must not inherit the exemption."""
        assert not fpm.is_exempt_host("cloudfront.net.attacker.com")
        assert not fpm.is_exempt_host("notcloudfront.net")

    def test_every_label_is_judged_independently(self):
        """Pins the bug where only the highest-entropy label was tested.

        In this host the English label 'push-alerts' scores higher than the
        random 'kj3h4kj2h34', so ranking-then-testing misses the signal.
        """
        p = fpm.host_entropy_profile("https://kj3h4kj2h34.push-alerts.xyz")
        assert p["qualifies"] is True
        assert p["label"] == "kj3h4kj2h34"

    def test_short_labels_never_qualify(self):
        assert fpm.is_high_entropy_host("https://a1b2.com") is False

    def test_bare_hostname_without_subdomain(self):
        assert fpm.is_high_entropy_host("https://x7k2m9q1w8.top") is True

    def test_empty_origin_is_safe(self):
        assert fpm.is_high_entropy_host("") is False
        assert fpm.host_entropy_profile("")["qualifies"] is False


class TestAdvisoryOnlyPreselection:
    """The core safety property of H-05.

    Set H-05's autoselect to True and test_entropy_match_does_not_preselect
    fails - which is the whole reason the field exists.
    """

    def test_entropy_match_does_not_preselect(self):
        origin = "https://d9mp99u07b.example.com"
        assert fpm.is_suspicious(origin) is True
        assert fpm.should_preselect(origin) is False
        assert [h.id for h in fpm.match_heuristics(origin)] == ["H-05"]

    def test_named_threat_preselects_alone(self):
        """A named scam network is direct evidence, not hostname shape."""
        assert fpm.should_preselect("https://gisbotnetwork.co.in") is True

    def test_single_shape_signal_does_not_preselect(self):
        """'.co.in' alone is an ordinary Indian commercial domain.

        Revert should_preselect() to 'any autoselect rule matched' and this
        fails - legitimate Indian businesses would arrive pre-ticked.
        """
        origin = "https://legitimatebank.co.in"
        assert fpm.is_suspicious(origin) is True, "should still be visible"
        assert fpm.should_preselect(origin) is False

    def test_two_shape_signals_preselect(self):
        origin = "https://d9mp99u07b.something.co.in"
        ids = [h.id for h in fpm.match_heuristics(origin)]
        assert len(ids) >= 2
        assert fpm.should_preselect(origin) is True

    def test_combined_match_preselects(self):
        """A row matching two independent shape rules is ticked."""
        origin = "https://d9mp99u07b.co.in"
        ids = [h.id for h in fpm.match_heuristics(origin)]
        assert "H-01" in ids and "H-05" in ids
        assert fpm.should_preselect(origin) is True

    def test_clean_origin_neither_flags_nor_preselects(self):
        origin = "https://news.bbc.co.uk"
        assert fpm.is_suspicious(origin) is False
        assert fpm.should_preselect(origin) is False

    @pytest.mark.parametrize("origin", LEGIT_CORPUS)
    def test_no_legitimate_site_is_ever_preselected(self, origin):
        """The strongest property: nothing real is ever pre-ticked."""
        assert fpm.should_preselect(origin) is False, \
            f"{origin} would arrive pre-ticked for deletion"

    def test_cdn_host_matching_hex_rule_is_not_preselected(self):
        """Pins a pre-existing bug found by the corpus gate.

        'abc123def456' is entirely hex characters, so H-02 fires on the real
        BunnyCDN host abc123def456.b-cdn.net. Before the exemption in
        should_preselect(), that row arrived pre-ticked for deletion.
        """
        origin = "https://abc123def456.b-cdn.net"
        assert "H-02" in [h.id for h in fpm.match_heuristics(origin)]
        assert fpm.is_suspicious(origin) is True, "should still be visible"
        assert fpm.should_preselect(origin) is False, "must not be pre-ticked"

    def test_heuristic_tiers_are_declared(self):
        by_id = {h.id: h for h in fpm.HEURISTICS}
        assert by_id["H-05"].tier == fpm.TIER_ADVISORY
        assert by_id["H-03"].tier == fpm.TIER_NAMED_THREAT
        assert all(by_id[i].tier == fpm.TIER_SHAPE for i in ("H-01", "H-02", "H-04"))


class TestHeuristicTableIntegrity:
    def test_ids_unique_and_sequential(self):
        ids = [h.id for h in fpm.HEURISTICS]
        assert ids == sorted(set(ids))

    def test_every_rule_has_serialisable_expression(self):
        assert all(isinstance(h.expression, str) and h.expression for h in fpm.HEURISTICS)

    def test_every_rule_is_callable(self):
        for h in fpm.HEURISTICS:
            assert h.test("https://example.com") in (True, False)

    def test_diff_records_advisory_matches(self):
        rows = [(1, "https://d9mp99u07b.example.com", "desktop-notification")]
        diff = fpm.build_permission_diff(rows, [])
        assert diff[0]["flagged"] is True
        assert [h["id"] for h in diff[0]["heuristics"]] == ["H-05"]
        assert diff[0]["action"] == "keep"
