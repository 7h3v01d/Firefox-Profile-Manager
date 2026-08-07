#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright 2026 Leon Priest <https://github.com/7h3v01d>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Firefox Profile Manager
------------------------
A small PyQt6 utility to:
  1. Find Firefox profiles on this machine
  2. Back them up to a zip file
  3. Clean out malicious notification permissions / stuck session
     data (the classic "fake TROJAN VIRUS FOUND" push-notification
     scam) with a review step before anything is deleted
  4. Restore a profile from a previous backup

Nothing here touches Windows itself - it only ever works inside the
Firefox profile folder, and every destructive action is reversible:
cleaning takes an automatic backup first (unless you untick it) and
writes a forensic snapshot, while restoring keeps the profile it
replaced alongside as '<name>.pre-restore-<timestamp>'.

Write operations are refused while Firefox holds the profile, and also
if that cannot be determined. Each destructive function enforces this
itself rather than trusting the caller, so a long backup cannot open a
window in which Firefox starts and the later steps proceed anyway.

Install:
    pip install PyQt6

Run:
    python firefox_profile_manager.py
"""

import json
import math
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import NamedTuple

try:  # POSIX advisory locking; absent on Windows
    import fcntl
except ImportError:  # pragma: no cover - platform dependent
    fcntl = None

from PyQt6.QtCore import QObject, Qt, QThread, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QApplication,
    QProgressBar,
    QCheckBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

__version__ = "1.0.0"

APP_TITLE = "Firefox Profile Manager"
FLAG_EMOJI = "\u26a0\ufe0f"

# Heuristics that flag near-certain scam push-notification senders.
#
# Each carries a stable ID so that logs, the permission diff, and forensic
# snapshots can record *why* an entry was flagged, rather than just that it
# was. IDs are append-only: never renumber a heuristic, retire it instead,
# or old snapshots stop meaning what they say.
#
# This is intentionally conservative - matching only FLAGS an entry for the
# user, it never auto-deletes anything without confirmation.
# --------------------------------------------------------------------------
# Statistical hostname analysis (advisory)
# --------------------------------------------------------------------------

# Hosting and CDN providers that legitimately issue machine-generated
# hostnames. Without this, 'd2k1ftgv7pobq7.cloudfront.net' scores exactly
# like a scam domain - the maths cannot tell them apart, so provenance has
# to. Suffix match, so it also covers deeper subdomains.
ENTROPY_EXEMPT_SUFFIXES = (
    "cloudfront.net", "amazonaws.com", "akamaihd.net", "akamaized.net",
    "azureedge.net", "azurewebsites.net", "fastly.net", "fastlylb.net",
    "cdn77.org", "jsdelivr.net", "gstatic.com", "googleapis.com",
    "googleusercontent.com", "googlevideo.com", "ggpht.com",
    "fbcdn.net", "cdninstagram.com", "cloudflare.net", "cloudflare.com",
    "cloudflarestorage.com", "herokuapp.com", "github.io", "githubusercontent.com",
    "vercel.app", "netlify.app", "pages.dev", "workers.dev", "wp.com",
    "twimg.com", "licdn.com", "shopify.com", "myshopify.com",
    "digitaloceanspaces.com", "backblazeb2.com", "b-cdn.net", "stackpathdns.com",
)

ENTROPY_MIN_LABEL_LEN = 8
ENTROPY_MIN_BITS = 2.5
ENTROPY_MIN_DIGIT_RATIO = 0.2
ENTROPY_MAX_VOWEL_RATIO = 0.15
VOWELS = set("aeiou")


def shannon_entropy(text: str) -> float:
    """Bits per character. Random strings score high, words score low."""
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    total = 0.0
    for c in counts.values():
        p = c / n
        total -= p * math.log2(p)
    return total


def hostname_from_origin(origin: str) -> str:
    """Strip scheme, port, path and Firefox's '^' origin attributes."""
    host = (origin or "").strip()
    host = re.sub(r"^[a-z][a-z0-9+.-]*://", "", host, flags=re.IGNORECASE)
    host = host.split("^", 1)[0]      # e.g. '...^privateBrowsingId=1'
    host = host.split("/", 1)[0]
    host = host.rsplit(":", 1)[0] if re.search(r":\d+$", host) else host
    return host.strip(".").lower()


def is_exempt_host(host: str) -> bool:
    return any(host == s or host.endswith("." + s) for s in ENTROPY_EXEMPT_SUFFIXES)


def _label_stats(label: str) -> dict:
    letters = [ch for ch in label if ch.isalpha()]
    return {
        "label": label,
        "entropy": shannon_entropy(label),
        "digit_ratio": sum(ch.isdigit() for ch in label) / len(label) if label else 0.0,
        "vowel_ratio": (sum(ch in VOWELS for ch in letters) / len(letters))
                       if letters else 0.0,
        "length": len(label),
    }


def _label_qualifies(stats: dict) -> bool:
    if stats["length"] < ENTROPY_MIN_LABEL_LEN or stats["entropy"] < ENTROPY_MIN_BITS:
        return False
    return (stats["digit_ratio"] >= ENTROPY_MIN_DIGIT_RATIO
            or stats["vowel_ratio"] <= ENTROPY_MAX_VOWEL_RATIO)


def host_entropy_profile(origin: str) -> dict:
    """Stats for the most random-looking label in a hostname.

    The TLD is excluded (it is fixed and carries no signal); every other
    label is a candidate, because a scam domain's randomness often sits in
    the registrable name itself ('x7k2m9q1w8.top') rather than a subdomain.

    Each label is judged on its own. Ranking by entropy alone and testing
    only the winner is wrong: in 'kj3h4kj2h34.push-alerts.xyz' the hyphenated
    English label scores higher than the random one, and the actual signal
    would be missed.
    """
    host = hostname_from_origin(origin)
    labels = [l for l in host.split(".") if l]
    candidates = labels[:-1] if len(labels) >= 2 else labels
    exempt = is_exempt_host(host)

    empty = {"host": host, "label": "", "entropy": 0.0, "digit_ratio": 0.0,
             "vowel_ratio": 0.0, "length": 0, "exempt": exempt, "qualifies": False}
    if not candidates:
        return empty

    scored = [_label_stats(l) for l in candidates]
    qualifying = [s for s in scored if _label_qualifies(s)]
    chosen = max(qualifying or scored, key=lambda s: s["entropy"])

    return {**empty, **chosen, "qualifies": bool(qualifying)}


def is_high_entropy_host(origin: str) -> bool:
    """Advisory signal only - see H-05. Never pre-selects a row.

    Entropy alone is not enough: 'stackoverflow' is long and high-entropy
    but obviously a word. Machine-generated labels additionally carry either
    a heavy digit mix or almost no vowels, so both are required.
    """
    p = host_entropy_profile(origin)
    return p["qualifies"] and not p["exempt"]


# Evidence tiers. A named scam network is direct evidence and stands alone;
# rules that only observe the SHAPE of a hostname are circumstantial, and an
# exemption list for them will always be incomplete, so two independent
# shape signals are required before a row is nominated for deletion.
TIER_NAMED_THREAT = "named"     # sufficient on its own
TIER_SHAPE = "shape"            # needs corroboration
TIER_ADVISORY = "advisory"      # never nominates, flags only

SHAPE_SIGNALS_REQUIRED = 2


class Heuristic(NamedTuple):
    id: str
    description: str
    test: "object"        # callable: (origin: str) -> bool
    expression: str       # serialisable, human-readable form of the rule
    tier: str             # one of TIER_* above

    @property
    def autoselect(self) -> bool:
        """Kept for readability: can this rule contribute to preselection?"""
        return self.tier in (TIER_NAMED_THREAT, TIER_SHAPE)


def _regex_rule(pattern: re.Pattern):
    def rule(origin: str) -> bool:
        return bool(pattern.search(origin or ""))
    return rule


_P_COIN = re.compile(r"\.co\.in$", re.IGNORECASE)
_P_HEX = re.compile(r"^(?:https?://)?[a-f0-9]{8,}\.", re.IGNORECASE)
_P_GIS = re.compile(r"gisbotnetwork", re.IGNORECASE)
_P_PUSH = re.compile(
    r"(push|notif|alert)[a-z0-9]*\.(xyz|top|club|online|site|icu|rest)$", re.IGNORECASE)


HEURISTICS = [
    Heuristic("H-01", "Uses the .co.in domain, heavily abused by ad networks",
              _regex_rule(_P_COIN), _P_COIN.pattern, TIER_SHAPE),
    Heuristic("H-02", "Long random hex-looking subdomain",
              _regex_rule(_P_HEX), _P_HEX.pattern, TIER_SHAPE),
    Heuristic("H-03", "Known scam push-notification network",
              _regex_rule(_P_GIS), _P_GIS.pattern, TIER_NAMED_THREAT),
    Heuristic("H-04", "Notification-themed name on a low-cost TLD",
              _regex_rule(_P_PUSH), _P_PUSH.pattern, TIER_SHAPE),
    # H-05 is statistical rather than a known-bad pattern, so it FLAGS but
    # never pre-ticks: legitimate CDN hostnames are genuinely high-entropy,
    # and a pre-ticked row is one careless click from deletion.
    #
    # The expression is BUILT FROM THE CONSTANTS, never written by hand. A
    # hand-written copy silently goes stale the moment a threshold is tuned,
    # and this string is what forensic snapshots record as the rule that
    # produced the decision.
    Heuristic("H-05", "Subdomain looks statistically random (advisory only)",
              lambda origin: is_high_entropy_host(origin),
              (f"label length >= {ENTROPY_MIN_LABEL_LEN} "
               f"AND shannon entropy >= {ENTROPY_MIN_BITS} bits/char "
               f"AND (digit ratio >= {ENTROPY_MIN_DIGIT_RATIO} "
               f"OR vowel ratio <= {ENTROPY_MAX_VOWEL_RATIO}), "
               "excluding known CDN/hosting suffixes"),
              TIER_ADVISORY),
]


# --------------------------------------------------------------------------
# Dark-industrial theme (obsidian / teal / phosphor / amber, JetBrains Mono)
# --------------------------------------------------------------------------

# Palette - also used for per-row colouring in the widgets below.
OBSIDIAN_0 = "#0b0e10"   # window base
OBSIDIAN_1 = "#111519"   # panels
OBSIDIAN_2 = "#0d1114"   # inputs / lists
GRAPHITE   = "#232a30"   # borders
GRAPHITE_2 = "#2d363d"   # hover / lighter border
TEXT       = "#d7dde3"   # primary text
TEXT_DIM   = "#8a949c"   # secondary text
TEAL       = "#2fd6c3"   # accent / focus
GREEN      = "#4be08a"   # positive / primary action
AMBER      = "#ffb454"   # caution / flagged

THEME_QSS = """
* {
    font-family: "JetBrains Mono", "Cascadia Mono", "Consolas", monospace;
    font-size: 12px;
}

QMainWindow, QWidget {
    background-color: #0b0e10;
    color: #d7dde3;
}

QLabel { color: #d7dde3; background: transparent; }
QLabel#statusLabel { color: #8a949c; padding: 2px 0; }

/* ---- Group boxes: industrial panels ---- */
QGroupBox {
    background-color: #111519;
    border: 1px solid #232a30;
    border-radius: 0px;
    margin-top: 16px;
    padding: 12px 10px 10px 10px;
    font-weight: bold;
    color: #2fd6c3;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 8px;
    padding: 2px 6px;
    background-color: #0b0e10;
    color: #2fd6c3;
    letter-spacing: 1px;
}

/* ---- Buttons: flat, zero-radius ---- */
QPushButton {
    background-color: #161b20;
    color: #d7dde3;
    border: 1px solid #2d363d;
    border-radius: 0px;
    padding: 7px 14px;
}
QPushButton:hover { border-color: #2fd6c3; color: #2fd6c3; }
QPushButton:pressed { background-color: #0b0e10; }
QPushButton:disabled { color: #55606a; border-color: #232a30; }

/* Positive / safe action (backup) */
QPushButton#primaryButton { border-color: #4be08a; color: #4be08a; }
QPushButton#primaryButton:hover { background-color: #4be08a; color: #0b0e10; }

/* Destructive / caution action (clean, restore) */
QPushButton#dangerButton { border-color: #ffb454; color: #ffb454; }
QPushButton#dangerButton:hover { background-color: #ffb454; color: #0b0e10; }

/* ---- Lists ---- */
QListWidget {
    background-color: #0d1114;
    border: 1px solid #232a30;
    border-radius: 0px;
    outline: 0;
    padding: 2px;
}
QListWidget::item { padding: 4px 6px; color: #d7dde3; }
QListWidget::item:selected { background-color: #16302e; color: #2fd6c3; }
QListWidget::item:hover { background-color: #141a1f; }

/* Checkbox indicators (both QCheckBox and checkable list items) */
QCheckBox { color: #d7dde3; spacing: 8px; background: transparent; }
QCheckBox::indicator, QListWidget::indicator {
    width: 14px; height: 14px;
    border: 1px solid #2d363d;
    border-radius: 0px;
    background-color: #0b0e10;
}
QCheckBox::indicator:hover, QListWidget::indicator:hover { border-color: #2fd6c3; }
QCheckBox::indicator:checked, QListWidget::indicator:checked {
    background-color: #4be08a; border-color: #4be08a;
}

/* ---- Tabs ---- */
QTabWidget::pane { border: 1px solid #232a30; border-radius: 0px; top: -1px; }
QTabBar::tab {
    background-color: #0d1114;
    color: #8a949c;
    border: 1px solid #232a30;
    border-bottom: none;
    border-radius: 0px;
    padding: 7px 18px;
    margin-right: 2px;
    letter-spacing: 1px;
}
QTabBar::tab:selected {
    background-color: #111519;
    color: #2fd6c3;
    border-top: 2px solid #2fd6c3;
}
QTabBar::tab:hover:!selected { color: #d7dde3; }

/* ---- Log terminal ---- */
QProgressBar#progressBar {
    background-color: #0d1114;
    border: none;
    border-radius: 0px;
}
QProgressBar#progressBar::chunk { background-color: #2fd6c3; }

QPlainTextEdit#summaryBox {
    background-color: #0d1114;
    color: #d7dde3;
    border: 1px solid #232a30;
    border-radius: 0px;
}

QPlainTextEdit#logBox {
    background-color: #07090b;
    color: #4be08a;
    border: 1px solid #232a30;
    border-radius: 0px;
    selection-background-color: #16302e;
    selection-color: #2fd6c3;
}

/* ---- Splitter ---- */
QSplitter::handle { background-color: #232a30; }
QSplitter::handle:vertical { height: 3px; }
QSplitter::handle:hover { background-color: #2fd6c3; }

/* ---- Scrollbars ---- */
QScrollBar:vertical { background: #0b0e10; width: 12px; margin: 0; }
QScrollBar::handle:vertical { background: #2d363d; min-height: 24px; border-radius: 0px; }
QScrollBar::handle:vertical:hover { background: #2fd6c3; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal { background: #0b0e10; height: 12px; margin: 0; }
QScrollBar::handle:horizontal { background: #2d363d; min-width: 24px; border-radius: 0px; }
QScrollBar::handle:horizontal:hover { background: #2fd6c3; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }

/* ---- Dialogs inherit the base ---- */
QMessageBox, QFileDialog { background-color: #111519; }
"""


# --------------------------------------------------------------------------
# Firefox process / profile discovery
# --------------------------------------------------------------------------

def firefox_is_running() -> bool:
    """Advisory, machine-wide 'is any Firefox running' check.

    FAILS CLOSED: if the probe cannot be run (tool missing, blocked by
    policy, timeout), this reports True. An unanswerable question about
    whether a database is in use must not read as 'safe to write'.

    This is deliberately coarse - it says nothing about *which* profile is
    open. Write operations gate on profile_lock_state() instead; this only
    drives the advisory banner.
    """
    try:
        if sys.platform.startswith("win"):
            out = subprocess.check_output(
                ["tasklist", "/FI", "IMAGENAME eq firefox.exe"],
                text=True, stderr=subprocess.DEVNULL, timeout=10,
            )
            return "firefox.exe" in out.lower()
        out = subprocess.run(
            ["pgrep", "-x", "firefox"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
        )
        return out.returncode == 0
    except Exception:
        return True


def firefox_root() -> Path | None:
    """Root folder that contains profiles.ini, per-OS."""
    home = Path.home()
    if sys.platform.startswith("win"):
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "Mozilla" / "Firefox"
    elif sys.platform == "darwin":
        return home / "Library" / "Application Support" / "Firefox"
    else:
        return home / ".mozilla" / "firefox"
    return None


def local_cache_root() -> Path | None:
    """Where cache2/ lives (separate from the roaming profile on Windows)."""
    if sys.platform.startswith("win"):
        localappdata = os.environ.get("LOCALAPPDATA")
        if localappdata:
            return Path(localappdata) / "Mozilla" / "Firefox" / "Profiles"
    return None


def parse_profiles():
    """Return list of dicts: name, path (Path), is_default (bool)."""
    root = firefox_root()
    profiles = []
    if not root:
        return profiles
    ini_path = root / "profiles.ini"
    if not ini_path.exists():
        return profiles

    section = None
    data = {}
    sections = []
    for raw_line in ini_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            if section is not None:
                sections.append((section, data))
            section = line[1:-1]
            data = {}
        else:
            if "=" in line:
                k, v = line.split("=", 1)
                data[k.strip()] = v.strip()
    if section is not None:
        sections.append((section, data))

    for name, data in sections:
        if not name.startswith("Profile"):
            continue
        path_val = data.get("Path")
        if not path_val:
            continue
        is_relative = data.get("IsRelative", "1") == "1"
        full_path = (root / path_val) if is_relative else Path(path_val)
        profiles.append({
            "name": data.get("Name", name),
            "path": full_path,
            "is_default": data.get("Default", "0") == "1",
        })
    return profiles


# --------------------------------------------------------------------------
# Profile lock state (deny-first gate for every write operation)
# --------------------------------------------------------------------------

class LockState(Enum):
    """Whether Firefox currently holds the selected profile."""

    FREE = "free"          # verified not in use - writes permitted
    LOCKED = "locked"      # Firefox has this profile open - writes refused
    UNKNOWN = "unknown"    # could not determine - writes refused (fail closed)


def profile_lock_state(profile_path: Path) -> LockState:
    """Is *this* profile currently open in Firefox?

    Firefox guards each profile with a lock file, so this is the correct
    granularity: process-name matching cannot tell you which profile is in
    use, and would wrongly block cleaning profile B while profile A is open.

    Windows keeps 'parent.lock' on disk permanently and holds an exclusive
    handle while running, so presence proves nothing - the test is whether
    the file can be opened for writing. POSIX uses an fcntl advisory lock on
    '.parentlock', so the test is whether that lock can be taken.

    Anything ambiguous returns UNKNOWN, which callers must treat as refusal.
    """
    try:
        if not profile_path.is_dir():
            return LockState.UNKNOWN
    except OSError:
        return LockState.UNKNOWN

    if sys.platform.startswith("win"):
        lock_file = profile_path / "parent.lock"
        try:
            if not lock_file.exists():
                # Never launched, or cleanly removed - nothing holds it.
                return LockState.FREE
            with open(lock_file, "a+b"):
                return LockState.FREE
        except PermissionError:
            return LockState.LOCKED
        except OSError:
            return LockState.UNKNOWN

    lock_file = profile_path / ".parentlock"
    try:
        if not lock_file.exists():
            # A live POSIX profile also has a 'lock' symlink; trust it if present.
            if (profile_path / "lock").is_symlink():
                return LockState.LOCKED
            return LockState.FREE
        if fcntl is None:
            return LockState.UNKNOWN
        with open(lock_file, "a+b") as fh:
            try:
                fcntl.lockf(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (BlockingIOError, PermissionError, OSError):
                return LockState.LOCKED
            try:
                fcntl.lockf(fh, fcntl.LOCK_UN)
            except OSError:
                pass
            return LockState.FREE
    except PermissionError:
        return LockState.LOCKED
    except OSError:
        return LockState.UNKNOWN


def require_profile_writable(profile_path: Path):
    """Raise unless this profile is verifiably not in use.

    Called by every destructive primitive rather than trusting the caller.
    The GUI's ensure_writable() check happens when the button is clicked,
    but cleanup can run for minutes afterwards - a full backup on a large
    profile is slow - and Firefox may be launched in that window. A check
    at the top of the sequence says nothing about the state at the bottom
    of it, so each primitive re-establishes the invariant immediately
    before it writes.

    This makes the GUI check a convenience and this function the actual
    boundary.
    """
    state = profile_lock_state(profile_path)
    if state is not LockState.FREE:
        raise RuntimeError(describe_lock_state(state))


def describe_lock_state(state: LockState) -> str:
    if state is LockState.FREE:
        return "Profile is not in use."
    if state is LockState.LOCKED:
        return (
            "Firefox currently has this profile open.\n\n"
            "Close Firefox completely, then try again. On Windows, check Task "
            "Manager and end every leftover firefox.exe process."
        )
    return (
        "Could not verify whether Firefox has this profile open.\n\n"
        "Refusing to continue rather than risk corrupting the profile "
        "database. Close Firefox completely and try again."
    )


# --------------------------------------------------------------------------
# Profile validation
# --------------------------------------------------------------------------

# prefs.js is the load-bearing marker: every Firefox profile has one, and
# nothing else does. permissions.sqlite is deliberately NOT required - a
# freshly created profile has not written one yet.
PROFILE_MARKER = "prefs.js"
PROFILE_CORROBORATING = ("times.json", "places.sqlite", "cookies.sqlite")

# Marker written at the root of archives this tool produces, so restore can
# tell "a backup we made" from "a zip that happens to be profile-shaped".
BACKUP_MANIFEST_NAME = "ffpm-backup.json"
BACKUP_FORMAT = "firefox-profile-manager-backup"
BACKUP_FORMAT_VERSION = 1

# Accepted as corroborating evidence that an archive holds a real profile.
# Broader than PROFILE_CORROBORATING because a backup legitimately captures
# artefacts a live folder check would not rely on.
ARCHIVE_CORROBORATING = (
    "times.json", "places.sqlite", "cookies.sqlite",
    "compatibility.ini", "extensions.json", "permissions.sqlite",
)


def validate_profile(profile_path: Path):
    """Return (ok, reason). Guards against acting on a non-profile folder."""
    try:
        if not profile_path.is_dir():
            return False, f"Not a folder: {profile_path}"
        if not (profile_path / PROFILE_MARKER).is_file():
            return False, (
                f"'{profile_path}' does not look like a Firefox profile "
                f"(no {PROFILE_MARKER})."
            )
        if not any((profile_path / n).exists() for n in PROFILE_CORROBORATING):
            return False, (
                f"'{profile_path}' has {PROFILE_MARKER} but none of "
                f"{', '.join(PROFILE_CORROBORATING)} - refusing to treat it "
                "as a Firefox profile."
            )
    except OSError as e:
        return False, f"Could not inspect '{profile_path}': {e}"
    return True, "Looks like a Firefox profile."


# --------------------------------------------------------------------------
# Backup / restore
# --------------------------------------------------------------------------

class BackupVerificationError(Exception):
    """Raised when a written archive fails its own manifest check."""


class IncompleteBackupError(BackupVerificationError):
    """Raised when source files could not be read into the archive.

    Distinct from BackupVerificationError because the two claims differ:
    'every entry in this archive is intact' is not 'every file in the
    profile is in this archive'. A user reading 'verified' will assume the
    second, so an incomplete backup must never be presented as verified.
    """


class BackupResult(NamedTuple):
    zip_path: Path
    written: int
    skipped: int
    uncompressed: int
    skipped_files: tuple = ()

    @property
    def complete(self) -> bool:
        return self.skipped == 0


def unique_path(path: Path) -> Path:
    """A path that does not exist yet, appending -1, -2, ... if needed.

    Timestamps are only second-resolution, so two operations on the same
    profile within one second would otherwise collide - and for a backup
    opened with mode 'w' that means silently replacing the first archive.
    """
    if not path.exists():
        return path
    stem, suffix, parent = path.stem, path.suffix, path.parent
    for n in range(1, 1000):
        candidate = parent / f"{stem}-{n}{suffix}"
        if not candidate.exists():
            return candidate
    raise OSError(f"Could not find an unused name based on {path}")


def verify_backup(zip_path: Path, expected_names):
    """Confirm the archive is readable, CRC-clean, and internally complete.

    Verification is against a manifest recorded while writing, not against a
    hardcoded list of 'important' files: logins.json and key4.db legitimately
    do not exist on a profile with no saved passwords, and an alert that
    fires on a healthy profile just teaches the user to ignore alerts.

    NOTE: this can only attest to what reached the archive. Files that could
    not be read never enter the manifest, so completeness of the *source* is
    a separate check - see BackupResult.complete.
    """
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            bad = zf.testzip()
            if bad is not None:
                raise BackupVerificationError(f"Corrupt entry in backup: {bad}")
            actual = {i.filename for i in zf.infolist()}
    except zipfile.BadZipFile as e:
        raise BackupVerificationError(f"Backup is not a readable zip: {e}") from e
    except OSError as e:
        raise BackupVerificationError(f"Backup could not be reopened: {e}") from e

    missing = set(expected_names) - actual
    if missing:
        sample = ", ".join(sorted(missing)[:5])
        raise BackupVerificationError(
            f"{len(missing)} file(s) recorded during backup are missing from "
            f"the archive (e.g. {sample})."
        )
    return len(actual)


def backup_profile(profile_path: Path, dest_dir: Path, log,
                   require_complete: bool = False) -> BackupResult:
    """Zip a profile and verify the result.

    require_complete=True additionally refuses to return a partial backup.
    Used for the automatic pre-cleanup safety copy, where proceeding to
    delete things on the strength of an incomplete safety net is the exact
    situation the backup exists to prevent.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_path = unique_path(dest_dir / f"{profile_path.name}_backup_{stamp}.zip")
    log(f"Backing up '{profile_path}' -> '{zip_path}' ...")

    manifest = []
    skipped_files = []
    uncompressed = 0
    with zipfile.ZipFile(zip_path, "x", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(BACKUP_MANIFEST_NAME, json.dumps({
            "format": BACKUP_FORMAT,
            "format_version": BACKUP_FORMAT_VERSION,
            "profile": profile_path.name,
            "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tool": f"{APP_TITLE} {__version__}",
        }, indent=2))
        for root, _dirs, files in os.walk(profile_path):
            for fname in files:
                full = Path(root) / fname
                # skip giant/irrelevant cache subfolders to keep backups fast
                if "cache2" in full.parts or "startupCache" in full.parts:
                    continue
                arcname = full.relative_to(profile_path.parent)
                try:
                    size = full.stat().st_size
                    zf.write(full, arcname)
                    manifest.append(arcname.as_posix())
                    uncompressed += size
                except (PermissionError, OSError) as e:
                    skipped_files.append(full.name)
                    log(f"  (skipped {full.name}: {e})")

    if not manifest:
        raise BackupVerificationError(
            f"Nothing was backed up from '{profile_path}' - refusing to "
            "present an empty archive as a safety net."
        )

    verify_backup(zip_path, manifest)
    result = BackupResult(zip_path, len(manifest), len(skipped_files),
                          uncompressed, tuple(skipped_files))

    if skipped_files:
        sample = ", ".join(skipped_files[:5])
        log(f"ARCHIVE VERIFIED ({len(manifest)} entries intact) but BACKUP "
            f"INCOMPLETE: {len(skipped_files)} source file(s) could not be "
            f"read ({sample}).")
        if require_complete:
            raise IncompleteBackupError(
                f"The safety backup is incomplete: {len(skipped_files)} file(s) "
                f"could not be read ({sample}).\n\n"
                "Cleanup has been cancelled. This usually means Firefox is "
                "still running and holding those files."
            )
    else:
        log(f"Archive verified and backup complete: {len(manifest)} files, "
            f"saved to {zip_path}")
    return result


class ArchiveRejected(Exception):
    """Raised when a backup archive fails validation - nothing is written."""


def _is_unsafe_member(name: str) -> bool:
    """True if a zip entry name escapes the extraction root ('Zip Slip')."""
    if not name or name in (".", ".."):
        return True
    if name.startswith("/") or name.startswith("\\"):
        return True
    # Windows drive-absolute ('C:foo') and UNC paths
    if re.match(r"^[A-Za-z]:", name) or name.startswith("\\\\"):
        return True
    parts = re.split(r"[\\/]", name)
    return any(p == ".." for p in parts)


def inspect_backup_archive(zip_path: Path, expected_profile: str | None = None):
    """Validate an archive and summarise it. Raises ArchiveRejected on danger.

    Restore accepts any file the user picks, so this cannot assume the
    archive is one of ours. Every entry is checked for path traversal,
    absolute paths, and symlinks before a single byte is written, and the
    archive must describe exactly one top-level profile folder.
    """
    try:
        zf = zipfile.ZipFile(zip_path, "r")
    except (zipfile.BadZipFile, OSError) as e:
        raise ArchiveRejected(f"Not a readable zip file: {e}") from e

    with zf:
        infos = zf.infolist()
        if not infos:
            raise ArchiveRejected("Archive is empty.")

        tops = set()
        manifest = None
        for info in infos:
            name = info.filename
            if _is_unsafe_member(name):
                raise ArchiveRejected(
                    "Archive contains an entry that would write outside the "
                    f"profile folder: {name!r}\n\nRefusing to restore. Only "
                    "use backup files created by this tool."
                )
            # Reject symlinks: mode 0o120000 in the high bits of external_attr
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise ArchiveRejected(
                    f"Archive contains a symbolic link ({name!r}), which "
                    "could redirect writes outside the profile. Refusing."
                )
            if name == BACKUP_MANIFEST_NAME:
                try:
                    manifest = json.loads(zf.read(name).decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError, OSError):
                    manifest = None
                continue
            tops.add(re.split(r"[\\/]", name)[0])

        if len(tops) != 1:
            raise ArchiveRejected(
                "Archive should contain exactly one profile folder, found "
                f"{len(tops)}: {', '.join(sorted(tops))}"
            )
        top = tops.pop()

        if expected_profile is not None and top.casefold() != expected_profile.casefold():
            raise ArchiveRejected(
                f"This backup is of profile '{top}', but the selected profile "
                f"is '{expected_profile}'.\n\nRestoring it would write to the "
                "wrong profile. Select the matching profile first."
            )

        # Names relative to the profile folder. Matching on suffix was wrong:
        # 'junk/prefs.js'.endswith('prefs.js') is True, so an archive with
        # everything buried in a subfolder passed validation while not being
        # a viable profile - Firefox requires prefs.js at the profile root.
        relative = {
            re.split(r"[\\/]", i.filename, 1)[-1].replace("\\", "/")
            for i in infos if i.filename != BACKUP_MANIFEST_NAME
        }
        root_names = {n for n in relative if "/" not in n}

        def has(*wanted):
            """True if any of these sit at the profile root."""
            return any(n in root_names for n in wanted)

        # Structural safety is not enough: an archive can be perfectly
        # contained and still not be a Firefox profile. Restoring replaces
        # the profile wholesale, so a zip holding only 'hello.txt' would
        # destroy a working profile without a single unsafe path in it.
        if not has(PROFILE_MARKER):
            raise ArchiveRejected(
                f"Archive does not contain {PROFILE_MARKER} at the top level "
                "of the profile folder, and does not appear to be a Firefox "
                "profile backup.\n\nRefusing to replace a profile with it."
            )
        if not has(*ARCHIVE_CORROBORATING):
            raise ArchiveRejected(
                f"Archive contains {PROFILE_MARKER} but none of "
                f"{', '.join(ARCHIVE_CORROBORATING)}.\n\nIt does not look "
                "like a complete Firefox profile backup; refusing to restore."
            )

        return {
            "top_level": top,
            "entries": len(infos),
            "uncompressed": sum(i.file_size for i in infos),
            "manifest": manifest,
            "is_ours": bool(manifest and manifest.get("format") == BACKUP_FORMAT),
            "has_prefs": has("prefs.js"),
            "has_places": has("places.sqlite"),
            "has_permissions": has("permissions.sqlite"),
            "has_logins": has("logins.json", "key4.db"),
            "has_extensions": has("extensions.json"),
            "has_cookies": has("cookies.sqlite"),
            # Session data legitimately lives in a subfolder as well as at
            # the root, so this one stays a whole-archive check.
            "has_session": any("sessionstore" in n for n in relative),
        }


def describe_backup_archive(info: dict) -> str:
    """Human-readable dry-run summary shown before an overwrite."""
    def mark(present):
        return "yes" if present else "not in this backup"

    mb = info["uncompressed"] / (1024 * 1024)
    origin = ("created by this tool" if info.get("is_ours")
              else "NOT created by this tool - contents verified as profile-shaped")
    return (
        f"Profile folder:  {info['top_level']}\n"
        f"Source:          {origin}\n"
        f"Files:           {info['entries']:,}  ({mb:,.1f} MB uncompressed)\n\n"
        f"Bookmarks & history:   {mark(info['has_places'])}\n"
        f"Saved logins:          {mark(info['has_logins'])}\n"
        f"Settings (prefs.js):   {mark(info['has_prefs'])}\n"
        f"Site permissions:      {mark(info['has_permissions'])}\n"
        f"Extensions:            {mark(info['has_extensions'])}\n"
        f"Cookies:               {mark(info['has_cookies'])}\n"
        f"Saved session/tabs:    {mark(info['has_session'])}"
    )


def restore_profile(zip_path: Path, profile_path: Path, log):
    """Replace the profile with the archive's contents.

    This is a replacement, not a merge. The old extractall() overwrote
    matching files but left behind anything created since the backup, so a
    'restore' could not actually undo an infection. Here the archive is
    staged in full, then swapped into place, and the previous profile is
    kept alongside as '<name>.pre-restore-<stamp>' so the restore itself
    remains reversible.
    """
    info = inspect_backup_archive(zip_path, expected_profile=profile_path.name)

    require_profile_writable(profile_path)

    parent = profile_path.parent
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    staging = Path(tempfile.mkdtemp(prefix="ffpm_restore_", dir=str(parent)))
    log(f"Restoring '{zip_path}' -> '{profile_path}' ({info['entries']} entries) ...")

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            root = staging.resolve()
            for member in zf.infolist():
                if member.filename == BACKUP_MANIFEST_NAME:
                    continue
                target = (staging / member.filename).resolve()
                # Belt and braces: verify containment after resolution too.
                if not target.is_relative_to(root):
                    raise ArchiveRejected(
                        f"Entry escapes the extraction root: {member.filename!r}"
                    )
                zf.extract(member, staging)

        staged_profile = staging / info["top_level"]
        if not staged_profile.is_dir():
            raise ArchiveRejected("Archive did not contain the expected profile folder.")

        sidecar = unique_path(parent / f"{profile_path.name}.pre-restore-{stamp}")
        moved = False
        if profile_path.exists():
            os.rename(profile_path, sidecar)
            moved = True
        try:
            os.rename(staged_profile, profile_path)
        except OSError:
            if moved:  # put the original back before surfacing the failure
                os.rename(sidecar, profile_path)
            raise

        log(f"Restore complete. Previous profile kept at: {sidecar}")
        return sidecar
    finally:
        shutil.rmtree(staging, ignore_errors=True)


# --------------------------------------------------------------------------
# Cleaning
# --------------------------------------------------------------------------

def match_heuristics(origin: str):
    """Every heuristic that fires for this origin, in ID order."""
    return [h for h in HEURISTICS if h.test(origin or "")]


def should_preselect(origin: str) -> bool:
    """Should this row arrive pre-ticked for deletion?

    Deliberately stricter than is_suspicious():

    - advisory rules such as H-05 mark a row for human attention without
      nominating it for deletion;
    - known CDN and hosting providers are never pre-ticked, whichever rule
      fired. H-02 ('long hex-looking subdomain') matches real hostnames like
      'abc123def456.b-cdn.net', and a pre-ticked row is one careless click
      from deleting a permission the user actually wanted.

    Exempt hosts are still FLAGGED and still listed - the user can tick them
    deliberately. This only removes them from bulk pre-selection.
    """
    matches = match_heuristics(origin)
    if any(h.tier == TIER_NAMED_THREAT for h in matches):
        return True
    if is_exempt_host(hostname_from_origin(origin)):
        return False
    shape_signals = sum(1 for h in matches
                        if h.tier in (TIER_SHAPE, TIER_ADVISORY))
    return shape_signals >= SHAPE_SIGNALS_REQUIRED


def is_suspicious(origin: str) -> bool:
    return bool(match_heuristics(origin))


def format_heuristics(matches) -> str:
    """'H-01, H-02' - compact form for list rows and log lines."""
    return ", ".join(h.id for h in matches)


class SchemaStatus(Enum):
    """Whether permissions.sqlite matches the layout this tool can edit."""

    OK = "ok"                    # moz_perms with the columns we need
    NO_DATABASE = "no_database"  # profile has never written one
    UNSUPPORTED = "unsupported"  # table/columns changed - read-only
    UNREADABLE = "unreadable"    # corrupt, locked, or not sqlite - read-only


# The columns this tool reads and keys deletions on. If a future Firefox
# renames or drops any of these, we degrade to read-only rather than issuing
# DELETE statements against a schema we do not understand.
REQUIRED_PERMS_COLUMNS = {"id", "origin", "type"}
PERMS_TABLE = "moz_perms"


# SQLite sidecars. In WAL mode recent writes live in -wal, not the main
# file, so copying only the database yields a stale snapshot - a scan run
# while Firefox is open could miss the very permission it is looking for
# and report the profile clean.
SQLITE_SIDECARS = ("-wal", "-shm")


def has_live_wal(db_path: Path) -> bool:
    """True if a non-empty write-ahead log sits beside this database."""
    wal = Path(str(db_path) + "-wal")
    try:
        return wal.is_file() and wal.stat().st_size > 0
    except OSError:
        return False


def _copy_for_read(db_path: Path):
    """Copy a sqlite database and its sidecars to a temp dir for reading.

    The copy lands outside the profile: a crash mid-read must not leave
    stray files inside the profile folder, where the next backup would
    sweep them up.

    The -wal and -shm files are copied alongside, so SQLite can recover
    committed-but-uncheckpointed transactions from the copy and we see the
    same data Firefox would.
    """
    tmp_dir = Path(tempfile.mkdtemp(prefix="ffpm_read_"))
    tmp_copy = tmp_dir / db_path.name
    shutil.copy2(db_path, tmp_copy)
    for suffix in SQLITE_SIDECARS:
        sidecar = Path(str(db_path) + suffix)
        if sidecar.exists():
            try:
                shutil.copy2(sidecar, Path(str(tmp_copy) + suffix))
            except OSError:
                pass  # a missing sidecar is recoverable; a missing db is not
    return tmp_dir, tmp_copy


def inspect_permissions_schema(profile_path: Path) -> SchemaStatus:
    db_path = profile_path / "permissions.sqlite"
    if not db_path.exists():
        return SchemaStatus.NO_DATABASE
    tmp_dir = None
    try:
        tmp_dir, tmp_copy = _copy_for_read(db_path)
        conn = sqlite3.connect(str(tmp_copy))
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                (PERMS_TABLE,),
            )
            if cur.fetchone() is None:
                return SchemaStatus.UNSUPPORTED
            cur.execute(f"PRAGMA table_info({PERMS_TABLE})")
            columns = {row[1] for row in cur.fetchall()}
            if not REQUIRED_PERMS_COLUMNS.issubset(columns):
                return SchemaStatus.UNSUPPORTED
            return SchemaStatus.OK
        finally:
            conn.close()
    except sqlite3.DatabaseError:
        return SchemaStatus.UNREADABLE
    except OSError:
        return SchemaStatus.UNREADABLE
    finally:
        if tmp_dir is not None:
            shutil.rmtree(tmp_dir, ignore_errors=True)


def describe_schema_status(status: SchemaStatus) -> str:
    return {
        SchemaStatus.OK: "",
        SchemaStatus.NO_DATABASE:
            "This profile has no permissions.sqlite yet - no sites have been "
            "granted or denied permissions.",
        SchemaStatus.UNSUPPORTED:
            "permissions.sqlite uses a layout this tool does not recognise "
            "(Firefox may have changed it). Showing read-only; permission "
            "deletion is disabled to avoid damaging the database.",
        SchemaStatus.UNREADABLE:
            "permissions.sqlite could not be read (corrupt, or still in use). "
            "Permission deletion is disabled.",
    }[status]


def read_notification_permissions(profile_path: Path):
    """Return list of (rowid, origin, perm_type) for notification-ish perms."""
    db_path = profile_path / "permissions.sqlite"
    results = []
    if inspect_permissions_schema(profile_path) is not SchemaStatus.OK:
        return results
    tmp_dir = None
    try:
        tmp_dir, tmp_copy = _copy_for_read(db_path)
        conn = sqlite3.connect(str(tmp_copy))
        try:
            cur = conn.cursor()
            cur.execute(f"SELECT id, origin, type FROM {PERMS_TABLE}")
            for rowid, origin, ptype in cur.fetchall():
                if ptype and "notification" in str(ptype).lower():
                    results.append((rowid, origin, ptype))
        finally:
            conn.close()
    except (sqlite3.DatabaseError, OSError):
        return []
    finally:
        if tmp_dir is not None:
            shutil.rmtree(tmp_dir, ignore_errors=True)
    return results


def delete_permission_rows(profile_path: Path, rowids, log):
    """Delete permission rows. Refuses on any unrecognised schema."""
    db_path = profile_path / "permissions.sqlite"
    if not rowids:
        return 0

    status = inspect_permissions_schema(profile_path)
    if status is not SchemaStatus.OK:
        raise RuntimeError(
            "Refusing to modify permissions.sqlite: "
            + describe_schema_status(status)
        )

    require_profile_writable(profile_path)

    conn = sqlite3.connect(str(db_path))
    try:
        cur = conn.cursor()
        cur.executemany(
            f"DELETE FROM {PERMS_TABLE} WHERE id = ?", [(r,) for r in rowids]
        )
        removed = conn.total_changes
        conn.commit()
    finally:
        conn.close()
    log(f"Removed {removed} notification permission entr{'y' if removed == 1 else 'ies'}.")
    return removed


def clear_session_restore(profile_path: Path, log):
    """Remove stored session so a malicious tab doesn't reopen.

    Deletion is VERIFIED rather than assumed. rmtree(ignore_errors=True)
    swallows failures, so a locked or permission-denied sessionstore folder
    would survive while the tool reported success - and this is precisely
    the data whose survival brings the scam popups straight back on the next
    launch. Failure here is therefore loud, not a warning.
    """
    require_profile_writable(profile_path)
    removed = 0
    failed = []
    sessionstore_dir = profile_path / "sessionstore-backups"
    for candidate in [profile_path / "sessionstore.jsonlz4", sessionstore_dir]:
        if not candidate.exists():
            continue
        try:
            if candidate.is_file():
                candidate.unlink()
            else:
                shutil.rmtree(candidate)
        except OSError as e:
            failed.append(f"{candidate.name} ({e})")
            continue
        if candidate.exists():      # rmtree can fail partially and silently
            failed.append(f"{candidate.name} (still present after deletion)")
            continue
        removed += 1

    if failed:
        raise RuntimeError(
            "Could not remove saved session data:\n  "
            + "\n  ".join(failed)
            + "\n\nThe scam tab may reopen when Firefox next starts. Close "
              "Firefox completely and try again."
        )
    log(f"Cleared session restore data ({removed} item(s)).")
    return removed


def matching_local_cache_dirs(profile_path: Path):
    """Local-cache folders belonging to exactly this profile.

    Firefox names the LOCALAPPDATA cache folder identically to the roaming
    profile folder (e.g. 'q1w2e3r4.default-release'), so the match must be
    exact. An earlier prefix match on the pre-dot token was unsafe: profile
    ids are not prefix-free, so cleaning 'abc.default' would also have wiped
    the cache of an unrelated 'abcdef.default-release' sitting beside it.

    Comparison is case-insensitive because Windows paths are, but it is still
    a whole-name equality test, never a prefix test.
    """
    lroot = local_cache_root()
    if not lroot or not lroot.exists():
        return []
    target = profile_path.name.casefold()
    return [sub for sub in lroot.iterdir()
            if sub.is_dir() and sub.name.casefold() == target]


def clear_cache(profile_path: Path, log):
    """Delete cache folders for this profile only.

    Unlike session data, a surviving cache folder is not a security problem
    - it costs disk space and nothing else - so failure is reported as a
    warning rather than raised. It is still REPORTED: counting a folder as
    cleared without checking would make the log untrue.
    """
    require_profile_writable(profile_path)
    cleared = 0
    failed = []

    targets = [profile_path / n for n in ("cache2", "startupCache", "shader-cache")]
    # Windows keeps the big cache separately under LOCALAPPDATA
    targets += [sub / "cache2" for sub in matching_local_cache_dirs(profile_path)]

    for c in targets:
        if not c.exists():
            continue
        try:
            shutil.rmtree(c)
        except OSError as e:
            failed.append(f"{c} ({e})")
            continue
        if c.exists():
            failed.append(f"{c} (still present after deletion)")
            continue
        cleared += 1

    log(f"Cleared {cleared} cache folder(s).")
    for entry in failed:
        log(f"  WARNING: could not remove cache folder {entry}")
    if failed:
        log(f"  {len(failed)} cache folder(s) could not be removed. This uses "
            "disk space but is otherwise harmless.")
    return cleared, tuple(failed)


# Firefox's addon signedState values (toolkit/mozapps/extensions).
SIGNED_STATES = {
    -2: "broken signature",
    -1: "unknown",
    0: "UNSIGNED",
    1: "preliminarily signed",
    2: "signed",
    3: "system add-on",
    4: "privileged",
}


def list_extensions(profile_path: Path):
    """Inventory add-ons, including signing state - one rogue extension is
    often the actual culprit, and unsigned is the strongest single signal."""
    ext_file = profile_path / "extensions.json"
    exts = []
    if not ext_file.exists():
        return exts
    try:
        data = json.loads(ext_file.read_text(encoding="utf-8", errors="ignore"))
    except (json.JSONDecodeError, OSError):
        return exts

    for addon in data.get("addons", []):
        signed_state = addon.get("signedState", -1)
        install_ms = addon.get("installDate")
        installed = ""
        if isinstance(install_ms, (int, float)) and install_ms > 0:
            try:
                installed = datetime.fromtimestamp(install_ms / 1000).strftime("%Y-%m-%d")
            except (OverflowError, OSError, ValueError):
                installed = ""
        exts.append({
            "id": addon.get("id", "?"),
            "name": (addon.get("defaultLocale") or {}).get("name", addon.get("id", "?")),
            "active": addon.get("active", False),
            "type": addon.get("type", "extension"),
            "signed_state": signed_state,
            "signed_label": SIGNED_STATES.get(signed_state, "unknown"),
            "is_unsigned": signed_state == 0,
            "is_system": signed_state in (3, 4) or addon.get("location") == "app-system-defaults",
            "installed": installed,
            "permissions": (addon.get("userPermissions") or {}).get("permissions", []),
        })
    return exts


def read_pref(profile_path: Path, name: str):
    """Read a single user_pref() from prefs.js. Returns None if unset.

    Deliberately a line-scanner, not a JS parser: prefs.js is machine-written
    one-pref-per-line, and anything cleverer would be more to go wrong.
    """
    prefs = profile_path / "prefs.js"
    if not prefs.exists():
        return None
    pattern = re.compile(
        r'^\s*user_pref\(\s*"' + re.escape(name) + r'"\s*,\s*(.+?)\s*\)\s*;\s*$'
    )
    try:
        for line in prefs.read_text(encoding="utf-8", errors="ignore").splitlines():
            m = pattern.match(line)
            if not m:
                continue
            raw = m.group(1).strip()
            if raw == "true":
                return True
            if raw == "false":
                return False
            if raw.startswith('"') and raw.endswith('"'):
                return raw[1:-1]
            try:
                return int(raw)
            except ValueError:
                return raw
    except OSError:
        return None
    return None


def session_restore_enabled(profile_path: Path) -> bool:
    """browser.startup.page == 3 means 'restore previous session'.

    This is what lets a scam tab resurrect itself after cleanup, so it is
    called out separately in the health report.
    """
    return read_pref(profile_path, "browser.startup.page") == 3


def directory_size(path: Path) -> int:
    total = 0
    if not path.exists():
        return 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += (Path(root) / f).stat().st_size
            except OSError:
                continue
    return total


def cache_size(profile_path: Path) -> int:
    """Bytes across every cache folder this tool would clear."""
    total = sum(directory_size(profile_path / n)
                for n in ("cache2", "startupCache", "shader-cache"))
    for sub in matching_local_cache_dirs(profile_path):
        total += directory_size(sub / "cache2")
    return total


def human_size(num_bytes: int) -> str:
    size = float(num_bytes)
    if size < 1024:
        return f"{int(size)} B"
    for unit in ("KB", "MB", "GB"):
        size /= 1024
        if size < 1024 or unit == "GB":
            return f"{size:,.1f} {unit}"
    return f"{size:,.1f} GB"


# --------------------------------------------------------------------------
# Firefox troubleshooting launcher
# --------------------------------------------------------------------------

def find_firefox_binary() -> Path | None:
    """Locate the Firefox executable, for launching troubleshooting mode."""
    found = shutil.which("firefox")
    if found:
        return Path(found)

    candidates = []
    if sys.platform.startswith("win"):
        for var in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
            base = os.environ.get(var)
            if base:
                candidates.append(Path(base) / "Mozilla Firefox" / "firefox.exe")
    elif sys.platform == "darwin":
        candidates.append(Path("/Applications/Firefox.app/Contents/MacOS/firefox"))
    else:
        candidates += [Path("/usr/bin/firefox"), Path("/usr/local/bin/firefox"),
                       Path("/snap/bin/firefox")]

    for c in candidates:
        if c.exists():
            return c
    return None


def launch_troubleshoot_mode(log):
    """Start Firefox with add-ons disabled.

    This is the honest limit of what a third-party tool should do about
    'Refresh Firefox': there is no supported command line for the refresh
    itself, so reimplementing it would mean rebuilding a profile by hand and
    owning the risk of getting it wrong. The -safe-mode dialog offers both
    Troubleshoot Mode and Refresh, so Mozilla owns the destructive part.
    """
    exe = find_firefox_binary()
    if exe is None:
        raise RuntimeError(
            "Could not find the Firefox program on this computer.\n\n"
            "Start Firefox yourself and use the menu > Help > "
            "Troubleshoot Mode instead."
        )
    log(f"Launching {exe} -safe-mode ...")
    subprocess.Popen([str(exe), "-safe-mode"])
    return exe


def read_firefox_version(profile_path: Path) -> str:
    """Best-effort Firefox build that last used this profile."""
    ini = profile_path / "compatibility.ini"
    if not ini.exists():
        return "unknown"
    try:
        for line in ini.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.strip().lower().startswith("lastversion="):
                return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return "unknown"


def build_health_report(profile_path: Path, profile_count: int) -> dict:
    """One-screen assessment of a profile, plus plain-language advice.

    Read-only. Nothing here modifies the profile; it exists so someone who
    is not a developer can see what is wrong in a single glance.
    """
    schema = inspect_permissions_schema(profile_path)
    perms = read_notification_permissions(profile_path) if schema is SchemaStatus.OK else []
    flagged = [(rid, o, t) for rid, o, t in perms if is_suspicious(o)]
    extensions = list_extensions(profile_path)
    unsigned = [e for e in extensions if e["is_unsigned"] and not e["is_system"]]
    restore_on = session_restore_enabled(profile_path)
    lock = profile_lock_state(profile_path)

    recommendations = []
    if flagged:
        recommendations.append(
            f"Remove {len(flagged)} flagged notification permission(s) on the Clean tab."
        )
    if restore_on:
        recommendations.append(
            "Turn off 'Restore previous session' (Settings > General) so a "
            "malicious tab cannot reopen itself."
        )
    if unsigned:
        names = ", ".join(e["name"] for e in unsigned[:3])
        recommendations.append(
            f"Review {len(unsigned)} unsigned extension(s): {names}. "
            "Remove unfamiliar ones from about:addons."
        )
    if schema is SchemaStatus.UNSUPPORTED:
        recommendations.append(
            "This tool cannot read this profile's permissions database; check "
            "notification permissions manually in Firefox settings."
        )
    if lock is not LockState.FREE:
        recommendations.append("Close Firefox completely before cleaning or restoring.")
    if has_live_wal(profile_path / "permissions.sqlite"):
        recommendations.append(
            "The permission database has unwritten changes pending. Close "
            "Firefox and scan again for a definitive result."
        )
    if not recommendations:
        recommendations.append("Nothing obviously wrong with this profile.")

    return {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "profile_name": profile_path.name,
        "profile_path": str(profile_path),
        "firefox_version": read_firefox_version(profile_path),
        "profile_count": profile_count,
        "lock_state": lock,
        "schema": schema,
        "live_wal": has_live_wal(profile_path / "permissions.sqlite"),
        "permissions_total": len(perms),
        "permissions_flagged": len(flagged),
        "flagged_origins": [
            {"origin": o, "heuristics": format_heuristics(match_heuristics(o))}
            for _rid, o, _t in flagged
        ],
        "extensions_total": len(extensions),
        "extensions_active": sum(1 for e in extensions if e["active"]),
        "extensions_unsigned": len(unsigned),
        "unsigned_names": [e["name"] for e in unsigned],
        "session_restore": restore_on,
        "cache_bytes": cache_size(profile_path),
        "recommendations": recommendations,
    }


_LOCK_LABELS = {
    LockState.FREE: "no",
    LockState.LOCKED: "yes",
    # An inability to determine state must not be reported as a fact.
    LockState.UNKNOWN: "UNKNOWN (could not determine)",
}


def format_health_report(report: dict) -> str:
    lines = [
        f"{APP_TITLE} {__version__} - health report",
        f"Generated:  {report['generated']}",
        "",
        f"Profile:            {report['profile_name']}",
        f"Location:           {report['profile_path']}",
        f"Firefox version:    {report['firefox_version']}",
        f"Profiles on PC:     {report['profile_count']}",
        f"Profile in use:     {_LOCK_LABELS[report['lock_state']]}",
        "",
        f"Notification sites: {report['permissions_total']}",
        f"  flagged:          {report['permissions_flagged']}",
    ]
    for entry in report["flagged_origins"]:
        lines.append(f"    - {entry['origin']}  ({entry['heuristics']})")
    lines += [
        "",
        f"Extensions:         {report['extensions_total']} "
        f"({report['extensions_active']} active)",
        f"  unsigned:         {report['extensions_unsigned']}",
    ]
    for name in report["unsigned_names"]:
        lines.append(f"    - {name}")
    lines += [
        "",
        f"Restore session:    {'ENABLED' if report['session_restore'] else 'disabled'}",
        f"Cache:              {human_size(report['cache_bytes'])}",
        f"Pending DB writes:  {'yes' if report['live_wal'] else 'no'}",
        "",
        "Recommendations",
        "---------------",
    ]
    lines += [f"  {i}. {r}" for i, r in enumerate(report["recommendations"], 1)]
    return "\n".join(lines)


def build_permission_diff(perm_rows, selected_ids):
    """Per-row record of what is about to be removed, and on what grounds.

    'Removed 6 entries' is unauditable. This produces, for every permission
    the tool can see, the origin, whether it was selected for deletion, and
    which heuristics fired - so the decision can be reviewed after the fact.
    """
    selected = set(selected_ids)
    diff = []
    for rowid, origin, ptype in perm_rows:
        matches = match_heuristics(origin)
        diff.append({
            "id": rowid,
            "origin": origin,
            "type": ptype,
            "flagged": bool(matches),
            "heuristics": [{"id": h.id, "description": h.description} for h in matches],
            "action": "remove" if rowid in selected else "keep",
        })
    return diff


def format_permission_diff(diff) -> str:
    """Log-friendly rendering of the diff."""
    removing = [d for d in diff if d["action"] == "remove"]
    if not removing:
        return "No notification permissions selected for removal."
    lines = [f"Removing {len(removing)} notification permission(s):"]
    for d in removing:
        why = format_heuristics_from_diff(d) or "manually selected"
        lines.append(f"  - {d['origin']}  [{d['type']}]  ({why})")
    keeping = len(diff) - len(removing)
    lines.append(f"Keeping {keeping} permission(s).")
    return "\n".join(lines)


def format_heuristics_from_diff(entry) -> str:
    return ", ".join(h["id"] for h in entry["heuristics"])


def write_forensic_snapshot(profile_path: Path, dest_dir: Path, perm_rows,
                            selected_ids, log) -> Path:
    """Preserve evidence before cleanup, so 'what infected this?' is answerable.

    Everything here is read-only with respect to the profile. Written before
    any deletion, so the snapshot describes the machine as found.
    """
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    snap_dir = dest_dir / f"forensic_{profile_path.name}_{stamp}"
    snap_dir.mkdir(parents=True, exist_ok=True)

    diff = build_permission_diff(perm_rows, selected_ids)

    # Raw database copy - the primary artefact.
    db = profile_path / "permissions.sqlite"
    if db.exists():
        # Capture the sidecars too: without -wal the copy can omit exactly
        # the recent writes the snapshot exists to preserve.
        for src in [db] + [Path(str(db) + sfx) for sfx in SQLITE_SIDECARS]:
            if not src.exists():
                continue
            try:
                shutil.copy2(src, snap_dir / src.name)
            except OSError as e:
                log(f"  (could not copy {src.name}: {e})")

    extensions = list_extensions(profile_path)

    report = {
        "captured_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool": f"{APP_TITLE} {__version__} forensic snapshot",
        "profile": {
            "name": profile_path.name,
            "path": str(profile_path),
            "firefox_version": read_firefox_version(profile_path),
            "lock_state": profile_lock_state(profile_path).value,
            "permissions_schema": inspect_permissions_schema(profile_path).value,
        },
        "heuristics": [
            {"id": h.id, "description": h.description, "pattern": h.expression,
             "autoselect": h.autoselect}
            for h in HEURISTICS
        ],
        "notification_permissions": diff,
        "extensions": extensions,
        "summary": {
            "permissions_total": len(diff),
            "permissions_flagged": sum(1 for d in diff if d["flagged"]),
            "permissions_to_remove": sum(1 for d in diff if d["action"] == "remove"),
            "extensions_total": len(extensions),
            "extensions_active": sum(1 for e in extensions if e.get("active")),
        },
    }

    (snap_dir / "snapshot.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    # Plain-text companion, for pasting into a support conversation.
    lines = [
        f"{APP_TITLE} - forensic snapshot",
        f"Captured: {report['captured_utc']}",
        f"Profile:  {profile_path.name}  ({profile_path})",
        f"Firefox:  {report['profile']['firefox_version']}",
        "",
        format_permission_diff(diff),
        "",
        f"Extensions ({len(extensions)}):",
    ]
    for e in extensions:
        lines.append(f"  - {e['name']}  ({'active' if e['active'] else 'disabled'})  {e['id']}")
    (snap_dir / "snapshot.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    log(f"Forensic snapshot written to {snap_dir}")
    return snap_dir


# --------------------------------------------------------------------------
# Background work
# --------------------------------------------------------------------------

class Worker(QObject):
    """Runs one callable off the UI thread.

    Every operation here walks the filesystem - a large profile can take
    tens of seconds to zip or to size. Doing that on the UI thread makes
    Windows paint 'Not Responding', and the intended audience reasonably
    concludes the tool has crashed and kills it mid-write. That is a data
    integrity problem wearing a UX costume.

    The callable receives a log function; calling it emits `progress`, which
    is delivered on the UI thread by Qt's queued connections.
    """

    progress = pyqtSignal(str)
    finished = pyqtSignal(object)
    failed = pyqtSignal(str, str)   # message, exception class name

    def __init__(self, fn):
        super().__init__()
        self._fn = fn

    @pyqtSlot()
    def run(self):
        try:
            result = self._fn(self.progress.emit)
        except Exception as e:  # surfaced to the UI thread, never swallowed
            self.failed.emit(str(e), type(e).__name__)
            return
        self.finished.emit(result)


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_TITLE} {__version__}")
        self.resize(880, 640)

        self.profiles = []
        self.selected_profile_path: Path | None = None
        self._busy = False
        self._worker_refs = []      # keeps threads/workers alive while running
        self._action_buttons = []

        central = QWidget()
        self.setCentralWidget(central)
        outer = QVBoxLayout(central)

        # Profile picker row, shared across tabs
        picker_row = QHBoxLayout()
        picker_row.addWidget(QLabel("Firefox profile:"))
        self.profile_list = QListWidget()
        self.profile_list.setMaximumHeight(90)
        self.profile_list.currentRowChanged.connect(self.on_profile_selected)
        picker_row.addWidget(self.profile_list, 1)
        refresh_btn = QPushButton("Rescan profiles")
        refresh_btn.clicked.connect(self.load_profiles)
        self._register_action(refresh_btn)
        picker_row.addWidget(refresh_btn)
        outer.addLayout(picker_row)

        self.status_label = QLabel("")
        self.status_label.setObjectName("statusLabel")
        outer.addWidget(self.status_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setObjectName("progressBar")
        self.progress_bar.setRange(0, 0)      # indeterminate
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(4)
        self.progress_bar.setVisible(False)
        outer.addWidget(self.progress_bar)

        splitter = QSplitter(Qt.Orientation.Vertical)
        outer.addWidget(splitter, 1)

        self.tabs = QTabWidget()
        splitter.addWidget(self.tabs)

        self.log_box = QPlainTextEdit()
        self.log_box.setObjectName("logBox")
        self.log_box.setReadOnly(True)
        self.log_box.setMaximumBlockCount(2000)
        splitter.addWidget(self.log_box)
        splitter.setSizes([420, 180])

        self.tabs.addTab(self.build_health_tab(), "Health")
        self.tabs.addTab(self.build_backup_tab(), "Backup")
        self.tabs.addTab(self.build_clean_tab(), "Clean")
        self.tabs.addTab(self.build_restore_tab(), "Restore")

        self.default_backup_dir = Path.home() / "FirefoxProfileBackups"

        self.load_profiles()

    # ---- logging ----
    def log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_box.appendPlainText(f"[{ts}] {msg}")

    def refresh_status(self):
        """Recompute the advisory banner after an operation."""
        if not self.profiles:
            return
        state = (profile_lock_state(self.selected_profile_path)
                 if self.selected_profile_path else LockState.UNKNOWN)
        note = {
            LockState.FREE: "Selected profile is not in use.",
            LockState.LOCKED: "Selected profile is OPEN in Firefox - close it before cleaning or restoring.",
            LockState.UNKNOWN: "Could not determine whether the selected profile is in use.",
        }[state]
        self.status_label.setText(f"Found {len(self.profiles)} profile(s). {note}")

    # ---- profile handling ----
    def load_profiles(self):
        self.profile_list.clear()
        self.profiles = parse_profiles()
        if not self.profiles:
            self.status_label.setText("No Firefox profiles found on this machine.")
            self.log("No profiles.ini found, or it contains no profiles.")
            return
        for p in self.profiles:
            label = p["name"]
            if p["is_default"]:
                label += "  (default)"
            label += f"   -  {p['path']}"
            item = QListWidgetItem(label)
            self.profile_list.addItem(item)
        self.profile_list.setCurrentRow(0)
        self.refresh_status()
        self.log(f"Loaded {len(self.profiles)} profile(s). "
                 f"Firefox process detected: {firefox_is_running()}")

    def on_profile_selected(self, row: int):
        if 0 <= row < len(self.profiles):
            self.selected_profile_path = self.profiles[row]["path"]
            self.refresh_notification_list()
            self.refresh_extension_list()
            if hasattr(self, "health_view"):
                self.health_view.setPlainText("")
                self._health_report = None
                self.export_btn.setEnabled(False)

    def require_profile(self) -> Path | None:
        if not self.selected_profile_path:
            QMessageBox.warning(self, APP_TITLE, "Select a profile first.")
            return None
        return self.selected_profile_path

    def ensure_writable(self, profile: Path) -> bool:
        """Hard gate for every write operation. No override is offered.

        Corrupting a profile database is not a risk worth handing to the
        user as a Yes/No question - the failure mode is losing bookmarks and
        saved logins, and the fix (close Firefox) is trivial.
        """
        ok, reason = validate_profile(profile)
        if not ok:
            self.log(f"BLOCKED: {reason}")
            QMessageBox.critical(self, APP_TITLE, reason)
            return False

        state = profile_lock_state(profile)
        if state is not LockState.FREE:
            self.log(f"BLOCKED: profile lock state = {state.value}")
            box = QMessageBox(self)
            box.setWindowTitle(APP_TITLE)
            box.setIcon(QMessageBox.Icon.Critical)
            box.setText(describe_lock_state(state))
            retry = box.addButton("Retry", QMessageBox.ButtonRole.AcceptRole)
            box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
            box.exec()
            if box.clickedButton() is retry:
                return self.ensure_writable(profile)
            return False
        return True

    # ---- background task plumbing ----
    def run_task(self, fn, on_success, busy_message: str,
                 on_error=None, on_finally=None):
        """Run `fn(log)` on a worker thread and deliver results to the UI.

        Refuses to start a second task while one is running: these
        operations mutate the same profile, and overlapping a restore with a
        cleanup is not something to leave to timing.
        """
        if self._busy:
            QMessageBox.information(
                self, APP_TITLE,
                "Another operation is already running. Wait for it to finish."
            )
            return

        thread = QThread(self)
        worker = Worker(fn)
        worker.moveToThread(thread)

        # Hold explicit references: without them the worker and thread can be
        # garbage collected mid-run, which surfaces as a silent crash.
        self._worker_refs.append((thread, worker))

        def cleanup():
            thread.quit()
            thread.wait()
            self._set_busy(False)
            if (thread, worker) in self._worker_refs:
                self._worker_refs.remove((thread, worker))
            worker.deleteLater()
            thread.deleteLater()
            if on_finally:
                on_finally()

        def handle_success(result):
            cleanup()
            on_success(result)

        def handle_failure(message, exc_name):
            cleanup()
            self.log(f"ERROR ({exc_name}): {message}")
            if on_error:
                on_error(message, exc_name)
            else:
                QMessageBox.critical(self, APP_TITLE, message)

        worker.progress.connect(self.log)
        worker.finished.connect(handle_success)
        worker.failed.connect(handle_failure)
        thread.started.connect(worker.run)

        self._set_busy(True, busy_message)
        thread.start()

    def _set_busy(self, busy: bool, message: str = ""):
        self._busy = busy
        self.progress_bar.setVisible(busy)
        if busy:
            self.status_label.setText(message)
        for btn in self._action_buttons:
            btn.setEnabled(not busy)
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor) if busy \
            else QApplication.restoreOverrideCursor()

    def _register_action(self, button):
        """Track a button so it can be disabled while work is in flight."""
        self._action_buttons.append(button)
        return button

    # ---- Health tab ----
    def build_health_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.addWidget(QLabel(
            "A read-only summary of the selected profile: what has "
            "notification permission, what extensions are installed, and "
            "what is worth changing. Nothing here modifies anything."
        ))

        self.health_view = QPlainTextEdit()
        self.health_view.setObjectName("summaryBox")
        self.health_view.setReadOnly(True)
        self.health_view.setPlaceholderText(
            "Click 'Scan selected profile' to check this profile."
        )
        layout.addWidget(self.health_view, 1)

        row = QHBoxLayout()
        scan_btn = QPushButton("Scan selected profile")
        scan_btn.setObjectName("primaryButton")
        scan_btn.clicked.connect(self.run_health_scan)
        self._register_action(scan_btn)
        row.addWidget(scan_btn)

        self.export_btn = QPushButton("Save report to file...")
        self.export_btn.clicked.connect(self.export_health_report)
        self.export_btn.setEnabled(False)
        row.addWidget(self.export_btn)

        troubleshoot_btn = QPushButton("Launch Firefox troubleshooting options...")
        troubleshoot_btn.clicked.connect(self.run_troubleshoot_mode)
        row.addWidget(troubleshoot_btn)
        layout.addLayout(row)

        self._health_report = None
        return w

    def run_health_scan(self):
        profile = self.require_profile()
        if not profile:
            return
        ok, reason = validate_profile(profile)
        if not ok:
            self.log(f"BLOCKED: {reason}")
            QMessageBox.critical(self, APP_TITLE, reason)
            return
        count = len(self.profiles)

        def work(log):
            log("Scanning profile...")
            return build_health_report(profile, count)

        def done(report):
            self._health_report = report
            self.health_view.setPlainText(format_health_report(report))
            self.export_btn.setEnabled(True)
            self.log(
                f"Health scan: {report['permissions_flagged']} flagged permission(s), "
                f"{report['extensions_unsigned']} unsigned extension(s), "
                f"cache {human_size(report['cache_bytes'])}."
            )
            self.refresh_status()

        self.run_task(work, done, "Scanning profile...")

    def export_health_report(self):
        if not self._health_report:
            return
        stamp = datetime.now().strftime("%Y-%m-%d")
        default = str(self.default_backup_dir / f"FirefoxHealth_{stamp}.txt")
        f, _ = QFileDialog.getSaveFileName(
            self, "Save health report", default, "Text files (*.txt)")
        if not f:
            return
        try:
            Path(f).write_text(
                format_health_report(self._health_report) + "\n", encoding="utf-8")
            self.log(f"Health report saved to {f}")
            QMessageBox.information(self, APP_TITLE, f"Report saved to:\n{f}")
        except OSError as e:
            self.log(f"ERROR saving report: {e}")
            QMessageBox.critical(self, APP_TITLE, f"Could not save report:\n{e}")

    def run_troubleshoot_mode(self):
        if QMessageBox.question(
            self, APP_TITLE,
            "This starts Firefox with all extensions temporarily disabled, "
            "which helps work out whether an extension is causing the "
            "problem.\n\nThe window that appears also offers Firefox's own "
            "'Refresh Firefox' option. Refresh is Mozilla's feature, not this "
            "tool's - it rebuilds the profile and removes extensions and "
            "settings, so take a backup first if you intend to use it.\n\n"
            "Launch it now?"
        ) != QMessageBox.StandardButton.Yes:
            return
        try:
            launch_troubleshoot_mode(self.log)
        except Exception as e:
            self.log(f"ERROR launching troubleshoot mode: {e}")
            QMessageBox.warning(self, APP_TITLE, str(e))

    # ---- Backup tab ----
    def build_backup_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.addWidget(QLabel(
            "Creates a zip copy of the whole profile (bookmarks, passwords, "
            "settings, extensions...) so you have a safety net before cleaning."
        ))
        self.backup_dir_label = QLabel("Backup folder: (not set - will use ~/FirefoxProfileBackups)")
        layout.addWidget(self.backup_dir_label)

        row = QHBoxLayout()
        choose_btn = QPushButton("Choose backup folder...")
        choose_btn.clicked.connect(self.choose_backup_dir)
        row.addWidget(choose_btn)
        run_btn = QPushButton("Back up selected profile now")
        run_btn.setObjectName("primaryButton")
        run_btn.clicked.connect(self.run_backup)
        self._register_action(run_btn)
        row.addWidget(run_btn)
        layout.addLayout(row)
        layout.addStretch(1)
        return w

    def choose_backup_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Choose backup folder")
        if d:
            self.default_backup_dir = Path(d)
            self.backup_dir_label.setText(f"Backup folder: {d}")

    def run_backup(self):
        profile = self.require_profile()
        if not profile:
            return

        ok, reason = validate_profile(profile)
        if not ok:
            self.log(f"BLOCKED: {reason}")
            QMessageBox.critical(self, APP_TITLE, reason)
            return

        # Backup only reads, so a locked profile is a warning rather than a
        # refusal: an inconsistent snapshot still beats having no snapshot.
        if profile_lock_state(profile) is not LockState.FREE:
            resp = QMessageBox.question(
                self, APP_TITLE,
                "Firefox appears to have this profile open, so the databases "
                "may be captured mid-write and the backup could be slightly "
                "inconsistent.\n\nBacking up is read-only and safe to do "
                "anyway. Continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if resp != QMessageBox.StandardButton.Yes:
                return

        dest = self.default_backup_dir

        def work(log):
            return backup_profile(profile, dest, log)

        def done(result):
            mb = result.uncompressed / (1024 * 1024)
            if result.complete:
                QMessageBox.information(
                    self, APP_TITLE,
                    f"Archive verified and backup complete.\n\n{result.zip_path}\n\n"
                    f"{result.written:,} files ({mb:,.1f} MB)"
                )
            else:
                sample = ", ".join(result.skipped_files[:5])
                QMessageBox.warning(
                    self, APP_TITLE,
                    f"BACKUP INCOMPLETE.\n\n{result.zip_path}\n\n"
                    f"The {result.written:,} files in the archive are intact, "
                    f"but {result.skipped} file(s) could not be read and are "
                    f"NOT in it ({sample}).\n\nThis is not a complete recovery "
                    "copy. Close Firefox completely and back up again."
                )
            self.refresh_status()

        def failed(message, exc_name):
            QMessageBox.critical(
                self, APP_TITLE,
                f"Backup failed:\n\n{message}\n\nDo not rely on any file it "
                "may have produced."
            )

        self.run_task(work, done, "Backing up profile...", on_error=failed)

    # ---- Clean tab ----
    def build_clean_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.addWidget(QLabel(
            "Removes the site permissions and stuck-session data that cause "
            "fake 'TROJAN VIRUS FOUND' style popup notifications. Rows flagged "
            "\u26a0\ufe0f look like scam push-notification domains, but review "
            "the list yourself before deleting."
        ))

        perm_box = QGroupBox("Sites allowed to send notifications")
        perm_layout = QVBoxLayout(perm_box)
        self.perm_list = QListWidget()
        self.perm_list.setSelectionMode(QListWidget.SelectionMode.NoSelection)
        perm_layout.addWidget(self.perm_list)
        btn_row = QHBoxLayout()
        select_sus_btn = QPushButton("Check known-bad \u26a0\ufe0f entries")
        select_sus_btn.clicked.connect(self.select_suspicious)
        select_all_btn = QPushButton("Check all")
        select_all_btn.clicked.connect(lambda: self.set_all_perm_checks(True))
        select_none_btn = QPushButton("Uncheck all")
        select_none_btn.clicked.connect(lambda: self.set_all_perm_checks(False))
        btn_row.addWidget(select_sus_btn)
        btn_row.addWidget(select_all_btn)
        btn_row.addWidget(select_none_btn)
        perm_layout.addLayout(btn_row)
        layout.addWidget(perm_box)

        options_box = QGroupBox("Also clean")
        options_layout = QVBoxLayout(options_box)
        self.chk_session = QCheckBox("Clear saved session / restore-tabs data (stops a malicious tab reopening)")
        self.chk_session.setChecked(True)
        self.chk_cache = QCheckBox("Clear browser cache")
        self.chk_cache.setChecked(True)
        self.chk_backup_first = QCheckBox("Back up the profile automatically before cleaning (recommended)")
        self.chk_backup_first.setChecked(True)
        self.chk_forensic = QCheckBox(
            "Write a forensic snapshot first (records what was found, and why, before deleting)"
        )
        self.chk_forensic.setChecked(True)
        options_layout.addWidget(self.chk_session)
        options_layout.addWidget(self.chk_cache)
        options_layout.addWidget(self.chk_backup_first)
        options_layout.addWidget(self.chk_forensic)
        layout.addWidget(options_box)

        ext_box = QGroupBox("Installed extensions (review only - remove unfamiliar ones from within Firefox)")
        ext_layout = QVBoxLayout(ext_box)
        self.ext_list = QListWidget()
        self.ext_list.setMaximumHeight(110)
        ext_layout.addWidget(self.ext_list)
        layout.addWidget(ext_box)

        clean_btn = QPushButton("Run cleanup on selected profile")
        clean_btn.setObjectName("dangerButton")
        clean_btn.clicked.connect(self.run_clean)
        self._register_action(clean_btn)
        layout.addWidget(clean_btn)

        return w

    def refresh_notification_list(self):
        self.perm_list.clear()
        if not self.selected_profile_path:
            return

        status = inspect_permissions_schema(self.selected_profile_path)
        self._schema_status = status
        if status is not SchemaStatus.OK:
            msg = describe_schema_status(status)
            item = QListWidgetItem(msg)
            item.setForeground(QColor(AMBER if status is SchemaStatus.NO_DATABASE else "#ff6b6b"))
            self.perm_list.addItem(item)
            self._perm_rows = []
            self.log(f"permissions.sqlite schema: {status.value}")
            return

        perms = read_notification_permissions(self.selected_profile_path)
        self._perm_rows = perms
        for rowid, origin, ptype in perms:
            matches = match_heuristics(origin)
            flagged = bool(matches)
            prefix = FLAG_EMOJI + " " if flagged else ""
            why = f"   ({format_heuristics(matches)})" if flagged else ""
            text = f"{prefix}{origin}   [{ptype}]{why}"
            item = QListWidgetItem(text)
            if flagged:
                item.setToolTip("\n".join(f"{h.id}: {h.description}" for h in matches))
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked if should_preselect(origin)
                               else Qt.CheckState.Unchecked)
            item.setData(Qt.ItemDataRole.UserRole, rowid)
            if flagged:
                item.setForeground(QColor(AMBER))
            self.perm_list.addItem(item)
        if not perms:
            placeholder = QListWidgetItem("No notification permissions found in this profile.")
            placeholder.setForeground(QColor(TEXT_DIM))
            self.perm_list.addItem(placeholder)

    def refresh_extension_list(self):
        self.ext_list.clear()
        if not self.selected_profile_path:
            return
        for ext in list_extensions(self.selected_profile_path):
            status = "active" if ext["active"] else "disabled"
            bits = [status, ext["signed_label"]]
            if ext["installed"]:
                bits.append(f"installed {ext['installed']}")
            item = QListWidgetItem(f"{ext['name']}  ({', '.join(bits)})  -  {ext['id']}")
            if ext["is_unsigned"] and not ext["is_system"]:
                item.setForeground(QColor(AMBER))
                item.setToolTip("Unsigned add-on - review this one carefully.")
            if ext["permissions"]:
                item.setToolTip((item.toolTip() + "\n\n" if item.toolTip() else "")
                                + "Permissions: " + ", ".join(ext["permissions"][:12]))
            self.ext_list.addItem(item)
        if self.ext_list.count() == 0:
            self.ext_list.addItem("No extension data found.")

    def select_suspicious(self):
        """Tick rows that known-bad rules matched.

        Advisory-only matches (H-05) are left alone: they mark a row for a
        human look, not for bulk deletion.
        """
        for rowid, origin, _ptype in getattr(self, "_perm_rows", []):
            if not should_preselect(origin):
                continue
            for i in range(self.perm_list.count()):
                item = self.perm_list.item(i)
                if item.data(Qt.ItemDataRole.UserRole) == rowid:
                    item.setCheckState(Qt.CheckState.Checked)

    def set_all_perm_checks(self, checked: bool):
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        for i in range(self.perm_list.count()):
            item = self.perm_list.item(i)
            if item.flags() & Qt.ItemFlag.ItemIsUserCheckable:
                item.setCheckState(state)

    def run_clean(self):
        profile = self.require_profile()
        if not profile:
            return
        if not self.ensure_writable(profile):
            return

        to_delete = []
        for i in range(self.perm_list.count()):
            item = self.perm_list.item(i)
            if (item.flags() & Qt.ItemFlag.ItemIsUserCheckable) and item.checkState() == Qt.CheckState.Checked:
                to_delete.append(item.data(Qt.ItemDataRole.UserRole))

        summary = (
            f"About to clean profile:\n{profile}\n\n"
            f"- Remove {len(to_delete)} notification permission(s)\n"
            f"- Clear session/restore data: {'yes' if self.chk_session.isChecked() else 'no'}\n"
            f"- Clear cache: {'yes' if self.chk_cache.isChecked() else 'no'}\n"
            f"- Backup first: {'yes' if self.chk_backup_first.isChecked() else 'no'}\n"
            f"- Forensic snapshot first: {'yes' if self.chk_forensic.isChecked() else 'no'}\n\n"
            "Continue?"
        )
        if QMessageBox.question(self, APP_TITLE, summary) != QMessageBox.StandardButton.Yes:
            return

        perm_rows = list(getattr(self, "_perm_rows", []))
        do_forensic = self.chk_forensic.isChecked()
        do_backup = self.chk_backup_first.isChecked()
        do_session = self.chk_session.isChecked()
        do_cache = self.chk_cache.isChecked()
        dest = self.default_backup_dir

        def work(log):
            if do_forensic:
                write_forensic_snapshot(profile, dest, perm_rows, to_delete, log)

            if do_backup:
                # require_complete: proceeding to delete on the strength of a
                # partial safety net defeats the purpose of taking one.
                backup_profile(profile, dest, log, require_complete=True)

            if to_delete:
                diff = build_permission_diff(perm_rows, to_delete)
                for line in format_permission_diff(diff).splitlines():
                    log(line)
                delete_permission_rows(profile, to_delete, log)
            else:
                log("No permission rows selected for deletion.")

            if do_session:
                clear_session_restore(profile, log)
            if do_cache:
                clear_cache(profile, log)
            log("Cleanup finished.")
            return True

        def done(_result):
            self.refresh_notification_list()
            self.refresh_status()
            QMessageBox.information(
                self, APP_TITLE,
                "Cleanup finished.\n\nNext: open Firefox and check Settings > "
                "Privacy & Security > Permissions > Notifications to confirm "
                "the scam sites are gone, and untick 'Restore previous session' "
                "under Settings > General if it's enabled."
            )

        def failed(message, exc_name):
            if exc_name == "IncompleteBackupError":
                QMessageBox.critical(
                    self, APP_TITLE,
                    f"{message}\n\nNothing has been deleted."
                )
            else:
                QMessageBox.critical(self, APP_TITLE, f"Cleanup failed:\n\n{message}")

        self.run_task(work, done, "Cleaning profile...", on_error=failed)

    # ---- Restore tab ----
    def build_restore_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.addWidget(QLabel(
            "Restores a profile from a backup zip created by this tool. This "
            "REPLACES the profile: anything added since the backup was taken "
            "is removed. The current profile is kept alongside as a "
            "'.pre-restore-...' folder so this is reversible."
        ))
        row = QHBoxLayout()
        self.restore_path_label = QLabel("No backup file chosen.")
        choose_btn = QPushButton("Choose backup .zip...")
        choose_btn.clicked.connect(self.choose_restore_file)
        row.addWidget(choose_btn)
        row.addWidget(self.restore_path_label, 1)
        layout.addLayout(row)

        summary_box = QGroupBox("What this backup contains")
        summary_layout = QVBoxLayout(summary_box)
        self.restore_summary = QPlainTextEdit()
        self.restore_summary.setObjectName("summaryBox")
        self.restore_summary.setReadOnly(True)
        self.restore_summary.setPlaceholderText(
            "Choose a backup .zip to see what it contains before restoring."
        )
        summary_layout.addWidget(self.restore_summary)
        layout.addWidget(summary_box, 1)

        run_btn = QPushButton("Restore into selected profile")
        run_btn.setObjectName("dangerButton")
        run_btn.clicked.connect(self.run_restore)
        self._register_action(run_btn)
        layout.addWidget(run_btn)
        layout.addStretch(1)
        self._restore_zip: Path | None = None
        self._restore_info: dict | None = None
        return w

    def choose_restore_file(self):
        default_dir = str(self.default_backup_dir) if self.default_backup_dir.exists() else str(Path.home())
        f, _ = QFileDialog.getOpenFileName(self, "Choose backup zip", default_dir, "Zip files (*.zip)")
        if not f:
            return
        chosen = Path(f)
        try:
            info = inspect_backup_archive(chosen)
        except ArchiveRejected as e:
            self._restore_zip = None
            self.restore_path_label.setText("No backup file chosen.")
            self.restore_summary.setPlainText("")
            self.log(f"REJECTED archive: {e}")
            QMessageBox.critical(self, APP_TITLE, f"Backup file rejected:\n\n{e}")
            return

        self._restore_zip = chosen
        self._restore_info = info
        self.restore_path_label.setText(f)
        self.restore_summary.setPlainText(describe_backup_archive(info))
        self.log(f"Inspected backup '{chosen.name}': {info['entries']} entries.")

    def run_restore(self):
        profile = self.require_profile()
        if not profile:
            return
        if not getattr(self, "_restore_zip", None):
            QMessageBox.warning(self, APP_TITLE, "Choose a backup zip first.")
            return
        if not self.ensure_writable(profile):
            return
        if QMessageBox.question(
            self, APP_TITLE,
            f"This will REPLACE the contents of:\n{profile}\n\nwith:\n"
            f"{self._restore_zip}\n\n"
            f"{describe_backup_archive(self._restore_info)}\n\n"
            "Anything added since this backup was taken will be removed. "
            "The current profile will be kept alongside as a "
            "'.pre-restore-...' folder.\n\nContinue?"
        ) != QMessageBox.StandardButton.Yes:
            return
        zip_path = self._restore_zip

        def work(log):
            return restore_profile(zip_path, profile, log)

        def done(sidecar):
            self.refresh_notification_list()
            self.refresh_extension_list()
            self.refresh_status()
            QMessageBox.information(
                self, APP_TITLE,
                "Restore complete.\n\nThe profile as it was before this "
                f"restore has been kept at:\n{sidecar}\n\nDelete that folder "
                "once you're happy with the result."
            )

        def failed(message, exc_name):
            if exc_name == "ArchiveRejected":
                QMessageBox.critical(self, APP_TITLE, f"Backup file rejected:\n\n{message}")
            else:
                QMessageBox.critical(self, APP_TITLE, f"Restore failed:\n\n{message}")

        self.run_task(work, done, "Restoring profile...", on_error=failed)


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")  # neutral base so the QSS renders the same everywhere
    app.setFont(QFont("JetBrains Mono", 10))
    app.setStyleSheet(THEME_QSS)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
