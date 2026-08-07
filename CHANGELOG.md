# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-08

First public release. The tool began as a utility to remove the fake
"TROJAN VIRUS FOUND" push-notification scam from a family member's Firefox
profile, and was hardened over six adversarial review passes into a
defensive profile-repair utility.

Test suite: 276 tests, 274 passing on Windows 11 / Python 3.11
(2 skipped: POSIX-only lock paths).

### Added

- **Health tab** — read-only one-screen assessment: notification permissions
  and which are flagged, extensions with signing state and install dates,
  whether *Restore previous session* is enabled, cache size, Firefox version,
  and plain-language recommendations. Exportable to a text file for remote
  support.
- **Forensic snapshots** — written before any deletion. Records what was
  found, which heuristic flagged each entry and why, installed extensions,
  Firefox version, and a copy of `permissions.sqlite` with its WAL sidecars.
  Produces both `snapshot.json` and a pasteable `snapshot.txt`.
- **Permission diff** — the cleanup log records every permission, whether it
  was removed or kept, and which rule fired, instead of a bare count.
  Manually selected entries are labelled as such.
- **Restore dry-run** — choosing a backup validates it immediately and shows
  what it contains before anything is overwritten.
- **Heuristic IDs with an evidence hierarchy** — H-03 identifies a named scam
  network and can pre-select on its own; H-01/H-02/H-04 are circumstantial
  hostname-shape signals requiring two agreeing signals; H-05 is statistical
  and advisory only. Known CDN and hosting providers are never pre-selected.
- **Statistical hostname analysis (H-05)** — Shannon entropy plus digit and
  vowel composition, gated by a corpus of real hostnames as a false-positive
  regression test.
- **Troubleshooting launcher** — starts Firefox with extensions disabled. The
  dialog Firefox shows also offers its own *Refresh Firefox*; this tool
  deliberately does not reimplement refresh.
- **Background worker thread** — long operations no longer freeze the window.
- **Dark industrial theme** — flat zero-radius controls, JetBrains Mono,
  semantic colour for safe versus destructive actions.
- Apache-2.0 licensing with SPDX headers.

### Changed

- **Restore is now a replacement, not a merge.** Previously `extractall`
  overwrote matching files but left everything else, so files added after the
  backup survived a "restore". The archive is now staged and swapped into
  place, and the profile it replaced is kept as
  `<name>.pre-restore-<timestamp>` so the restore is itself reversible.
- **Backup completeness is reported separately from archive integrity.**
  "Archive verified" (every entry intact) and "backup complete" (no source
  file skipped) are different claims. The automatic pre-cleanup backup uses
  `require_complete=True` and cancels cleanup rather than deleting on the
  strength of a partial safety net.
- **Write operations are refused, not warned about,** while Firefox holds the
  profile. Detection uses the per-profile lock file rather than process-name
  matching, so one open profile does not block work on another.
- Session and cache deletion are verified rather than assumed. A session that
  cannot be removed fails loudly, since its survival is what brings the scam
  popups back; a cache folder that cannot be removed is a warning.
- Backup and sidecar filenames are collision-proof.

### Fixed

- **Cache scoping** — `clear_cache` matched local cache folders by the pre-dot
  prefix of the profile id, so cleaning `abc.default` could also delete the
  cache of an unrelated `abcdef.default-release`. Now an exact,
  case-insensitive whole-name match.
- **Restore accepted archives that were not Firefox profiles** — a zip
  containing only `hello.txt` could replace a working profile. Archives now
  require `prefs.js` plus a corroborating artefact, matched at the profile
  root rather than by filename suffix (`junk/prefs.js` previously satisfied
  the check).
- **Restore could write to the wrong profile** — extraction used the archive's
  own folder name, so restoring profile A's backup with B selected silently
  wrote to A.
- **Firefox detection failed open** — a failed or blocked probe reported "not
  running". It now fails closed, with a timeout.
- **Schema drift was unhandled** — `DELETE` statements were issued against
  whatever layout `permissions.sqlite` happened to have. An unrecognised
  schema now degrades to read-only.
- **Stale reads from WAL-mode databases** — copying only the main database
  omitted recent writes, so a scan could report a profile clean while the
  scam permission sat uncommitted in the write-ahead log. The `-wal` and
  `-shm` sidecars are now copied alongside.
- **Time-of-check/time-of-use race** — the lock was checked when the button
  was clicked, but cleanup can run for minutes afterwards. Every destructive
  function now re-establishes the invariant immediately before it writes
  rather than trusting its caller.
- **A legitimate CDN host was pre-selected for deletion** — H-02 matches
  `abc123def456.b-cdn.net` because the label is entirely hex characters.
- **Forensic snapshots could state a rule that did not produce the decision** —
  H-05's recorded expression was hand-written and went stale when the entropy
  threshold was retuned. It is now generated from the constants.
- **Uncertain lock state was reported as fact** — `UNKNOWN` rendered as
  "Firefox running: yes". It is now reported as unknown while still refusing
  writes.
- A `prefs.js` prefix collision meant `browser.startup.pagecount` could be
  read as `browser.startup.page`.
- Mozilla system add-ons were counted as unsigned, producing a warning on
  every healthy machine.
- The scratch copy used for reading `permissions.sqlite` was written inside
  the profile folder, where the next backup would sweep it up.

### Known limitations

- The lock check is a probe, not a held lock. Firefox could in principle start
  in the microseconds between the check and the write. Closing this fully
  would require holding an interprocess lock across every mutation using
  Firefox's own semantics. The realistic window has gone from minutes to
  microseconds; the residual case is documented rather than engineered away.
- Heuristic flagging is a heuristic, not a guarantee. Review the list before
  deleting.
- The CDN exemption list is hand-maintained and will drift as providers
  appear.
- Only profiles registered in `profiles.ini` are discovered.
