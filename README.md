# Firefox Profile Manager

A small desktop tool (PyQt6) for backing up, cleaning, and restoring Mozilla Firefox profiles — built specifically to deal with the fake "TROJAN VIRUS FOUND" / "Click here to secure your data!" popup scam that abuses Firefox's website-notification feature.

It does **not** scan your computer for viruses and makes no claims about Windows itself. It only ever reads and edits files inside your Firefox profile folder.

## Why this exists

Some scam websites trick you into allowing "notifications," then send a stream of fake system-looking alerts (Trojan warnings, "Update Windows" buttons, etc.) that appear to come from Firefox itself and can't easily be dismissed. This isn't malware on your PC — it's a permission Firefox granted to a malicious site, plus a saved browser tab that keeps reopening it.

This tool finds and removes that permission, clears the saved session/tabs so the scam page doesn't come back, and takes a backup first so nothing is lost.

## Features

- **Find profiles** — automatically locates every Firefox profile on the machine (Windows, macOS, Linux)
- **Health** — one read-only screen showing notification permissions and which are flagged, installed extensions and which are unsigned, whether *Restore previous session* is on, cache size and Firefox version, with plain-language recommendations. Exportable to a `.txt` file for remote support.
- **Launch troubleshooting options** — starts Firefox with extensions disabled. The dialog Firefox shows also offers its own *Refresh Firefox*; this tool deliberately does not reimplement refresh.
- **Backup** — zips a full profile (bookmarks, saved logins, settings, extensions) to a chosen folder
- **Clean**
  - Lists every site with notification permission and flags ⚠️ ones that look like scam domains (random hex subdomains, `.co.in`, known scam-network names, etc.) — you review and choose what to delete, nothing is removed automatically
  - Optionally clears saved session/restore-tabs data, so a malicious tab can't reopen itself
  - Optionally clears the browser cache
  - Automatically backs up the profile first, then verifies it. **Archive verified** (every entry intact) and **backup complete** (no source file skipped) are reported separately — and if the automatic pre-cleanup backup is incomplete, cleanup is cancelled rather than proceeding on a partial safety net
  - Optionally writes a **forensic snapshot** before deleting anything: which sites had permission, which heuristic flagged each one, installed extensions, and the Firefox version
  - Shows installed extensions with signing state and install date, highlighting unsigned ones (removal is done inside Firefox itself)
- **Restore** — roll back to any backup zip created by this tool, with a dry-run summary shown before anything is overwritten. Archives must be demonstrably Firefox profiles (`prefs.js` plus a corroborating artefact); backups made by this tool carry a manifest so the summary can say whether it produced them

## Requirements

- Python 3.9+
- [PyQt6](https://pypi.org/project/PyQt6/)

```bash
pip install PyQt6
```

## Usage

```bash
python firefox_profile_manager.py
```

1. **Close Firefox completely first.** Cleaning and restoring are refused outright while Firefox holds the profile. On Windows, check Task Manager and end every `firefox.exe` process — Firefox locks its database files while running, and cleaning/restoring won't work correctly otherwise. The app will warn you if it detects Firefox running, but the check isn't foolproof.
2. Pick the profile you want to work on from the list at the top.
3. **Health tab** — click *Scan selected profile* for an overview of what's wrong and what to do about it. Good starting point.
4. **Backup tab** — choose a folder (defaults to `~/FirefoxProfileBackups`) and click *Back up selected profile now*. Do this before cleaning, especially the first time.
5. **Clean tab** — review the list of sites with notification permission. Suspicious-looking ones are pre-checked; use *Check all flagged ⚠️ entries* to re-select them, or check/uncheck manually. Choose whether to also clear session data and cache, then click *Run cleanup on selected profile*.
6. **Restore tab** — if anything looks wrong afterward, choose a backup `.zip` and restore it back into the profile.
7. Reopen Firefox and confirm under **Settings → Privacy & Security → Permissions → Notifications** that the scam site is gone. Also worth unticking **Settings → General → Restore previous session** if it's enabled, so a bad tab can't come back on its own.

## What it changes on disk

All actions are scoped to the selected Firefox profile folder (and, on Windows, the matching cache folder under `%LOCALAPPDATA%`):

| Action | Files touched |
|---|---|
| Backup | Reads the whole profile folder (skips `cache2`/`startupCache` to keep it fast); writes a `.zip` |
| Clean — permissions | `permissions.sqlite` — deletes selected rows from `moz_perms` |
| Clean — session | Deletes `sessionstore.jsonlz4` and the `sessionstore-backups` folder |
| Clean — cache | Deletes `cache2`, `startupCache`, `shader-cache` folders (plus the matching `cache2` under `%LOCALAPPDATA%`, matched on the profile folder's exact name) |
| Restore | Stages a backup `.zip`, then replaces the profile with it; the previous profile is kept as `<name>.pre-restore-<timestamp>` |
| Forensic snapshot | Read-only; writes `snapshot.json`, `snapshot.txt` and a copy of `permissions.sqlite` to the backup folder |

The tool never touches Windows system files, the registry, or anything outside the Firefox profile.

## Notes on correctness

- Long operations (backup, restore, cleanup, health scan) run on a background thread, so the window stays responsive and does not appear to have crashed mid-write.
- SQLite reads copy the `-wal` and `-shm` sidecars alongside the database. In WAL mode recent writes live in the log rather than the main file, so copying only the database can produce a stale scan — the health report warns when pending writes are present.
- "Profile in use" is reported as `no`, `yes`, or `UNKNOWN`; an inability to determine the state blocks writes but is never reported as fact.

## Limitations

- Only manages Firefox profiles registered in `profiles.ini` — profiles you point Firefox at manually via `-profile` won't show up automatically.
- The ⚠️ flagging is a heuristic (pattern-matching and statistical analysis of the site's address), not a guarantee — always glance over the list yourself before deleting. Each rule has a stable ID (H-01, H-02, ...) shown next to the flagged row and recorded in the cleanup log and forensic snapshot.
- Flagging and pre-selection are separate. Rules matching known-bad patterns (H-01 to H-04) pre-tick a row; the statistical rule H-05 only flags it for your attention, because legitimate CDN hostnames are genuinely random-looking. Known CDN and hosting providers are never pre-ticked at all.
- Write operations (clean, restore) are refused outright while Firefox has the profile open, and also if that cannot be determined. Backups are read-only and proceed with a warning.
- Extension review is read-only; disable or remove unfamiliar extensions from within Firefox (`about:addons`), then re-check the list here.
- If Firefox is running, database writes (clean/restore) can fail or be incomplete — always close it first.

## Tests

```bash
pip install pytest
pytest -q
```

The suite pins the local-cache scoping behaviour: reverting
`matching_local_cache_dirs()` to a prefix match makes it fail.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

```
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: Copyright 2026 Leon Priest <https://github.com/7h3v01d>
```
