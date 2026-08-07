# Firefox Profile Manager — User Manual

**Version 1.0.0**

---

## What this tool does

If Firefox keeps showing alarming pop-ups — "TROJAN VIRUS FOUND", "Your PC is
infected!", "Click here to secure your data!" — this tool removes the cause.

**Your computer is almost certainly not infected.** What happened is that a
website asked permission to send notifications, that permission was granted
(often by accident, or by a button designed to trick you), and the site now
uses it to push fake warnings that look like they come from Windows or Firefox.

This tool finds that permission, shows it to you, and removes it once you
confirm. It also clears the saved browser session, so the offending tab cannot
reopen itself the next time Firefox starts.

## What this tool does *not* do

- It is **not** an antivirus and does not scan your computer.
- It never touches Windows itself, the registry, or any file outside your
  Firefox profile folder.
- It never deletes anything without showing you first and asking.

---

## Before you start

### 1. Close Firefox completely

This is the one step you must not skip. Firefox locks its own files while it is
running, and the tool will **refuse** to clean or restore until it is closed.

1. Close every Firefox window.
2. Press **Ctrl + Shift + Esc** to open Task Manager.
3. Look for any remaining **Firefox** entries in the list.
4. Right-click each one and choose **End task**.

If you skip this, the tool will simply stop and ask you to try again. It will
not damage anything — but you will not get very far.

### 2. Start the tool

Double-click **run.bat**, or open a command prompt in the tool's folder and run:

```
python firefox_profile_manager.py
```

A dark window titled *Firefox Profile Manager 1.0.0* opens.

### 3. Choose the profile

At the top of the window is a list labelled **Firefox profile**. Most people
have one entry, marked `(default)`. Click it to select it.

Everything you do afterwards applies only to the profile selected here.

Under the list is a status line telling you whether that profile is currently
in use. It should say the profile is not in use. If it says the profile is
**open in Firefox**, go back and close Firefox properly.

---

## Step-by-step: fixing the pop-ups

The four tabs are meant to be used in order: **Health → Backup → Clean →
Restore** (the last only if something goes wrong).

### Step 1 — Health: find out what is wrong

Click the **Health** tab, then **Scan selected profile**.

This only reads; it changes nothing. After a moment you get a report like this:

```
Profile:            q1w2e3r4.default-release
Firefox version:    141.0
Profile in use:     no

Notification sites: 5
  flagged:          3
    - https://a3f9c1e0b2.push-alert.xyz  (H-02, H-05)
    - https://secure-updates.co.in  (H-01)
    - https://gisbotnetwork-cdn.top  (H-03)

Extensions:         2 (2 active)
  unsigned:         1
    - PDF Converter Pro

Restore session:    ENABLED
Cache:              1.8 GB
Pending DB writes:  no

Recommendations
---------------
  1. Remove 3 flagged notification permission(s) on the Clean tab.
  2. Turn off 'Restore previous session' (Settings > General) so a
     malicious tab cannot reopen itself.
  3. Review 1 unsigned extension(s): PDF Converter Pro.
```

**How to read this:**

| Line | What it means |
|---|---|
| **Notification sites** | How many websites are allowed to send you pop-ups |
| **flagged** | How many of those look like scams |
| **unsigned** extensions | Add-ons not verified by Mozilla — worth a close look |
| **Restore session** | If ENABLED, Firefox reopens old tabs, including bad ones |
| **Cache** | Temporary files; safe to clear, just frees space |
| **Pending DB writes** | If yes, close Firefox and scan again for accurate results |

**Save report to file...** writes all of this to a text file. Useful if you are
helping someone remotely and want them to send you the results.

### Step 2 — Backup: make a safety copy

Click the **Backup** tab.

1. Click **Choose backup folder...** and pick somewhere easy to find. If you
   skip this, backups go to `FirefoxProfileBackups` in your user folder.
2. Click **Back up selected profile now**.

The backup includes bookmarks, saved passwords, history, settings, and
extensions. When it finishes you will see one of two messages:

- **"Archive verified and backup complete"** — everything was captured. Good.
- **"BACKUP INCOMPLETE"** — some files could not be read, and they are named.
  This almost always means Firefox is still running. Close it and back up
  again. Do not treat this file as a full safety copy.

Do this at least once before your first clean.

### Step 3 — Clean: remove the scam permissions

Click the **Clean** tab.

#### 3a. Review the list

Under **Sites allowed to send notifications** is every site with permission to
send you pop-ups. Entries that look like scams are marked ⚠️ in amber, with a
code showing why. Hover over one to see the reason in plain words.

Entries that are almost certainly bad arrive **already ticked**. Entries that
are merely unusual are flagged but left unticked, so you decide.

**Read this list before continuing.** The ⚠️ marks are educated guesses, not
certainties. You are looking for names you do not recognise — random letters
and numbers, odd endings like `.xyz`, `.top`, `.icu`, or names imitating
security software.

Leave ticked anything you don't recognise. Untick anything you *do* recognise
and want to keep — a news site or webmail you deliberately allowed.

Three buttons help:

- **Check known-bad ⚠️ entries** — re-tick the confident matches
- **Check all** / **Uncheck all** — select or clear everything

#### 3b. Choose the extra options

Under **Also clean**:

| Option | Recommendation |
|---|---|
| Clear saved session / restore-tabs data | **Leave ticked.** This is what stops the bad tab reopening. |
| Clear browser cache | Optional. Frees space; costs slightly slower page loads at first. |
| Back up the profile automatically before cleaning | **Leave ticked.** |
| Write a forensic snapshot first | **Leave ticked.** Records what was found before deleting it. |

#### 3c. Run it

Click **Run cleanup on selected profile**. A summary appears listing exactly
what is about to happen. Read it, then confirm.

If Firefox has been reopened in the meantime, the tool stops and tells you.
Nothing is deleted. Close Firefox and try again.

#### 3d. Check the extensions

Below the permission list is **Installed extensions**. This is review-only —
the tool never removes add-ons.

Anything shown in amber is **unsigned**, meaning Mozilla has not verified it.
If you do not recognise it, remove it from inside Firefox: open a tab, go to
`about:addons`, and remove it there.

### Step 4 — Finish inside Firefox

Reopen Firefox and do two things:

1. Go to **Settings → Privacy & Security → Permissions → Notifications →
   Settings**. Confirm the scam sites are gone. While you are there, tick
   **Block new requests asking to allow notifications** to prevent a repeat.
2. Go to **Settings → General** and untick **Open previous windows and tabs**
   if it is on.

The pop-ups should now be gone. If they return, see *Troubleshooting* below.

---

## If something goes wrong: Restore

The **Restore** tab puts a profile back exactly as it was when you backed it up.

1. Close Firefox completely.
2. Click **Choose backup .zip...** and pick your backup file.
3. Read the **What this backup contains** panel. It tells you what is in the
   file — bookmarks, saved logins, settings — and whether this tool created it.
4. Click **Restore into selected profile** and confirm.

**Important:** restore is a *replacement*, not a merge. Anything added since
the backup was taken is removed. That is what makes it a genuine undo.

Your current profile is not thrown away — it is kept beside the original with
`.pre-restore-` and a timestamp in the name. Once you are happy with the
result, you can delete that folder.

---

## Troubleshooting

### "Firefox currently has this profile open"

Firefox is still running. Close every window, then end any remaining Firefox
processes in Task Manager (**Ctrl + Shift + Esc**). Click **Retry**.

### "Could not verify whether Firefox has this profile open"

The tool could not determine the state, so it refused rather than risk damaging
the profile. Close Firefox, and if it persists, restart the computer.

### The pop-ups came back

Work through these in order:

1. **Did you clear session data?** If not, run the clean again with that option
   ticked.
2. **Is "Open previous windows and tabs" still on?** Turn it off in
   Settings → General.
3. **Is an extension responsible?** On the **Health** tab, click **Launch
   Firefox troubleshooting options...**. This starts Firefox with all add-ons
   disabled. If the pop-ups stop, an extension is the cause — remove it from
   `about:addons`.
4. **Still there?** The window Firefox shows also offers **Refresh Firefox**,
   which rebuilds the profile from scratch while keeping bookmarks, history and
   passwords. That is Mozilla's own feature, not this tool's — take a backup
   first.

### "BACKUP INCOMPLETE"

Some files could not be read, and the message names them. Close Firefox
completely and back up again. If it persists, try backing up to a different
folder or drive.

### Cleanup was cancelled because the safety backup was incomplete

Deliberate. The tool will not delete things when its safety net has holes in
it. Close Firefox properly and run it again.

### "Could not remove saved session data"

The session files are locked, so the scam tab could still reopen. This is
almost always Firefox still running. Close it fully and clean again.

### A site I actually wanted got removed

Reopen the site in Firefox and allow notifications again when it asks. Or
restore your backup and redo the clean, unticking that entry.

---

## Understanding the ⚠️ codes

Each flag has a code, shown next to the entry and recorded in the logs.

| Code | Meaning |
|---|---|
| **H-01** | Uses `.co.in`, a domain heavily abused by ad networks |
| **H-02** | Long random hex-looking subdomain |
| **H-03** | A known scam push-notification network |
| **H-04** | Notification-themed name on a cheap top-level domain |
| **H-05** | The address looks statistically random (advisory only) |

**How ticking is decided.** H-03 identifies a specifically known scam network,
so it can tick an entry on its own. H-01, H-02 and H-04 describe only the
*shape* of an address, and any one of them also matches innocent sites — `.co.in`
is an ordinary Indian business domain, and real content-delivery addresses
genuinely look random. So at least two must agree before an entry is ticked.
H-05 never ticks anything; it only draws your eye.

Everything flagged is still listed and can be ticked by hand. The rules only
decide what arrives pre-ticked.

---

## Where files are saved

Everything the tool writes goes to your chosen backup folder (by default
`FirefoxProfileBackups` in your user folder):

| File | What it is |
|---|---|
| `<profile>_backup_<date>.zip` | A full profile backup |
| `forensic_<profile>_<date>/snapshot.json` | Machine-readable record of what was found |
| `forensic_<profile>_<date>/snapshot.txt` | The same in plain text, for sharing |
| `forensic_<profile>_<date>/permissions.sqlite` | Copy of the permissions database as found |
| `FirefoxHealth_<date>.txt` | An exported health report |

The `.pre-restore-<timestamp>` folder created by a restore sits next to your
profile, not in the backup folder.

---

## Quick reference

| I want to... | Do this |
|---|---|
| See what's wrong | **Health** tab → *Scan selected profile* |
| Make a safety copy | **Backup** tab → *Back up selected profile now* |
| Remove scam pop-ups | **Clean** tab → review list → *Run cleanup* |
| Undo everything | **Restore** tab → choose backup → *Restore* |
| Test whether an add-on is to blame | **Health** tab → *Launch Firefox troubleshooting options* |
| Send results to someone helping me | **Health** tab → *Save report to file...* |

---

## Safety notes

- Cleaning and restoring are **refused** while Firefox has the profile open,
  and also if that cannot be determined. This is deliberate and cannot be
  overridden — writing to a database Firefox is using can corrupt bookmarks
  and saved passwords.
- Backing up is read-only, so it is allowed while Firefox is open. You will be
  warned that the copy may be slightly inconsistent.
- Nothing is deleted without an explicit confirmation showing what will happen.
- A forensic snapshot is written before any deletion, so you can always find
  out afterwards what was on the machine.

---

*Firefox Profile Manager 1.0.0 — Licensed under Apache-2.0.*
*Firefox is a trademark of the Mozilla Foundation. This tool is not affiliated
with or endorsed by Mozilla.*
