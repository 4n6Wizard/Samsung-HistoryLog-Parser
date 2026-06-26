# Samsung Secure Folder History Log Parser — v1.0

A forensic tool that parses the Samsung Secure Folder **HistoryLog** database and
produces analyst-friendly CSV and HTML reports of file-transfer (move-in/move-out)
activity between the personal profile and the Secure Folder.

This release is a **standalone Windows 64-bit executable** — no Python
installation is required.

## Download

➡️ **Get the latest build from the [Releases page](https://github.com/4n6Wizard/Samsung-HistoryLog-Parser/releases/latest)** — download `SecureFolderHistoryLogParser-v1.0-win64.zip`.

> Note: the green **"Code → Download ZIP"** button only downloads source files (the README), **not** the program. Use the Releases link above to get the executable.

## Overview

This tool parses the **HistoryLog** SQLite database from a Samsung device's
**Secure Folder** (`com.samsung.knox.securefolder`, user profile **150**) and
reconstructs file transfer activity into analyst-friendly **CSV** and **HTML**
reports.

The Secure Folder is an isolated, encrypted container (Android user 150) on
Samsung devices. Its HistoryLog records each file moved into or out of the
container as paired `request`/`result` events. This tool reads that log and, for
each event, decodes:

- **Direction** — personal profile (user 0) ↔ Secure Folder (user 150),
  e.g. `[0 -> 150]` (move-in) or `[150 -> 0]` (move-out)
- **Source app** that initiated the transfer (Gallery, MyFiles, etc.)
- **Requested vs. moved file counts** (flags partial transfers)
- **Source and destination *folder* paths** — the folders involved in the transfer
- **Timestamps and durations**

It then pairs the request/result events and outputs a consolidated forensic
report in both CSV and HTML.

> **Important limitation:** The HistoryLog records the **folders** involved and the
> **number of files** moved — it does **not** store the individual **file names** of
> the transferred items. Reports therefore show *which folders* were moved into or
> out of the Secure Folder and *how many* files, but not the specific file names.

## Contents

| File | Description |
|------|-------------|
| `SecureFolderHistoryLogParser.exe` | The parser (standalone, no dependencies). |
| `Sample_Report.csv`  | Example CSV output for reference. |
| `Sample_Report.html` | Example HTML forensic report for reference. |
| `README.md` | This file. |

## Usage

1. Run `SecureFolderHistoryLogParser.exe`.
2. Follow the on-screen prompts to point it at the extracted HistoryLog data.
3. The tool writes a consolidated CSV and HTML report to the output location you choose.

> **Note:** Windows SmartScreen may warn that the publisher is unknown because the
> executable is not code-signed. This is expected for an unsigned build — choose
> *More info → Run anyway* if you trust the source.

## Output

- **CSV** — one row per event, suitable for filtering and import into other tools.
- **HTML** — a formatted forensic report with paired move-in/move-out events,
  timestamps, durations, source/destination paths, and analyst notes/warnings.

See `Sample_Report.csv` and `Sample_Report.html` for examples of the output format
(generated from synthetic test data).

## Version

v1.0
