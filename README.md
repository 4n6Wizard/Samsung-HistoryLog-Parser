# Samsung Secure Folder History Log Parser — v1.0

A forensic tool that parses the Samsung Secure Folder **HistoryLog** database and
produces analyst-friendly CSV and HTML reports of file-transfer (move-in/move-out)
activity between the personal profile and the Secure Folder.

This release is a **standalone Windows 64-bit executable** — no Python
installation is required.

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
