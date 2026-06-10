# Changelog

All notable changes to wevtail are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-10

Initial release.

### Added
- Live push-based follow of Windows event log channels via the Win32
  `EvtSubscribe` API (no polling).
- Multiple channels followed at once, interleaved with fair draining.
- Gapless backfill-then-follow handoff using event bookmarks.
- Colorized one-line human output with audit success/failure decoded from
  Security-channel keywords; `--multiline` for full messages.
- JSON-lines output (`--json`) with a flat, jq-friendly schema.
- Server-side filtering: event IDs and ranges (`-e`), minimum severity (`-l`),
  provider (`-p`), time window (`--since`), and raw XPath (`-q`).
- `.evtx` file replay with the same rendering and filtering as live channels.
- Remote tailing over RPC (`-r`/`-u`/`--password`).
- `--list` to enumerate channels.
- MSI installer (adds wevtail to PATH) and portable zip, published to GitHub
  Releases by a tag-triggered workflow.

[Unreleased]: https://github.com/Ldogg123/wevtail/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Ldogg123/wevtail/releases/tag/v0.1.0
