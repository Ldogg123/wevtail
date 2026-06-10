<div align="center">

# wevtail

### `tail -f` for Windows event logs

[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011%20%7C%20Server-0078D6?logo=windows&logoColor=white)](https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log)
[![Built with Rust](https://img.shields.io/badge/built%20with-Rust-000000?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

Follow Windows event log channels **live** — push-based, no polling — with colorized
or JSON-lines output, XPath filtering, `.evtx` replay, and remote-host tailing.

</div>

---

Windows has no native way to *follow* an event log. `wevtutil` and `Get-WinEvent` are
query-only, so admins end up writing the same 300 ms PowerShell polling loop over and
over. **wevtail** subscribes to channels through the Win32 `EvtSubscribe` API and streams
events to your terminal the instant they're written — like `tail -f`, but for `wevt`.

```text
2026-06-10 10:15:18.826 WARN  System euchcmon/0 Detected unrecognized USB driver (\Driver\nxusbf).
2026-06-10 10:15:53.204 INFO  System Kernel-General/16 The access history in hive ... was cleared
2026-06-10 10:16:01.471 INFO  System Service Control Manager/7036 The Print Spooler service entered the running state.
2026-06-10 10:16:09.880 FAIL  Security Security-Auditing/4625 An account failed to log on. Account: user. Status: 0xC000006A
```

*(severity is color-coded in a real terminal: `CRIT`/`FAIL` red, `WARN` yellow, `INFO`/`AUDIT` green, `VERB` grey)*

## Features

- **Live push-based follow** — events arrive the moment they're logged, via `EvtSubscribe`. No polling, no missed events, no busy-wait.
- **Multiple channels at once** — `wevtail System Security "Microsoft-Windows-Sysmon/Operational"` interleaves them in one stream, fairly drained so no channel starves the others.
- **Gapless backfill → follow** — prints the last *N* events tail-style, then resumes the live stream exactly where the backfill ended (bookmark handoff), so nothing is lost or duplicated in between.
- **Colorized human output** — one greppable line per event, severity-colored, with audit success/failure decoded from Security-channel keywords.
- **JSON-lines mode** — one flat, `jq`-friendly object per line for piping into anything.
- **Server-side filtering** — event IDs and ranges, minimum severity, provider, time window, or raw XPath — all compiled into a single query the Event Log service evaluates.
- **`.evtx` replay** — read exported log files with the same rendering and filtering as live channels.
- **Remote tailing** — follow another machine's logs over RPC, the way Event Viewer's "Connect to Another Computer" does.
- **Single static binary** — pure Rust over `wevtapi`, no runtime, no dependencies to install on the target.

## Install

> ⚠️ wevtail is **not code-signed**, so on first run Windows SmartScreen shows
> *"Windows protected your PC"* — click **More info → Run anyway**. Verify the
> SHA-256 checksum (below) first to confirm your download is genuine.

### Option A — MSI installer (recommended)

1. Download `wevtail-X.Y.Z-x86_64.msi` from the [latest release](https://github.com/Ldogg123/wevtail/releases/latest).
2. (Recommended) [verify the checksum](#verifying-a-download).
3. Run it — `wevtail.exe` is installed and added to your `PATH`, so `wevtail` works in any new terminal.

### Option B — Portable zip (no installer)

Download `wevtail-X.Y.Z-x86_64-pc-windows-msvc.zip` from the [latest release](https://github.com/Ldogg123/wevtail/releases/latest), [verify it](#verifying-a-download), then extract `wevtail.exe` anywhere and run it.

### Option C — Build from source

Requires the [Rust toolchain](https://rustup.rs) (stable, MSVC):

```powershell
cargo install --git https://github.com/Ldogg123/wevtail
# …or from a clone:  cargo build --release   (binary at target\release\wevtail.exe)
```

### Verifying a download

Each release ships a `SHA256SUMS.txt`. Hash your file with a built-in Windows tool and compare:

```powershell
Get-FileHash .\wevtail-X.Y.Z-x86_64.msi -Algorithm SHA256      # PowerShell
certutil -hashfile wevtail-X.Y.Z-x86_64.msi SHA256             # or cmd
```

The printed hash must match the matching line in `SHA256SUMS.txt`.

No admin rights are needed to read most channels (the `Security` channel is the notable
exception — see [Security channel](#security-channel)). Installing the MSI system-wide does
require elevation, since it writes to Program Files and the machine `PATH`.

## Quick start

```powershell
wevtail                                        # follow System + Application
wevtail Security -e 4624,4625                  # watch logons (needs elevation)
wevtail "Microsoft-Windows-Sysmon/Operational" --json | jq .
wevtail System -l error --since 2h             # errors from the last two hours
wevtail exported.evtx -n 50                     # last 50 events of an export
wevtail -r dc01.lab -u 'LAB\admin' Security    # tail a remote DC
wevtail --list                                  # what channels exist?
```

Like `tail`, wevtail prints the last 10 matching events and then follows. Press `Ctrl+C`
to stop.

## Usage

```text
wevtail [OPTIONS] [CHANNEL|FILE]...
```

| Option | Value | Default | Description |
|---|---|---|---|
| `[CHANNEL\|FILE]...` | | `System Application` | Channels to follow, or `.evtx` files to replay |
| `-n`, `--lines` | `N` | `10` | Backfill the last *N* matching events before following (`0` = none; for files `0` = all) |
| `--no-follow` | | | Print matching events and exit instead of following |
| `--from-start` | | | Start from the oldest record (full replay, then follow). Conflicts with `--since` |
| `--since` | `WHEN` | | Only events newer than a duration (`15m`, `2h30m`, `1d`) or timestamp (`2026-06-10T12:00`) |
| `-q`, `--query` | `XPATH` | | Raw XPath filter, e.g. `"*[System[EventID=4625]]"` (mutually exclusive with `-e`/`-l`/`-p`/`--since`) |
| `-e`, `--id` | `ID` | | Filter by event id(s): `4625`, `4624,4625`, or a range `4000-4999` |
| `-l`, `--level` | `LEVEL` | | Minimum severity: `critical`, `error`, `warning`, `info`, `verbose` |
| `-p`, `--provider` | `NAME` | | Filter by provider name (repeatable) |
| `--json` | | | Output one JSON object per event (JSON lines) |
| `--multiline` | | | Print full multi-line messages (default collapses each event to one line) |
| `--no-color` | | | Disable colored output |
| `-r`, `--remote` | `HOST` | | Tail the event logs of a remote computer |
| `-u`, `--username` | `USER` | | Username for the remote session — `DOMAIN\user` or `user@domain` (requires `--remote`) |
| `--password` | `PASS` | | Password for the remote session — prompted if omitted (requires `--username`) |
| `--list` | | | List available channels and exit |
| `-h`, `--help` | | | Print help |
| `-V`, `--version` | | | Print version |

## The tailing model

By default wevtail does what `tail -f` does: a **backfill** of the last `-n` events,
then a **live follow**. The handoff is bookmark-based — the subscription resumes from the
exact position the backfill ended, so no event is dropped or repeated across the seam.

| You want… | Command |
|---|---|
| Last 10, then follow (default) | `wevtail System` |
| Last 100, then follow | `wevtail System -n 100` |
| Only new events, no history | `wevtail System -n 0` |
| Everything in the channel, then follow | `wevtail System --from-start` |
| Just print and exit (no follow) | `wevtail System --no-follow` |
| Everything from the last 2 hours, then follow | `wevtail System --since 2h` |

`--since` accepts a **duration** (`30s`, `15m`, `2h30m`, `1d`) or a **timestamp** (an
RFC 3339 instant, or a local civil time like `2026-06-10T12:00`). It maps to a server-side
`timediff()` window, so the filtering happens in the Event Log service.

## Filtering

Every flag filter compiles to a **single XPath query** that the Event Log service
evaluates — wevtail never filters client-side. Combine them freely (they're AND-ed):

```powershell
wevtail Security -e 4625 -l warning            # failed logons, warning or worse
wevtail System -e 7000-7045 -p "Service Control Manager"
wevtail Application --since 1h -e 1000,1001
```

- **`-e`/`--id`** — single ids (`4625`), comma lists (`4624,4625`), and inclusive ranges (`4000-4999`).
- **`-p`/`--provider`** — exact provider name; repeat the flag for several (OR-ed).
- **`-l`/`--level`** — minimum severity. The mapping to the underlying Windows `Level` field:

  | `-l` value | Matches |
  |---|---|
  | `critical` | Level 1 |
  | `error` | Levels 1–2 |
  | `warning` | Levels 1–3 |
  | `info` | Level 0 (LogAlways/audit) and 1–4 |
  | `verbose` | everything (no level constraint) |

- **`-q`/`--query`** — when the flag filters aren't enough, pass raw XPath. This is
  mutually exclusive with `-e`/`-l`/`-p`/`--since`. wevtail uses the Event Log service's
  [XPath 1.0 subset](https://learn.microsoft.com/en-us/windows/win32/wes/consuming-events),
  so functions like `band()` and `timediff()` are available:

  ```powershell
  wevtail Security -q "*[System[band(Keywords,4503599627370496)]]"   # audit-failure events
  wevtail System   -q "*[System[Level=1 or Level=2]]"                 # critical + error
  ```

## Output

### Human format (default)

Each event collapses to one greppable line:

```text
2026-06-10 10:16:09.880 FAIL  Security Security-Auditing/4625 An account failed to log on...
└──── local time ─────┘ └sev┘ └channel┘ └─ provider/id ─┘  └─────── message ───────┘
```

| Column | Notes |
|---|---|
| **timestamp** | Converted to your **local** time zone, millisecond precision (dimmed) |
| **severity** | 5-char label, color-coded — see table below |
| **channel** | Shown only when following more than one source (cyan) |
| **provider/id** | `Microsoft-Windows-` prefix stripped for brevity (magenta) |
| **message** | The resolved publisher message, whitespace-collapsed to one line |

Severity is derived the way Windows actually means it — for Security-channel audit events
(which all carry `Level 0` = *LogAlways*), success/failure comes from the event's
**keywords**, not its level:

| Label | JSON `severity` | Color | Derived from |
|---|---|---|---|
| `CRIT` | `critical` | bold bright red | Level 1 |
| `ERROR` | `error` | red | Level 2 |
| `WARN` | `warning` | yellow | Level 3 |
| `INFO` | `info` | green | Level 0/4 (and anything else) |
| `VERB` | `verbose` | grey | Level 5 |
| `AUDIT` | `audit_success` | green | Keyword `0x0020000000000000` |
| `FAIL` | `audit_failure` | bold bright red | Keyword `0x0010000000000000` |

Use `--multiline` to keep the original multi-line message formatting (indented under each
event) instead of collapsing to one line.

When the publisher isn't installed locally (common when replaying a `.evtx` from another
machine), wevtail can't resolve a message and falls back to printing the raw `Key=Value`
event data.

### JSON lines (`--json`)

One flat object per line — built to feel familiar if you've used winlogbeat/NXLog, but
without the nesting ceremony, so it's pleasant to `jq`. Always-present fields are the core
identity of the event; the rest appear only when the event actually carries them.

```json
{"ts":"2026-06-10T14:16:09.880Z","channel":"Security","provider":"Microsoft-Windows-Security-Auditing","event_id":4625,"severity":"audit_failure","level":0,"task":12544,"keywords":"0x8010000000000000","record_id":284119,"computer":"DC1","pid":712,"message":"An account failed to log on...","data":{"TargetUserName":"user","LogonType":"3","Status":"0xc000006a"}}
```

| Field | Type | Always? | Meaning |
|---|---|---|---|
| `ts` | string | when timed | Event time, RFC 3339 **UTC** (note: JSON is UTC; human output is local) |
| `channel` | string | ✓ | Event log channel |
| `provider` | string | ✓ | Full provider name (prefix not stripped) |
| `event_id` | number | ✓ | Windows Event ID |
| `severity` | string | ✓ | Derived: `critical`/`error`/`warning`/`info`/`verbose`/`audit_success`/`audit_failure` |
| `level` | number | ✓ | Raw Windows `Level` (0–5) |
| `task` | number | optional | Task/category number |
| `keywords` | string | optional | 64-bit keyword bitmask as hex (e.g. `0x8010000000000000`) |
| `record_id` | number | optional | `EventRecordID` — monotonic per-channel cursor |
| `computer` | string | optional | Originating computer name |
| `pid` / `tid` | number | optional | Process / thread ID |
| `user_sid` | string | optional | SID of the associated user |
| `activity_id` | string | optional | Correlation GUID |
| `message` | string | optional | Resolved publisher message (verbatim, not collapsed) |
| `data` | object | optional | `EventData`/`UserData` parameters, all string values |

Because every field is a bare token, `jq` and `grep` both just work:

```powershell
# Failed-logon usernames, live
wevtail Security -e 4625 --json | jq -r '.data.TargetUserName'

# Count events by provider from an export
wevtail dump.evtx --json | jq -r .provider | Group-Object -NoElement | Sort-Object Count -Descending

# Without jq — PowerShell speaks JSON natively
wevtail System -n 50 --no-follow --json | ConvertFrom-Json |
    Group-Object provider -NoElement | Sort-Object Count -Descending
```

Color is auto-enabled for a terminal and turned off automatically for `--json`, `--no-color`,
a set `NO_COLOR` environment variable, or when stdout isn't a TTY (e.g. piped to a file).

## Live multi-channel follow

Pass several channels and wevtail follows them all in one stream, prefixing each line with
its channel so the source is always clear:

```powershell
wevtail System Application "Windows PowerShell"
```

The follow loop drains **every** signaled channel on each wakeup, so a chatty channel
can't starve a quiet one. The ceiling is **64 channels** per invocation (the
`WaitForMultipleObjects` limit); `.evtx` files don't count against it.

## Remote tailing

```powershell
wevtail -r dc01.lab -u 'LAB\admin' Security        # prompts for password
wevtail -r 10.0.0.5 -u admin@lab.local System Application
wevtail -r fileserver01                            # current credentials, default channels
```

This uses the same RPC path as Event Viewer's *Connect to Another Computer*. Notes:

- **Credentials** accept `DOMAIN\user` or `user@domain`; omit `-u` to use your current
  login. If you pass `-u` without `--password`, wevtail prompts (and keeps the password in
  a zeroizing buffer).
- The **target** must have the **Remote Event Log Management** firewall rule group enabled
  — wevtail tells you so if the connection is refused.
- Messages are resolved from the **remote** machine's publisher metadata, so events render
  correctly even when the provider isn't installed locally.

## Security channel

Reading `Security` requires elevation or membership in the **Event Log Readers** group.
Without it, wevtail says so plainly instead of dumping a raw error code:

```text
$ wevtail Security -n 1 --no-follow
wevtail: access denied to 'Security' — run elevated, or add your account to the 'Event Log Readers' group
wevtail: no channels could be opened
```

From an elevated terminal, the marquee security demo:

```powershell
wevtail Security -e 4624,4625        # watch successful + failed logons, color-coded
```

## `.evtx` replay

wevtail reads exported log files with the same rendering and filtering as live channels.
Export with the built-in `wevtutil` (a separate Microsoft tool — not part of wevtail), then
replay:

```powershell
wevtutil epl System sys.evtx          # 1. export with wevtUTIL (Windows built-in)
wevtail sys.evtx -n 0                  # 2. replay ALL events with wevtail
wevtail sys.evtx -e 41                 # replay only Kernel-Power 41 (unexpected shutdowns)
wevtail sys.evtx --json | jq -r .provider | Group-Object -NoElement | Sort-Object Count -Descending
```

A target is treated as a file (not a channel) if it ends in `.evtx`/`.evt`/`.etl` or names
an existing file. For files, `-n 0` means **all** events (for channels it means none).

## Examples

<details open>
<summary><b>A gallery of real commands</b></summary>

```text
# Last 3 System events, no follow
$ wevtail System -n 3 --no-follow
2026-06-10 17:45:42.615 WARN  euchcmon/0 Detected unrecognized USB driver (\Driver\nxusbf).
2026-06-10 17:45:42.615 WARN  euchcmon/0 Detected unrecognized USB driver (\Driver\nxusbh).
2026-06-10 17:45:42.615 WARN  euchcmon/0 Detected unrecognized USB driver (\Driver\PnpManager).

# Service start/stop only (Event ID 7036)
$ wevtail System -e 7036 -n 2 --no-follow
2026-06-09 17:54:59.018 INFO  VfpExt/7036 The service entered the Driver load start state.
2026-06-09 17:54:59.019 INFO  VfpExt/7036 The service entered the Driver load complete state.

# Warnings and worse from the last 6 hours
$ wevtail System -l warning --since 6h --no-follow
2026-06-10 11:52:56.152 WARN  euchcmon/0 Detected unrecognized USB driver (\Driver\nxusbf).

# Discover channels
$ wevtail --list
AirSpaceChannel
AMSI/Debug
Analytic
Application
Autodesk REX
...

# One JSON object per event
$ wevtail Application -e 10001 -n 1 --no-follow --json
{"channel":"Application","computer":"HOST","data":{"RmSessionId":"0","UTCStartTime":"2026-06-10T21:08:50.7426197Z"},"event_id":10001,"keywords":"0x8000000000000000","level":4,"message":"Ending session 0 started 2026-06-10T21:08:50.742619700Z.","pid":12900,"provider":"Microsoft-Windows-RestartManager","record_id":351078,"severity":"info","task":0,"tid":64900,"ts":"2026-06-10T21:09:38.7106277Z","user_sid":"S-1-5-18"}

# Plays nicely with pipes — exits 0 when the reader closes early
$ wevtail System --no-follow -n 50 | head -1
2026-06-10 16:01:54.937 WARN  euchcmon/0 Detected unrecognized USB driver (\Driver\nxusbf).
```

</details>

## Behavior notes

- **Exit codes** — `0` on success (including a broken pipe, so `| head` is clean), `1` on
  error. A single bad channel among several is reported but doesn't abort the others; only
  if *every* channel fails to open does wevtail exit non-zero.
- **Time zones** — human output is **local** time; JSON `ts` is **UTC**.
- **Color** — auto for terminals, off for pipes/`--json`/`--no-color`/`NO_COLOR`.

## How it works

wevtail is a thin, safe layer over the Win32 Windows Event Log API (`wevtapi.dll`) via the
[`windows`](https://crates.io/crates/windows) crate. It uses the **pull subscription
model**: each channel gets a manual-reset signal event, the main thread blocks on all of
them with `WaitForMultipleObjects`, and drains ready events with `EvtNext` — no polling and
no FFI callbacks. Backfill uses a reverse-direction `EvtQuery` plus an `EvtCreateBookmark`
handoff; rendering goes through `EvtRender` (event XML, parsed with
[`quick-xml`](https://crates.io/crates/quick-xml)) and `EvtFormatMessage` for the
human-readable message.

## Limitations

- Windows only (10 / 11 / Server equivalents). The event log API is Windows-native.
- At most **64** live channels per invocation (`WaitForMultipleObjects` limit).
- Filtering uses the Event Log service's XPath 1.0 subset, not full XPath.
- `Analytic`/`Debug` channels can't be subscribed to live (a Windows restriction); export
  and replay them instead.

## Building

```powershell
cargo build --release        # optimized binary
cargo test                   # unit tests (XML parser, XPath builder, formatter)
cargo clippy --all-targets   # lints
```

## Releasing

Pushing a `vX.Y.Z` tag triggers [`.github/workflows/release.yml`](.github/workflows/release.yml),
which builds the MSI (`cargo-wix`) and a portable zip, generates `SHA256SUMS.txt`, and
publishes them to a GitHub Release. The tag **must** match the `Cargo.toml` version (the
workflow fails otherwise). The MSI's `UpgradeCode` lives in [`wix/main.wxs`](wix/main.wxs)
and must stay stable across releases so in-place upgrades and PATH cleanup work.

```powershell
# 1. bump `version` in Cargo.toml and add a CHANGELOG.md entry
# 2. cargo build --release; cargo test          # refreshes & verifies Cargo.lock
git commit -am "release: v0.2.0"
git tag -a v0.2.0 -m "v0.2.0"                    # tag == Cargo.toml version
git push && git push --tags                      # -> workflow builds & publishes
```

## Prior art and name

The `wevt` prefix comes from `wevtapi`, the Win32 API wevtail is built on. Not to be
confused with [christian-korneck/evtail](https://github.com/christian-korneck/evtail), an
unrelated (and dormant) Go tool with a similar goal — wevtail is an independent Rust
implementation that adds multiple-channel follow, JSON-lines output, XPath filtering,
`.evtx` replay, and remote tailing. It also pairs with, rather than replaces, Microsoft's
built-in `wevtutil` (which handles export and one-shot queries).

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
