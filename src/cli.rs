//! Command-line interface.

use clap::Parser;

use crate::filter::MinLevel;

#[derive(Parser, Debug)]
#[command(
    name = "wevtail",
    version,
    about = "tail -f for Windows event logs",
    long_about = "Follow Windows event log channels live (push-based, no polling), \
                  replay .evtx files, and filter with XPath — like tail -f, but for wevt.\n\n\
                  Examples:\n  \
                  wevtail                                  follow System + Application\n  \
                  wevtail Security -e 4624,4625            watch logons (needs elevation)\n  \
                  wevtail \"Microsoft-Windows-Sysmon/Operational\" --json | jq .\n  \
                  wevtail System -l error --since 2h       errors from the last two hours\n  \
                  wevtail exported.evtx -n 50              last 50 events of an export\n  \
                  wevtail -r dc01.lab -u LAB\\\\admin Security   tail a remote DC"
)]
pub struct Cli {
    /// Channels to follow, or .evtx files to replay (default: System Application)
    #[arg(value_name = "CHANNEL|FILE")]
    pub channels: Vec<String>,

    /// Print the last N matching events before following (0 = none; for files: 0 = all)
    #[arg(short = 'n', long = "lines", default_value_t = 10, value_name = "N")]
    pub lines: u32,

    /// Print matching events and exit instead of following
    #[arg(long)]
    pub no_follow: bool,

    /// Start from the oldest record (full replay, then follow)
    #[arg(long, conflicts_with = "since")]
    pub from_start: bool,

    /// Only events newer than a duration (15m, 2h30m) or timestamp (2026-06-10T12:00)
    #[arg(long, value_name = "WHEN")]
    pub since: Option<String>,

    /// Raw XPath filter, e.g. "*[System[EventID=4625]]"
    #[arg(short = 'q', long, value_name = "XPATH")]
    pub query: Option<String>,

    /// Filter by event id(s): 4625 or 4624,4625 or 4000-4999
    #[arg(short = 'e', long = "id", value_delimiter = ',', value_name = "ID")]
    pub ids: Vec<String>,

    /// Minimum severity to show
    #[arg(short = 'l', long, value_enum, value_name = "LEVEL")]
    pub level: Option<MinLevel>,

    /// Filter by provider name (repeatable)
    #[arg(short = 'p', long = "provider", value_name = "NAME")]
    pub providers: Vec<String>,

    /// Output one JSON object per event (JSON lines)
    #[arg(long)]
    pub json: bool,

    /// Print full multi-line messages (default collapses each event to one line)
    #[arg(long)]
    pub multiline: bool,

    /// Disable colored output
    #[arg(long)]
    pub no_color: bool,

    /// Tail the event logs of a remote computer
    #[arg(short = 'r', long, value_name = "HOST")]
    pub remote: Option<String>,

    /// Username for the remote session (DOMAIN\user or user@domain)
    #[arg(short = 'u', long, requires = "remote", value_name = "USER")]
    pub username: Option<String>,

    /// Password for the remote session (prompted when --username is given without it)
    #[arg(long, requires = "username", value_name = "PASS")]
    pub password: Option<String>,

    /// List available channels and exit
    #[arg(long)]
    pub list: bool,
}
