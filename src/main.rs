//! wevtail — tail -f for Windows event logs.

mod cli;
mod event;
mod filter;
mod output;
mod wevt;

use std::io::{self, IsTerminal, Write};

use anyhow::{Context, Result, bail};
use clap::Parser;
use windows::Win32::System::EventLog::EVT_HANDLE;

use cli::Cli;
use wevt::{QueryDirection, QuerySource, Session, StartMode};

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(e) => {
            if is_broken_pipe(&e) {
                0
            } else {
                eprintln!("wevtail: {e:#}");
                1
            }
        }
    };
    std::process::exit(code);
}

fn is_broken_pipe(e: &anyhow::Error) -> bool {
    e.chain()
        .filter_map(|c| c.downcast_ref::<io::Error>())
        .any(|io| io.kind() == io::ErrorKind::BrokenPipe)
}

fn run() -> Result<()> {
    let mut cli = Cli::parse();

    let session = match &cli.remote {
        Some(host) => {
            // Hold the plaintext password in a Zeroizing buffer so its heap
            // memory is wiped on drop, and take it out of the Cli struct so
            // clap's copy doesn't linger for the whole process.
            let password: Option<zeroize::Zeroizing<String>> =
                match (cli.username.as_ref(), cli.password.take()) {
                    (Some(_), Some(p)) => Some(zeroize::Zeroizing::new(p)),
                    (Some(_), None) => Some(zeroize::Zeroizing::new(
                        rpassword::prompt_password(format!("Password for {host}: "))
                            .context("could not read password")?,
                    )),
                    _ => None,
                };
            Session::remote(
                host,
                cli.username.as_deref(),
                password.as_ref().map(|z| z.as_str()),
            )?
        }
        None => Session::local(),
    };

    if cli.list {
        let mut channels = wevt::list_channels(&session)?;
        channels.sort_by_key(|a| a.to_lowercase());
        let mut out = io::stdout().lock();
        for ch in channels {
            writeln!(out, "{ch}")?;
        }
        return Ok(());
    }

    let since_ms = cli.since.as_deref().map(filter::parse_since).transpose()?;
    let xpath = filter::build_xpath(&filter::Filters {
        raw: cli.query.as_deref(),
        ids: &cli.ids,
        min_level: cli.level,
        providers: &cli.providers,
        since_ms,
    })?;

    let targets: Vec<String> = if cli.channels.is_empty() {
        vec!["System".to_string(), "Application".to_string()]
    } else {
        cli.channels.clone()
    };
    let (files, channels): (Vec<&String>, Vec<&String>) =
        targets.iter().partition(|t| looks_like_file(t));

    if channels.len() > wevt::MAX_CHANNELS {
        bail!(
            "too many channels ({}); wevtail can follow at most {}",
            channels.len(),
            wevt::MAX_CHANNELS
        );
    }

    let color = !cli.json
        && !cli.no_color
        && std::env::var_os("NO_COLOR").is_none()
        && io::stdout().is_terminal()
        && output::enable_vt();
    let formatter = output::Formatter {
        json: cli.json,
        color,
        show_channel: files.len() + channels.len() > 1,
        multiline: cli.multiline,
    };
    let mut printer = Printer {
        formatter,
        publishers: wevt::PublisherCache::new(&session),
        out: io::stdout(),
    };

    // Window/replay semantics: --since and --from-start define the start of
    // the stream; otherwise we backfill the last N events tail-style.
    let full_replay = cli.from_start || since_ms.is_some();

    for file in &files {
        let path = std::path::absolute(file.as_str())
            .with_context(|| format!("bad path '{file}'"))?
            .to_string_lossy()
            .into_owned();
        if full_replay || cli.lines == 0 {
            print_all_forward(&session, &path, xpath.as_deref(), QuerySource::File, &mut printer, file)?;
        } else {
            print_last_n(&session, &path, xpath.as_deref(), QuerySource::File, cli.lines as usize, &mut printer, file)?;
        }
    }

    if channels.is_empty() {
        return Ok(());
    }

    let mut subscriptions = Vec::new();
    let mut failures = 0usize;
    for channel in &channels {
        match setup_channel(&session, channel, &cli, xpath.as_deref(), full_replay, &mut printer) {
            Ok(Some(sub)) => subscriptions.push(sub),
            Ok(None) => {}
            // A broken pipe during backfill (e.g. `| head`) is a clean exit,
            // not a channel-open failure — let it reach main()'s handler.
            Err(e) if is_broken_pipe(&e) => return Err(e),
            Err(e) => {
                eprintln!("wevtail: {e:#}");
                failures += 1;
            }
        }
    }
    if failures == channels.len() && failures > 0 {
        bail!("no channels could be opened");
    }
    if cli.no_follow || subscriptions.is_empty() {
        return Ok(());
    }

    loop {
        // Block until at least one channel signals, then drain *every*
        // subscription so a chatty low-index channel can't starve the rest
        // (WaitForMultipleObjects always reports the lowest signaled index).
        wevt::wait_any(&subscriptions)?;
        for sub in &subscriptions {
            let label = sub.label.clone();
            sub.drain_with(|ev| printer.emit(&label, ev))?;
        }
    }
}

/// Per-channel setup: backfill, then subscribe with a gapless handoff.
/// Returns `None` when not following (--no-follow).
fn setup_channel(
    session: &Session,
    channel: &str,
    cli: &Cli,
    xpath: Option<&str>,
    full_replay: bool,
    printer: &mut Printer,
) -> Result<Option<wevt::Subscription>> {
    if cli.no_follow {
        if full_replay {
            print_all_forward(session, channel, xpath, QuerySource::Channel, printer, channel)?;
        } else {
            print_last_n(session, channel, xpath, QuerySource::Channel, cli.lines as usize, printer, channel)?;
        }
        return Ok(None);
    }
    if full_replay {
        // --since relies on the timediff() XPath to bound the window; the
        // subscription scans from the oldest record and then keeps following.
        return Ok(Some(wevt::subscribe(session, channel, xpath, StartMode::Oldest)?));
    }
    let bookmark = print_last_n(
        session,
        channel,
        xpath,
        QuerySource::Channel,
        cli.lines as usize,
        printer,
        channel,
    )?;
    let mode = match &bookmark {
        Some(b) => StartMode::AfterBookmark(b),
        // No bookmark: either the user opted out of backfill (-n 0 → future
        // events only), or the backfill found nothing — in which case start
        // from the oldest record so a sparse channel stays gapless.
        None if cli.lines == 0 => StartMode::Future,
        None => StartMode::Oldest,
    };
    Ok(Some(wevt::subscribe(session, channel, xpath, mode)?))
}

/// Print the last `n` matching events (oldest first), returning a bookmark at
/// the newest one so a subscription can resume exactly after it.
fn print_last_n(
    session: &Session,
    path: &str,
    xpath: Option<&str>,
    source: QuerySource,
    n: usize,
    printer: &mut Printer,
    label: &str,
) -> Result<Option<windows::core::Owned<EVT_HANDLE>>> {
    if n == 0 {
        return Ok(None);
    }
    let q = wevt::query(session, path, xpath, source, QueryDirection::Reverse)?;
    let mut events = Vec::new();
    while events.len() < n {
        let want = (n - events.len()).min(16);
        let batch = wevt::next_events(*q, want, false)?;
        if batch.is_empty() {
            break;
        }
        events.extend(batch);
    }
    let bookmark = match events.first() {
        Some(newest) => Some(wevt::bookmark_from(**newest)?),
        None => None,
    };
    for ev in events.iter().rev() {
        printer.emit(label, **ev)?;
    }
    Ok(bookmark)
}

fn print_all_forward(
    session: &Session,
    path: &str,
    xpath: Option<&str>,
    source: QuerySource,
    printer: &mut Printer,
    label: &str,
) -> Result<()> {
    let q = wevt::query(session, path, xpath, source, QueryDirection::Forward)?;
    loop {
        let batch = wevt::next_events(*q, 16, false)?;
        if batch.is_empty() {
            return Ok(());
        }
        for ev in &batch {
            printer.emit(label, **ev)?;
        }
    }
}

struct Printer<'s> {
    formatter: output::Formatter,
    publishers: wevt::PublisherCache<'s>,
    out: io::Stdout,
}

impl Printer<'_> {
    /// Render, parse, resolve the message, and print one event. Malformed
    /// events are reported to stderr but never kill the tail; only I/O
    /// errors (e.g. broken pipe) propagate.
    fn emit(&mut self, channel_label: &str, ev: EVT_HANDLE) -> Result<()> {
        let xml = match wevt::render_xml(ev) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("wevtail: failed to render event: {e:#}");
                return Ok(());
            }
        };
        let mut rec = match event::parse_event_xml(&xml) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("wevtail: failed to parse event XML: {e:#}");
                return Ok(());
            }
        };
        if rec.channel.is_empty() {
            rec.channel = channel_label.to_string();
        }
        let metadata = self.publishers.get(&rec.provider);
        rec.message = wevt::format_message(metadata, ev);
        let mut out = self.out.lock();
        self.formatter
            .write_record(&mut out, &rec)
            .context("write failed")?;
        Ok(())
    }
}

fn looks_like_file(arg: &str) -> bool {
    let lower = arg.to_ascii_lowercase();
    lower.ends_with(".evtx")
        || lower.ends_with(".evt")
        || lower.ends_with(".etl")
        || std::path::Path::new(arg).is_file()
}
