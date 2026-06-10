//! Thin safe layer over the modern Windows event log API (wevtapi.dll, winevt.h).
//!
//! Uses the pull subscription model: each subscription gets a manual-reset
//! signal event; the main thread waits on all of them with
//! `WaitForMultipleObjects` and drains via `EvtNext`. This keeps everything
//! single-threaded (no FFI callbacks) at the cost of a 64-channel ceiling.

use std::collections::HashMap;
use std::ffi::c_void;

use anyhow::{Result, anyhow, bail};
use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_EVT_CHANNEL_NOT_FOUND, ERROR_EVT_INVALID_QUERY,
    ERROR_EVT_MAX_INSERTS_REACHED, ERROR_EVT_UNRESOLVED_PARAMETER_INSERT,
    ERROR_EVT_UNRESOLVED_VALUE_INSERT, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_OPERATION,
    ERROR_NO_MORE_ITEMS, ERROR_TIMEOUT, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WIN32_ERROR,
};
use windows::Win32::System::EventLog::{
    EVT_HANDLE, EVT_RPC_LOGIN, EvtClose, EvtCreateBookmark, EvtFormatMessage,
    EvtFormatMessageEvent, EvtGetExtendedStatus, EvtNext, EvtNextChannelPath, EvtOpenChannelEnum,
    EvtOpenPublisherMetadata, EvtOpenSession, EvtQuery, EvtQueryChannelPath, EvtQueryFilePath,
    EvtQueryForwardDirection, EvtQueryReverseDirection, EvtRender, EvtRenderEventXml,
    EvtRpcLogin, EvtRpcLoginAuthDefault, EvtSubscribe, EvtSubscribeStartAfterBookmark,
    EvtSubscribeStartAtOldestRecord, EvtSubscribeToFutureEvents, EvtUpdateBookmark,
};
use windows::Win32::System::Threading::{
    CreateEventW, INFINITE, ResetEvent, WaitForMultipleObjects,
};
use windows::core::{Owned, PCWSTR, PWSTR};

/// `WaitForMultipleObjects` cannot wait on more than 64 handles.
pub const MAX_CHANNELS: usize = 64;

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn is_win32(e: &windows::core::Error, w: WIN32_ERROR) -> bool {
    e.code() == w.to_hresult()
}

// RPC errors live in a different windows-rs feature module; compare numerically.
const RPC_S_SERVER_UNAVAILABLE: WIN32_ERROR = WIN32_ERROR(1722);
const RPC_S_INVALID_BOUND: WIN32_ERROR = WIN32_ERROR(1734);

/// EvtFormatMessage returns these when a message string has inserts it can't
/// substitute, but the buffer still holds the message with the literal `%n`
/// placeholders left in — usable output, not a failure. (Matches how
/// winlogbeat and Get-WinEvent treat 15029/15030/15031.)
fn is_partial_insert(e: &windows::core::Error) -> bool {
    is_win32(e, ERROR_EVT_UNRESOLVED_VALUE_INSERT)
        || is_win32(e, ERROR_EVT_UNRESOLVED_PARAMETER_INSERT)
        || is_win32(e, ERROR_EVT_MAX_INSERTS_REACHED)
}

/// Detail string for ERROR_EVT_INVALID_QUERY failures (position of the
/// syntax error etc.), straight from the service.
fn extended_status() -> Option<String> {
    unsafe {
        let mut used = 0u32;
        if EvtGetExtendedStatus(None, &mut used) != ERROR_INSUFFICIENT_BUFFER.0 || used == 0 {
            return None;
        }
        let mut buf = vec![0u16; used as usize];
        if EvtGetExtendedStatus(Some(&mut buf), &mut used) != 0 {
            return None;
        }
        let n = (used as usize).min(buf.len());
        let s = String::from_utf16_lossy(&buf[..n])
            .trim_end_matches('\0')
            .trim()
            .to_string();
        (!s.is_empty()).then_some(s)
    }
}

/// Translate the open/subscribe failures users actually hit into actionable messages.
fn friendly_open_error(e: windows::core::Error, what: &str) -> anyhow::Error {
    if is_win32(&e, ERROR_EVT_CHANNEL_NOT_FOUND) {
        anyhow!("channel '{what}' not found (run `wevtail --list` to see available channels)")
    } else if is_win32(&e, ERROR_ACCESS_DENIED) {
        anyhow!(
            "access denied to '{what}' — run elevated, or add your account to the 'Event Log Readers' group \
             (on a remote session this can also mean bad credentials)"
        )
    } else if is_win32(&e, ERROR_EVT_INVALID_QUERY) {
        match extended_status() {
            Some(detail) => anyhow!("invalid XPath query for '{what}': {detail}"),
            None => anyhow!(
                "invalid XPath query for '{what}' (event log queries support a subset of XPath 1.0)"
            ),
        }
    } else if is_win32(&e, RPC_S_SERVER_UNAVAILABLE) {
        anyhow!(
            "cannot reach the event log service for '{what}' — on the remote machine, enable the \
             'Remote Event Log Management' firewall rule group"
        )
    } else {
        anyhow!(e).context(format!("failed to open '{what}'"))
    }
}

/// A local or remote event log session. `None` means the local machine.
pub struct Session(Option<Owned<EVT_HANDLE>>);

impl Session {
    pub fn local() -> Self {
        Session(None)
    }

    pub fn remote(server: &str, user: Option<&str>, password: Option<&str>) -> Result<Self> {
        // Accept DOMAIN\user and user@domain forms.
        let (domain, user) = match user {
            Some(u) => match u.split_once('\\') {
                Some((d, u)) => (Some(d.to_string()), Some(u.to_string())),
                None => match u.split_once('@') {
                    Some((u, d)) => (Some(d.to_string()), Some(u.to_string())),
                    None => (None, Some(u.to_string())),
                },
            },
            None => (None, None),
        };

        let mut server_w = to_wide(server);
        let mut user_w = user.as_deref().map(to_wide);
        let mut domain_w = domain.as_deref().map(to_wide);
        let mut password_w = password.map(to_wide);

        fn pwstr(v: &mut Option<Vec<u16>>) -> PWSTR {
            v.as_mut().map_or(PWSTR::null(), |b| PWSTR(b.as_mut_ptr()))
        }

        let login = EVT_RPC_LOGIN {
            Server: PWSTR(server_w.as_mut_ptr()),
            User: pwstr(&mut user_w),
            Domain: pwstr(&mut domain_w),
            Password: pwstr(&mut password_w),
            Flags: EvtRpcLoginAuthDefault.0,
        };
        let result = unsafe {
            EvtOpenSession(EvtRpcLogin, &login as *const _ as *const c_void, None, None)
        };
        // EvtOpenSession copies the credentials, so wipe our UTF-16 copy. The
        // caller owns the plaintext (in a Zeroizing buffer) and wipes that.
        if let Some(p) = password_w.as_mut() {
            p.fill(0);
        }
        // EvtOpenSession is lazy — it usually fails here only on bad input;
        // unreachable-host/firewall and bad-credential failures often surface
        // now, so give them the same actionable hints as query/subscribe.
        let h = result.map_err(|e| friendly_open_error(e, server))?;
        Ok(Session(Some(unsafe { Owned::new(h) })))
    }

    fn raw(&self) -> Option<EVT_HANDLE> {
        self.0.as_ref().map(|h| **h)
    }
}

/// Render an event as its XML representation.
pub fn render_xml(event: EVT_HANDLE) -> Result<String> {
    unsafe {
        let mut used = 0u32;
        let mut props = 0u32;
        match EvtRender(None, event, EvtRenderEventXml.0, 0, None, &mut used, &mut props) {
            Ok(()) => return Ok(String::new()),
            Err(e) if is_win32(&e, ERROR_INSUFFICIENT_BUFFER) => {}
            Err(e) => return Err(anyhow!(e).context("EvtRender size probe failed")),
        }
        // EvtRender sizes are in bytes; round up to whole UTF-16 units.
        let mut buf = vec![0u16; (used as usize).div_ceil(2)];
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            (buf.len() * 2) as u32,
            Some(buf.as_mut_ptr().cast()),
            &mut used,
            &mut props,
        )
        .map_err(|e| anyhow!(e).context("EvtRender failed"))?;
        let n = (used as usize / 2).min(buf.len());
        Ok(String::from_utf16_lossy(&buf[..n])
            .trim_end_matches('\0')
            .to_string())
    }
}

/// Resolve the human-readable message for an event, if the publisher provides one.
///
/// Returns `None` when the publisher is unregistered or the message can't be
/// resolved — callers fall back to rendering the raw event data.
pub fn format_message(metadata: Option<EVT_HANDLE>, event: EVT_HANDLE) -> Option<String> {
    unsafe {
        let mut used = 0u32;
        let probe = EvtFormatMessage(
            metadata,
            Some(event),
            0,
            None,
            EvtFormatMessageEvent.0,
            None,
            &mut used,
        );
        match probe {
            Ok(()) => return None,
            Err(e) if is_win32(&e, ERROR_INSUFFICIENT_BUFFER) || is_partial_insert(&e) => {}
            Err(_) => return None,
        }
        if used == 0 {
            return None;
        }
        // EvtFormatMessage sizes are in WCHARs (unlike EvtRender's bytes).
        let mut buf = vec![0u16; used as usize];
        let res = EvtFormatMessage(
            metadata,
            Some(event),
            0,
            None,
            EvtFormatMessageEvent.0,
            Some(&mut buf),
            &mut used,
        );
        match res {
            Ok(()) => {}
            // Partial message with literal %n inserts left in — still useful.
            Err(e) if is_partial_insert(&e) => {}
            Err(_) => return None,
        }
        let n = (used as usize).min(buf.len());
        let s = String::from_utf16_lossy(&buf[..n])
            .trim_end_matches('\0')
            .trim_end()
            .to_string();
        (!s.is_empty()).then_some(s)
    }
}

/// Caches `EvtOpenPublisherMetadata` handles per provider; failed lookups are
/// cached too so unregistered providers aren't retried per event.
pub struct PublisherCache<'s> {
    session: &'s Session,
    map: HashMap<String, Option<Owned<EVT_HANDLE>>>,
}

impl<'s> PublisherCache<'s> {
    pub fn new(session: &'s Session) -> Self {
        PublisherCache {
            session,
            map: HashMap::new(),
        }
    }

    pub fn get(&mut self, provider: &str) -> Option<EVT_HANDLE> {
        if provider.is_empty() {
            return None;
        }
        if !self.map.contains_key(provider) {
            let wide = to_wide(provider);
            let h = unsafe {
                EvtOpenPublisherMetadata(
                    self.session.raw(),
                    PCWSTR(wide.as_ptr()),
                    PCWSTR::null(),
                    0,
                    0,
                )
            }
            .ok()
            .map(|h| unsafe { Owned::new(h) });
            self.map.insert(provider.to_string(), h);
        }
        self.map.get(provider).unwrap().as_ref().map(|h| **h)
    }
}

pub enum QuerySource {
    Channel,
    File,
}

pub enum QueryDirection {
    Forward,
    Reverse,
}

/// Open a query over a channel or an .evtx file.
pub fn query(
    session: &Session,
    path: &str,
    xpath: Option<&str>,
    source: QuerySource,
    direction: QueryDirection,
) -> Result<Owned<EVT_HANDLE>> {
    let flags = match source {
        QuerySource::Channel => EvtQueryChannelPath.0,
        QuerySource::File => EvtQueryFilePath.0,
    } | match direction {
        QueryDirection::Forward => EvtQueryForwardDirection.0,
        QueryDirection::Reverse => EvtQueryReverseDirection.0,
    };
    let path_w = to_wide(path);
    let query_w = to_wide(xpath.unwrap_or("*"));
    let h = unsafe {
        EvtQuery(
            session.raw(),
            PCWSTR(path_w.as_ptr()),
            PCWSTR(query_w.as_ptr()),
            flags,
        )
    }
    .map_err(|e| friendly_open_error(e, path))?;
    Ok(unsafe { Owned::new(h) })
}

/// Pull the next batch of events from a query or subscription handle.
/// An empty vec means the result set is (currently) drained.
///
/// `subscription` marks a live pull subscription (vs a one-shot query): a
/// drained subscription can report `ERROR_INVALID_OPERATION`/`ERROR_TIMEOUT`
/// in addition to `ERROR_NO_MORE_ITEMS`, whereas on a query those codes are
/// genuine failures that must not be mistaken for end-of-results.
pub fn next_events(
    handle: EVT_HANDLE,
    batch: usize,
    subscription: bool,
) -> Result<Vec<Owned<EVT_HANDLE>>> {
    let mut want = batch.max(1);
    let mut raw = vec![0isize; want];
    let mut returned = 0u32;
    // Timeout 0: never block — the wait happens on the signal event instead.
    let result = loop {
        match unsafe { EvtNext(handle, &mut raw[..want], 0, 0, &mut returned) } {
            // Very large events can overflow EvtNext's internal RPC buffer
            // (RPC_S_INVALID_BOUND); the docs' remedy is a smaller batch.
            Err(e) if is_win32(&e, RPC_S_INVALID_BOUND) && want > 1 => {
                want = (want / 2).max(1);
                returned = 0;
                continue;
            }
            other => break other,
        }
    };
    match result {
        Ok(()) => Ok(raw[..returned as usize]
            .iter()
            .map(|&v| unsafe { Owned::new(EVT_HANDLE(v)) })
            .collect()),
        Err(e) if is_win32(&e, ERROR_NO_MORE_ITEMS) => Ok(Vec::new()),
        Err(e)
            if subscription
                && (is_win32(&e, ERROR_INVALID_OPERATION) || is_win32(&e, ERROR_TIMEOUT)) =>
        {
            Ok(Vec::new())
        }
        Err(e) => Err(anyhow!(e).context("EvtNext failed")),
    }
}

/// Create a bookmark positioned at `event`, for gapless query→subscribe handoff.
pub fn bookmark_from(event: EVT_HANDLE) -> Result<Owned<EVT_HANDLE>> {
    let bm = unsafe { EvtCreateBookmark(PCWSTR::null()) }
        .map_err(|e| anyhow!(e).context("EvtCreateBookmark failed"))?;
    let bm = unsafe { Owned::new(bm) };
    unsafe { EvtUpdateBookmark(*bm, event) }
        .map_err(|e| anyhow!(e).context("EvtUpdateBookmark failed"))?;
    Ok(bm)
}

pub enum StartMode<'a> {
    /// Only events logged after the subscription is created.
    Future,
    /// Everything in the channel, then keep following.
    Oldest,
    /// Events after the bookmarked position (closes the backfill→follow gap).
    AfterBookmark(&'a Owned<EVT_HANDLE>),
}

/// A live pull-model subscription to one channel.
pub struct Subscription {
    pub label: String,
    signal: Owned<HANDLE>,
    handle: Owned<EVT_HANDLE>,
}

pub fn subscribe(
    session: &Session,
    channel: &str,
    xpath: Option<&str>,
    mode: StartMode,
) -> Result<Subscription> {
    // Manual-reset, initially signaled: the documented pull-model pattern —
    // the first wait falls through and the drain discovers any backlog.
    let signal = unsafe { CreateEventW(None, true, true, PCWSTR::null()) }
        .map_err(|e| anyhow!(e).context("CreateEventW failed"))?;
    let signal = unsafe { Owned::new(signal) };

    let channel_w = to_wide(channel);
    let query_w = to_wide(xpath.unwrap_or("*"));
    let (flags, bookmark) = match mode {
        StartMode::Future => (EvtSubscribeToFutureEvents.0, None),
        StartMode::Oldest => (EvtSubscribeStartAtOldestRecord.0, None),
        StartMode::AfterBookmark(b) => (EvtSubscribeStartAfterBookmark.0, Some(**b)),
    };
    let h = unsafe {
        EvtSubscribe(
            session.raw(),
            Some(*signal),
            PCWSTR(channel_w.as_ptr()),
            PCWSTR(query_w.as_ptr()),
            bookmark,
            None,
            None,
            flags,
        )
    }
    .map_err(|e| friendly_open_error(e, channel))?;

    Ok(Subscription {
        label: channel.to_string(),
        signal,
        handle: unsafe { Owned::new(h) },
    })
}

impl Subscription {
    pub fn signal_handle(&self) -> HANDLE {
        *self.signal
    }

    /// Drain all currently-available events, invoking `f` for each, then
    /// reset the signal. Re-checks once after the reset to close the race
    /// where an event lands between the final empty EvtNext and ResetEvent.
    pub fn drain_with(&self, mut f: impl FnMut(EVT_HANDLE) -> Result<()>) -> Result<()> {
        loop {
            let batch = next_events(*self.handle, 16, true)?;
            if !batch.is_empty() {
                for ev in &batch {
                    f(**ev)?;
                }
                continue;
            }
            unsafe { ResetEvent(*self.signal) }
                .map_err(|e| anyhow!(e).context("ResetEvent failed"))?;
            let recheck = next_events(*self.handle, 16, true)?;
            if recheck.is_empty() {
                return Ok(());
            }
            for ev in &recheck {
                f(**ev)?;
            }
        }
    }
}

/// Block until any subscription has events; returns its index.
pub fn wait_any(subs: &[Subscription]) -> Result<usize> {
    let handles: Vec<HANDLE> = subs.iter().map(|s| s.signal_handle()).collect();
    let res = unsafe { WaitForMultipleObjects(&handles, false, INFINITE) };
    if res == WAIT_FAILED {
        bail!(
            "WaitForMultipleObjects failed: {}",
            windows::core::Error::from_thread()
        );
    }
    let idx = res.0.wrapping_sub(WAIT_OBJECT_0.0) as usize;
    if idx >= subs.len() {
        bail!("unexpected wait result: {}", res.0);
    }
    Ok(idx)
}

/// Enumerate channel names visible to the session.
pub fn list_channels(session: &Session) -> Result<Vec<String>> {
    let e = unsafe { EvtOpenChannelEnum(session.raw(), 0) }
        .map_err(|e| friendly_open_error(e, "the event log service"))?;
    let e = unsafe { Owned::new(e) };
    let mut out = Vec::new();
    loop {
        let mut used = 0u32;
        match unsafe { EvtNextChannelPath(*e, None, &mut used) } {
            Ok(()) => {}
            Err(err) if is_win32(&err, ERROR_NO_MORE_ITEMS) => break,
            Err(err) if is_win32(&err, ERROR_INSUFFICIENT_BUFFER) => {
                let mut buf = vec![0u16; used as usize];
                unsafe { EvtNextChannelPath(*e, Some(&mut buf), &mut used) }
                    .map_err(|e| anyhow!(e).context("EvtNextChannelPath failed"))?;
                let n = (used as usize).min(buf.len());
                out.push(
                    String::from_utf16_lossy(&buf[..n])
                        .trim_end_matches('\0')
                        .to_string(),
                );
            }
            Err(err) => return Err(anyhow!(err).context("EvtNextChannelPath failed")),
        }
    }
    Ok(out)
}

// EvtClose is referenced only through Owned<EVT_HANDLE>'s Free impl, but keep
// the import alive for documentation purposes.
#[allow(dead_code)]
fn _close(h: EVT_HANDLE) {
    unsafe {
        let _ = EvtClose(h);
    }
}
