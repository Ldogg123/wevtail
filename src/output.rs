//! Human-readable (colorized) and JSON-lines output.

use std::io::{self, Write};

use owo_colors::{OwoColorize, Style};
use serde_json::{Map, Value, json};

use crate::event::{EventRecord, Severity};

pub struct Formatter {
    pub json: bool,
    pub color: bool,
    pub show_channel: bool,
    pub multiline: bool,
}

impl Formatter {
    pub fn write_record(&self, w: &mut impl Write, rec: &EventRecord) -> io::Result<()> {
        if self.json {
            self.write_json(w, rec)
        } else {
            self.write_human(w, rec)
        }
    }

    fn paint(&self, s: &str, style: Style) -> String {
        if self.color {
            s.style(style).to_string()
        } else {
            s.to_string()
        }
    }

    fn write_human(&self, w: &mut impl Write, rec: &EventRecord) -> io::Result<()> {
        let sev = rec.severity();
        let ts = match &rec.time_utc {
            Some(t) => t
                .to_zoned(jiff::tz::TimeZone::system())
                .strftime("%Y-%m-%d %H:%M:%S%.3f")
                .to_string(),
            None => format!("{:<23}", "-"),
        };

        let mut line = String::new();
        line.push_str(&self.paint(&ts, Style::new().dimmed()));
        line.push(' ');
        line.push_str(&self.paint(&format!("{:<5}", sev.label()), severity_style(sev)));
        line.push(' ');
        if self.show_channel && !rec.channel.is_empty() {
            line.push_str(&self.paint(&rec.channel, Style::new().cyan()));
            line.push(' ');
        }
        let provider = rec
            .provider
            .strip_prefix("Microsoft-Windows-")
            .unwrap_or(&rec.provider);
        let source = format!(
            "{}/{}",
            if provider.is_empty() { "?" } else { provider },
            rec.event_id
        );
        line.push_str(&self.paint(&source, Style::new().magenta()));
        line.push(' ');

        match (&rec.message, self.multiline) {
            (Some(m), true) => {
                let mut lines = m.lines();
                if let Some(first) = lines.next() {
                    line.push_str(first);
                }
                writeln!(w, "{line}")?;
                for l in lines {
                    writeln!(w, "    {l}")?;
                }
                return Ok(());
            }
            (Some(m), false) => line.push_str(&collapse_whitespace(m)),
            (None, _) => line.push_str(&format_data(&rec.data)),
        }
        writeln!(w, "{line}")
    }

    fn write_json(&self, w: &mut impl Write, rec: &EventRecord) -> io::Result<()> {
        let mut m = Map::new();
        if let Some(t) = &rec.time_utc {
            m.insert("ts".to_string(), json!(t.to_string()));
        }
        m.insert("channel".to_string(), json!(rec.channel));
        m.insert("provider".to_string(), json!(rec.provider));
        m.insert("event_id".to_string(), json!(rec.event_id));
        m.insert("severity".to_string(), json!(rec.severity().json_name()));
        m.insert("level".to_string(), json!(rec.level));
        if let Some(v) = rec.task {
            m.insert("task".to_string(), json!(v));
        }
        if let Some(v) = rec.keywords {
            m.insert("keywords".to_string(), json!(format!("{v:#x}")));
        }
        if let Some(v) = rec.record_id {
            m.insert("record_id".to_string(), json!(v));
        }
        if !rec.computer.is_empty() {
            m.insert("computer".to_string(), json!(rec.computer));
        }
        if let Some(v) = rec.pid {
            m.insert("pid".to_string(), json!(v));
        }
        if let Some(v) = rec.tid {
            m.insert("tid".to_string(), json!(v));
        }
        if let Some(v) = &rec.user_sid {
            m.insert("user_sid".to_string(), json!(v));
        }
        if let Some(v) = &rec.activity_id {
            m.insert("activity_id".to_string(), json!(v));
        }
        if let Some(msg) = &rec.message {
            m.insert("message".to_string(), json!(msg));
        }
        if !rec.data.is_empty() {
            let mut d = Map::new();
            for (k, v) in &rec.data {
                d.insert(k.clone(), json!(v));
            }
            m.insert("data".to_string(), Value::Object(d));
        }
        let s = serde_json::to_string(&Value::Object(m))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        writeln!(w, "{s}")
    }
}

fn severity_style(sev: Severity) -> Style {
    match sev {
        Severity::Critical => Style::new().bright_red().bold(),
        Severity::Error => Style::new().red(),
        Severity::Warning => Style::new().yellow(),
        Severity::Info => Style::new().green(),
        Severity::Verbose => Style::new().dimmed(),
        Severity::AuditSuccess => Style::new().green(),
        Severity::AuditFailure => Style::new().bright_red().bold(),
    }
}

fn collapse_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn format_data(data: &[(String, String)]) -> String {
    if data.is_empty() {
        return "(no message)".to_string();
    }
    data.iter()
        .map(|(k, v)| {
            if v.is_empty() || v.chars().any(char::is_whitespace) {
                format!("{k}=\"{v}\"")
            } else {
                format!("{k}={v}")
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Enable ANSI escape processing on legacy conhost; Windows Terminal already
/// has it on. Returns false when stdout is not a console that supports VT.
pub fn enable_vt() -> bool {
    use windows::Win32::System::Console::{
        CONSOLE_MODE, ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode, GetStdHandle,
        STD_OUTPUT_HANDLE, SetConsoleMode,
    };
    unsafe {
        let Ok(handle) = GetStdHandle(STD_OUTPUT_HANDLE) else {
            return false;
        };
        let mut mode = CONSOLE_MODE(0);
        if GetConsoleMode(handle, &mut mode).is_err() {
            return false;
        }
        SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> EventRecord {
        EventRecord {
            channel: "Security".to_string(),
            provider: "Microsoft-Windows-Security-Auditing".to_string(),
            event_id: 4625,
            level: 0,
            keywords: Some(0x8010000000000000),
            time_utc: "2026-06-10T17:00:01.123Z".parse().ok(),
            record_id: Some(42),
            computer: "DC1".to_string(),
            pid: Some(712),
            message: Some("An account failed to log on.\n\nSubject:\n\tSecurity ID: S-1-0-0".to_string()),
            data: vec![("TargetUserName".to_string(), "bob".to_string())],
            ..Default::default()
        }
    }

    #[test]
    fn human_line_is_single_line_by_default() {
        let f = Formatter { json: false, color: false, show_channel: true, multiline: false };
        let mut buf = Vec::new();
        f.write_record(&mut buf, &record()).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert_eq!(s.lines().count(), 1);
        assert!(s.contains("FAIL"));
        assert!(s.contains("Security-Auditing/4625"));
        assert!(s.contains("An account failed to log on. Subject: Security ID: S-1-0-0"));
    }

    #[test]
    fn json_line_round_trips() {
        let f = Formatter { json: true, color: false, show_channel: true, multiline: false };
        let mut buf = Vec::new();
        f.write_record(&mut buf, &record()).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["event_id"], 4625);
        assert_eq!(v["severity"], "audit_failure");
        assert_eq!(v["data"]["TargetUserName"], "bob");
        assert_eq!(v["keywords"], "0x8010000000000000");
    }

    #[test]
    fn data_fallback_when_no_message() {
        let mut rec = record();
        rec.message = None;
        let f = Formatter { json: false, color: false, show_channel: false, multiline: false };
        let mut buf = Vec::new();
        f.write_record(&mut buf, &rec).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("TargetUserName=bob"));
    }
}
