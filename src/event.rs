//! Parse the event XML produced by `EvtRender` into a flat record.

use anyhow::{Context, Result};
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event as XmlEvent};

#[derive(Debug, Default, Clone)]
pub struct EventRecord {
    pub channel: String,
    pub provider: String,
    pub event_id: u32,
    pub level: u8,
    pub task: Option<u16>,
    pub keywords: Option<u64>,
    pub time_utc: Option<jiff::Timestamp>,
    pub record_id: Option<u64>,
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub computer: String,
    pub user_sid: Option<String>,
    pub activity_id: Option<String>,
    /// EventData / UserData values, in document order.
    pub data: Vec<(String, String)>,
    /// Resolved publisher message, filled in by the caller.
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    Error,
    Warning,
    Info,
    Verbose,
    AuditSuccess,
    AuditFailure,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "CRIT",
            Severity::Error => "ERROR",
            Severity::Warning => "WARN",
            Severity::Info => "INFO",
            Severity::Verbose => "VERB",
            Severity::AuditSuccess => "AUDIT",
            Severity::AuditFailure => "FAIL",
        }
    }

    pub fn json_name(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "info",
            Severity::Verbose => "verbose",
            Severity::AuditSuccess => "audit_success",
            Severity::AuditFailure => "audit_failure",
        }
    }
}

impl EventRecord {
    /// Security-channel events carry audit keywords instead of meaningful
    /// levels (Level 0 = LogAlways), so keywords win over the level field.
    pub fn severity(&self) -> Severity {
        const KW_AUDIT_FAILURE: u64 = 0x0010_0000_0000_0000;
        const KW_AUDIT_SUCCESS: u64 = 0x0020_0000_0000_0000;
        if let Some(k) = self.keywords {
            if k & KW_AUDIT_FAILURE != 0 {
                return Severity::AuditFailure;
            }
            if k & KW_AUDIT_SUCCESS != 0 {
                return Severity::AuditSuccess;
            }
        }
        match self.level {
            1 => Severity::Critical,
            2 => Severity::Error,
            3 => Severity::Warning,
            5 => Severity::Verbose,
            _ => Severity::Info, // 0 = LogAlways, 4 = Informational
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Section {
    None,
    System,
    EventData,
    UserData,
}

pub fn parse_event_xml(xml: &str) -> Result<EventRecord> {
    let mut reader = Reader::from_str(xml);
    let mut rec = EventRecord::default();

    let mut section = Section::None;
    // Local name of the open element whose text we're accumulating.
    let mut current: Option<String> = None;
    let mut data_name: Option<String> = None;
    let mut pending = String::new();
    let mut unnamed = 0u32;

    loop {
        match reader.read_event().context("malformed event XML")? {
            XmlEvent::Eof => break,
            XmlEvent::Start(e) => {
                let name = lname(e.local_name());
                pending.clear();
                match section {
                    Section::None if name == "System" => section = Section::System,
                    Section::None if name == "EventData" => section = Section::EventData,
                    Section::None if name == "UserData" => section = Section::UserData,
                    Section::System => {
                        open_system_element(&mut rec, &name, &e)?;
                        current = Some(name);
                    }
                    Section::EventData => {
                        // EvtRender's EventData is flat (<Data Name=..>text</Data>);
                        // a Data element with nested child markup is not modeled
                        // and its direct text would be lost — rare enough in
                        // practice to leave as a known limitation.
                        if name == "Data" {
                            data_name = attr(&e, "Name")?;
                        }
                        current = Some(name);
                    }
                    Section::UserData => current = Some(name),
                    _ => current = None,
                }
            }
            XmlEvent::Empty(e) => {
                let name = lname(e.local_name());
                match section {
                    Section::System => open_system_element(&mut rec, &name, &e)?,
                    Section::EventData if name == "Data" => {
                        let key = match attr(&e, "Name")? {
                            Some(n) => n,
                            None => {
                                unnamed += 1;
                                format!("param{unnamed}")
                            }
                        };
                        rec.data.push((key, String::new()));
                    }
                    _ => {}
                }
            }
            XmlEvent::Text(t) => {
                pending.push_str(&t.decode().context("undecodable text in event XML")?);
            }
            XmlEvent::CData(t) => {
                pending.push_str(&String::from_utf8_lossy(&t.into_inner()));
            }
            XmlEvent::GeneralRef(r) => {
                // quick-xml 0.40 surfaces &amp; &#xNN; etc. as separate events.
                let name = r.decode().context("undecodable entity reference")?;
                match resolve_ref(&name) {
                    Some(resolved) => pending.push_str(&resolved),
                    None => {
                        pending.push('&');
                        pending.push_str(&name);
                        pending.push(';');
                    }
                }
            }
            XmlEvent::End(e) => {
                let name = lname(e.local_name());
                let text = pending.trim().to_string();
                pending.clear();
                match section {
                    Section::System => {
                        if name == "System" {
                            section = Section::None;
                        } else if current.as_deref() == Some(name.as_str()) {
                            close_system_element(&mut rec, &name, &text);
                        }
                    }
                    Section::EventData => {
                        if name == "EventData" {
                            section = Section::None;
                        } else if name == "Data" {
                            let key = match data_name.take() {
                                Some(n) => n,
                                None => {
                                    unnamed += 1;
                                    format!("param{unnamed}")
                                }
                            };
                            rec.data.push((key, text));
                        } else if name == "Binary" && !text.is_empty() {
                            rec.data.push(("Binary".to_string(), text));
                        }
                    }
                    Section::UserData => {
                        if name == "UserData" {
                            section = Section::None;
                        } else if !text.is_empty() {
                            rec.data.push((name, text));
                        }
                    }
                    Section::None => {}
                }
                current = None;
            }
            _ => {}
        }
    }
    Ok(rec)
}

fn lname(n: quick_xml::name::LocalName) -> String {
    String::from_utf8_lossy(n.as_ref()).into_owned()
}

fn attr(e: &BytesStart, name: &str) -> Result<Option<String>> {
    for a in e.attributes() {
        let a = a.context("malformed attribute in event XML")?;
        if a.key.as_ref() == name.as_bytes() {
            return Ok(Some(
                a.normalized_value(quick_xml::XmlVersion::Implicit1_0)
                    .context("undecodable attribute value")?
                    .into_owned(),
            ));
        }
    }
    Ok(None)
}

fn open_system_element(rec: &mut EventRecord, name: &str, e: &BytesStart) -> Result<()> {
    match name {
        "Provider" => {
            if let Some(v) = attr(e, "Name")? {
                rec.provider = v;
            } else if let Some(v) = attr(e, "EventSourceName")? {
                rec.provider = v;
            }
        }
        "TimeCreated" => {
            if let Some(v) = attr(e, "SystemTime")? {
                rec.time_utc = v.parse().ok();
            }
        }
        "Execution" => {
            rec.pid = attr(e, "ProcessID")?.and_then(|v| v.parse().ok());
            rec.tid = attr(e, "ThreadID")?.and_then(|v| v.parse().ok());
        }
        "Security" => {
            rec.user_sid = attr(e, "UserID")?.filter(|s| !s.is_empty());
        }
        "Correlation" => {
            rec.activity_id = attr(e, "ActivityID")?.filter(|s| !s.is_empty());
        }
        _ => {}
    }
    Ok(())
}

fn close_system_element(rec: &mut EventRecord, name: &str, text: &str) {
    if text.is_empty() {
        return;
    }
    match name {
        "EventID" => rec.event_id = text.parse().unwrap_or(0),
        "Level" => rec.level = text.parse().unwrap_or(0),
        "Task" => rec.task = text.parse().ok(),
        "Keywords" => rec.keywords = parse_u64_flexible(text),
        "EventRecordID" => rec.record_id = text.parse().ok(),
        "Channel" => rec.channel = text.to_string(),
        "Computer" => rec.computer = text.to_string(),
        _ => {}
    }
}

fn parse_u64_flexible(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else {
        s.parse().ok()
    }
}

fn resolve_ref(name: &str) -> Option<String> {
    match name {
        "amp" => Some("&".to_string()),
        "lt" => Some("<".to_string()),
        "gt" => Some(">".to_string()),
        "quot" => Some("\"".to_string()),
        "apos" => Some("'".to_string()),
        _ => {
            let n = name.strip_prefix('#')?;
            let cp = if let Some(hex) = n.strip_prefix('x').or_else(|| n.strip_prefix('X')) {
                u32::from_str_radix(hex, 16).ok()?
            } else {
                n.parse().ok()?
            };
            char::from_u32(cp).map(|c| c.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECURITY_4625: &str = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime="2026-06-10T17:00:01.1234567Z"/><EventRecordID>123456</EventRecordID><Correlation ActivityID="{aabbccdd-1111-2222-3333-444455556666}"/><Execution ProcessID="712" ThreadID="716"/><Channel>Security</Channel><Computer>DC1.lab.local</Computer><Security/></System><EventData><Data Name="TargetUserName">bob</Data><Data Name="LogonType">3</Data><Data Name="Status">0xc000006d</Data></EventData></Event>"#;

    const CLASSIC_7036: &str = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Service Control Manager" Guid="{555908d1-a6d7-4695-8e1e-26931d2012f4}" EventSourceName="Service Control Manager"/><EventID Qualifiers="16384">7036</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8080000000000000</Keywords><TimeCreated SystemTime="2026-06-10T16:59:59.000000000Z"/><EventRecordID>998</EventRecordID><Correlation/><Execution ProcessID="0" ThreadID="0"/><Channel>System</Channel><Computer>box</Computer><Security/></System><EventData><Data Name="param1">Windows Update</Data><Data Name="param2">running</Data><Binary>7700750061007500</Binary></EventData></Event>"#;

    const USERDATA_EVENT: &str = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-TerminalServices-LocalSessionManager" Guid="{5d896912-022d-40aa-a3a8-4fa5515c76d7}"/><EventID>21</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x1000000000000000</Keywords><TimeCreated SystemTime="2026-06-10T12:00:00.000Z"/><EventRecordID>55</EventRecordID><Correlation/><Execution ProcessID="1234" ThreadID="5678"/><Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel><Computer>box</Computer><Security UserID="S-1-5-18"/></System><UserData><EventXML xmlns="Event_NS"><User>LAB\bob</User><SessionID>2</SessionID><Address>10.0.0.5 &amp; backup</Address></EventXML></UserData></Event>"#;

    #[test]
    fn parses_security_audit_failure() {
        let rec = parse_event_xml(SECURITY_4625).unwrap();
        assert_eq!(rec.event_id, 4625);
        assert_eq!(rec.channel, "Security");
        assert_eq!(rec.provider, "Microsoft-Windows-Security-Auditing");
        assert_eq!(rec.level, 0);
        assert_eq!(rec.keywords, Some(0x8010000000000000));
        assert_eq!(rec.severity(), Severity::AuditFailure);
        assert_eq!(rec.pid, Some(712));
        assert_eq!(rec.tid, Some(716));
        assert_eq!(rec.record_id, Some(123456));
        assert_eq!(rec.computer, "DC1.lab.local");
        assert!(rec.time_utc.is_some());
        assert_eq!(
            rec.data,
            vec![
                ("TargetUserName".to_string(), "bob".to_string()),
                ("LogonType".to_string(), "3".to_string()),
                ("Status".to_string(), "0xc000006d".to_string()),
            ]
        );
    }

    #[test]
    fn parses_classic_event_with_qualifiers_and_binary() {
        let rec = parse_event_xml(CLASSIC_7036).unwrap();
        assert_eq!(rec.event_id, 7036);
        assert_eq!(rec.provider, "Service Control Manager");
        assert_eq!(rec.severity(), Severity::Info);
        assert_eq!(rec.data[0], ("param1".to_string(), "Windows Update".to_string()));
        assert_eq!(rec.data[1], ("param2".to_string(), "running".to_string()));
        assert_eq!(rec.data[2].0, "Binary");
    }

    #[test]
    fn parses_userdata_with_entity_refs() {
        let rec = parse_event_xml(USERDATA_EVENT).unwrap();
        assert_eq!(rec.event_id, 21);
        assert_eq!(rec.user_sid.as_deref(), Some("S-1-5-18"));
        assert!(rec.data.contains(&("User".to_string(), "LAB\\bob".to_string())));
        assert!(rec.data.contains(&("SessionID".to_string(), "2".to_string())));
        // entity reference reassembled across text fragments
        assert!(rec.data.contains(&("Address".to_string(), "10.0.0.5 & backup".to_string())));
    }

    #[test]
    fn severity_mapping() {
        fn severity_of(level: u8, keywords: Option<u64>) -> Severity {
            EventRecord { level, keywords, ..Default::default() }.severity()
        }
        assert_eq!(severity_of(1, None), Severity::Critical);
        assert_eq!(severity_of(2, None), Severity::Error);
        assert_eq!(severity_of(3, None), Severity::Warning);
        assert_eq!(severity_of(4, None), Severity::Info);
        assert_eq!(severity_of(5, None), Severity::Verbose);
        assert_eq!(severity_of(0, None), Severity::Info);
        assert_eq!(severity_of(0, Some(0x8020000000000000)), Severity::AuditSuccess);
        assert_eq!(severity_of(0, Some(0x8010000000000000)), Severity::AuditFailure);
    }
}
