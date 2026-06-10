//! Build event log XPath queries from CLI filter flags.

use anyhow::{Context, Result, bail, ensure};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum MinLevel {
    Critical,
    Error,
    Warning,
    Info,
    Verbose,
}

pub struct Filters<'a> {
    pub raw: Option<&'a str>,
    pub ids: &'a [String],
    pub min_level: Option<MinLevel>,
    pub providers: &'a [String],
    pub since_ms: Option<i64>,
}

/// Compose an XPath query, or `None` for "everything".
pub fn build_xpath(f: &Filters) -> Result<Option<String>> {
    if let Some(raw) = f.raw {
        ensure!(
            f.ids.is_empty() && f.min_level.is_none() && f.providers.is_empty()
                && f.since_ms.is_none(),
            "--query cannot be combined with --id/--level/--provider/--since"
        );
        return Ok(Some(raw.to_string()));
    }
    let mut parts = Vec::new();
    if let Some(expr) = id_expr(f.ids)? {
        parts.push(expr);
    }
    if let Some(expr) = provider_expr(f.providers)? {
        parts.push(expr);
    }
    if let Some(expr) = f.min_level.and_then(level_expr) {
        parts.push(expr);
    }
    if let Some(ms) = f.since_ms {
        parts.push(format!("TimeCreated[timediff(@SystemTime) <= {ms}]"));
    }
    if parts.is_empty() {
        Ok(None)
    } else {
        Ok(Some(format!("*[System[{}]]", parts.join(" and "))))
    }
}

fn id_expr(ids: &[String]) -> Result<Option<String>> {
    if ids.is_empty() {
        return Ok(None);
    }
    let mut parts = Vec::new();
    for raw in ids {
        let raw = raw.trim();
        if let Some((a, b)) = raw.split_once('-') {
            let a: u32 = a
                .trim()
                .parse()
                .with_context(|| format!("invalid event id range '{raw}'"))?;
            let b: u32 = b
                .trim()
                .parse()
                .with_context(|| format!("invalid event id range '{raw}'"))?;
            ensure!(a <= b, "event id range '{raw}' is reversed");
            parts.push(format!("(EventID >= {a} and EventID <= {b})"));
        } else {
            let v: u32 = raw
                .parse()
                .with_context(|| format!("invalid event id '{raw}'"))?;
            parts.push(format!("EventID={v}"));
        }
    }
    Ok(Some(if parts.len() == 1 {
        parts.pop().unwrap()
    } else {
        format!("({})", parts.join(" or "))
    }))
}

fn provider_expr(providers: &[String]) -> Result<Option<String>> {
    if providers.is_empty() {
        return Ok(None);
    }
    let mut alts = Vec::new();
    for p in providers {
        alts.push(format!("@Name={}", xpath_string_literal(p)?));
    }
    Ok(Some(format!("Provider[{}]", alts.join(" or "))))
}

/// XPath 1.0 string literals have no escape mechanism; pick a quote style.
fn xpath_string_literal(s: &str) -> Result<String> {
    if !s.contains('\'') {
        Ok(format!("'{s}'"))
    } else if !s.contains('"') {
        Ok(format!("\"{s}\""))
    } else {
        bail!("provider name cannot contain both single and double quotes")
    }
}

/// Level 0 (LogAlways) is included only at info and below, so audit events
/// survive an `-l info` filter but not `-l error`.
fn level_expr(min: MinLevel) -> Option<String> {
    match min {
        MinLevel::Critical => Some("Level=1".to_string()),
        MinLevel::Error => Some("(Level >= 1 and Level <= 2)".to_string()),
        MinLevel::Warning => Some("(Level >= 1 and Level <= 3)".to_string()),
        MinLevel::Info => Some("(Level=0 or (Level >= 1 and Level <= 4))".to_string()),
        MinLevel::Verbose => None,
    }
}

/// Parse `--since`: a duration ("15m", "2h30m", "1d") or a timestamp
/// ("2026-06-10T12:00", RFC 3339). Returns the window size in milliseconds.
pub fn parse_since(s: &str) -> Result<i64> {
    if let Ok(span) = s.parse::<jiff::Span>() {
        let now = jiff::Zoned::now();
        let ms = span
            .total((jiff::Unit::Millisecond, &now))
            .context("invalid --since duration")?;
        ensure!(ms > 0.0, "--since duration must be positive");
        // Round sub-millisecond spans up to 1ms; `ms as i64` would truncate
        // e.g. `--since 500us` to a zero-width window that matches nothing.
        return Ok((ms.ceil() as i64).max(1));
    }
    let ts: jiff::Timestamp = if let Ok(t) = s.parse() {
        t
    } else {
        let dt: jiff::civil::DateTime = s.parse().with_context(|| {
            format!("--since must be a duration (15m, 2h30m) or a timestamp (2026-06-10T12:00), got '{s}'")
        })?;
        dt.to_zoned(jiff::tz::TimeZone::system())
            .context("could not resolve --since in the system time zone")?
            .timestamp()
    };
    let ms = (jiff::Timestamp::now() - ts)
        .total(jiff::Unit::Millisecond)
        .context("invalid --since timestamp")? as i64;
    ensure!(ms > 0, "--since timestamp is in the future");
    Ok(ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filters<'a>(
        raw: Option<&'a str>,
        ids: &'a [String],
        min_level: Option<MinLevel>,
        providers: &'a [String],
        since_ms: Option<i64>,
    ) -> Filters<'a> {
        Filters { raw, ids, min_level, providers, since_ms }
    }

    #[test]
    fn empty_filters_mean_no_query() {
        let f = filters(None, &[], None, &[], None);
        assert_eq!(build_xpath(&f).unwrap(), None);
    }

    #[test]
    fn raw_query_passes_through() {
        let f = filters(Some("*[System[EventID=1]]"), &[], None, &[], None);
        assert_eq!(build_xpath(&f).unwrap().unwrap(), "*[System[EventID=1]]");
    }

    #[test]
    fn raw_query_rejects_other_filters() {
        let ids = vec!["4625".to_string()];
        let f = filters(Some("*"), &ids, None, &[], None);
        assert!(build_xpath(&f).is_err());
    }

    #[test]
    fn composes_all_parts() {
        let ids = vec!["4624".to_string(), "4000-4010".to_string()];
        let providers = vec!["ESENT".to_string()];
        let f = filters(None, &ids, Some(MinLevel::Warning), &providers, Some(900000));
        assert_eq!(
            build_xpath(&f).unwrap().unwrap(),
            "*[System[(EventID=4624 or (EventID >= 4000 and EventID <= 4010)) \
             and Provider[@Name='ESENT'] \
             and (Level >= 1 and Level <= 3) \
             and TimeCreated[timediff(@SystemTime) <= 900000]]]"
                .replace("             ", "")
        );
    }

    #[test]
    fn provider_with_apostrophe_uses_double_quotes() {
        let providers = vec!["O'Brien Soft".to_string()];
        let f = filters(None, &[], None, &providers, None);
        assert_eq!(
            build_xpath(&f).unwrap().unwrap(),
            "*[System[Provider[@Name=\"O'Brien Soft\"]]]"
        );
    }

    #[test]
    fn rejects_bad_ids() {
        let ids = vec!["abc".to_string()];
        let f = filters(None, &ids, None, &[], None);
        assert!(build_xpath(&f).is_err());

        let ids = vec!["500-100".to_string()];
        let f = filters(None, &ids, None, &[], None);
        assert!(build_xpath(&f).is_err());
    }

    #[test]
    fn parse_since_duration() {
        let ms = parse_since("15m").unwrap();
        assert_eq!(ms, 15 * 60 * 1000);
        let ms = parse_since("2h30m").unwrap();
        assert_eq!(ms, 150 * 60 * 1000);
        assert!(parse_since("garbage").is_err());
    }

    #[test]
    fn parse_since_subms_rounds_up_not_to_zero() {
        // Sub-millisecond spans must not truncate to a zero-width window.
        assert_eq!(parse_since("500us").unwrap(), 1);
        assert_eq!(parse_since("1ns").unwrap(), 1);
    }
}
