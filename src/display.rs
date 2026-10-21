//! Terminal-only derived views. Never emit attacker-controlled terminal escapes.
use serde_json::Value;
use std::fmt::Write;

fn safe(value: &Value) -> String {
    let text = value.as_str().map(str::to_owned).unwrap_or_else(|| {
        if value.is_null() { "?".to_owned() } else { value.to_string() }
    });
    // Escaping all non-ASCII also neutralizes bidi formatting and OSC sequences.
    text.chars().flat_map(char::escape_default).collect()
}

pub fn event(value: &Value) -> String {
    let detail = &value["details"];
    let kind = value["event"].as_str().unwrap_or("unknown");
    let activity = match kind {
        "cowrie.command.input" => format!("COMMAND {}", safe(&detail["input"])),
        "cowrie.command.failed" => format!("UNSUPPORTED {}", safe(&detail["input"])),
        "cowrie.login.success" | "cowrie.login.failed" => format!("LOGIN {} user={} password={}",
            if kind.ends_with("success") { "accepted" } else { "failed" }, safe(&detail["username"]), safe(&detail["password"])),
        "cowrie.session.connect" => format!("CONNECTED source_port={} destination_port={}", safe(&detail["src_port"]), safe(&detail["dst_port"])),
        "cowrie.session.closed" => format!("DISCONNECTED duration_seconds={} duration_ms={}", safe(&detail["duration"]), safe(&detail["duration_ms"])),
        "cowrie.client.version" => format!("CLIENT {}", safe(&detail["version"])),
        "cowrie.log.closed" => format!("RECORDING {}", safe(&detail["ttylog"])),
        "cowrie.session.file_upload" | "cowrie.session.file_download" | "cowrie.session.file_download.failed" => format!("{} url={} file={} sha256={}", kind, safe(&detail["url"]), safe(&detail["outfile"]), safe(&detail["shasum"])),
        "http.request" => format!("HTTP {} {} bytes={} complete={} error={}", safe(&value["method"]), safe(&value["target"]), safe(&value["bytes"]), safe(&value["complete"]), safe(&value["error"])),
        _ => safe(&value["event"]),
    };
    format!("{} [{}] {} session={} {}", safe(&value["time"]), safe(&value["protocol"]), safe(&value["src_ip"]), safe(&value["session"]), activity)
}

pub fn coverage(value: &Value) -> String {
    let mut output = format!("Observed {} | coverage={} | retained events={}\n", safe(&value["observed_at"]), safe(&value["coverage"]), safe(&value["event_count"]));
    if let Some(warnings) = value["warnings"].as_array() {
        for warning in warnings { let _ = writeln!(output, "WARNING {}", safe(warning)); }
    }
    output
}

pub fn report(value: &Value) -> String {
    let mut output = coverage(value);
    if let Some(sessions) = value["summary"]["sessions"].as_array() {
        let _ = writeln!(output, "Session summaries (retained events only):");
        for session in sessions {
            let _ = writeln!(output, "  {} [{}] source={} closed_observed={} duration_seconds={} logins={} commands={}",
                safe(&session["session"]), safe(&session["protocol"]), safe(&session["src_ip"]), safe(&session["closed"]), safe(&session["duration_seconds"]),
                session["logins"].as_array().map_or(0,Vec::len), session["commands"].as_array().map_or(0,Vec::len));
            if let Some(recordings) = session["recordings"].as_array() {
                for recording in recordings { let _ = writeln!(output, "    recording={}", safe(&recording["ttylog"])); }
            }
        }
    }
    if let Some(events) = value["events"].as_array() {
        for item in events { let _ = writeln!(output, "{}", event(item)); }
    }
    if let Some(indicators) = value["indicators"].as_array() {
        let _ = writeln!(output, "Passive indicators (never contacted):");
        for indicator in indicators { let _ = writeln!(output, "  {} {}", safe(&indicator["type"]), safe(&indicator["value"])); }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn commands_cannot_inject_terminal_controls_or_extra_lines() {
        let item = json!({"event":"cowrie.command.input","details":{"input":"id\n\u{1b}]52;c;injected\u{7}\u{202e}"},"session":"x\rspoof"});
        let output = event(&item);
        assert!(!output.contains('\n'));
        assert!(!output.contains('\r'));
        assert!(!output.contains('\u{1b}'));
        assert!(!output.contains('\u{7}'));
        assert!(!output.contains('\u{202e}'));
        assert!(output.contains("COMMAND id\\n"));
    }
    #[test]
    fn shows_login_outcome_and_redacted_credential() {
        let output = event(&json!({"event":"cowrie.login.success","details":{"username":"root","password":"[redacted]"}}));
        assert!(output.contains("LOGIN accepted user=root password=[redacted]"));
    }
    #[test]
    fn partial_coverage_is_visible_without_events() {
        let output = report(&json!({"coverage":"partial","warnings":["missing\nsource"],"events":[],"event_count":0}));
        assert!(output.contains("coverage=partial"));
        assert!(output.contains("WARNING missing\\nsource"));
    }
}
