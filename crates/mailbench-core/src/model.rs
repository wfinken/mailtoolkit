use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Instant;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status { Pass, Warn, Fail, Skip, Info, Error }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub test: String,
    pub target: String,
    pub status: Status,
    pub summary: String,
    pub evidence: Value,
    pub next_steps: Vec<String>,
    pub duration_ms: u64,
}
impl Finding {
    pub fn new(test: &str, target: &str, status: Status, summary: impl Into<String>, evidence: Value) -> Self {
        Self { test: test.into(), target: target.into(), status, summary: summary.into(), evidence, next_steps: vec![], duration_ms: 0 }
    }
    pub fn timed(mut self, start: Instant) -> Self { self.duration_ms = start.elapsed().as_millis() as u64; self }
    pub fn advice(mut self, text: &str) -> Self { self.next_steps.push(text.into()); self }
    pub fn error(test: &str, target: &str, error: impl std::fmt::Display) -> Self {
        Self::new(test, target, Status::Error, error.to_string(), Value::Null)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub schema_version: u32,
    pub id: String,
    pub timestamp: String,
    pub target: String,
    pub findings: Vec<Finding>,
}
impl Session {
    pub fn new(target: &str, findings: Vec<Finding>) -> Self {
        Self { schema_version: 1, id: uuid::Uuid::new_v4().to_string(), timestamp: chrono::Utc::now().to_rfc3339(), target: target.into(), findings }
    }
    pub fn exit_code(&self) -> i32 {
        if self.findings.iter().any(|f| f.status == Status::Error) { 4 }
        else if self.findings.iter().any(|f| f.status == Status::Fail) { 1 }
        else if self.findings.iter().any(|f| f.status == Status::Warn) { 2 }
        else { 0 }
    }
    pub fn markdown(&self) -> String {
        let mut s = format!("# Mailbench assessment\n\nTarget: {}\n\nDate: {}\n\n", self.target, self.timestamp);
        for f in &self.findings {
            s.push_str(&format!("## {} — {:?}\n\n{}\n\n", f.test, f.status, f.summary));
            for step in &f.next_steps { s.push_str(&format!("- {step}\n")); }
            // Four-space indentation prevents raw evidence from closing a code fence.
            for line in serde_json::to_string_pretty(&f.evidence).unwrap_or_default().lines() { s.push_str(&format!("    {line}\n")); }
            s.push('\n');
        }
        s
    }
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn errors_are_not_failures() {
        let s = Session::new("x", vec![Finding::error("dns", "x", "timeout")]);
        assert_eq!(s.exit_code(), 4);
        assert_eq!(serde_json::to_value(&s).unwrap()["findings"][0]["status"], "ERROR");
    }
}
