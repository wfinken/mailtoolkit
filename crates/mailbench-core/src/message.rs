use crate::{smtp::single_line, Finding, Status};
use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use mailparse::MailHeaderMap;
use serde_json::json;

pub fn build(
    sender: &str,
    to: &[String],
    subject: &str,
    body: &str,
    html: bool,
    headers: &[String],
) -> Result<(String, Vec<u8>)> {
    for value in std::iter::once(sender)
        .chain(to.iter().map(String::as_str))
        .chain(std::iter::once(subject))
    {
        single_line(value)?;
    }
    if !sender.is_ascii() || to.iter().any(|r| !r.is_ascii()) {
        bail!("SMTPUTF8 envelope addresses are not supported in the native MVP sender");
    }
    let id = uuid::Uuid::new_v4().to_string();
    let mut message=format!("From: {sender}\r\nTo: {}\r\nSubject: =?UTF-8?B?{}?=\r\nDate: {}\r\nMessage-ID: <{id}@mailbench.local>\r\nX-Mailbench-ID: {id}\r\nMIME-Version: 1.0\r\n",to.join(", "),STANDARD.encode(subject),chrono::Utc::now().to_rfc2822());
    for header in headers {
        single_line(header)?;
        let Some((name, _)) = header.split_once(':') else {
            bail!("Custom header requires Name: value");
        };
        if name.is_empty() || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
            bail!("Invalid header name");
        }
        if [
            "from",
            "to",
            "subject",
            "date",
            "message-id",
            "x-mailbench-id",
            "mime-version",
            "content-type",
            "content-transfer-encoding",
        ]
        .contains(&name.to_ascii_lowercase().as_str())
        {
            bail!("Reserved header: {name}");
        }
        message.push_str(header);
        message.push_str("\r\n");
    }
    message.push_str(&format!(
        "Content-Type: {}; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n",
        if html { "text/html" } else { "text/plain" }
    ));
    let encoded = STANDARD.encode(body);
    for chunk in encoded.as_bytes().chunks(76) {
        message.push_str(std::str::from_utf8(chunk)?);
        message.push_str("\r\n");
    }
    Ok((id, message.into_bytes()))
}
pub fn inspect(raw: &[u8]) -> Finding {
    match mailparse::parse_mail(raw) {
        Ok(parsed) => {
            let headers: Vec<_> = parsed
                .headers
                .iter()
                .map(|h| json!({"name":h.get_key(),"value":h.get_value()}))
                .collect();
            let received = parsed.headers.get_all_values("Received");
            Finding::new(
                "message",
                "message",
                Status::Info,
                format!(
                    "{} bytes; {} Received hops; receiver authentication claims are untrusted",
                    raw.len(),
                    received.len()
                ),
                json!({"headers":headers,"received":received,"authentication_results":parsed.headers.get_all_values("Authentication-Results"),"subject":parsed.headers.get_first_value("Subject"),"from":parsed.headers.get_first_value("From"),"to":parsed.headers.get_first_value("To"),"content_type":parsed.ctype.mimetype,"mime_parts":count_parts(&parsed),"size_bytes":raw.len()}),
            )
        }
        Err(e) => Finding::new(
            "message",
            "message",
            Status::Fail,
            format!("Malformed message: {e}"),
            json!({"raw":String::from_utf8_lossy(raw),"size_bytes":raw.len()}),
        ),
    }
}
fn count_parts(mail: &mailparse::ParsedMail<'_>) -> usize {
    1 + mail.subparts.iter().map(count_parts).sum::<usize>()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_utf8_and_correlation() {
        let (id, raw) = build(
            "a@example.com",
            &["b@example.net".into()],
            "Résumé",
            "Hello 🌍",
            false,
            &[],
        )
        .unwrap();
        let parsed = mailparse::parse_mail(&raw).unwrap();
        assert_eq!(parsed.get_body().unwrap(), "Hello 🌍");
        assert_eq!(
            parsed.headers.get_first_value("X-Mailbench-ID").unwrap(),
            id
        );
    }
    #[test]
    fn rejects_header_injection() {
        assert!(build("a@example.com", &[], "a\r\nBcc: x", "", false, &[]).is_err());
        assert!(build(
            "a@example.com",
            &[],
            "a",
            "",
            false,
            &["X-Mailbench-ID: fake".into()]
        )
        .is_err());
    }
}
