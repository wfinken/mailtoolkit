//! DNS policy inspection and independent authentication. Receiver headers are never trusted as proof.
use crate::{dns::Dns, Finding, Status};
use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use mail_auth::{common::parse::TxtRecordParser, spf::Spf};
use mail_auth::{dmarc::verify::DmarcParameters, spf::verify::SpfParameters};
use mail_auth::{AuthenticatedMessage, DkimResult, DmarcResult, MessageAuthenticator, SpfResult};
use rsa::{
    pkcs1::DecodeRsaPublicKey, pkcs8::DecodePublicKey, traits::PublicKeyParts, RsaPublicKey,
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    net::IpAddr,
    time::{Duration, Instant},
};

pub fn tags(record: &str) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for item in record.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        let (key, value) = item
            .split_once('=')
            .ok_or_else(|| anyhow!("Tag has no '=': {item}"))?;
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            bail!("Invalid tag name");
        }
        if out
            .insert(key.to_string(), value.trim().to_string())
            .is_some()
        {
            bail!("Duplicate tag: {key}");
        }
    }
    Ok(out)
}
fn fail(
    test: &str,
    domain: &str,
    error: impl std::fmt::Display,
    raw: serde_json::Value,
) -> Finding {
    Finding::new(test, domain, Status::Fail, error.to_string(), raw)
        .advice("Compare the published DNS record with the intended configuration.")
}
pub async fn dkim_key(dns: &Dns, domain: &str, selector: &str) -> Finding {
    let start = Instant::now();
    let name = format!("{selector}._domainkey.{domain}");
    let records = match dns.txt(&name).await {
        Ok(r) => r,
        Err(e) => return Finding::error("dkim.dns", &name, e).timed(start),
    };
    let raw = json!({"records":records});
    if records.len() != 1 {
        return fail(
            "dkim.dns",
            &name,
            "Expected exactly one DKIM key record",
            raw,
        )
        .timed(start);
    }
    let parsed = validate_dkim_key(&records[0]);
    match parsed {
        Ok((kind, bits)) => Finding::new(
            "dkim.dns",
            &name,
            if kind == "rsa" && bits < 2048 {
                Status::Warn
            } else {
                Status::Pass
            },
            format!("Valid {kind} public key ({bits} bits); message signature not yet tested"),
            json!({"records":records,"key_type":kind,"key_bits":bits}),
        )
        .timed(start),
        Err(e) => fail("dkim.dns", &name, e, raw).timed(start),
    }
}
pub fn validate_dkim_key(record: &str) -> Result<(String, usize)> {
    let t = tags(record)?;
    if let Some(v) = t.get("v") {
        if v != "DKIM1" || !record.trim_start().starts_with("v=DKIM1;") {
            bail!("Invalid DKIM version or version order");
        }
    }
    let p = t.get("p").ok_or_else(|| anyhow!("Missing public key p="))?;
    if p.is_empty() {
        bail!("Public key revoked (empty p=)");
    }
    let compact: String = p.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let bytes = STANDARD.decode(compact)?;
    let kind = t.get("k").map(String::as_str).unwrap_or("rsa");
    match kind {
        "rsa" => {
            let key = RsaPublicKey::from_public_key_der(&bytes)
                .or_else(|_| RsaPublicKey::from_pkcs1_der(&bytes))?;
            let bits = key.n().bits();
            if bits < 1024 {
                bail!("RSA key is below 1024 bits");
            }
            Ok((kind.into(), bits))
        }
        "ed25519" => {
            if bytes.len() != 32 {
                bail!("Ed25519 key must contain 32 bytes");
            }
            Ok((kind.into(), 256))
        }
        _ => bail!("Unsupported DKIM key type: {kind}"),
    }
}
pub async fn dmarc_record(dns: &Dns, domain: &str) -> Finding {
    let start = Instant::now();
    let name = format!("_dmarc.{domain}");
    let records = match dns.txt(&name).await {
        Ok(r) => r,
        Err(e) => return Finding::error("dmarc.dns", domain, e).timed(start),
    };
    let candidates: Vec<_> = records
        .iter()
        .filter(|r| r.starts_with("v=DMARC1;"))
        .collect();
    if candidates.len() != 1 {
        return fail(
            "dmarc.dns",
            domain,
            "Expected exactly one DMARC policy",
            json!({"records":records}),
        )
        .timed(start);
    }
    match validate_dmarc(candidates[0]) {
        Ok(t)=>Finding::new("dmarc.dns",domain,if t["p"]=="none" {Status::Warn} else {Status::Pass},format!("Published DMARC policy: {}. Message alignment requires independent evaluation.",t["p"]),json!({"records":records,"tags":t,"scope":"exact queried domain; inherited policy is evaluated by dmarc evaluate"})).timed(start),
        Err(e)=>fail("dmarc.dns",domain,e,json!({"records":records})).timed(start)
    }
}
pub fn validate_dmarc(record: &str) -> Result<BTreeMap<String, String>> {
    if !record.starts_with("v=DMARC1;") {
        bail!("DMARC version must be first");
    }
    let t = tags(record)?;
    for name in ["p", "sp"] {
        if (name == "p" || t.contains_key(name))
            && !matches!(
                t.get(name).map(String::as_str),
                Some("none" | "quarantine" | "reject")
            )
        {
            bail!("Invalid or missing {name} policy");
        }
    }
    for name in ["adkim", "aspf"] {
        if let Some(v) = t.get(name) {
            if v != "r" && v != "s" {
                bail!("Invalid alignment mode {name}");
            }
        }
    }
    if let Some(pct) = t.get("pct") {
        if pct.parse::<u8>()? > 100 {
            bail!("pct exceeds 100");
        }
    }
    for name in ["rua", "ruf"] {
        if let Some(v) = t.get(name) {
            if !v
                .split(',')
                .all(|s| s.trim().starts_with("mailto:") && s.contains('@'))
            {
                bail!("Invalid reporting address in {name}");
            }
        }
    }
    Ok(t)
}
pub fn validate_spf(record: &str) -> Result<()> {
    Spf::parse(record.as_bytes())?;
    let mut modifiers = std::collections::BTreeSet::new();
    for term in record.split_whitespace().skip(1) {
        // Unknown modifiers are extensible; unknown mechanisms are not.
        if let Some((name, value)) = term.split_once('=').filter(|(name, _)| !name.contains(':')) {
            if !name.starts_with(|c: char| c.is_ascii_alphabetic())
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            {
                bail!("Invalid SPF modifier name: {name}");
            }
            let name = name.to_ascii_lowercase();
            if matches!(name.as_str(), "redirect" | "exp")
                && (value.is_empty() || !modifiers.insert(name))
            {
                bail!("Empty or duplicate SPF modifier");
            }
            continue;
        }
        let mechanism = term.trim_start_matches(['+', '-', '~', '?']);
        let name = mechanism
            .split([':', '/'])
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        if !matches!(
            name.as_str(),
            "all" | "include" | "a" | "mx" | "ptr" | "ip4" | "ip6" | "exists"
        ) {
            bail!("Unknown SPF mechanism: {name}");
        }
        if matches!(name.as_str(), "ip4" | "ip6") {
            let value = mechanism
                .split_once(':')
                .ok_or_else(|| anyhow!("IP mechanism requires an address"))?
                .1;
            let (address, prefix) = value
                .split_once('/')
                .map_or((value, None), |(a, p)| (a, Some(p)));
            let maximum = if name == "ip4" {
                address.parse::<std::net::Ipv4Addr>()?;
                32
            } else {
                address.parse::<std::net::Ipv6Addr>()?;
                128
            };
            if prefix
                .map(str::parse::<u16>)
                .transpose()?
                .is_some_and(|p| p > maximum)
            {
                bail!("Invalid {name} CIDR length");
            }
        }
    }
    Ok(())
}

pub async fn spf_record(dns: &Dns, domain: &str) -> Finding {
    let start = Instant::now();
    let records = match dns.txt(domain).await {
        Ok(r) => r,
        Err(e) => return Finding::error("spf.dns", domain, e).timed(start),
    };
    let spf: Vec<_> = records
        .iter()
        .filter(|s| s.split_whitespace().next() == Some("v=spf1"))
        .collect();
    if spf.len() != 1 {
        return fail(
            "spf.dns",
            domain,
            "Expected exactly one SPF record",
            json!({"records":records}),
        )
        .timed(start);
    }
    if let Err(error) = validate_spf(spf[0]) {
        return fail("spf.dns", domain, error, json!({"records":records})).timed(start);
    }
    let terms: Vec<_> = spf[0].split_whitespace().skip(1).collect();
    // This is a static inspection, not a fabricated check_host result or recursive lookup count.
    let lookups = terms
        .iter()
        .filter(|s| {
            matches!(
                s.trim_start_matches(['+', '-', '~', '?'])
                    .split([':', '/', '='])
                    .next(),
                Some("include" | "a" | "mx" | "exists" | "ptr" | "redirect")
            )
        })
        .count();
    Finding::new("spf.dns",domain,Status::Pass,"SPF syntax is valid; use spf test with a sending IP for authorization evaluation",json!({"records":records,"terms":terms,"top_level_dns_terms":lookups,"evaluation":"not performed"})).timed(start)
}
fn spf_status(r: SpfResult) -> Status {
    match r {
        SpfResult::Pass => Status::Pass,
        SpfResult::TempError => Status::Error,
        SpfResult::Fail | SpfResult::PermError => Status::Fail,
        _ => Status::Warn,
    }
}
pub async fn spf_test(
    domain: &str,
    ip: IpAddr,
    ehlo: &str,
    sender: &str,
    deadline: Duration,
) -> Finding {
    let start = Instant::now();
    let auth = match MessageAuthenticator::new_system_conf() {
        Ok(a) => a,
        Err(e) => return Finding::error("spf", domain, e),
    };
    match tokio::time::timeout(deadline,auth.verify_spf(SpfParameters::verify_mail_from(ip,ehlo,"mailbench.local",sender))).await {
        Ok(out)=>Finding::new("spf",domain,spf_status(out.result()),format!("SPF {:?} for {} from {}",out.result(),sender,ip),json!({"result":format!("{:?}",out.result()),"ip":ip,"mail_from":sender,"ehlo":ehlo,"resolver":"system","details":format!("{out:?}")})).timed(start),
        Err(e)=>Finding::error("spf",domain,e).timed(start)
    }
}
pub async fn verify_message(
    raw: &[u8],
    identity: Option<(IpAddr, &str, &str)>,
    deadline: Duration,
) -> Vec<Finding> {
    let start = Instant::now();
    let Some(message) = AuthenticatedMessage::parse(raw) else {
        return vec![fail(
            "message",
            "message",
            "Message could not be parsed",
            json!({}),
        )];
    };
    let auth = match MessageAuthenticator::new_system_conf() {
        Ok(a) => a,
        Err(e) => return vec![Finding::error("auth", "message", e)],
    };
    let results = match tokio::time::timeout(deadline, auth.verify_dkim(&message)).await {
        Ok(r) => r,
        Err(e) => return vec![Finding::error("dkim.verify", "message", e)],
    };
    let mut findings = vec![];
    if results.is_empty() {
        findings.push(Finding::new(
            "dkim.verify",
            "message",
            Status::Fail,
            "Message contains no DKIM signatures",
            json!({}),
        ));
    }
    for (i, r) in results.iter().enumerate() {
        let status = match r.result() {
            DkimResult::Pass => Status::Pass,
            DkimResult::TempError(_) => Status::Error,
            _ => Status::Fail,
        };
        findings.push(
            Finding::new(
                "dkim.verify",
                &format!("signature {}", i + 1),
                status,
                format!("DKIM {:?}", r.result()),
                json!({"details":format!("{r:?}")}),
            )
            .timed(start),
        );
    }
    if let Some((ip, ehlo, sender)) = identity {
        let spf = match tokio::time::timeout(
            deadline,
            auth.verify_spf(SpfParameters::verify_mail_from(
                ip,
                ehlo,
                "mailbench.local",
                sender,
            )),
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                findings.push(Finding::error("spf", "message", e));
                return findings;
            }
        };
        findings.push(Finding::new(
            "spf",
            "message",
            spf_status(spf.result()),
            format!("SPF {:?}", spf.result()),
            json!({"ip":ip,"ehlo":ehlo,"mail_from":sender,"details":format!("{spf:?}")}),
        ));
        let mail_domain = sender.rsplit_once('@').map(|(_, d)| d).unwrap_or(ehlo);
        match tokio::time::timeout(
            deadline,
            auth.verify_dmarc(DmarcParameters::new(&message, &results, mail_domain, &spf)),
        )
        .await
        {
            Ok(r) => {
                let pass =
                    r.dkim_result() == &DmarcResult::Pass || r.spf_result() == &DmarcResult::Pass;
                findings.push(Finding::new("dmarc.evaluate","message",if pass {Status::Pass} else {Status::Fail},if pass {"DMARC passed with an independently authenticated aligned identity"} else {"DMARC did not pass; inspect policy, authentication, and alignment evidence"},json!({"dkim_alignment":format!("{:?}",r.dkim_result()),"spf_alignment":format!("{:?}",r.spf_result()),"details":format!("{r:?}")})).timed(start));
            }
            Err(e) => findings.push(Finding::error("dmarc.evaluate", "message", e)),
        }
    } else {
        findings.push(Finding::new("dmarc.evaluate","message",Status::Skip,"Provide original client IP, EHLO, and envelope sender; receiver headers alone are not proof",json!({})));
    }
    findings
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_ambiguous_records() {
        assert!(tags("v=DKIM1; p=abc; p=def").is_err());
        assert!(validate_dkim_key("v=DKIM1;p=").is_err());
        assert!(validate_dkim_key("v=DKIM1;k=ed25519;p=YWJj").is_err());
        assert!(validate_dmarc("v=DMARC1;p=reject;p=none").is_err());
        assert!(validate_dmarc("v=DMARC1;p=reject;pct=101").is_err());
        assert!(validate_dmarc("v=DMARC1;p=reject;adkim=s;rua=mailto:reports@example.com").is_ok());
    }
    #[test]
    fn validates_spf_syntax() {
        assert!(validate_spf("v=spf1 ip4:192.0.2.0/24 -all").is_ok());
        assert!(validate_spf("v=spf1 exists:%{l1r=}.example.com -all").is_ok());
        assert!(validate_spf("v=spf1 unknown-mechanism -all").is_err());
        assert!(validate_spf("v=spf1 ip4:not-an-ip -all").is_err());
        assert!(validate_spf("v=spf1 ip4:192.0.2.1/99 -all").is_err());
        assert!(validate_spf("v=spf1 redirect=a.example redirect=b.example").is_err());
    }
    #[tokio::test]
    async fn unsigned_message_cannot_pass_dkim() {
        let results = verify_message(
            b"From: a@example.com\r\nTo: b@example.net\r\nSubject: Test\r\n\r\nbody\r\n",
            None,
            Duration::from_secs(2),
        )
        .await;
        assert!(!results
            .iter()
            .any(|f| f.test == "dkim.verify" && f.status == Status::Pass));
    }
}
