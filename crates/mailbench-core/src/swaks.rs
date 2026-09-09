use crate::{Finding,Status,smtp::{SmtpOptions,TlsMode,single_line}};
use anyhow::Result;
use serde_json::json;
use std::{process::Stdio,time::{Duration,Instant}};
use tokio::process::Command;

pub fn args(o:&SmtpOptions,sender:&str,recipients:&[String],subject:&str,body:&str)->Result<Vec<String>> {
    for value in [o.host.as_str(),o.ehlo.as_str(),sender,subject] {single_line(value)?;}
    for r in recipients {single_line(r)?;}
    let mut args=vec!["--server".into(),o.host.clone(),"--port".into(),o.port.to_string(),"--ehlo".into(),o.ehlo.clone(),"--from".into(),sender.into(),"--to".into(),recipients.join(","),"--header".into(),format!("Subject: {subject}"),"--header".into(),format!("X-Mailbench-ID: {}",uuid::Uuid::new_v4()),"--body".into(),body.into(),"--timeout".into(),o.timeout_secs.to_string()];
    match o.tls {TlsMode::Starttls=>args.push("--tls".into()),TlsMode::Implicit=>args.push("--tls-on-connect".into()),TlsMode::Off=>{}}
    if o.tls!=TlsMode::Off && !o.no_verify {args.push("--tls-verify".into());}
    Ok(args)
}
pub fn quote(s:&str)->String {format!("'{}'",s.replace('\'',"'\\''"))}
pub fn command(args:&[String])->String {std::iter::once("swaks".to_owned()).chain(args.iter().map(|s|quote(s))).collect::<Vec<_>>().join(" ")}
pub async fn run(args:&[String],timeout:Duration)->Finding {
    let start=Instant::now();
    // Do not accept credential flags; authentication is implemented in the native sender.
    if args.iter().any(|a|a.to_ascii_lowercase().starts_with("--auth") || a=="-ap" || a=="-au") {return Finding::error("swaks","swaks","Use native send with --password-env or --password-stdin for authentication");}
    let mut cmd=Command::new("swaks");cmd.args(args).stdin(Stdio::null()).kill_on_drop(true);
    match tokio::time::timeout(timeout,cmd.output()).await {
        Ok(Ok(out))=>Finding::new("swaks","swaks",if out.status.success(){Status::Pass}else{Status::Fail},format!("Swaks exited with {}",out.status),json!({"command":command(args),"stdout":String::from_utf8_lossy(&out.stdout),"stderr":String::from_utf8_lossy(&out.stderr)})).timed(start),
        Ok(Err(e))=>Finding::error("swaks","swaks",e).advice("Install swaks separately or use native mailbench send.").timed(start),
        Err(e)=>Finding::error("swaks","swaks",e).timed(start)
    }
}
#[cfg(test)]mod tests{use super::*;#[test]fn shell_quote_is_literal(){assert_eq!(quote("a'b"),"'a'\\''b'");assert_eq!(quote("$(id)"),"'$(id)'");}}
