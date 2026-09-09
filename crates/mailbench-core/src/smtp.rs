use crate::{Finding, Status};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json,Value};
use std::{time::{Duration, Instant}, net::IpAddr};
use tokio::{io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt, BufReader}, net::{TcpStream,TcpSocket}};
use base64::{Engine, engine::general_purpose::STANDARD};

trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T:AsyncRead+AsyncWrite+Unpin+Send> Transport for T {}
type Stream=BufReader<Box<dyn Transport>>;
#[derive(Debug,Clone,Copy,Serialize,Deserialize,PartialEq,Eq,Default)]
#[serde(rename_all="kebab-case")]
pub enum TlsMode { #[default] Starttls, Implicit, Off }
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct SmtpOptions {
    pub host:String, pub port:u16, pub ehlo:String, pub tls:TlsMode,
    pub no_verify:bool, pub sni:Option<String>, pub source_ip:Option<IpAddr>, pub ca_file:Option<String>,
    pub timeout_secs:u64,
}
impl Default for SmtpOptions {
    fn default()->Self { Self {host:"localhost".into(),port:25,ehlo:"mailbench.local".into(),tls:TlsMode::Starttls,no_verify:false,sni:None,source_ip:None,ca_file:None,timeout_secs:10} }
}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct Event {pub elapsed_ms:u64,pub direction:String,pub text:String}
struct Connection {stream:Option<Stream>,events:Vec<Event>,start:Instant,tls_info:Value}
impl Connection {
    fn event(&mut self,direction:&str,text:impl Into<String>) {self.events.push(Event {elapsed_ms:self.start.elapsed().as_millis() as u64,direction:direction.into(),text:text.into()});}
    async fn reply(&mut self)->Result<(u16,Vec<String>)> {
        let mut lines=vec![]; let mut expected=None;
        loop {
            let mut bytes=vec![];
            loop {let b=self.stream.as_mut().context("No SMTP connection")?.read_u8().await?; bytes.push(b);if b==b'\n' {break;} if bytes.len()>8192 {bail!("SMTP response line exceeds 8192 bytes");}}
            let line=String::from_utf8_lossy(&bytes).trim_end_matches(['\r','\n']).to_owned();
            self.event("server",&line);
            let (code,more)=parse_reply_line(&line)?;
            if expected.is_some_and(|e|e!=code) {bail!("Inconsistent multiline SMTP reply");}
            expected=Some(code);lines.push(line);
            if !more {return Ok((code,lines));}
            if lines.len()>100 {bail!("SMTP response exceeds 100 lines");}
        }
    }
    async fn command(&mut self,line:&str,secret:bool)->Result<(u16,Vec<String>)> {
        single_line(line)?;
        self.event("client",if secret {"[AUTH REDACTED]"} else {line});
        let stream=self.stream.as_mut().context("No SMTP connection")?;
        stream.write_all(format!("{line}\r\n").as_bytes()).await?;stream.flush().await?;
        self.reply().await
    }
    async fn upgrade(&mut self,o:&SmtpOptions)->Result<()> {
        let stream=self.stream.take().context("No SMTP connection")?;
        if !stream.buffer().is_empty() {bail!("Unexpected bytes buffered before TLS upgrade");}
        let mut builder=native_tls::TlsConnector::builder();
        builder.min_protocol_version(Some(native_tls::Protocol::Tlsv12));
        if let Some(path)=&o.ca_file {builder.add_root_certificate(native_tls::Certificate::from_pem(&tokio::fs::read(path).await?)?);}
        builder.danger_accept_invalid_certs(o.no_verify);builder.danger_accept_invalid_hostnames(o.no_verify);
        let tls=tokio_native_tls::TlsConnector::from(builder.build()?).connect(o.sni.as_deref().unwrap_or(&o.host),stream.into_inner()).await?;
        let cert=tls.get_ref().peer_certificate()?.map(|c|c.to_der()).transpose()?;
        let mut details=json!({"verified":!o.no_verify,"hostname":o.sni.as_deref().unwrap_or(&o.host),"protocol":null,"cipher":null});
        if let Some(der)=cert {
            if let Ok((_,cert))=x509_parser::parse_x509_certificate(&der) {
                details["subject"]=json!(cert.subject().to_string());details["issuer"]=json!(cert.issuer().to_string());
                details["not_before"]=json!(cert.validity().not_before.to_string());details["not_after"]=json!(cert.validity().not_after.to_string());
                details["days_remaining"]=json!((cert.validity().not_after.timestamp()-chrono::Utc::now().timestamp())/86400);
                details["signature_algorithm"]=json!(cert.signature_algorithm.algorithm.to_id_string());
                details["certificate_der_base64"]=json!(STANDARD.encode(&der));
            }
        }
        self.tls_info=details;self.event("tls",if o.no_verify {"TLS established — CERTIFICATE VERIFICATION DISABLED"} else {"TLS established; certificate chain and hostname verified"});
        self.stream=Some(BufReader::new(Box::new(tls)));Ok(())
    }
}
pub fn single_line(s:&str)->Result<()> {if s.contains(['\r','\n','\0']) {bail!("Newlines and NUL are forbidden in SMTP commands and header fields");}Ok(())}
pub fn parse_reply_line(line:&str)->Result<(u16,bool)> {
    let b=line.as_bytes();if b.len()<3 || !b[..3].iter().all(u8::is_ascii_digit) {bail!("Malformed SMTP response");}
    let code=line[..3].parse::<u16>()?;if !(200..600).contains(&code) {bail!("Invalid SMTP status code");}
    let more=match b.get(3) {Some(b'-')=>true,Some(b' ')|None=>false,_=>bail!("Invalid SMTP reply separator")};Ok((code,more))
}
pub fn endpoint(value:&str,default_port:u16)->Result<(String,u16)> {
    if let Ok(addr)=value.parse::<std::net::SocketAddr>() {return Ok((addr.ip().to_string(),addr.port()));}
    if value.parse::<IpAddr>().is_ok() {return Ok((value.into(),default_port));}
    if let Some((host,port))=value.rsplit_once(':') {if host.contains(':') || host.is_empty() {bail!("Use [IPv6]:port syntax");}return Ok((host.into(),port.parse()?));}
    if value.is_empty() {bail!("SMTP host is empty");}Ok((value.into(),default_port))
}
async fn connect(o:&SmtpOptions)->Result<TcpStream> {
    if let Some(source)=o.source_ip {
        let addresses=tokio::net::lookup_host((o.host.as_str(),o.port)).await?;
        let mut last=None;
        for address in addresses.filter(|a|a.is_ipv4()==source.is_ipv4()) {
            let socket=if source.is_ipv4() {TcpSocket::new_v4()?} else {TcpSocket::new_v6()?};
            socket.bind((source,0).into())?;
            match socket.connect(address).await {Ok(s)=>return Ok(s),Err(e)=>last=Some(e)}
        }
        bail!("Could not connect using source address: {last:?}")
    } else {Ok(TcpStream::connect((o.host.as_str(),o.port)).await?)}
}
pub struct Submission<'a> {pub sender:&'a str,pub recipients:&'a [String],pub message:&'a [u8],pub username:Option<&'a str>,pub password:Option<&'a str>}
pub async fn run(o:&SmtpOptions,submission:Option<Submission<'_>>)->Finding {
    let target=format!("{}:{}",o.host,o.port);let start=Instant::now();
    let secrets:Vec<String>=submission.as_ref().and_then(|s|s.password.map(|p|(s.username.unwrap_or(""),p))).map(|(u,p)|vec![p.to_string(),STANDARD.encode(format!("\0{u}\0{p}"))]).unwrap_or_default();
    let mut c=Connection {stream:None,events:vec![],start,tls_info:Value::Null};
    let result=tokio::time::timeout(Duration::from_secs(o.timeout_secs),async {
        single_line(&o.ehlo)?;
        c.event("connect",&target);c.stream=Some(BufReader::new(Box::new(connect(o).await?)));
        if o.tls==TlsMode::Implicit {c.upgrade(o).await?;}
        let (code,_)=c.reply().await?;if code!=220 {bail!("SMTP banner rejected with {code}");}
        let (mut code,mut extensions)=c.command(&format!("EHLO {}",o.ehlo),false).await?;
        if code!=250 && o.tls==TlsMode::Off {
            (code,extensions)=c.command(&format!("HELO {}",o.ehlo),false).await?;
        }
        if code!=250 {bail!("EHLO/HELO failed with {code}");}
        if o.tls==TlsMode::Starttls {
            if !extensions.iter().any(|s|s.get(4..).is_some_and(|v|v.eq_ignore_ascii_case("STARTTLS"))) {bail!("STARTTLS required but not advertised");}
            let (mut code,_)=c.command("STARTTLS",false).await?;if code!=220 {bail!("STARTTLS refused with {code}");}
            c.upgrade(o).await?;
            (code,extensions)=c.command(&format!("EHLO {}",o.ehlo),false).await?;
            if code!=250 {bail!("Post-TLS EHLO failed with {code}");}
        }
        if let Some(s)=submission {
            single_line(s.sender)?;for recipient in s.recipients {single_line(recipient)?;}
            if s.recipients.is_empty() {bail!("At least one recipient required");}
            if let Some(user)=s.username {
                if o.tls==TlsMode::Off || o.no_verify {bail!("AUTH requires verified TLS");}
                let pass=s.password.context("SMTP password missing")?;
                if !extensions.iter().any(|e|e.get(4..).is_some_and(|v|v.to_ascii_uppercase().starts_with("AUTH") && v.split_whitespace().any(|m|m.eq_ignore_ascii_case("PLAIN")))) {bail!("Server does not advertise AUTH PLAIN");}
                let payload=STANDARD.encode(format!("\0{user}\0{pass}"));
                let (code,_)=c.command(&format!("AUTH PLAIN {payload}"),true).await?;
                if code!=235 {bail!("AUTH rejected with {code}");}
            }
            let (code,_)=c.command(&format!("MAIL FROM:<{}>",s.sender),false).await?;if code!=250 {bail!("MAIL FROM rejected with {code}");}
            for recipient in s.recipients {let (code,_)=c.command(&format!("RCPT TO:<{recipient}>"),false).await?;if code!=250 && code!=251 {bail!("RCPT TO rejected with {code}");}}
            let (code,_)=c.command("DATA",false).await?;if code!=354 {bail!("DATA rejected with {code}");}
            c.event("client",format!("[MESSAGE BODY OMITTED: {} bytes]",s.message.len()));
            let wire=dot_stuff(s.message);c.stream.as_mut().unwrap().write_all(&wire).await?;c.stream.as_mut().unwrap().flush().await?;
            let (code,_)=c.reply().await?;if code!=250 {bail!("Message rejected after DATA with {code}");}
        }
        // Successful acceptance/probe is not invalidated by a server closing on QUIT.
        let _=c.command("QUIT",false).await;
        Ok::<_,anyhow::Error>(extensions)
    }).await;
    let (status,summary,extensions)=match result {
        Ok(Ok(ext))=>(if o.no_verify || o.tls==TlsMode::Off {Status::Warn} else {Status::Pass},"SMTP session completed; submission does not prove sink delivery".into(),json!(ext)),
        Ok(Err(e))=>(if e.downcast_ref::<std::io::Error>().is_some() {Status::Error}else{Status::Fail},e.to_string(),Value::Null),
        Err(e)=>(Status::Error,format!("SMTP session timed out: {e}"),Value::Null)
    };
    let mut summary=summary;
    for secret in secrets.iter().filter(|s|!s.is_empty()) {summary=summary.replace(secret,"[REDACTED]");for event in &mut c.events {event.text=event.text.replace(secret,"[REDACTED]");}}
    Finding::new("smtp",&target,status,summary,json!({"extensions":extensions,"transcript":c.events,"tls":c.tls_info,"tls_mode":o.tls,"verification_disabled":o.no_verify})).timed(start)
}
pub fn dot_stuff(raw:&[u8])->Vec<u8> {
    let mut out=Vec::with_capacity(raw.len()+32);let mut begin=true;let mut i=0;
    while i<raw.len() {
        let b=raw[i];
        if b==b'\r' || b==b'\n' {
            if b==b'\r' && raw.get(i+1)==Some(&b'\n') {i+=1;}
            out.extend_from_slice(b"\r\n");begin=true;
        } else {if begin && b==b'.' {out.push(b'.');}out.push(b);begin=false;}
        i+=1;
    }
    if !out.ends_with(b"\r\n") {out.extend_from_slice(b"\r\n");}
    out.extend_from_slice(b".\r\n");out
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn validates_replies_and_injection() {assert_eq!(parse_reply_line("250-STARTTLS").unwrap(),(250,true));assert!(parse_reply_line("250Xbad").is_err());assert!(single_line("hi\r\nRCPT TO:x").is_err());}
    #[test] fn handles_ipv6() {assert_eq!(endpoint("[::1]:2525",25).unwrap(),("::1".into(),2525));}
    #[test] fn prevents_early_data_termination() {assert_eq!(dot_stuff(b"hello\n.\nworld"),b"hello\r\n..\r\nworld\r\n.\r\n");}
    #[tokio::test] async fn captures_probe() {
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let port=listener.local_addr().unwrap().port();
        let server=tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt;
            let (mut socket,_)=listener.accept().await.unwrap();socket.write_all(b"220 local ESMTP\r\n").await.unwrap();
            let mut reader=BufReader::new(socket);let mut line=String::new();reader.read_line(&mut line).await.unwrap();assert!(line.starts_with("EHLO"));
            reader.get_mut().write_all(b"250-local\r\n250 SIZE 10000\r\n").await.unwrap();line.clear();reader.read_line(&mut line).await.unwrap();assert_eq!(line,"QUIT\r\n");reader.get_mut().write_all(b"221 bye\r\n").await.unwrap();
        });
        let finding=run(&SmtpOptions {host:"127.0.0.1".into(),port,tls:TlsMode::Off,..Default::default()},None).await;
        assert_eq!(finding.status,Status::Warn);assert!(finding.evidence["transcript"].as_array().unwrap().len()>=6);server.await.unwrap();
    }
}
