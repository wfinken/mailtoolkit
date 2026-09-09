use anyhow::{bail,Context,Result};
use clap::{Parser,Subcommand,Args,ValueEnum};
use mailbench_core::{*,auth,dns::Dns,message,smtp::{self,SmtpOptions,TlsMode},storage,swaks};
use serde_json::json;
use std::{net::IpAddr,path::PathBuf,time::Duration};

#[derive(Parser)]
#[command(name="mailbench",version,about="Local-first email infrastructure diagnostics")]
struct Cli {
    #[arg(long,global=true)] json:bool,
    #[arg(short='q',long,global=true)] quiet:bool,
    #[arg(short='v',long,global=true,action=clap::ArgAction::Count)] verbose:u8,
    #[arg(long,global=true)] no_color:bool,
    #[arg(long,global=true,default_value_t=10,value_parser=clap::value_parser!(u64).range(1..=300))] timeout:u64,
    #[arg(long,global=true,help="Save this result locally; may contain infrastructure and message metadata")] save:bool,
    #[command(subcommand)] command:Cmd,
}
#[derive(Subcommand)]
enum Cmd {
    Check(Check),
    Dns {kind:String,target:String,record_type:Option<String>,#[arg(long)] resolver:Option<IpAddr>,#[arg(long)] tcp:bool},
    Mx {domain:String}, Ptr {ip:IpAddr},
    Spf {#[command(subcommand)] command:Spf},
    Dkim {#[command(subcommand)] command:Dkim},
    Dmarc {#[command(subcommand)] command:Dmarc},
    Smtp {#[command(subcommand)] command:Smtp},
    Tls(Probe), Send(Send),
    Swaks(Send),
    Message {#[command(subcommand)] command:Message},
    Headers {file:PathBuf}, Auth(Evaluate),
    Profile {#[command(subcommand)] command:Profile},
    History {#[command(subcommand)] command:History},
    Report {id:String,#[arg(long,value_enum,default_value_t=ReportFormat::Markdown)] format:ReportFormat,#[arg(long)] output:Option<PathBuf>},
    Config {#[command(subcommand)] command:Config}, Doctor,
}
#[derive(Args)]
struct Check {domain:Option<String>,#[arg(long)]profile:Option<String>,#[arg(long)]smtp:Option<String>,#[arg(long)]ip:Option<IpAddr>,#[arg(long)]selector:Option<String>}
#[derive(Subcommand)]
enum Spf {Check {domain:String},Test {domain:String,#[arg(long)]ip:IpAddr,#[arg(long)]mail_from:Option<String>,#[arg(long,default_value="mailbench.local")]ehlo:String}}
#[derive(Subcommand)]
enum Dkim {Check {domain:String,#[arg(long)]selector:String},Inspect {name:String},Verify {file:PathBuf}}
#[derive(Subcommand)]
enum Dmarc {Check {domain:String},Evaluate(Evaluate)}
#[derive(Args)]
struct Evaluate {file:PathBuf,#[arg(long)]ip:IpAddr,#[arg(long)]mail_from:String,#[arg(long)]ehlo:String}
#[derive(Subcommand)]enum Smtp {Test(Probe)}
#[derive(Clone,Copy,ValueEnum)]enum Mode {Starttls,Implicit,Off}
impl From<Mode> for TlsMode {fn from(m:Mode)->Self {match m {Mode::Starttls=>Self::Starttls,Mode::Implicit=>Self::Implicit,Mode::Off=>Self::Off}}}
#[derive(Args)]
struct Probe {host:String,#[arg(long,value_enum)]tls_mode:Option<Mode>,#[arg(long,default_value="mailbench.local")]ehlo:String,#[arg(long)]no_verify:bool,#[arg(long)]sni:Option<String>,#[arg(long)]source_ip:Option<IpAddr>}
impl Probe {fn options(&self,timeout:u64)->Result<SmtpOptions> {let (host,port)=smtp::endpoint(&self.host,25)?;Ok(SmtpOptions {host,port,ehlo:self.ehlo.clone(),tls:self.tls_mode.map(Into::into).unwrap_or(if port==465 {TlsMode::Implicit} else {TlsMode::Starttls}),no_verify:self.no_verify,sni:self.sni.clone(),source_ip:self.source_ip,timeout_secs:timeout})}}
#[derive(Args)]
struct Send {
    #[command(flatten)]probe:Probe,
    #[arg(long)]from:String,#[arg(long,required=true)]to:Vec<String>,
    #[arg(long,default_value="[MAILBENCH] SMTP Test")]subject:String,
    #[arg(long,default_value="Mailbench implementation test.")]body:String,
    #[arg(long)]html:bool,#[arg(long)]header:Vec<String>,
    #[arg(long)]username:Option<String>,#[arg(long,conflicts_with="password_stdin")]password_env:Option<String>,#[arg(long)]password_stdin:bool,
    #[arg(long,help="Build the message/command without sending")]dry_run:bool,
}
#[derive(Subcommand)]enum Message {Inspect {file:PathBuf},Build {#[arg(long)]from:String,#[arg(long,required=true)]to:Vec<String>,#[arg(long,default_value="[MAILBENCH] SMTP Test")]subject:String,#[arg(long,default_value="Mailbench test")]body:String,#[arg(long)]html:bool,#[arg(long)]output:PathBuf}}
#[derive(Subcommand)]enum Profile {List,Show {name:String},Import {file:PathBuf}}
#[derive(Subcommand)]enum History {List,Show {id:String},Delete {id:String},Clear {#[arg(long)]yes:bool},Diff {before:String,after:String}}
#[derive(Subcommand)]enum Config {Path,Validate}
#[derive(Clone,Copy,ValueEnum)]enum ReportFormat {Json,Markdown,Html}
async fn read_message(path:&PathBuf)->Result<Vec<u8>> {
    let bytes=if path.as_os_str()=="-" {use tokio::io::AsyncReadExt;let mut b=vec![];tokio::io::stdin().take(25*1024*1024+1).read_to_end(&mut b).await?;b} else {if tokio::fs::metadata(path).await?.len()>25*1024*1024 {bail!("Message exceeds 25 MiB");}tokio::fs::read(path).await?};
    if bytes.len()>25*1024*1024 {bail!("Message exceeds 25 MiB");}Ok(bytes)
}
fn info(test:&str,value:serde_json::Value)->Finding {Finding::new(test,"local",Status::Info,"Local operation completed",value)}
fn escape_html(s:&str)->String {s.replace('&',"&amp;").replace('<',"&lt;").replace('>',"&gt;").replace('"',"&quot;")}
async fn execute(cli:&Cli)->Result<Session> {
    let timeout=Duration::from_secs(cli.timeout);
    // Lazy DNS construction keeps profiles/history/message inspection usable offline.
    let dns=||Dns::new(None,false,timeout);
    let findings=match &cli.command {
        Cmd::Dns {kind,target,record_type,resolver,tcp}=>{
            let record=if kind.eq_ignore_ascii_case("query") {record_type.as_deref().context("dns query requires a record type")?} else {if record_type.is_some(){bail!("Unexpected third DNS argument");}kind.as_str()};
            vec![Dns::new(*resolver,*tcp,timeout)?.query(target,record.to_ascii_uppercase().parse().context("Unknown DNS record type")?).await]
        },
        Cmd::Mx {domain}=>vec![dns()?.mx(domain).await],Cmd::Ptr {ip}=>vec![dns()?.ptr(*ip).await],
        Cmd::Spf {command}=>match command {
            Spf::Check {domain}=>vec![auth::spf_record(&dns()?,domain).await],
            Spf::Test {domain,ip,mail_from,ehlo}=>{let sender=mail_from.clone().unwrap_or_else(||format!("postmaster@{domain}"));if sender.rsplit_once('@').map(|(_,d)|d)!=Some(domain.as_str()) {bail!("MAIL FROM domain must equal the domain being tested");}vec![auth::spf_test(domain,*ip,ehlo,&sender,timeout).await]}
        },
        Cmd::Dkim {command}=>match command {
            Dkim::Check {domain,selector}=>vec![auth::dkim_key(&dns()?,domain,selector).await],
            Dkim::Inspect {name}=>{let (selector,domain)=name.split_once("._domainkey.").context("Expected selector._domainkey.domain")?;vec![auth::dkim_key(&dns()?,domain,selector).await]},
            Dkim::Verify {file}=>auth::verify_message(&read_message(file).await?,None,timeout).await,
        },
        Cmd::Dmarc {command:Dmarc::Check {domain}}=>vec![auth::dmarc_record(&dns()?,domain).await],
        Cmd::Dmarc {command:Dmarc::Evaluate(e)}|Cmd::Auth(e)=>auth::verify_message(&read_message(&e.file).await?,Some((e.ip,&e.ehlo,&e.mail_from)),timeout).await,
        Cmd::Smtp {command:Smtp::Test(p)}|Cmd::Tls(p)=>vec![smtp::run(&p.options(cli.timeout)?,None).await],
        Cmd::Send(s)|Cmd::Swaks(s)=>{
            let options=s.probe.options(cli.timeout)?;
            if matches!(&cli.command,Cmd::Swaks(_)) {
                if s.username.is_some()||s.password_env.is_some()||s.password_stdin||s.html||!s.header.is_empty() {bail!("Swaks builder supports plain messages without authentication; use native send for those options");}
                let args=swaks::args(&options,&s.from,&s.to,&s.subject,&s.body)?;
                if s.dry_run {vec![info("swaks.command",json!({"command":swaks::command(&args)}))]} else {vec![swaks::run(&args,timeout).await]}
            } else {
                let (id,raw)=message::build(&s.from,&s.to,&s.subject,&s.body,s.html,&s.header)?;
                if s.dry_run {vec![info("message.build",json!({"trace_id":id,"message":String::from_utf8_lossy(&raw)}))]} else {
                    let password=if let Some(env)=&s.password_env {Some(std::env::var(env).context("Password environment variable is unset")?)} else if s.password_stdin {use tokio::io::AsyncBufReadExt;let mut line=String::new();tokio::io::BufReader::new(tokio::io::stdin()).read_line(&mut line).await?;Some(line.trim_end_matches(['\r','\n']).to_string())} else {None};
                    if s.username.is_some()!=password.is_some() {bail!("Provide username and either password-env or password-stdin together");}
                    let mut finding=smtp::run(&options,Some(smtp::Submission {sender:&s.from,recipients:&s.to,message:&raw,username:s.username.as_deref(),password:password.as_deref()})).await;
                    finding.evidence["trace_id"]=json!(id);vec![finding]
                }
            }
        },
        Cmd::Headers {file}|Cmd::Message {command:Message::Inspect {file}}=>vec![message::inspect(&read_message(file).await?)],
        Cmd::Message {command:Message::Build {from,to,subject,body,html,output}}=>{let (id,raw)=message::build(from,to,subject,body,*html,&[])?;tokio::fs::write(output,&raw).await?;vec![info("message.build",json!({"path":output,"trace_id":id,"size_bytes":raw.len()}))]},
        Cmd::Check(c)=>{
            let profile=c.profile.as_deref().map(storage::load_profile).transpose()?;
            let domain=c.domain.as_deref().or(profile.as_ref().map(|p|p.domain.as_str())).context("Provide a domain or --profile")?;
            let ip=c.ip.or(profile.as_ref().and_then(|p|p.sending_ip));let selector=c.selector.as_deref().or(profile.as_ref().and_then(|p|p.selector.as_deref()));let d=dns()?;
            let (mx,spf,dmarc)=tokio::join!(d.mx(domain),auth::spf_record(&d,domain),auth::dmarc_record(&d,domain));let mut fs=vec![mx,spf,dmarc];
            if let Some(selector)=selector {fs.push(auth::dkim_key(&d,domain,selector).await);} else {fs.push(Finding::new("dkim.dns",domain,Status::Skip,"Supply --selector to test DKIM DNS",json!({})));}
            if let Some(ip)=ip {let sender=profile.as_ref().and_then(|p|p.mail_from.clone()).unwrap_or_else(||format!("postmaster@{domain}"));let (ptr,spf)=tokio::join!(d.ptr(ip),auth::spf_test(domain,ip,"mailbench.local",&sender,timeout));fs.extend([ptr,spf]);}
            if let Some(host)=&c.smtp {let (host,port)=smtp::endpoint(host,25)?;fs.push(smtp::run(&SmtpOptions {host,port,timeout_secs:cli.timeout,tls:if port==465 {TlsMode::Implicit}else{TlsMode::Starttls},..Default::default()},None).await);} else if let Some(profile)=&profile {let mut options=profile.smtp.clone();options.timeout_secs=cli.timeout;fs.push(smtp::run(&options,None).await);}
            fs.push(Finding::new("delivery",domain,Status::Skip,"Environment check sends no email. Use send and analyze the sink copy to verify delivery.",json!({})));fs
        },
        Cmd::Profile {command}=>match command {
            Profile::List=>vec![info("profiles",json!({"profiles":storage::profiles()?}))],Profile::Show {name}=>vec![info("profile",json!(storage::load_profile(name)?))],
            Profile::Import {file}=>{let profile:storage::Profile=toml_profile(file)?;storage::save_profile(&profile)?;vec![info("profile.import",json!({"name":profile.name}))]}
        },
        Cmd::History {command}=>match command {
            History::List=>vec![info("history",json!({"sessions":storage::sessions()?}))],History::Show {id}=>return storage::load_session(id),
            History::Delete {id}=>{storage::delete_session(id)?;vec![info("history.delete",json!({"id":id}))]},
            History::Clear {yes}=>{if !yes {bail!("Clear history requires --yes");}let sessions=storage::sessions()?;for s in &sessions {storage::delete_session(&s.id)?;}vec![info("history.clear",json!({"deleted":sessions.len()}))]},
            History::Diff {before,after}=>{let a=storage::load_session(before)?;let b=storage::load_session(after)?;vec![info("history.diff",json!({"before":a,"after":b,"changed":a.findings.iter().map(|f|json!({"test":f.test,"target":f.target,"before":f,"after":b.findings.iter().find(|g|g.test==f.test && g.target==f.target)})).collect::<Vec<_>>()}))]}
        },
        Cmd::Report {id,format,output}=>{let session=storage::load_session(id)?;let text=match format {ReportFormat::Json=>serde_json::to_string_pretty(&session)?,ReportFormat::Markdown=>session.markdown(),ReportFormat::Html=>format!("<!doctype html><meta charset=utf-8><title>Mailbench report</title><style>body{{font:15px system-ui;max-width:1000px;margin:40px auto}}pre{{white-space:pre-wrap}}</style><pre>{}</pre>",escape_html(&session.markdown()))};if let Some(path)=output {tokio::fs::write(path,text).await?;vec![info("report",json!({"path":path}))]}else{vec![info("report",json!({"content":text}))]}},
        Cmd::Config {command}=>match command {Config::Path=>vec![info("config",json!({"path":storage::root()?}))],Config::Validate=>vec![info("config",json!({"profiles":storage::profiles()?.len(),"valid":true}))]},
        Cmd::Doctor=>{
            let mut fs=vec![info("doctor.platform",json!({"os":std::env::consts::OS,"arch":std::env::consts::ARCH,"config":storage::root()?}))];
            fs.push(match dns() {Ok(d)=>Finding::new("doctor.dns","system",Status::Info,"System resolver configuration loaded; reachability not tested",json!({"resolver":d.label})),Err(e)=>Finding::error("doctor.dns","system",e)});
            for (name,arg) in [("swaks","--version"),("openssl","version")] {let mut command=tokio::process::Command::new(name);command.arg(arg).kill_on_drop(true);fs.push(match tokio::time::timeout(timeout,command.output()).await {Ok(Ok(out))=>Finding::new("doctor.dependency",name,if out.status.success(){Status::Info}else{Status::Warn},String::from_utf8_lossy(&out.stdout),json!({"optional":true})),_=>Finding::new("doctor.dependency",name,Status::Warn,"Optional tool not available",json!({"optional":true}))});}fs
        }
    };
    let target=findings.first().map(|f|f.target.as_str()).unwrap_or("local");Ok(Session::new(target,findings.clone()))
}
fn toml_profile(path:&PathBuf)->Result<storage::Profile> {storage::parse_profile(&std::fs::read_to_string(path)?)}
#[tokio::main]
async fn main() {
    let cli=match Cli::try_parse() {Ok(c)=>c,Err(e)=>{let code=if e.use_stderr(){3}else{0};let _=e.print();std::process::exit(code);}};
    let result=execute(&cli).await;
    let (session,mut exit)=match result {Ok(s)=>{let code=s.exit_code();(s,code)},Err(e)=>(Session::new("configuration",vec![Finding::error("configuration","local",format!("{e:#}"))]),3)};
    if cli.save {if let Err(e)=storage::save_session(&session) {eprintln!("Could not save history: {e}");exit=4;}}
    if cli.json {println!("{}",serde_json::to_string_pretty(&session).expect("session is serializable"));}
    else if !cli.quiet {println!("MAILBENCH  {}\n",session.target);for f in &session.findings {println!("{:?}\t{}\t{} ({} ms)",f.status,f.test,f.summary,f.duration_ms);for advice in &f.next_steps {println!("  → {advice}");}if cli.verbose>0 || f.status==Status::Info {println!("{}",serde_json::to_string_pretty(&f.evidence).unwrap());}}println!("\nSession: {}",session.id);}
    std::process::exit(exit);
}
