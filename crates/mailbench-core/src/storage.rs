use crate::{Session,smtp::SmtpOptions};
use anyhow::{bail,Context,Result};
use serde::{Serialize,Deserialize};
use std::{path::{Path,PathBuf},fs::{self,OpenOptions},io::Write};
#[derive(Debug,Clone,Serialize,Deserialize,Default)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub name:String,pub domain:String,
    #[serde(default)] pub smtp:SmtpOptions,
    pub sending_ip:Option<std::net::IpAddr>,pub mail_from:Option<String>,pub recipient:Option<String>,pub selector:Option<String>,
    pub username:Option<String>,pub password_env:Option<String>,
    #[serde(default)] pub tags:Vec<String>,
}
pub fn root()->Result<PathBuf> {
    if let Some(path)=std::env::var_os("MAILBENCH_CONFIG_DIR") {return Ok(path.into());}
    if let Some(path)=std::env::var_os("XDG_CONFIG_HOME") {return Ok(PathBuf::from(path).join("mailbench"));}
    Ok(PathBuf::from(std::env::var_os("HOME").context("HOME is unset; set MAILBENCH_CONFIG_DIR")?).join(".config/mailbench"))
}
pub fn safe_name(name:&str)->Result<()> {if name.is_empty() || !name.bytes().all(|b|b.is_ascii_alphanumeric() || b==b'-' || b==b'_') {bail!("Name must use only letters, numbers, hyphens, and underscores");}Ok(())}
pub fn write_private(path:&Path,bytes:&[u8])->Result<()> {
    let parent=path.parent().context("Path has no parent")?;fs::create_dir_all(parent)?;
    #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;fs::set_permissions(parent,fs::Permissions::from_mode(0o700))?;}
    let tmp=parent.join(format!(".{}.tmp",uuid::Uuid::new_v4()));
    let mut options=OpenOptions::new();options.write(true).create_new(true);
    #[cfg(unix)] {use std::os::unix::fs::OpenOptionsExt;options.mode(0o600);}
    let result=(|| {let mut file=options.open(&tmp)?;file.write_all(bytes)?;file.sync_all()?;fs::rename(&tmp,path)?;Ok::<_,anyhow::Error>(())})();
    if result.is_err() {let _=fs::remove_file(tmp);}result
}
pub fn save_profile(profile:&Profile)->Result<()> {safe_name(&profile.name)?;write_private(&root()?.join("profiles").join(format!("{}.toml",profile.name)),toml::to_string_pretty(profile)?.as_bytes())}
pub fn load_profile(name:&str)->Result<Profile> {safe_name(name)?;Ok(toml::from_str(&fs::read_to_string(root()?.join("profiles").join(format!("{name}.toml")))?)?)}
pub fn profiles()->Result<Vec<Profile>> {
    let path=root()?.join("profiles");if !path.exists() {return Ok(vec![]);}
    let mut items=vec![];for entry in fs::read_dir(path)? {let entry=entry?;if entry.path().extension().is_some_and(|s|s=="toml") {items.push(toml::from_str(&fs::read_to_string(entry.path())?)?);}}Ok(items)
}
pub fn save_session(session:&Session)->Result<()> {safe_name(&session.id)?;write_private(&root()?.join("sessions").join(format!("{}.json",session.id)),&serde_json::to_vec_pretty(session)?)}
pub fn load_session(id:&str)->Result<Session> {safe_name(id)?;Ok(serde_json::from_slice(&fs::read(root()?.join("sessions").join(format!("{id}.json")))?)?)}
pub fn sessions()->Result<Vec<Session>> {
    let path=root()?.join("sessions");if !path.exists() {return Ok(vec![]);}
    let mut items:Vec<Session>=vec![];for entry in fs::read_dir(path)? {let entry=entry?;if entry.path().extension().is_some_and(|s|s=="json") {items.push(serde_json::from_slice(&fs::read(entry.path())?)?);}}
    items.sort_by(|a,b|b.timestamp.cmp(&a.timestamp));Ok(items)
}
pub fn delete_session(id:&str)->Result<()> {safe_name(id)?;fs::remove_file(root()?.join("sessions").join(format!("{id}.json")))?;Ok(())}
#[cfg(test)] mod tests {use super::*;#[test]fn blocks_path_escape(){for s in ["../x","/tmp/a","a/b",""] {assert!(safe_name(s).is_err());}assert!(safe_name("customer-a_2").is_ok());}}
pub fn parse_profile(text:&str)->Result<Profile> {let profile:Profile=toml::from_str(text)?;safe_name(&profile.name)?;if profile.domain.is_empty() {bail!("Profile domain is empty");}if !(1..=300).contains(&profile.smtp.timeout_secs) {bail!("Profile timeout must be 1..300 seconds");}Ok(profile)}
