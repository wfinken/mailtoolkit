use crate::{Finding, Status};
use anyhow::{Context, Result};
use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    proto::rr::{RData, RecordType},
    TokioAsyncResolver,
};
use serde_json::json;
use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct Dns {
    pub resolver: TokioAsyncResolver,
    pub label: String,
}
impl Dns {
    pub fn new(server: Option<IpAddr>, tcp: bool, timeout: Duration) -> Result<Self> {
        let mut opts = ResolverOpts::default();
        opts.timeout = timeout;
        opts.attempts = 1;
        let (config, label) = if let Some(ip) = server {
            let mut config = ResolverConfig::new();
            config.add_name_server(NameServerConfig::new(
                SocketAddr::new(ip, 53),
                if tcp { Protocol::Tcp } else { Protocol::Udp },
            ));
            (config, ip.to_string())
        } else {
            let (mut config, _) = hickory_resolver::system_conf::read_system_conf()
                .context("read system DNS configuration")?;
            if tcp {
                let mut c = ResolverConfig::new();
                for n in config.name_servers() {
                    c.add_name_server(NameServerConfig::new(n.socket_addr, Protocol::Tcp));
                }
                config = c;
            }
            (config, "system".into())
        };
        Ok(Self {
            resolver: TokioAsyncResolver::tokio(config, opts),
            label,
        })
    }
    pub async fn txt(&self, name: &str) -> Result<Vec<String>> {
        Ok(self
            .resolver
            .txt_lookup(name)
            .await?
            .iter()
            .map(|r| {
                let bytes: Vec<u8> = r
                    .txt_data()
                    .iter()
                    .flat_map(|b| b.iter().copied())
                    .collect();
                String::from_utf8_lossy(&bytes).into_owned()
            })
            .collect())
    }
    pub async fn query(&self, name: &str, kind: RecordType) -> Finding {
        let start = Instant::now();
        let lookup_name = if kind == RecordType::PTR {
            match name.parse::<IpAddr>() {
                Ok(ip) => reverse_name(ip),
                Err(_) => name.into(),
            }
        } else {
            name.into()
        };
        match self.resolver.lookup(lookup_name, kind).await {
            Ok(answer) => {
                let rows: Vec<_> = answer.record_iter().map(|r| json!({"name": r.name().to_utf8(), "type": r.record_type().to_string(), "ttl": r.ttl(), "value": r.data().map(ToString::to_string)})).collect();
                Finding::new("dns", name, if rows.is_empty() {Status::Warn} else {Status::Pass}, format!("{} {} record(s)", rows.len(), kind), json!({"records": rows, "resolver": self.label, "dnssec": "not independently validated", "authoritative": null})).timed(start)
            }
            Err(e) => Finding::error("dns", name, e).timed(start),
        }
    }
    pub async fn mx(&self, name: &str) -> Finding {
        let start = Instant::now();
        let answer = match self.resolver.mx_lookup(name).await {
            Ok(a) => a,
            Err(e) => return Finding::error("mx", name, e).timed(start),
        };
        let mut mx: Vec<_> = answer.iter().collect();
        mx.sort_by_key(|r| r.preference());
        let mut rows = vec![];
        let mut status = Status::Pass;
        for record in &mx {
            let host = record.exchange().to_utf8();
            if host == "." {
                let valid = mx.len() == 1 && record.preference() == 0;
                return Finding::new(
                    "mx",
                    name,
                    if valid { Status::Info } else { Status::Fail },
                    if valid {
                        "Null MX: domain explicitly does not accept email"
                    } else {
                        "Invalid null MX mixed with other records or nonzero preference"
                    },
                    json!({"null_mx":true}),
                )
                .timed(start);
            }
            let ips = self.resolver.lookup_ip(host.as_str()).await;
            let addresses: Vec<_> = ips
                .as_ref()
                .map(|a| a.iter().map(|ip| ip.to_string()).collect())
                .unwrap_or_default();
            let cname = self
                .resolver
                .lookup(host.as_str(), RecordType::CNAME)
                .await
                .ok()
                .is_some_and(|a| a.iter().any(|r| matches!(r, RData::CNAME(_))));
            if addresses.is_empty() {
                status = Status::Fail;
            } else if cname && status != Status::Fail {
                status = Status::Warn;
            }
            rows.push(json!({"host": host, "preference": record.preference(), "addresses": addresses, "cname": cname, "error": ips.err().map(|e|e.to_string())}));
        }
        Finding::new(
            "mx",
            name,
            status,
            format!(
                "{} MX target(s); SMTP probing is a separate explicit operation",
                rows.len()
            ),
            json!({"records":rows}),
        )
        .timed(start)
    }
    pub async fn ptr(&self, ip: IpAddr) -> Finding {
        let start = Instant::now();
        let target = ip.to_string();
        let names = match self.resolver.reverse_lookup(ip).await {
            Ok(a) => a,
            Err(e) => return Finding::error("ptr", &target, e).timed(start),
        };
        let mut rows = vec![];
        let mut confirmed = false;
        for name in names.iter() {
            let result = self.resolver.lookup_ip(name.to_utf8()).await;
            let addresses: Vec<_> = result
                .as_ref()
                .map(|r| r.iter().collect())
                .unwrap_or_default();
            let matches = addresses.contains(&ip);
            confirmed |= matches;
            rows.push(json!({"hostname":name.to_utf8(), "addresses":addresses,"matches":matches,"error":result.err().map(|e|e.to_string())}));
        }
        Finding::new(
            "ptr",
            &target,
            if confirmed {
                Status::Pass
            } else {
                Status::Fail
            },
            if confirmed {
                "Forward-confirmed reverse DNS"
            } else {
                "PTR does not resolve back to the tested IP"
            },
            json!({"records":rows}),
        )
        .timed(start)
    }
}
pub fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => {
            let b = ip.octets();
            format!("{}.{}.{}.{}.in-addr.arpa.", b[3], b[2], b[1], b[0])
        }
        IpAddr::V6(ip) => {
            let h = format!("{:032x}", u128::from(ip));
            format!(
                "{}.ip6.arpa.",
                h.chars()
                    .rev()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>()
                    .join(".")
            )
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reverses_both_families() {
        assert_eq!(
            reverse_name("192.0.2.1".parse().unwrap()),
            "1.2.0.192.in-addr.arpa."
        );
        assert!(reverse_name("::1".parse().unwrap()).starts_with("1.0.0.0."));
    }
}
