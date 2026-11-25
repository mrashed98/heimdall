//! Where alerts may be sent. Every delivery resolves its destination here and
//! connects only to the addresses this module returns, so a check made at
//! send time is the check the connection obeys (no DNS rebinding window).
//!
//! Two rules:
//! - Never: link-local and cloud metadata addresses, unspecified, multicast
//!   and broadcast. No alert destination lives there, and the metadata
//!   service is where cloud credentials are taken from.
//! - Console channels only, when `console_channels.allowed_hosts` is set:
//!   the destination must match one of its rules. It is config-only on
//!   purpose: it limits what console admins can reach, so they can't edit it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use ipnet::IpNet;
use serde::Deserialize;

/// How long a destination lookup may take.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Who defined the channel: an operator in `heimdall.yaml`, or an admin in
/// the console.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Config,
    Console,
}

/// One `allowed_hosts` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostRule {
    /// `alertmanager.monitoring.svc`: this host name only.
    Exact(String),
    /// `*.example.com`: any subdomain of `example.com`, not the apex.
    Suffix(String),
    /// `10.0.0.0/8` or `10.1.2.3`: any address in the network.
    Net(IpNet),
}

impl FromStr for HostRule {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if let Ok(net) = s.parse::<IpNet>() {
            return Ok(HostRule::Net(net));
        }
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(HostRule::Net(IpNet::from(ip)));
        }
        let (wild, name) = match s.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, s),
        };
        let name = normalize(name);
        let valid = !name.is_empty()
            && name.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            });
        if !valid {
            return Err(format!(
                "`{s}` is not a host name, `*.domain`, IP address or CIDR network"
            ));
        }
        Ok(if wild {
            HostRule::Suffix(name)
        } else {
            HostRule::Exact(name)
        })
    }
}

impl<'de> Deserialize<'de> for HostRule {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// `console_channels` in `heimdall.yaml`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleChannels {
    /// When non-empty, console channels may only send to these hosts.
    #[serde(default)]
    pub allowed_hosts: Vec<HostRule>,
}

fn normalize(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Whether `ip` is never a valid alert destination.
pub fn forbidden(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => forbidden_v4(v4),
        IpAddr::V6(v6) => {
            if embedded_v4(v6).is_some_and(forbidden_v4) {
                return true;
            }
            let seg = v6.segments();
            v6.is_unspecified()
                || v6.is_multicast()
                // fe80::/10, link-local.
                || (seg[0] & 0xffc0) == 0xfe80
                // AWS's IPv6 instance metadata address.
                || v6 == Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254)
        }
    }
}

/// The IPv4 address an IPv6 address carries, in every form that can reach
/// it: mapped (`::ffff:a.b.c.d`), compatible (`::a.b.c.d`), NAT64
/// (`64:ff9b::/96`, `64:ff9b:1::/48`, last 32 bits) and 6to4 (`2002::/16`,
/// bits 16-47).
fn embedded_v4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = v6.segments();
    let last = Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8);
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }
    if s[..6] == [0; 6] && !v6.is_unspecified() && !v6.is_loopback() {
        return Some(last);
    }
    if (s[0], s[1]) == (0x64, 0xff9b) {
        return Some(last);
    }
    if s[0] == 0x2002 {
        return Some(Ipv4Addr::new(
            (s[1] >> 8) as u8,
            s[1] as u8,
            (s[2] >> 8) as u8,
            s[2] as u8,
        ));
    }
    None
}

fn forbidden_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_link_local() // 169.254.0.0/16: AWS, GCP, Azure, OpenStack metadata
        || o[0] == 0 // 0.0.0.0/8
        || ip.is_multicast()
        || ip.is_broadcast()
        // Alibaba Cloud's metadata address.
        || ip == Ipv4Addr::new(100, 100, 100, 200)
        // Azure's WireServer (VM agent and extension settings).
        || ip == Ipv4Addr::new(168, 63, 129, 16)
}

/// The destination rules, built from the config.
#[derive(Debug, Clone, Default)]
pub struct Egress {
    console_allow: Vec<HostRule>,
}

impl Egress {
    pub fn new(cfg: &ConsoleChannels) -> Egress {
        Egress {
            console_allow: cfg.allowed_hosts.clone(),
        }
    }

    /// The addresses a channel from `origin` may connect to for `host`, or
    /// why it may not. `host` may be a name or an IP literal (IPv6 with or
    /// without brackets).
    pub async fn resolve(
        &self,
        host: &str,
        port: u16,
        origin: Origin,
    ) -> Result<Vec<SocketAddr>, String> {
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        let literal = bare.parse::<IpAddr>().ok();
        let addrs: Vec<SocketAddr> = match literal {
            Some(ip) => vec![SocketAddr::new(ip, port)],
            None => {
                let lookup = tokio::net::lookup_host((bare, port));
                match tokio::time::timeout(LOOKUP_TIMEOUT, lookup).await {
                    Ok(Ok(it)) => it.collect(),
                    Ok(Err(e)) => return Err(format!("cannot resolve the destination host: {e}")),
                    Err(_) => return Err("resolving the destination host timed out".to_string()),
                }
            }
        };
        let name = literal.is_none().then(|| normalize(bare));
        let name_allowed = match (&name, origin) {
            (_, Origin::Config) => true,
            (_, Origin::Console) if self.console_allow.is_empty() => true,
            (Some(n), Origin::Console) => self.console_allow.iter().any(|r| match r {
                HostRule::Exact(h) => h == n,
                HostRule::Suffix(s) => n.len() > s.len() + 1 && n.ends_with(&format!(".{s}")),
                HostRule::Net(_) => false,
            }),
            (None, Origin::Console) => false,
        };
        let mut blocked: Option<IpAddr> = None;
        let ok: Vec<SocketAddr> = addrs
            .into_iter()
            .filter(|a| {
                let ip = a.ip();
                let allowed = !forbidden(ip)
                    && (name_allowed
                        || self.console_allow.iter().any(|r| match r {
                            HostRule::Net(net) => net.contains(&canonical(ip)),
                            _ => false,
                        }));
                if !allowed {
                    blocked.get_or_insert(ip);
                }
                allowed
            })
            .collect();
        if ok.is_empty() {
            return Err(match blocked {
                // Never the host name: for some webhooks it is part of the
                // secret URL.
                Some(ip) if forbidden(ip) => {
                    format!("the destination is {ip}, a link-local or metadata address")
                }
                Some(_) => "the destination is not in console_channels.allowed_hosts".to_string(),
                None => "the destination host has no address".to_string(),
            });
        }
        Ok(ok)
    }
}

impl Egress {
    /// The check made when a console channel is saved: the same as at send
    /// time, except that a host name is only looked up when an allowlist is
    /// set, so a destination whose DNS is briefly down can still be saved
    /// (sending checks it again anyway).
    pub async fn check_console(&self, host: &str, port: u16) -> Result<(), String> {
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        if bare.parse::<IpAddr>().is_err() && self.console_allow.is_empty() {
            return Ok(());
        }
        self.resolve(host, port, Origin::Console).await.map(|_| ())
    }
}

/// An IPv4 address written as IPv6 (`::ffff:a.b.c.d`) as plain IPv4, so
/// IPv4 networks in `allowed_hosts` match it.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(rules: &[&str]) -> Egress {
        Egress {
            console_allow: rules.iter().map(|r| r.parse().unwrap()).collect(),
        }
    }

    #[test]
    fn metadata_and_link_local_are_forbidden() {
        for ip in [
            "169.254.169.254",
            "169.254.0.1",
            "100.100.100.200",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "fe80::1",
            "fd00:ec2::254",
            "::",
            "ff02::1",
            "::ffff:169.254.169.254",
            "::169.254.169.254",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b:1::a9fe:a9fe",
            "2002:a9fe:a9fe::1",
            "168.63.129.16",
        ] {
            assert!(forbidden(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.1",
            "8.8.8.8",
            "::1",
            "fd00::1",
            "64:ff9b::808:808",
            "2002:808:808::1",
        ] {
            assert!(!forbidden(ip.parse().unwrap()), "{ip}");
        }
    }

    #[tokio::test]
    async fn forbidden_literals_fail_for_every_origin() {
        let e = Egress::default();
        for host in [
            "169.254.169.254",
            "[fd00:ec2::254]",
            "::ffff:169.254.169.254",
        ] {
            for origin in [Origin::Config, Origin::Console] {
                let err = e.resolve(host, 80, origin).await.unwrap_err();
                assert!(err.contains("metadata"), "{host}: {err}");
            }
        }
        assert!(e.resolve("127.0.0.1", 80, Origin::Console).await.is_ok());
    }

    #[tokio::test]
    async fn allowlist_limits_console_channels_only() {
        let e = allow(&["*.example.com", "hooks.internal", "10.0.0.0/8"]);
        let console = |h: &'static str| {
            let e = e.clone();
            async move { e.resolve(h, 443, Origin::Console).await }
        };
        assert!(console("10.1.2.3").await.is_ok());
        assert!(console("::ffff:10.1.2.3").await.is_ok());
        assert!(console("127.0.0.1").await.is_err());
        assert!(console("192.168.1.1").await.is_err());
        // `localhost` resolves to loopback, which no rule allows.
        assert!(console("localhost").await.is_err());
        assert!(e.resolve("127.0.0.1", 443, Origin::Config).await.is_ok());
    }

    #[test]
    fn name_rules_match_names() {
        let rules = allow(&["*.example.com", "Hooks.Internal."]).console_allow;
        assert_eq!(rules[0], HostRule::Suffix("example.com".into()));
        assert_eq!(rules[1], HostRule::Exact("hooks.internal".into()));
        assert!("bad host".parse::<HostRule>().is_err());
        assert!("*.".parse::<HostRule>().is_err());
        assert_eq!(
            "10.1.2.3".parse::<HostRule>().unwrap(),
            HostRule::Net("10.1.2.3/32".parse().unwrap())
        );
    }
}
