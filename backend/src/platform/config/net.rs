//! Trusted-proxy handling.
//!
//! Threat: rate limiting, audit source attribution and abuse detection all depend
//! on knowing who sent a request. `X-Forwarded-For` is a client-supplied header —
//! anyone can send `X-Forwarded-For: 1.2.3.4` and, if it is trusted blindly, evade
//! every per-IP limit by rotating a header value (TH-38).
//!
//! Rule implemented here: proxy headers are honoured **only** when the immediate
//! peer address is inside a configured trusted CIDR. Otherwise the peer address is
//! used and the headers are ignored entirely.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An IP network in CIDR form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    addr: IpAddr,
    prefix_len: u8,
}

impl IpNet {
    pub fn parse(s: &str) -> Result<Self, String> {
        let (addr_part, prefix_part) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr_part
            .trim()
            .parse()
            .map_err(|_| format!("`{addr_part}` is not a valid IP address"))?;
        let max = if addr.is_ipv4() { 32u8 } else { 128u8 };
        let prefix_len = match prefix_part {
            // A bare address means a single host.
            None => max,
            Some(p) => {
                let n: u8 = p
                    .trim()
                    .parse()
                    .map_err(|_| format!("`{p}` is not a valid prefix length"))?;
                if n > max {
                    return Err(format!(
                        "prefix /{n} exceeds the maximum /{max} for this family"
                    ));
                }
                n
            }
        };
        Ok(Self { addr, prefix_len })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(candidate)) => {
                Self::prefix_matches(&net.octets(), &candidate.octets(), self.prefix_len)
            }
            (IpAddr::V6(net), IpAddr::V6(candidate)) => {
                Self::prefix_matches(&net.octets(), &candidate.octets(), self.prefix_len)
            }
            // An IPv4-mapped IPv6 peer (::ffff:10.0.0.1) is compared against IPv4
            // networks by its mapped form; without this, a proxy behind a
            // dual-stack listener would silently stop being trusted.
            (IpAddr::V4(net), IpAddr::V6(candidate)) => match candidate.to_ipv4_mapped() {
                Some(v4) => Self::prefix_matches(&net.octets(), &v4.octets(), self.prefix_len),
                None => false,
            },
            (IpAddr::V6(_), IpAddr::V4(_)) => false,
        }
    }

    fn prefix_matches(net: &[u8], candidate: &[u8], prefix_len: u8) -> bool {
        let full_bytes = (prefix_len / 8) as usize;
        let remaining_bits = prefix_len % 8;

        if net[..full_bytes] != candidate[..full_bytes] {
            return false;
        }
        if remaining_bits == 0 {
            return true;
        }
        let mask = 0xFFu8 << (8 - remaining_bits);
        (net[full_bytes] & mask) == (candidate[full_bytes] & mask)
    }
}

/// The set of networks whose `X-Forwarded-For` / `X-Real-IP` we believe.
#[derive(Debug, Clone, Default)]
pub struct TrustedProxies(Vec<IpNet>);

impl TrustedProxies {
    pub fn parse_list(csv: &str) -> Result<Self, String> {
        let mut nets = Vec::new();
        for entry in csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            nets.push(IpNet::parse(entry)?);
        }
        Ok(Self(nets))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn trusts(&self, peer: IpAddr) -> bool {
        self.0.iter().any(|n| n.contains(peer))
    }

    /// Resolve the effective client address.
    ///
    /// `forwarded_for` is the raw `X-Forwarded-For` value if present. Only the
    /// **last** entry is taken, and only from a trusted peer: entries to the left
    /// are appended by upstream hops and are attacker-controlled, so taking the
    /// first (the usual mistake) is exactly the spoofable choice.
    pub fn client_ip(&self, peer: IpAddr, forwarded_for: Option<&str>) -> IpAddr {
        if !self.trusts(peer) {
            return peer;
        }
        let Some(raw) = forwarded_for else {
            return peer;
        };
        raw.rsplit(',')
            .map(str::trim)
            .find_map(|candidate| {
                // Tolerate `[::1]:443` and `1.2.3.4:1234` forms.
                let cleaned = candidate
                    .trim_start_matches('[')
                    .split(']')
                    .next()
                    .unwrap_or(candidate);
                cleaned
                    .parse::<IpAddr>()
                    .ok()
                    .or_else(|| cleaned.rsplit_once(':').and_then(|(h, _)| h.parse().ok()))
            })
            .unwrap_or(peer)
    }
}

/// Loopback and RFC1918 defaults used for development only. Production must
/// configure this explicitly; an empty list means "trust nothing", which is the
/// correct fail-closed default.
pub fn development_default() -> TrustedProxies {
    TrustedProxies(vec![
        IpNet::parse("127.0.0.0/8").expect("static CIDR"),
        IpNet::parse("::1/128").expect("static CIDR"),
        IpNet::parse("10.0.0.0/8").expect("static CIDR"),
        IpNet::parse("172.16.0.0/12").expect("static CIDR"),
        IpNet::parse("192.168.0.0/16").expect("static CIDR"),
    ])
}

/// A conservative textual form for logs and the `*_hint` columns.
pub fn ip_hint(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v) => v.to_string(),
        IpAddr::V6(v) => v.to_string(),
    }
}

#[allow(dead_code)]
fn _assert_types(_: Ipv4Addr, _: Ipv6Addr) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).expect("test ip")
    }

    #[test]
    fn parses_v4_and_v6_cidrs_and_bare_hosts() {
        assert!(IpNet::parse("10.0.0.0/8").is_ok());
        assert!(IpNet::parse("::1/128").is_ok());
        assert!(
            IpNet::parse("192.168.1.5").is_ok(),
            "bare address means /32"
        );
        assert!(IpNet::parse("10.0.0.0/33").is_err());
        assert!(IpNet::parse("::1/129").is_err());
        assert!(IpNet::parse("not-an-ip").is_err());
        assert!(IpNet::parse("10.0.0.0/abc").is_err());
    }

    #[test]
    fn containment_respects_the_prefix() {
        let net = IpNet::parse("10.1.0.0/16").unwrap();
        assert!(net.contains(ip("10.1.0.1")));
        assert!(net.contains(ip("10.1.255.255")));
        assert!(!net.contains(ip("10.2.0.1")));

        let odd = IpNet::parse("192.168.1.0/25").unwrap();
        assert!(odd.contains(ip("192.168.1.127")));
        assert!(!odd.contains(ip("192.168.1.128")));

        let host = IpNet::parse("203.0.113.7").unwrap();
        assert!(host.contains(ip("203.0.113.7")));
        assert!(!host.contains(ip("203.0.113.8")));
    }

    #[test]
    fn ipv4_mapped_ipv6_peers_match_ipv4_networks() {
        let net = IpNet::parse("10.0.0.0/8").unwrap();
        assert!(net.contains(ip("::ffff:10.1.2.3")));
        assert!(!net.contains(ip("::ffff:11.1.2.3")));
        assert!(!net.contains(ip("2001:db8::1")));
    }

    /// The core anti-spoofing property.
    #[test]
    fn forwarded_headers_from_an_untrusted_peer_are_ignored() {
        let trusted = TrustedProxies::parse_list("10.0.0.0/8").unwrap();
        let attacker = ip("203.0.113.9");
        assert_eq!(
            trusted.client_ip(attacker, Some("1.2.3.4")),
            attacker,
            "an untrusted peer must not be able to choose its own identity"
        );
    }

    #[test]
    fn an_empty_trust_list_trusts_nothing() {
        let none = TrustedProxies::default();
        assert!(none.is_empty());
        assert_eq!(
            none.client_ip(ip("10.0.0.1"), Some("1.2.3.4")),
            ip("10.0.0.1")
        );
    }

    #[test]
    fn the_rightmost_entry_is_taken_from_a_trusted_peer() {
        let trusted = TrustedProxies::parse_list("10.0.0.0/8").unwrap();
        let proxy = ip("10.0.0.1");
        // The client sent "1.2.3.4"; our own proxy appended the real peer.
        // Taking the leftmost would take the attacker's value.
        assert_eq!(
            trusted.client_ip(proxy, Some("1.2.3.4, 198.51.100.7")),
            ip("198.51.100.7")
        );
    }

    #[test]
    fn tolerates_port_suffixes_and_bracketed_v6() {
        let trusted = TrustedProxies::parse_list("10.0.0.0/8").unwrap();
        let proxy = ip("10.0.0.1");
        assert_eq!(
            trusted.client_ip(proxy, Some("198.51.100.7:44321")),
            ip("198.51.100.7")
        );
        assert_eq!(
            trusted.client_ip(proxy, Some("[2001:db8::5]:443")),
            ip("2001:db8::5")
        );
    }

    #[test]
    fn garbage_forwarded_header_falls_back_to_the_peer() {
        let trusted = TrustedProxies::parse_list("10.0.0.0/8").unwrap();
        let proxy = ip("10.0.0.1");
        assert_eq!(trusted.client_ip(proxy, Some("not-an-ip")), proxy);
        assert_eq!(trusted.client_ip(proxy, Some("")), proxy);
        assert_eq!(trusted.client_ip(proxy, Some(&"9".repeat(100_000))), proxy);
    }
}
