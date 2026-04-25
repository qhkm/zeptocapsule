//! SSRF and DNS-rebinding defense.
//!
//! Pure IP classification — no DNS, no I/O. The proxy layer resolves the
//! hostname, classifies the resulting addresses, and pins one for the
//! request lifetime so a rebind to a private IP between policy check and
//! socket connect cannot bypass the gate.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};

/// Coarse classification of an IP address. Only [`IpClass::Public`] is safe
/// for capsule egress when `block_private_networks` is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpClass {
    Public,
    Loopback,
    /// RFC1918 (v4) — 10/8, 172.16/12, 192.168/16.
    Private,
    /// IPv6 unique-local (fc00::/7).
    UniqueLocal,
    /// 169.254/16 (v4) or fe80::/10 (v6).
    LinkLocal,
    /// 100.64/10 — carrier-grade NAT.
    CarrierGradeNat,
    /// 169.254.169.254 (v4) or fd00:ec2::254 (v6) — cloud-provider metadata.
    Metadata,
    Multicast,
    /// Reserved / documentation / benchmark / unspecified.
    Reserved,
}

impl IpClass {
    pub fn is_public(self) -> bool {
        matches!(self, IpClass::Public)
    }
}

/// Classify a single IP address.
pub fn classify_ip(ip: IpAddr) -> IpClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

/// One-shot question: should this IP be blocked when
/// `block_private_networks` is enabled? Equivalent to
/// `!classify_ip(ip).is_public()`.
pub fn is_private_or_metadata(ip: IpAddr) -> bool {
    !classify_ip(ip).is_public()
}

const AWS_V4_METADATA: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);

fn classify_v4(ip: Ipv4Addr) -> IpClass {
    if ip == AWS_V4_METADATA {
        return IpClass::Metadata;
    }
    if ip.is_loopback() {
        return IpClass::Loopback;
    }
    if ip.is_private() {
        return IpClass::Private;
    }
    if ip.is_link_local() {
        return IpClass::LinkLocal;
    }
    if ip.is_multicast() {
        return IpClass::Multicast;
    }
    if ip.is_broadcast() || ip.is_unspecified() || ip.is_documentation() {
        return IpClass::Reserved;
    }
    // 100.64.0.0/10 — RFC6598 carrier-grade NAT. Not exposed by std,
    // checked manually.
    let cgn: Ipv4Net = "100.64.0.0/10".parse().expect("valid CGN net");
    if cgn.contains(&ip) {
        return IpClass::CarrierGradeNat;
    }
    // RFC1112 reserved 240/4 (excluding broadcast which is already handled).
    if ip.octets()[0] >= 240 {
        return IpClass::Reserved;
    }
    // 192.0.0.0/24 protocol assignments and 198.18.0.0/15 benchmark.
    let proto: Ipv4Net = "192.0.0.0/24".parse().unwrap();
    let bench: Ipv4Net = "198.18.0.0/15".parse().unwrap();
    if proto.contains(&ip) || bench.contains(&ip) {
        return IpClass::Reserved;
    }
    IpClass::Public
}

/// AWS IMDS over IPv6: `fd00:ec2::254`.
const AWS_V6_METADATA: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254);

fn classify_v6(ip: Ipv6Addr) -> IpClass {
    if ip == AWS_V6_METADATA {
        return IpClass::Metadata;
    }
    if ip.is_loopback() {
        return IpClass::Loopback;
    }
    if ip.is_unspecified() {
        return IpClass::Reserved;
    }
    if ip.is_multicast() {
        return IpClass::Multicast;
    }
    // IPv4-mapped (::ffff:0:0/96) — classify by the embedded v4. An attacker
    // could otherwise bypass the v4 gates by encoding 127.0.0.1 as
    // ::ffff:127.0.0.1.
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return classify_v4(mapped);
    }
    let link_local: Ipv6Net = "fe80::/10".parse().unwrap();
    if link_local.contains(&ip) {
        return IpClass::LinkLocal;
    }
    let unique_local: Ipv6Net = "fc00::/7".parse().unwrap();
    if unique_local.contains(&ip) {
        return IpClass::UniqueLocal;
    }
    let documentation: Ipv6Net = "2001:db8::/32".parse().unwrap();
    if documentation.contains(&ip) {
        return IpClass::Reserved;
    }
    IpClass::Public
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    #[test]
    fn public_v4_classifies_as_public() {
        assert_eq!(classify_ip(ip("8.8.8.8")), IpClass::Public);
        assert_eq!(classify_ip(ip("1.1.1.1")), IpClass::Public);
        assert_eq!(classify_ip(ip("142.250.190.46")), IpClass::Public);
    }

    #[test]
    fn rfc1918_blocks() {
        assert_eq!(classify_ip(ip("10.0.0.1")), IpClass::Private);
        assert_eq!(classify_ip(ip("172.16.0.1")), IpClass::Private);
        assert_eq!(classify_ip(ip("172.31.255.255")), IpClass::Private);
        assert_eq!(classify_ip(ip("192.168.1.1")), IpClass::Private);
        // 172.32 is outside RFC1918.
        assert_eq!(classify_ip(ip("172.32.0.1")), IpClass::Public);
    }

    #[test]
    fn loopback_v4_blocks() {
        assert_eq!(classify_ip(ip("127.0.0.1")), IpClass::Loopback);
        assert_eq!(classify_ip(ip("127.255.255.254")), IpClass::Loopback);
    }

    #[test]
    fn link_local_blocks() {
        assert_eq!(classify_ip(ip("169.254.1.1")), IpClass::LinkLocal);
    }

    #[test]
    fn aws_v4_metadata_classifies_as_metadata() {
        assert_eq!(classify_ip(ip("169.254.169.254")), IpClass::Metadata);
    }

    #[test]
    fn carrier_grade_nat_blocks() {
        assert_eq!(classify_ip(ip("100.64.0.1")), IpClass::CarrierGradeNat);
        assert_eq!(classify_ip(ip("100.127.255.254")), IpClass::CarrierGradeNat);
        assert_eq!(classify_ip(ip("100.128.0.1")), IpClass::Public);
    }

    #[test]
    fn reserved_ranges_block() {
        assert_eq!(classify_ip(ip("0.0.0.0")), IpClass::Reserved);
        assert_eq!(classify_ip(ip("240.0.0.1")), IpClass::Reserved);
        assert_eq!(classify_ip(ip("198.18.0.1")), IpClass::Reserved);
        assert_eq!(classify_ip(ip("192.0.2.1")), IpClass::Reserved); // documentation
        assert_eq!(classify_ip(ip("192.0.0.1")), IpClass::Reserved); // protocol
    }

    #[test]
    fn broadcast_blocks() {
        assert_eq!(classify_ip(ip("255.255.255.255")), IpClass::Reserved);
    }

    #[test]
    fn multicast_blocks() {
        assert_eq!(classify_ip(ip("224.0.0.1")), IpClass::Multicast);
    }

    #[test]
    fn loopback_v6_blocks() {
        assert_eq!(classify_ip(ip("::1")), IpClass::Loopback);
    }

    #[test]
    fn ipv4_mapped_does_not_bypass_v4_gates() {
        // ::ffff:127.0.0.1 must classify as loopback, not Public.
        assert_eq!(classify_ip(ip("::ffff:127.0.0.1")), IpClass::Loopback);
        assert_eq!(classify_ip(ip("::ffff:10.0.0.1")), IpClass::Private);
        assert_eq!(classify_ip(ip("::ffff:169.254.169.254")), IpClass::Metadata);
    }

    #[test]
    fn unique_local_v6_blocks() {
        assert_eq!(classify_ip(ip("fc00::1")), IpClass::UniqueLocal);
        assert_eq!(classify_ip(ip("fd12:3456::1")), IpClass::UniqueLocal);
    }

    #[test]
    fn link_local_v6_blocks() {
        assert_eq!(classify_ip(ip("fe80::1")), IpClass::LinkLocal);
    }

    #[test]
    fn aws_v6_metadata_classifies_as_metadata() {
        assert_eq!(classify_ip(ip("fd00:ec2::254")), IpClass::Metadata);
    }

    #[test]
    fn documentation_v6_blocks() {
        assert_eq!(classify_ip(ip("2001:db8::1")), IpClass::Reserved);
    }

    #[test]
    fn public_v6_classifies_as_public() {
        assert_eq!(classify_ip(ip("2606:4700:4700::1111")), IpClass::Public);
    }

    #[test]
    fn unspecified_v6_blocks() {
        assert_eq!(classify_ip(ip("::")), IpClass::Reserved);
    }

    #[test]
    fn is_private_or_metadata_matches_classification() {
        assert!(!is_private_or_metadata(ip("8.8.8.8")));
        assert!(is_private_or_metadata(ip("10.0.0.1")));
        assert!(is_private_or_metadata(ip("169.254.169.254")));
        assert!(is_private_or_metadata(ip("127.0.0.1")));
        assert!(is_private_or_metadata(ip("::1")));
        assert!(is_private_or_metadata(ip("fc00::1")));
        assert!(is_private_or_metadata(ip("::ffff:10.0.0.1")));
    }
}
