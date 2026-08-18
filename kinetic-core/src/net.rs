//! Network IP address validation and Server-Side Request Forgery (SSRF) defenses.
//!
//! Provides IP filtering utilities for HTTP proxy forwarding to prevent malicious target resolution.

use std::net::IpAddr;

pub use crate::error::ssrf::SsrfError;

/// Checks whether an IP address is safe to connect to or proxy through.
///
/// Returns an `SsrfError` for loopback, unspecified, private, link-local, broadcast,
/// multicast, documentation, CGNAT (`100.64.0.0/10`), NAT64 (`64:ff9b::/96`),
/// and IPv4-mapped IPv6 internal targets.
///
/// # Examples
///
/// ```
/// use std::net::IpAddr;
/// use kinetic_core::net::{validate_ssrf_safe, SsrfError};
///
/// assert!(validate_ssrf_safe("1.1.1.1".parse::<IpAddr>().unwrap()).is_ok());
/// assert_eq!(validate_ssrf_safe("127.0.0.1".parse::<IpAddr>().unwrap()), Err(SsrfError::Loopback));
/// assert_eq!(validate_ssrf_safe("192.168.1.1".parse::<IpAddr>().unwrap()), Err(SsrfError::Private));
/// ```
pub fn validate_ssrf_safe(ip: IpAddr) -> Result<(), SsrfError> {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                return Err(SsrfError::Loopback);
            }
            if v4.is_unspecified() {
                return Err(SsrfError::Unspecified);
            }
            if v4.is_private() {
                return Err(SsrfError::Private);
            }
            if v4.is_link_local() || v4.is_broadcast() || v4.is_multicast() {
                return Err(SsrfError::LocalNetworkRouting);
            }
            if v4.is_documentation() {
                return Err(SsrfError::Reserved);
            }
            let octets = v4.octets();
            if octets[0] == 0 {
                return Err(SsrfError::Reserved); // 0.0.0.0/8
            }
            if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
                return Err(SsrfError::CgNat); // 100.64.0.0/10 CGNAT
            }
            Ok(())
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return Err(SsrfError::Loopback);
            }
            if v6.is_unspecified() {
                return Err(SsrfError::Unspecified);
            }
            if v6.is_multicast() {
                return Err(SsrfError::LocalNetworkRouting);
            }

            let segments = v6.segments();
            // IPv6 Link-Local (fe80::/10)
            if segments[0] & 0xffc0 == 0xfe80 {
                return Err(SsrfError::LocalNetworkRouting);
            }
            // IPv6 Unique Local (fc00::/7)
            if segments[0] & 0xfe00 == 0xfc00 {
                return Err(SsrfError::Private);
            }

            // IPv4-Compatible IPv6 (::/96) - Deprecated but some kernels still route to loopback
            if segments[0] == 0
                && segments[1] == 0
                && segments[2] == 0
                && segments[3] == 0
                && segments[4] == 0
                && segments[5] == 0
            {
                return Err(SsrfError::Ipv6MappedExploit);
            }

            // Check for IPv4-mapped IPv6 address that wraps a dangerous v4
            if let Some(v4_mapped) = v6.to_ipv4_mapped() {
                // If it resolves to an error, we can map it to a specific exploit log
                if let Err(_) = validate_ssrf_safe(IpAddr::V4(v4_mapped)) {
                    return Err(SsrfError::Ipv6MappedExploit);
                }
            }

            let segments = v6.segments();
            // IPv6 NAT64 64:ff9b::/96
            if segments[0] == 0x0064
                && segments[1] == 0xff9b
                && segments[2] == 0
                && segments[3] == 0
                && segments[4] == 0
                && segments[5] == 0
            {
                return Err(SsrfError::Nat64);
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_valid_public_ips() {
        assert!(validate_ssrf_safe("1.1.1.1".parse::<IpAddr>().unwrap()).is_ok());
        assert!(validate_ssrf_safe("8.8.8.8".parse::<IpAddr>().unwrap()).is_ok());
        assert!(validate_ssrf_safe("2606:4700:4700::1111".parse::<IpAddr>().unwrap()).is_ok());
    }

    #[test]
    fn test_loopback_ips() {
        assert_eq!(validate_ssrf_safe("127.0.0.1".parse::<IpAddr>().unwrap()), Err(SsrfError::Loopback));
        assert_eq!(validate_ssrf_safe("127.12.34.56".parse::<IpAddr>().unwrap()), Err(SsrfError::Loopback));
        assert_eq!(validate_ssrf_safe("::1".parse::<IpAddr>().unwrap()), Err(SsrfError::Loopback));
    }

    #[test]
    fn test_private_ips() {
        assert_eq!(validate_ssrf_safe("10.0.0.1".parse::<IpAddr>().unwrap()), Err(SsrfError::Private));
        assert_eq!(validate_ssrf_safe("192.168.1.1".parse::<IpAddr>().unwrap()), Err(SsrfError::Private));
        assert_eq!(validate_ssrf_safe("172.16.0.1".parse::<IpAddr>().unwrap()), Err(SsrfError::Private));
        assert_eq!(validate_ssrf_safe("fc00::1".parse::<IpAddr>().unwrap()), Err(SsrfError::Private)); // IPv6 Unique Local
        assert_eq!(validate_ssrf_safe("fd12::34".parse::<IpAddr>().unwrap()), Err(SsrfError::Private)); // IPv6 Unique Local
    }

    #[test]
    fn test_advanced_ipv6_wrappers() {
        // IPv4-mapped IPv6 pointing to loopback
        assert_eq!(validate_ssrf_safe("::ffff:127.0.0.1".parse::<IpAddr>().unwrap()), Err(SsrfError::Ipv6MappedExploit));
        // IPv4-compatible IPv6 pointing to loopback
        assert_eq!(validate_ssrf_safe("::127.0.0.1".parse::<IpAddr>().unwrap()), Err(SsrfError::Ipv6MappedExploit));
        // IPv6 NAT64
        assert_eq!(validate_ssrf_safe("64:ff9b::192.0.2.33".parse::<IpAddr>().unwrap()), Err(SsrfError::Nat64));
    }

    #[test]
    fn test_cgnat_and_zero() {
        assert_eq!(validate_ssrf_safe("0.0.0.0".parse::<IpAddr>().unwrap()), Err(SsrfError::Unspecified));
        assert_eq!(validate_ssrf_safe("100.64.0.1".parse::<IpAddr>().unwrap()), Err(SsrfError::CgNat));
        assert_eq!(validate_ssrf_safe("100.127.255.254".parse::<IpAddr>().unwrap()), Err(SsrfError::CgNat));
        // But 100.63.x.x is public, not CGNAT
        assert!(validate_ssrf_safe("100.63.255.255".parse::<IpAddr>().unwrap()).is_ok());
    }
}
