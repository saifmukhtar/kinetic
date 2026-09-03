//! SSRF risk evaluation utilities and IP address safety verification.

pub(crate) fn validate_ssrf_risk(
    ip: std::net::IpAddr,
) -> Result<(), kinetic_core::net::SecurityError> {
    kinetic_core::net::validate_ssrf_safe(ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::net::{IpAddr, Ipv4Addr};

    proptest! {
        #[test]
        fn test_ssrf_risk_loopback(
            a in 127u8..=127,
            b in 0u8..=255,
            c in 0u8..=255,
            d in 0u8..=255
        ) {
            let ip = IpAddr::V4(Ipv4Addr::new(a, b, c, d));
            prop_assert!(validate_ssrf_risk(ip).is_err());
        }

        #[test]
        fn test_ssrf_risk_internal_10(
            a in 10u8..=10,
            b in 0u8..=255,
            c in 0u8..=255,
            d in 0u8..=255
        ) {
            let ip = IpAddr::V4(Ipv4Addr::new(a, b, c, d));
            prop_assert!(validate_ssrf_risk(ip).is_err());
        }

        #[test]
        fn test_ssrf_risk_public(
            a in 1u8..=9, // Avoid 0 (unspecified) and 10 (internal)
            b in 0u8..=255,
            c in 0u8..=255,
            d in 0u8..=255
        ) {
            let ip = std::net::IpAddr::V4(Ipv4Addr::new(a, b, c, d));
            prop_assert!(validate_ssrf_risk(ip).is_ok());
        }
    }
}
