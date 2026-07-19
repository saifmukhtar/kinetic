pub(crate) fn is_ssrf_risk(ip: std::net::IpAddr) -> bool {
    !kinetic_core::net::is_ssrf_safe(ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::net::{IpAddr, Ipv4Addr};

    proptest! {
        #[test]
        fn test_fuzz_is_ssrf_risk_rejects_loopback(
            a in 127u8..=127,
            b in 0u8..=255,
            c in 0u8..=255,
            d in 0u8..=255
        ) {
            let ip = IpAddr::V4(Ipv4Addr::new(a, b, c, d));
            prop_assert!(is_ssrf_risk(ip));
        }

        #[test]
        fn test_fuzz_is_ssrf_risk_rejects_internal_10(
            a in 10u8..=10,
            b in 0u8..=255,
            c in 0u8..=255,
            d in 0u8..=255
        ) {
            let ip = IpAddr::V4(Ipv4Addr::new(a, b, c, d));
            prop_assert!(is_ssrf_risk(ip));
        }

        #[test]
        fn test_fuzz_is_ssrf_risk_allows_public(
            a in 1u8..=9, // Avoid 0 (unspecified) and 10 (internal)
            b in 0u8..=255,
            c in 0u8..=255,
            d in 0u8..=255
        ) {
            let ip = IpAddr::V4(Ipv4Addr::new(a, b, c, d));
            prop_assert!(!is_ssrf_risk(ip));
        }
    }
}
