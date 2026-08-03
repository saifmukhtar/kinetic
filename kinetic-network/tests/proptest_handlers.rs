use kinetic_network::event_loop::core::NetworkEventLoop;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn test_xor_tie_breaker_no_panic(
        kyn in any::<u64>(),
        payloads in prop::collection::vec(any::<Vec<u8>>(), 0..20)
    ) {
        // xor_tie_breaker handles parsing JSON internally, so throwing arbitrary bytes at it
        // tests the resilience of serde_json::from_slice and the filtering logic.
        let _ = NetworkEventLoop::xor_tie_breaker("test.kin", payloads, kyn);
    }
}
