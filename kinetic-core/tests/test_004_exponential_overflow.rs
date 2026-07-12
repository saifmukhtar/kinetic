use kinetic_core::consensus_math::ConsensusParams;

#[test]
fn test_004_exponential_overflow() {
    let params = ConsensusParams::default();

    // Pass in u64::MAX to trigger extreme drift
    let extreme_round = u64::MAX;

    // Under OLD logic, this might panic, return 0, or act unpredictably depending on Rust version
    // Under NEW logic, this should gracefully saturate at u64::MAX
    let iterations = params.required_iterations(
        &format!("{}{}", "test", kinetic_core::types::DOT_TLD),
        extreme_round,
    );

    assert_eq!(
        iterations,
        134_217_728 * 207, // 32x base (4,194,304 * 32 = 134,217,728) * multiplier for 4 chars (207)
        "SECURITY FLAW: Hardware drift overflow did not gracefully saturate to 32x cap!"
    );
}
