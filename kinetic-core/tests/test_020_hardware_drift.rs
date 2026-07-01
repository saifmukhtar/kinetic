use kinetic_core::consensus_math::ConsensusParams;

#[test]
fn test_hardware_drift_soft_lock() {
    let params = ConsensusParams::default();

    // Simulate current_round far in the future (e.g. 20 years)
    // hardware_drift_rounds = 2 years (21,024,000 rounds)
    // 20 years = 10 * 21_024,000 = 210,240,000 rounds
    let current_round_20_years = 210_240_000;

    let base_anchor = params.calculate_hardware_anchor(0);
    let anchor_20_years = params.calculate_hardware_anchor(current_round_20_years);

    // Without a cap, this will be 1024 * base_anchor!
    // We want to assert that the anchor is CAPPED at a reasonable limit (e.g., max 32x)
    assert!(
        anchor_20_years <= base_anchor * 32,
        "Hardware drift anchor grew to {} which is more than 32x the base!",
        anchor_20_years / base_anchor
    );
}
