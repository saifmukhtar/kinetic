use kinetic_core::consensus_math::ConsensusParams;
use kinetic_core::types::is_valid_apex_name;

#[test]
fn test_length_spam_penalty() {
    let params = ConsensusParams::default();

    // Normal 5 char name
    let iters_5 = params.required_iterations("hello.kin", 5000000, &[0u8; 32]);
    // Normal 15 char name
    let iters_15 = params.required_iterations("thisisalongname.kin", 5000000, &[0u8; 32]);

    // 25 char name (spam penalty triggers)
    let iters_25 = params.required_iterations("thisisanextremelylongname.kin", 5000000, &[0u8; 32]);

    // 63 char name (maximum valid apex label size, triggers spam penalty)
    let long_label = "a".repeat(63);
    let iters_63 = params.required_iterations(&format!("{}.kin", long_label), 5000000, &[0u8; 32]);

    assert!(
        iters_15 < iters_5,
        "Shorter name should be harder (more iterations)"
    );

    // Flat tail should pin 25 char to the same multiplier as 15 char
    assert_eq!(
        iters_25, iters_15,
        "Flat tail should pin 25 char to 15 char difficulty"
    );

    // Flat tail should pin 63 char as well
    assert_eq!(
        iters_63, iters_25,
        "Flat tail should pin 63 char to 25 char difficulty"
    );

    // Max length validation
    assert!(
        is_valid_apex_name(&format!("{}.kin", long_label)),
        "63 char label is valid"
    );

    let too_long = "a".repeat(64);
    assert!(
        !is_valid_apex_name(&format!("{}.kin", too_long)),
        "64 char label should be invalid"
    );
}
