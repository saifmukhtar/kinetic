#[test]
fn test_decay() {
    let params = kinetic_core::consensus_math::ConsensusParams::default();
    let a = params.required_iterations("a");
    let ab = params.required_iterations("ab");
    let abc = params.required_iterations("abc");
    let is_dev = kinetic_core::config::is_dev_mode();
    println!(
        "a: {}, ab: {}, abc: {}, is_dev_mode: {}",
        a, ab, abc, is_dev
    );
}
