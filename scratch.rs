fn main() {
    let name = "example.kin";
    let normalized = kinetic_core::types::normalize_name(name);
    let extracted = kinetic_core::types::extract_apex_domain(&normalized);
    let is_public = kinetic_core::types::PUBLIC_NAMES.contains(&extracted.as_str());
    println!("normalized: {}", normalized);
    println!("extracted: {}", extracted);
    println!("is_public: {}", is_public);
    println!("is_valid: {}", kinetic_core::types::is_valid_apex_name(name));
}
