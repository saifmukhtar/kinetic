fn main() {
    println!("{:?}", dirs::config_dir().unwrap_or_else(|| std::path::PathBuf::from(".")).join("kinetic").join("api.token"));
}
