fn main() {
    println!("{:?}", rustls::crypto::ring::default_provider().install_default());
}
