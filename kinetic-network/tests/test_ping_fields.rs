fn main() {
    let cfg = libp2p::ping::Config::default();
    let _ = cfg.with_interval(std::time::Duration::from_secs(5));
}
