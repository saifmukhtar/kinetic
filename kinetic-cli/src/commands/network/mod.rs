use clap::Subcommand;

pub mod atlas_sync;
pub mod banned;
pub mod bootstrap;
pub mod dns_flush;
pub mod gossip;
pub mod nat;
pub mod peer_id;
pub mod peers;
pub mod status;

#[derive(Subcommand)]
pub enum NetworkCommands {
    /// Get Swarm/DHT networking status
    Status,
    /// List connected peers
    Peers,
    /// List banned peers and strike counts
    Banned,
    /// Force a Kademlia DHT bootstrap
    Bootstrap,
    /// Get the local cryptographic Peer ID
    PeerId,
    /// Get the NAT status and public IP address
    Nat,
    /// Interact with the Gossipsub network
    Gossip {
        #[command(subcommand)]
        cmd: gossip::GossipCommands,
    },
    /// Manually trigger a global Atlas index synchronization
    AtlasSync,
    /// Flush the in-memory DNS cache
    DnsFlush,
}

pub async fn handle_network_command(
    cmd: NetworkCommands,
    config: &kinetic_core::config::KineticConfig,
    client: &reqwest::Client,
) -> anyhow::Result<()> {
    match cmd {
        NetworkCommands::Status => status::handle_status(config, client).await,
        NetworkCommands::Peers => peers::handle_peers(config, client).await,
        NetworkCommands::Banned => banned::handle_banned(config, client).await,
        NetworkCommands::Bootstrap => bootstrap::handle_bootstrap(config, client).await,
        NetworkCommands::PeerId => peer_id::handle_peer_id(config, client).await,
        NetworkCommands::Nat => nat::handle_nat(config, client).await,
        NetworkCommands::Gossip { cmd } => gossip::handle_gossip_command(cmd, config, client).await,
        NetworkCommands::AtlasSync => atlas_sync::handle_atlas_sync(config, client).await,
        NetworkCommands::DnsFlush => dns_flush::handle_dns_flush(config, client).await,
    }
}
