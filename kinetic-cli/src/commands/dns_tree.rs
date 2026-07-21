use clap::Subcommand;
use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};

/// Available subcommands for managing DNS Tree discovery.
#[derive(Subcommand)]
pub enum DnsTreeCommands {
    /// Generate a Cloudflare-ready DNS Tree from a list of Libp2p Multiaddrs.
    Generate {
        /// Path to a file containing one Multiaddr per line
        #[arg(long)]
        input: String,
        /// Path to save the generated JSON/Zone file
        #[arg(long)]
        output: String,
        /// The root domain to deploy this tree (e.g. seed.saifmukhtar.dev)
        #[arg(long)]
        domain: String,
    },
}

pub async fn handle_dns_tree_command(cmd: DnsTreeCommands) -> anyhow::Result<()> {
    match cmd {
        DnsTreeCommands::Generate { input, output, domain } => {
            let file = File::open(&input)?;
            let reader = BufReader::new(file);
            let mut leaves = Vec::new();
            
            for line in reader.lines() {
                let addr = line?.trim().to_string();
                if addr.is_empty() { continue; }
                
                let leaf_content = format!("kintree-leaf:{}", addr);
                let hash = hash_content(&leaf_content);
                leaves.push((hash, leaf_content));
            }
            
            if leaves.is_empty() {
                anyhow::bail!("No valid multiaddrs found in input file");
            }
            
            let mut tree_records = Vec::new();
            let mut leaf_hashes = Vec::new();
            
            for (hash, content) in &leaves {
                tree_records.push((format!("{}.{}", hash, domain), content.clone()));
                leaf_hashes.push(hash.clone());
            }
            
            let mut current_level = leaf_hashes;
            while current_level.len() > 1 {
                let mut next_level = Vec::new();
                for chunk in current_level.chunks(50) {
                    let branch_content = format!("kintree-branch:{}", chunk.join(","));
                    let branch_hash = hash_content(&branch_content);
                    tree_records.push((format!("{}.{}", branch_hash, domain), branch_content));
                    next_level.push(branch_hash);
                }
                current_level = next_level;
            }
            
            let root_hash = current_level[0].clone();
            let root_content = format!("kintree-root:v1 e={} seq=1", root_hash);
            tree_records.push((domain.clone(), root_content));
            
            let mut out_file = File::create(&output)?;
            for (subdomain, content) in tree_records.iter().rev() {
                writeln!(out_file, "{}\tIN\tTXT\t\"{}\"", subdomain, content)?;
            }
            
            println!("✅ Successfully generated DNS Tree with {} records!", tree_records.len());
            println!("Output saved to {}. You can import this zone file into your DNS provider.", output);
        }
    }
    Ok(())
}

fn hash_content(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let result = hasher.finalize();
    // Use the first 32 characters (160 bits) of the base32 string to keep DNS labels short
    BASE32_NOPAD.encode(&result).to_lowercase()[..32].to_string()
}
