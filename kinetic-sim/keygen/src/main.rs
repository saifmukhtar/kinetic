use libp2p::identity::Keypair;
use std::env;
use std::fs::File;
use std::io::Write;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: keygen <output_path>");
        std::process::exit(1);
    }
    
    let path = &args[1];
    let keypair = Keypair::generate_ed25519();
    
    // Save to file
    let mut file = File::create(path).unwrap();
    let encoded = keypair.to_protobuf_encoding().unwrap();
    file.write_all(&encoded).unwrap();
    
    // Print peer ID so python can capture it
    println!("{}", keypair.public().to_peer_id());
}
