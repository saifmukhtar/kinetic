use reqwest::blocking::Client;
use std::time::Duration;
use serde_json::Value;

fn main() {
    let client = Client::new();
    // Resolve via API to see if the daemon can resolve it
    let res = client.get("http://127.0.0.1:5461/resolve/test.kin")
        .timeout(Duration::from_secs(10))
        .send();
        
    match res {
        Ok(r) => {
            println!("Status: {}", r.status());
            println!("Body: {}", r.text().unwrap_or_default());
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }
}
