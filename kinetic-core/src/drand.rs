use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use serde::Deserialize;
use tracing::{info, warn};

#[derive(Debug, Deserialize)]
pub struct DrandResponse {
    pub round: u64,
    pub randomness: String,
    pub signature: String,
}

pub struct DrandClock {
    pub latest_pulse: Arc<RwLock<u64>>,
}

impl DrandClock {
    pub fn new() -> Self {
        Self {
            latest_pulse: Arc::new(RwLock::new(0)),
        }
    }

    /// Spawns a background task that polls the League of Entropy every 30 seconds.
    pub fn start_polling(&self) {
        let pulse_ref = Arc::clone(&self.latest_pulse);
        
        tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap();
                
            loop {
                match client.get("https://api.drand.sh/public/latest").send().await {
                    Ok(response) => {
                        if let Ok(drand_data) = response.json::<DrandResponse>().await {
                            let mut writer = pulse_ref.write().await;
                            if drand_data.round > *writer {
                                *writer = drand_data.round;
                                info!("Drand pulse updated to round {}", drand_data.round);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to fetch Drand pulse: {}", e);
                    }
                }
                
                // Drand rounds happen exactly every 30 seconds
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
    }

    /// Get the current cached round number.
    pub async fn current_round(&self) -> u64 {
        *self.latest_pulse.read().await
    }
}

impl Default for DrandClock {
    fn default() -> Self {
        Self::new()
    }
}
