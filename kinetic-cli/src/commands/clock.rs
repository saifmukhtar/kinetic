use clap::Args;
use kinetic_core::config::KineticConfig;
use kinetic_core::constants::{DRAND_GENESIS_TIME, DRAND_PERIOD};
use kinetic_core::types::clock::KineticTime;
use std::time::SystemTime;

#[derive(Args, Debug)]
pub struct ClockArgs {
    /// Act as a real-time digital clock by continuously printing the time every 3 seconds.
    #[arg(short, long)]
    pub listen: bool,
}

pub async fn handle_clock_command(
    args: ClockArgs,
    config: &KineticConfig,
    client: &reqwest::Client,
) -> anyhow::Result<()> {
    if args.listen {
        println!("🚀 Listening to Kinetic Network Time...");
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3));
        loop {
            interval.tick().await;
            print_current_time(config, client).await;
        }
    } else {
        print_current_time(config, client).await;
    }
    Ok(())
}

async fn print_current_time(config: &KineticConfig, client: &reqwest::Client) {
    let mut fetched_from_api = false;
    let mut current_time = None;

    // 1. Try to fetch from the local daemon API first
    let api_url = format!("http://127.0.0.1:{}/api/time", config.daemon.api_port);
    if let Ok(resp) = client.get(&api_url).send().await {
        if resp.status().is_success() {
            if let Ok(time) = resp.json::<KineticTime>().await {
                current_time = Some(time);
                fetched_from_api = true;
            }
        }
    }

    // 2. Offline Fallback: calculate mathematically using SystemTime
    let time = match current_time {
        Some(t) => t,
        None => {
            let now = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let current_round = if now > DRAND_GENESIS_TIME {
                (now - DRAND_GENESIS_TIME) / DRAND_PERIOD
            } else {
                0
            };

            KineticTime::from_drand_round(current_round)
        }
    };

    let sync_status = if fetched_from_api {
        "🟢 [Synced]"
    } else {
        "🔴 [Offline/Mathematical]"
    };

    println!("{} {}", sync_status, time.to_display_string());
}
