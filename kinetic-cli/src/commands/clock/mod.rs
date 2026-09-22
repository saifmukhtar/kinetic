//! Real-time Kinetic Network Time clock display and daemon sync monitor.

use clap::Args;
use kinetic_core::config::KineticConfig;
use kinetic_core::constants::BEACON_GENESIS;
use kinetic_kyn::types::CrystallizedKyn;
use std::time::SystemTime;

#[derive(Args, Debug)]
pub struct ClockArgs {
    /// Act as a real-time digital clock by continuously printing the time every 3 seconds.
    #[arg(short, long)]
    pub listen: bool,
}

/// Executes the `kinetic clock` command to render the current Network Time Oracle epoch.
///
/// > [!IMPORTANT]
/// > Kinetic relies heavily on synchronized network time (KYNs) rather than absolute UNIX time 
/// > for Proof-of-Work staleness and DNS epoch rotation.
///
/// ### Execution Flow
/// 1. Initiates an HTTP GET request to the Daemon's `/api/v1/micro/time/current` endpoint.
/// 2. If the daemon is online, displays the verified Kyn (including the exact KYN epoch).
/// 3. If the daemon is offline (Connection Refused), the CLI executes a mathematical fallback 
///    by locally checking the machine's `SystemTime` and subtracting `BEACON_GENESIS`
/// 4. If the `--listen` flag is provided, loops the CLI terminal output infinitely like a digital clock.
///
/// # Errors
/// Returns an `anyhow::Error` if terminal formatting fails or the system clock is severely de-synchronized.
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
    let api_url = format!(
        "http://{}:{}/api/v1/micro/time/current",
        config.daemon.bind_ip, config.daemon.api_port
    );
    if let Ok(resp) = client.get(&api_url).send().await
        && resp.status().is_success()
        && let Ok(time) = resp.json::<CrystallizedKyn>().await
    {
        current_time = Some(time);
        fetched_from_api = true;
    }

    // 2. Offline Fallback: calculate mathematically using SystemTime
    let time = match current_time {
        Some(t) => t,
        None => {
            let now = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let current_kyn = if now > BEACON_GENESIS {
                now - BEACON_GENESIS
            } else {
                0
            };

            CrystallizedKyn::from_kyn(
                kinetic_kyn::types::Kyn(current_kyn),
                kinetic_kyn::types::Kyn(kinetic_core::constants::KYN_GENESIS),
            )
        }
    };

    let sync_status = if fetched_from_api {
        "🟢 [Synced]"
    } else {
        "🔴 [Offline/Mathematical]"
    };

    println!(
        "{} {} Prisms, {} Facets, {} Kyns (Total Kyns: {})",
        sync_status, time.prism, time.facet, time.kyn, time.total
    );
}
