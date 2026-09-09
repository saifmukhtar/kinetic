use clap::Subcommand;
use comfy_table::{Table, Cell, Color};
use indicatif::{ProgressBar, ProgressStyle};

#[derive(Subcommand)]
pub enum AuthCommands {
    /// List all active application sessions
    List,
    /// Revoke a specific application session by its public ID
    Revoke {
        /// The public ID of the session to revoke
        #[arg(short, long)]
        id: String,
    },
}

pub async fn handle_auth_command(
    cmd: AuthCommands,
    config: &kinetic_core::config::KineticConfig,
    client: &reqwest::Client,
) -> anyhow::Result<()> {
    match cmd {
        AuthCommands::List => {
            let port = config.daemon.api_port;
            let url = format!("http://{}:{}/api/v1/micro/auth/sessions", config.daemon.bind_ip, port);
            
            let pb = ProgressBar::new_spinner();
            pb.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}")?);
            pb.set_message("Fetching active sessions...");
            pb.enable_steady_tick(std::time::Duration::from_millis(100));

            let resp = client.get(&url).send().await?;
            
            pb.finish_and_clear();

            if !resp.status().is_success() {
                anyhow::bail!("Failed to list auth sessions: {}", resp.text().await?);
            }
            
            let json: serde_json::Value = resp.json().await?;
            let sessions = json.get("sessions").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            
            if sessions.is_empty() {
                println!("No active application sessions found.");
                return Ok(());
            }

            let mut table = Table::new();
            table.set_header(vec![
                Cell::new("ID").fg(Color::Cyan),
                Cell::new("App Name").fg(Color::Green),
                Cell::new("Scopes").fg(Color::Yellow),
                Cell::new("Created").fg(Color::DarkGrey),
                Cell::new("Expiry (KYN)").fg(Color::Magenta),
            ]);

            for s in sessions {
                let id = s.get("id").and_then(|v| v.as_str()).unwrap_or("-");
                let app_name = s.get("app_name").and_then(|v| v.as_str()).unwrap_or("-");
                let empty = vec![];
                let scopes_arr = s.get("scopes").and_then(|v| v.as_array()).unwrap_or(&empty);
                let scopes: Vec<String> = scopes_arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect();
                let scopes_str = scopes.join(", ");
                let created_at = s.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0);
                let expiry = s.get("expiry_kyn").and_then(|v| v.as_u64()).unwrap_or(0);
                
                table.add_row(vec![
                    id.to_string(),
                    app_name.to_string(),
                    scopes_str,
                    created_at.to_string(),
                    expiry.to_string(),
                ]);
            }

            println!("\n{table}");
            Ok(())
        }
        AuthCommands::Revoke { id } => {
            let pb = ProgressBar::new_spinner();
            pb.set_style(ProgressStyle::default_spinner().template("{spinner:.red} {msg}")?);
            pb.set_message(format!("Revoking session {}...", id));
            pb.enable_steady_tick(std::time::Duration::from_millis(100));

            let port = config.daemon.api_port;
            let url = format!("http://{}:{}/api/v1/micro/auth/session/{}", config.daemon.bind_ip, port, id);
            let resp = client.delete(&url).send().await?;
            
            pb.finish_and_clear();

            if !resp.status().is_success() {
                anyhow::bail!("Failed to revoke session: {}", resp.text().await?);
            }
            
            println!("✅ Successfully revoked session: {}", id);
            Ok(())
        }
    }
}
