use kinetic_core::config::{ConfigContext, KineticConfig};
use std::fs;
use std::path::PathBuf;

#[cfg(not(target_arch = "wasm32"))]
pub fn load_config() -> KineticConfig {
    load_config_ctx(ConfigContext::Daemon)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn load_config_ctx(ctx: ConfigContext) -> KineticConfig {
    let config_path = std::env::var(kinetic_core::constants::ENV_CONFIG_PATH)
        .map(PathBuf::from)
        .unwrap_or_else(|_| get_base_dir().join("config.toml"));

    let config = match fs::read_to_string(&config_path) {
        Ok(config_str) => match toml::from_str(&config_str) {
            Ok(config) => config,
            Err(e) => {
                let err = kinetic_core::error::ConfigError::ParseFailed(e.to_string());
                tracing::error!(
                    error_code = err.code(),
                    "CRITICAL: Failed to parse configuration file at {:?}: {}",
                    config_path,
                    e
                );
                std::process::exit(1);
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut default_cfg = KineticConfig::default();
            default_cfg.drand.p2p_only = ctx == ConfigContext::Daemon;

            if let Some(parent) = config_path.parent()
                && let Err(e) = fs::create_dir_all(parent)
            {
                tracing::warn!("Failed to create config directory: {}", e);
            }

            if let Ok(toml_str) = toml::to_string_pretty(&default_cfg) {
                let mut options = std::fs::OpenOptions::new();
                options.write(true).create_new(true);

                match options.open(&config_path) {
                    Ok(mut file) => {
                        use std::io::Write;
                        if let Err(e) = file.write_all(toml_str.as_bytes()) {
                            let err = kinetic_core::error::ConfigError::WriteFailed(e.to_string());
                            tracing::error!(
                                error_code = err.code(),
                                "Failed to write default config to {:?}: {}. Refusing to start.",
                                config_path,
                                e
                            );
                            std::process::exit(1);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        // TOCTOU race condition mitigation
                    }
                    Err(e) => {
                        let err = kinetic_core::error::ConfigError::WriteFailed(e.to_string());
                        tracing::error!(
                            error_code = err.code(),
                            "Failed to create default config at {:?}: {}. Refusing to start.",
                            config_path,
                            e
                        );
                        std::process::exit(1);
                    }
                }
            }
            default_cfg
        }
        Err(e) => {
            let err = kinetic_core::error::ConfigError::ReadFailed(e.to_string());
            tracing::error!(
                error_code = err.code(),
                "Failed to read config.toml: {}. Refusing to start to avoid fail-open vulnerability.",
                e
            );
            std::process::exit(1);
        }
    };

    config.validate();
    config
}

#[cfg(not(target_arch = "wasm32"))]
pub fn save_config(config: &KineticConfig) -> Result<(), kinetic_core::error::KineticError> {
    let config_path = std::env::var(kinetic_core::constants::ENV_CONFIG_PATH)
        .map(PathBuf::from)
        .unwrap_or_else(|_| get_base_dir().join("config.toml"));

    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            kinetic_core::error::KineticError::Config(
                kinetic_core::error::ConfigError::DirectoryCreationFailed(e.to_string()),
            )
        })?;
    }

    let toml_str = toml::to_string_pretty(config).map_err(|e| {
        kinetic_core::error::KineticError::Config(
            kinetic_core::error::ConfigError::SerializationFailed(e.to_string()),
        )
    })?;
    fs::write(&config_path, toml_str).map_err(|e| {
        kinetic_core::error::KineticError::Config(kinetic_core::error::ConfigError::WriteFailed(
            e.to_string(),
        ))
    })
}

pub fn get_zones_dir() -> PathBuf {
    get_base_dir().join("zones")
}

pub fn get_base_dir() -> PathBuf {
    if let Ok(path) = std::env::var(kinetic_core::constants::ENV_DATA_DIR) {
        return PathBuf::from(path);
    }

    let salt_prefix = &kinetic_core::constants::NETWORK_SALT_HEX[0..4];
    let network_dir = format!("{}-{}", kinetic_core::constants::NSP, salt_prefix);

    #[cfg(not(target_arch = "wasm32"))]
    {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("kinetic")
            .join("networks")
            .join(network_dir)
    }

    #[cfg(target_arch = "wasm32")]
    {
        PathBuf::from(format!("/kinetic/networks/{}", network_dir))
    }
}

pub fn get_api_tokens_dir() -> PathBuf {
    get_base_dir().join("tokens")
}
