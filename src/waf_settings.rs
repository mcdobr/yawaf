// use crate::waf_running_mode::WafRunningMode;
use config::{ConfigError, Config, File, Environment};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct WafSettings {
    debug: bool,
    // running_mode: WafRunningMode,
    upstream: String,
}

impl WafSettings {
    pub fn new() -> Result<Self, ConfigError> {
        let mut config = Config::new();

        config.merge(File::with_name("config/default"))?;

        // YAWAF_UPSTREAM would set the upstream
        config.merge(Environment::with_prefix("yawaf"))?;

        log::debug!("upstream url: {:?}", config.get::<String>("upstream"));
        return config.try_into();
    }
}