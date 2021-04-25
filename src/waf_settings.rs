use config::{ConfigError, Config, File, Environment};
use serde::Deserialize;
use hyper::Uri;

#[derive(Debug, Deserialize)]
pub struct WafSettings {
    pub debug: bool,
    pub authority: String,
    pub port: u16,
    pub upstream: String,
    // running_mode: WafRunningMode,
}

impl WafSettings {
    pub fn new() -> Result<Self, ConfigError> {
        let mut config = Config::new();

        config.merge(File::with_name("config/default"))?;

        // YAWAF_UPSTREAM would set the upstream
        config.merge(Environment::with_prefix("yawaf"))?;

        log::debug!("Loaded configuration = {:?}", config);
        let result = config.try_into();
        log::info!("Loaded WAF settings = {:?}", result);
        return result;
    }
}