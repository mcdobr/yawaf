use config::{ConfigError, Config, File, Environment};
use serde::Deserialize;
use crate::engine::waf_engine_type::WafEngineType;

#[derive(Debug, Deserialize)]
pub struct WafSettings {
    pub debug: bool,
    pub authority: String,
    pub port: u16,
    pub upstream: String,
    pub engine_type: WafEngineType,
    pub rules_path: String,
    pub learning_model_path: String,
}

impl WafSettings {
    pub fn new() -> Result<Self, ConfigError> {
        let mut config = Config::new();

        config.merge(File::with_name("config/default"))?;

        // YAWAF_UPSTREAM would set the upstream
        config.merge(Environment::with_prefix("yawaf"))?;

        log::debug!("Loaded configuration = {:?}", config);
        let waf_settings_result = config.try_into();
        log::info!("Loaded WAF settings = {:?}", waf_settings_result);
        return waf_settings_result;
    }
}