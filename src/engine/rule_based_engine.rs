use async_trait::async_trait;
use crate::rules_parser::rule::Rule;
use crate::engine::waf_engine::WafEngine;
use hyper::{Response, Request, Body};
use crate::waf_error::WafError;
use crate::engine::waf_engine_type::WafEngineType::RuleBased;
use crate::engine::waf_engine_type::WafEngineType;
use crate::waf_running_mode::WafRunningMode;
use crate::waf_running_mode::WafRunningMode::{Off, On};

pub struct RuleBasedEngine {
    running_mode: WafRunningMode,
    rules: Vec<Rule>,
}

#[async_trait]
impl WafEngine for RuleBasedEngine {
    fn running_mode(&self) -> WafRunningMode {
        self.running_mode.clone()
    }

    fn engine_type(&self) -> WafEngineType {
        RuleBased
    }

    async fn inspect_request(&self, request: Request<Body>) -> Result<Request<Body>, WafError> {
        self.apply_rules(request)
            .await
            .map_err(|_err| WafError::new("Could not handle HTTP request"))
    }

    async fn inspect_response(&self, response: Response<Body>) -> Result<Response<Body>, WafError> {
        Ok(response)
    }
}

impl RuleBasedEngine {
    pub fn new(running_mode: WafRunningMode, rules: Vec<Rule>) -> Self {
        Self {
            running_mode,
            rules,
        }
    }

    async fn apply_rules(&self, mut request: Request<Body>) -> Result<Request<Body>, WafError> {
        if self.running_mode != Off {
            let mut matched_rules: Vec<Rule> = vec![];
            for rule in self.rules.iter() {
                let (reconstructed_request, is_matched) = rule.matches(request).await;
                request = reconstructed_request;
                if is_matched {
                    matched_rules.push(rule.clone());
                }
            }

            if !matched_rules.is_empty() {
                log::warn!("Request {:?} matches: {:?}", request, matched_rules);
                if self.running_mode == On {
                    log::warn!("Blocking request {:?}", request);
                    return Err(WafError::new("Blocked request"));
                }
            }
        }
        // Ok(bytes)
        Ok(request)
    }
}
