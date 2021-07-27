use async_trait::async_trait;
use crate::engine::waf_engine::WafEngine;
use hyper::{Response, Request, Body};
use crate::waf_error::WafError;
use crate::engine::waf_engine_type::WafEngineType;
use crate::engine::waf_engine_type::WafEngineType::LearningModelBased;
use crate::waf_running_mode::WafRunningMode;
use tract_onnx::prelude::{RunnableModel, TypedFact, TypedOp, Graph};

pub struct LearningModelBasedEngine {
    running_mode: WafRunningMode,
    model: RunnableModel<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>,
}

#[async_trait]
impl WafEngine for LearningModelBasedEngine {
    fn running_mode(&self) -> WafRunningMode {
        self.running_mode.clone()
    }

    fn engine_type(&self) -> WafEngineType {
        LearningModelBased
    }

    async fn inspect_request(&self, request: Request<Body>) -> Result<Request<Body>, WafError> {
        Ok(request)
    }

    async fn inspect_response(&self, response: Response<Body>) -> Result<Response<Body>, WafError> {
        Ok(response)
    }
}

impl LearningModelBasedEngine {
    pub fn new(running_mode: WafRunningMode, model: RunnableModel<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>) -> Self {
        Self {
            running_mode,
            model,
        }
    }
}