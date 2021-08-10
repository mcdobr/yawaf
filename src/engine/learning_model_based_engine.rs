use async_trait::async_trait;
use crate::engine::waf_engine::WafEngine;
use hyper::{Response, Request, Body};
use crate::waf_error::WafError;
use crate::engine::waf_engine_type::WafEngineType;
use crate::engine::waf_engine_type::WafEngineType::LearningModelBased;
use crate::waf_running_mode::WafRunningMode;
use tract_onnx::prelude::{RunnableModel, TypedFact, TypedOp, Graph, Tensor, tvec};
use tract_onnx::prelude::tract_ndarray::Array2;

const NORMAL_LABEL: i64 = 0;
const ANOMALOUS_LABEL: i64 = 1;

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
        let feature_vector: Tensor = Array2::<f32>::from_shape_vec(
            (1, 17),
            vec![
                200.423,
                // -0.52204418,
                 100.39849745,
                 2321.,
                 2.60876306,
                 2.16095812,
                 2.05754227,
                 2.19622297,
                 2.4339275,
                 2.55218664,
                 2.57392151,
                 2.,
                 2.36106683,
                 2.0,
                 2.40310087,
                 2.31618812,
                 2.08079797,
                 2.21198798
            ]).unwrap().into();


        let result = self.model.run(tvec!(feature_vector))
            .unwrap();

        let label = result[0].to_array_view::<i64>()
            .unwrap()
            .iter()
            .clone()
            .nth(0)
            .unwrap_or(&0i64)
            .clone();

        return if label == NORMAL_LABEL {
            Ok(request)
        } else {
            Err(WafError::new("Blocked request"))
        }
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

#[cfg(test)]
mod tests {
    use hyper::Request;

    #[tokio::test]
    async fn should_ingest_request_into_learning_engine() {
        let request = Request::builder()
            .body(())
            .unwrap();

        assert!(false);
    }
}
