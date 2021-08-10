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
        let feature_vector = LearningModelBasedEngine::extract_custom_features(&request);

        let label = self.classify(feature_vector);

        return if label == NORMAL_LABEL {
            Ok(request)
        } else {
            Err(WafError::new("Blocked request"))
        };
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

    fn extract_custom_features(_request: &Request<Body>) -> Tensor {
        unimplemented!("Not implemented yet!");
    }

    fn classify(&self, feature_vector: Tensor) -> i64 {
        let result = self.model.run(tvec!(feature_vector))
            .unwrap();

        let label = result[0].to_array_view::<i64>()
            .unwrap()
            .iter()
            .clone()
            .nth(0)
            .unwrap_or(&0i64)
            .clone();
        label
    }
}

#[cfg(test)]
mod tests {
    use hyper::{Request, Body};
    use tract_onnx::prelude::{Framework, InferenceModelExt, InferenceFact, Datum, tvec, Tensor};
    use crate::waf_running_mode::WafRunningMode;
    use crate::engine::learning_model_based_engine::{LearningModelBasedEngine, NORMAL_LABEL};
    use crate::engine::waf_engine::WafEngine;
    use tract_onnx::prelude::tract_data::internal::tract_ndarray::Array2;

    #[tokio::test]
    async fn should_be_able_to_classify_using_persisted_model() {
        let model = tract_onnx::onnx()
            .model_for_path("model/decision_tree.onnx").unwrap()
            .with_input_fact(0, InferenceFact::dt_shape(f32::datum_type(), tvec!(1, 17))).unwrap()
            .into_optimized().unwrap()
            .into_runnable().unwrap();
        let learning_engine = LearningModelBasedEngine::new(WafRunningMode::On, model);

        let feature_vector: Tensor = Array2::<f32>::from_shape_vec(
            (1, 17),
            vec![-0.52204418,
                 -0.39849745,
                 0.,
                 0.60876306,
                 -0.16095812,
                 2.05754227,
                 -0.19622297,
                 -0.4339275,
                 -0.55218664,
                 -0.57392151,
                 0.,
                 -0.36106683,
                 0.0,
                 -0.40310087,
                 -0.31618812,
                 0.08079797,
                 -0.21198798
            ]).unwrap().into();

        assert_eq!(learning_engine.classify(feature_vector), NORMAL_LABEL);
    }
}
