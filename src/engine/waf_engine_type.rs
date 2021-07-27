use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub enum WafEngineType {
    RuleBased,
    LearningModelBased,
}