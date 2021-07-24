use serde::Deserialize;

#[derive(Clone, PartialEq, Debug, Deserialize)]
pub enum WafRunningMode {
    DetectionOnly,
    On,
    Off
}