use async_trait::async_trait;
use hyper::{Request, Body, Response};
use crate::waf_error::WafError;
use crate::engine::waf_engine_type::WafEngineType;
use crate::waf_running_mode::WafRunningMode;


#[async_trait]
pub trait WafEngine {
    fn running_mode(&self) -> WafRunningMode;
    fn engine_type(&self) -> WafEngineType;
    async fn inspect_request(&self, request: Request<Body>) -> Result<Request<Body>, WafError>;
    async fn inspect_response(&self, response: Response<Body>) -> Result<Response<Body>, WafError>;
}