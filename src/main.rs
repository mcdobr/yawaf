mod reverse_proxy;
mod waf_running_mode;

pub mod rules_parser;
mod waf_error;
mod waf_settings;

use hyper::service::{make_service_fn, service_fn};
use std::convert::Infallible;
use hyper::{Server, Client};
use std::net::SocketAddr;
use hyper::client::HttpConnector;
use crate::reverse_proxy::ReverseProxy;
use crate::waf_running_mode::WafRunningMode::DetectionOnly;
use crate::waf_settings::WafSettings;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::Builder::from_env(env_logger::Env::default()
        .default_filter_or("debug")
    )
        .init();

    let waf_settings = WafSettings::new().unwrap();
    let http_connector = HttpConnector::new();
    let http_client = Client::builder().build(http_connector);

    let reverse_proxy = std::sync::Arc::new(ReverseProxy {
        client: http_client,
        scheme: "http".to_owned(),
        authority: waf_settings.authority,
        // WAF specific properties
        rules: vec![],
        running_mode: DetectionOnly,
    });

    let address = SocketAddr::from(([0, 0, 0, 0], waf_settings.port));

    let service = make_service_fn(move |_connection| {
        let reverse_proxy_service_ref = reverse_proxy.clone();
        async {
            return Ok::<_, Infallible>(service_fn(move |request| {
                let reverse_proxy_request_ref = reverse_proxy_service_ref.clone();
                async move {
                    reverse_proxy_request_ref.handle_request(request).await
                }
            }));
        }
    });


    let server = Server::bind(&address)
        .serve(service);
    server.await?;
    return Ok(());
}