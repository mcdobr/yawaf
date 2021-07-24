extern crate libinjection;

use std::{env, fs};
use std::convert::Infallible;
use std::fs::{DirEntry, ReadDir};
use std::net::SocketAddr;
use std::path::Path;

use hyper::{Client, Server};
use hyper::client::HttpConnector;
use hyper::http::HeaderValue;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};

use crate::reverse_proxy::ReverseProxy;
use crate::rules_parser::rule::{parse_rule, parse_rules, Rule};
use crate::waf::WebApplicationFirewall;
use crate::waf_running_mode::WafRunningMode;
use crate::waf_settings::WafSettings;
use crate::engine::rule_based_engine::RuleBasedEngine;

mod reverse_proxy;
mod waf_running_mode;

pub mod rules_parser;
mod waf_error;
mod injection;
mod waf;
mod waf_settings;
mod engine;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::Builder::from_env(env_logger::Env::default()
        .default_filter_or("debug")
    )
        .init();

    let waf_settings = WafSettings::new().unwrap();

    let current_directory = env::current_dir()?;
    log::debug!("yawaf executed from {}", current_directory.display());

    let rules_path = Path::new(&waf_settings.rules);
    log::debug!("yawaf rules path {:?}", rules_path);
    let rules_directory: ReadDir = fs::read_dir(rules_path).unwrap();

    let rule_files = rules_directory
        .filter_map(Result::ok)
        .filter(|file| file.path().extension().unwrap() == "conf")
        .collect::<Vec<DirEntry>>();
    log::debug!("{:?}", rule_files);

    let raw_rule_file_contents: Vec<String> = rule_files.into_iter()
        .map(|dir_entry| fs::read_to_string(dir_entry.path()).expect("Could not read rule file"))
        .collect::<Vec<String>>();

    let rules = raw_rule_file_contents.into_iter()
        .map(|file_content| parse_rules(file_content.as_str()))
        .collect::<Vec<Vec<Rule>>>();
    log::debug!("Loaded rules from configuration files: {:?}", rules);

    let http_connector = HttpConnector::new();
    let http_client = Client::builder().build(http_connector);

    let waf = WebApplicationFirewall {
        engine: Box::new(RuleBasedEngine::new(WafRunningMode::On, rules.concat())),
    };

    let reverse_proxy = std::sync::Arc::new(ReverseProxy {
        client: http_client,
        scheme: "http".to_owned(),
        authority: waf_settings.authority,
        web_application_firewall: waf,
    });

    let address = SocketAddr::from(([0, 0, 0, 0], waf_settings.port));
    log::info!("Listening on {:?}", address);

    let service = make_service_fn(move |socket: &AddrStream| {
        let remote_addr = socket.remote_addr();
        let reverse_proxy_service_ref = reverse_proxy.clone();
        async move {
            return Ok::<_, Infallible>(service_fn(move |request| {
                let reverse_proxy_request_ref = reverse_proxy_service_ref.clone();
                async move {
                    reverse_proxy_request_ref.handle_request(remote_addr, request).await
                }
            }));
        }
    });

    let server_listening_address = SocketAddr::from(([0, 0, 0, 0],
                                                     waf_settings.port));
    let server = Server::bind(&server_listening_address)
        .serve(service);
    server.await?;
    return Ok(());
}