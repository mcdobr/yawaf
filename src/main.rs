extern crate libinjection;

use std::{env, fs};
use std::convert::Infallible;
use std::fs::{DirEntry, ReadDir};
use std::net::SocketAddr;
use std::path::Path;

use hyper::{Client, Server};
use hyper::client::HttpConnector;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};

use crate::reverse_proxy::ReverseProxy;
use crate::rules_parser::rule::{parse_rules, Rule};
use crate::waf::WebApplicationFirewall;
use crate::waf_running_mode::WafRunningMode;
use crate::waf_settings::WafSettings;
use crate::engine::rule_based_engine::RuleBasedEngine;
use log4rs::append::console::ConsoleAppender;
use log4rs::Config;
use log4rs::config::{Appender, Root};
use log::LevelFilter;
use log4rs::append::file::FileAppender;
use log4rs::append::rolling_file::RollingFileAppender;
use log4rs::append::rolling_file::policy::compound::CompoundPolicy;
use log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger;
use log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller;
use log4rs::filter::threshold::ThresholdFilter;
use log4rs::encode::json::JsonEncoder;
use crate::engine::waf_engine::WafEngine;
use crate::engine::waf_engine_type::WafEngineType;
use crate::engine::learning_model_based_engine::LearningModelBasedEngine;
use onnxruntime::environment::Environment;
use onnxruntime::{LoggingLevel, GraphOptimizationLevel};
use onnxruntime::session::Session;
use onnxruntime::ndarray::Array;
use onnxruntime::tensor::OrtOwnedTensor;

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
    let logging_config = build_logging_config();
    let _handle = log4rs::init_config(logging_config).unwrap();

    let waf_settings = WafSettings::new().unwrap();

    let waf = WebApplicationFirewall::new(
        match waf_settings.engine_type {
            WafEngineType::RuleBased => {
                let rules = load_rules(&waf_settings);
                Box::new(RuleBasedEngine::new(WafRunningMode::On, rules))
            }
            WafEngineType::LearningModelBased => {
                let onnx_environment = Environment::builder()
                    .with_name("test")
                    .with_log_level(LoggingLevel::Verbose)
                    .build()?;

                let mut session: Session = onnx_environment.new_session_builder()?
                    .with_optimization_level(GraphOptimizationLevel::Basic)?
                    .with_number_threads(1)?
                    .with_model_from_file("model/occ_svm.onnx")?;


                log::info!("{:?}", session);
                // let arr = Array::from_vec(
                //     vec![-0.52204418,
                //          -0.39849745,
                //          0.,
                //          0.60876306,
                //          -0.16095812,
                //          2.05754227,
                //          -0.19622297,
                //          -0.4339275,
                //          -0.55218664,
                //          -0.57392151,
                //          0.,
                //          -0.36106683,
                //          0.0,
                //          -0.40310087,
                //          -0.31618812,
                //          0.08079797,
                //          -0.21198798
                //     ]);
                // let result: Vec<OrtOwnedTensor<f32, _>> = session.run(vec![arr])?;

                Box::new(LearningModelBasedEngine::new(WafRunningMode::On))
            }
        }
    );

    let http_connector = HttpConnector::new();
    let http_client = Client::builder().build(http_connector);

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

fn load_rules(waf_settings: &WafSettings) -> Vec<Rule> {
    let current_directory = env::current_dir().unwrap();
    log::debug!("yawaf executed from {}", current_directory.display());

    let rules_path = Path::new(&waf_settings.rules_path);
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
        .collect::<Vec<Vec<Rule>>>()
        .concat();
    log::info!("Loaded rules from configuration files: {:?}", rules);
    rules
}

fn build_logging_config() -> Config {
    let stdout = ConsoleAppender::builder()
        .build();

    let http_transactions_log_path = "log/transactions.log";
    let rolling_file_policy = CompoundPolicy::new(
        Box::new(SizeTrigger::new(bytesize::mib(50u64))),
        Box::new(FixedWindowRoller::builder().build("log/transactions.{}.log.gzip", 30).unwrap()),
    );

    let http_transactions_log_appender = RollingFileAppender::builder()
        // .encoder(Box::new(JsonEncoder::new()))
        .build(http_transactions_log_path, Box::new(rolling_file_policy))
        .unwrap();

    let logging_config = Config::builder()
        .appender(Appender::builder()
            .filter(Box::new(ThresholdFilter::new(log::LevelFilter::Info)))
            .build("stdout", Box::new(stdout)))
        .appender(Appender::builder()
            .build("transactions", Box::new(http_transactions_log_appender)))
        .build(Root::builder()
            .appender("stdout")
            .appender("transactions")
            .build(LevelFilter::Debug))
        .unwrap();
    logging_config
}