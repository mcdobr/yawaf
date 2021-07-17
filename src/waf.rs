use crate::rules_parser::rule::{parse_rule, Rule};
use crate::waf_running_mode::WafRunningMode;
use hyper::{Request, Body, Response, http};
use crate::waf_error::WafError;
use crate::waf_running_mode::WafRunningMode::{Off, On, DetectionOnly};
use std::net::SocketAddr;
use crate::rules_parser::rule_variable::RuleVariableType::RequestHeaders;
use hyper::header::COOKIE;
use futures::TryFutureExt;
use hyper::http::request::Parts;
use bytes::Bytes;
use std::error::Error;
use std::str::FromStr;

pub struct WebApplicationFirewall {
    pub(crate) rules: Vec<Rule>,
    pub(crate) running_mode: WafRunningMode,
}

impl WebApplicationFirewall {
    pub async fn inspect_request(&self, request: Request<Body>)
                                 -> Result<Request<Body>, WafError> {
        return self.apply_rules(request)
            .await
            .map_err(|_err| WafError::new("Could not handle HTTP request"));
    }

    async fn apply_rules(&self, mut request: Request<Body>) -> Result<Request<Body>, WafError> {
        if self.running_mode != Off {

            let mut matched_rules: Vec<Rule> = vec![];
            for rule in self.rules.iter() {
                let (reconstructed_request, is_matched) = rule.matches(request);
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

    pub fn inspect_response(&self, mut response: Response<Body>) -> Result<Response<Body>, WafError> {
        // todo: implement inspect logic for response
        return Ok(response);
    }
}

#[test]
fn should_apply_sqli_detection_from_rule() {
    // todo: how do i detect sqli attacks in GET requests if query params are percent encoded?
    //  should i manually url decode them and check? hyper::Uri does not seem to
    //  support special characters or
    let rule = parse_rule(r###"SecRule REQUEST_HEADERS "@detectSQLi" "id:152""###)
        .unwrap().1;

    let mut sqli_request = Request::builder()
        .method("GET")
        .uri("http://example.com")
        .header("abcd", "?' OR '1'='1'")
        .body(Body::empty())
        .unwrap();
    assert!(rule.matches(sqli_request).1);
}

#[test]
fn should_apply_xss_detection_from_rule() {
    let rule = parse_rule(r###"SecRule REQUEST_HEADERS "@detectXSS" "id:152""###)
        .unwrap().1;

    let mut xss_request = Request::builder()
        .method("POST")
        .uri("http://example.com")
        .header("content-type", "<script>alert(\"TEST\");</script>")
        .body(Body::empty())
        .unwrap();

    assert!(rule.matches(xss_request).1);
}

#[test]
fn should_match_ip() {
    let rule = parse_rule(r###"SecRule REMOTE_ADDR "@ipMatch 192.168.1.101" "id:35""###)
        .unwrap().1;
    let mut request = Request::builder()
        .method("POST")
        .uri("http://example.com")
        .body(Body::empty())
        .unwrap();

    request.extensions_mut().insert(SocketAddr::from(([10, 0, 0, 1], 10000)));
    assert!(!rule.matches(request).1);
}

#[test]
fn should_match_port() {
    let rule = parse_rule(r###"SecRule REMOTE_PORT "@lt 1024" "id:37""###)
        .unwrap().1;

    let mut request = Request::builder()
        .method("POST")
        .uri("http://example.com")
        .body(Body::empty())
        .unwrap();

    request.extensions_mut().insert(SocketAddr::from(([192, 168, 1, 101], 1000)));
    assert!(rule.matches(request).1);
}

#[test]
fn should_match_count_cookies() {
    let rule = parse_rule(r###"SecRule &REQUEST_COOKIES "@eq 1" "id:44""###)
        .unwrap().1;
    let mut request = Request::builder()
        .method("POST")
        .uri("https://example.com")
        .header(COOKIE, "abcd=efgh")
        .body(Body::empty())
        .unwrap();

    assert!(rule.matches(request).1);
}

#[test]
fn rule_should_match_trivial_dom_xss_attempt() {
    // todo: need to url decode the actual url
    let rule = parse_rule(r###"SecRule ARGS_GET "@rx (?i)<script[^>]*>[\s\S]*?" "id:3,block,t:urlDecode""###)
        .unwrap().1;

    let payload = urlencoding::encode("<scRiPt>alert(1);</scRiPt>").to_string();

    let raw_uri = format!("{}{}", "https://example.com?parameter=", payload.as_str());
    println!("{}", raw_uri);

    let uri = http::Uri::from_str(&*raw_uri).unwrap();
    println!("{}", uri);

    let mut request = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap();

    assert!(rule.matches(request).1);
}