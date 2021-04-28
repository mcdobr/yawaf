use crate::rules_parser::rule::{parse_rule, Rule};
use crate::waf_running_mode::WafRunningMode;
use hyper::{Request, Body};
use crate::waf_error::WafError;
use crate::waf_running_mode::WafRunningMode::{Off, On};

pub struct WebApplicationFirewall {
    pub(crate) rules: Vec<Rule>,
    pub(crate) running_mode: WafRunningMode,
}

impl WebApplicationFirewall {
    pub fn inspect_request(&self, request: &Request<Body>)
                           -> Option<WafError> {
        if self.running_mode != Off {
            let matched_rules: Vec<Rule> = self.rules.iter()
                .filter(|rule| {
                    return rule.matches(request);
                })
                .cloned()
                .collect();

            if !matched_rules.is_empty() {
                log::warn!("Request {:?} matches: {:?}", request, matched_rules);

                if self.running_mode == On {
                    log::warn!("Blocking request {:?}", request);
                    return Some(WafError::new("Blocked request"));
                }
            }
        }
        return None;
    }
}

#[test]
fn should_apply_sqli_detection_from_rule() {
    // todo: how do i detect sqli attacks in GET requests if query params are percent encoded?
    //  should i manually url decode them and check? hyper::Uri does not seem to
    //  support special characters or
    let rule = parse_rule(r###"SecRule REQUEST_HEADERS "@detectSQLi" "id:152""###)
        .unwrap().1;

    let sqli_request = Request::builder()
        .method("GET")
        .uri("http://example.com")
        .header("abcd", "?' OR '1'='1'")
        .body(Body::empty())
        .unwrap();
    assert!(rule.matches(&sqli_request));
}

#[test]
fn should_apply_xss_detection_from_rule() {
    let rule = parse_rule(r###"SecRule REQUEST_HEADERS "@detectXSS" "id:152""###)
        .unwrap().1;

    let xss_request = Request::builder()
        .method("POST")
        .uri("http://example.com")
        .header("content-type", "<script>alert(\"TEST\");</script>")
        .body(Body::empty())
        .unwrap();

    assert!(rule.matches(&xss_request));
}
