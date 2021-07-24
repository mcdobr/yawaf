use hyper::{Request, Body, Response};
use crate::waf_error::WafError;
use crate::engine::waf_engine::WafEngine;

pub struct WebApplicationFirewall {
    pub(crate) engine: Box<dyn WafEngine + Send + Sync>,
}

impl WebApplicationFirewall {
    pub fn new(engine: Box<dyn WafEngine + Send + Sync>) -> Self {
        Self {
            engine
        }
    }

    pub async fn inspect_request(&self, request: Request<Body>)
                                 -> Result<Request<Body>, WafError> {
        self.engine.inspect_request(request).await
    }

    pub async fn inspect_response(&self, response: Response<Body>)
                                  -> Result<Response<Body>, WafError> {
        self.engine.inspect_response(response).await
    }
}

#[cfg(test)]
mod tests {
    use crate::rules_parser::rule::parse_rule;
    use hyper::{Body, http, Request};
    use std::net::SocketAddr;
    use hyper::header::COOKIE;
    use std::str::FromStr;

    #[tokio::test]
    async fn should_apply_sqli_detection_from_rule() {
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
        assert!(rule.matches(sqli_request).await.1);
    }

    #[tokio::test]
    async fn should_apply_xss_detection_from_rule() {
        let rule = parse_rule(r###"SecRule REQUEST_HEADERS "@detectXSS" "id:152""###)
            .unwrap().1;

        let mut xss_request = Request::builder()
            .method("POST")
            .uri("http://example.com")
            .header("content-type", "<script>alert(\"TEST\");</script>")
            .body(Body::empty())
            .unwrap();

        assert!(rule.matches(xss_request).await.1);
    }

    #[tokio::test]
    async fn should_match_ip() {
        let rule = parse_rule(r###"SecRule REMOTE_ADDR "@ipMatch 192.168.1.101" "id:35""###)
            .unwrap().1;
        let mut request = Request::builder()
            .method("POST")
            .uri("http://example.com")
            .body(Body::empty())
            .unwrap();

        request.extensions_mut().insert(SocketAddr::from(([10, 0, 0, 1], 10000)));
        assert!(!rule.matches(request).await.1);
    }

    #[tokio::test]
    async fn should_match_port() {
        let rule = parse_rule(r###"SecRule REMOTE_PORT "@lt 1024" "id:37""###)
            .unwrap().1;

        let mut request = Request::builder()
            .method("POST")
            .uri("http://example.com")
            .body(Body::empty())
            .unwrap();

        request.extensions_mut().insert(SocketAddr::from(([192, 168, 1, 101], 1000)));
        assert!(rule.matches(request).await.1);
    }

    #[tokio::test]
    async fn should_match_count_cookies() {
        let rule = parse_rule(r###"SecRule &REQUEST_COOKIES "@eq 1" "id:44""###)
            .unwrap().1;
        let mut request = Request::builder()
            .method("POST")
            .uri("https://example.com")
            .header(COOKIE, "abcd=efgh")
            .body(Body::empty())
            .unwrap();

        assert!(rule.matches(request).await.1);
    }

    #[tokio::test]
    async fn rule_should_match_trivial_dom_xss_attempt() {
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

        assert!(rule.matches(request).await.1);
    }
}