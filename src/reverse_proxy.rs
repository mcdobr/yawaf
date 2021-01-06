use hyper::{Client, Request, Body, Response, Error, HeaderMap, Uri};
use hyper::client::HttpConnector;
use hyper::http::HeaderValue;
use crate::rule::Rule;
use crate::waf_running_mode::WafRunningMode;
use crate::waf_running_mode::WafRunningMode::Off;

pub(crate) struct ReverseProxy {
    pub(crate) scheme: String,
    pub(crate) authority: String,
    pub(crate) client: Client<HttpConnector>,

    // TODO: Needed for WAF; need to determine if to use composition and just have WAF
    //  inspect the request and then pass it on to reverse proxy
    pub(crate) rules: Vec<Rule>,
    pub(crate) running_mode: WafRunningMode,
}

impl ReverseProxy {
    pub(crate) async fn handle_request(&self, mut request: Request<Body>) -> Result<Response<Body>, Error> {
        // Inspect the request based on rules
        if self.running_mode != Off {
            let matched_rules: Vec<Rule> = self.rules.iter()
                .filter(|rule| {
                    if rule.matches(&request) {
                        return true;
                    } else {
                        return false;
                    }
                })
                .cloned()
                .collect();

            if !matched_rules.is_empty() {
                // log the request here


                // drop the request and do not forward to upstream server
            }
        }

        // Rewrite the request to pass it forward to upstream servers
        *request.uri_mut() = self.rewrite_uri(&request);
        *request.headers_mut() = self.build_header_map(&request);

        log::debug!("Request == {:?}", request);
        let response = self.client.request(request).await.unwrap();
        log::debug!("Response == {:?}", response);
        return Ok(response);
    }

    fn rewrite_uri(&self, request: &Request<Body>) -> Uri {
        // Change the request's URI
        let mut uri_builder = hyper::Uri::builder()
            .scheme(&*self.scheme)
            .authority(&*self.authority);
        // Copy path and query params
        if let Some(path_and_query) = request.uri().path_and_query() {
            uri_builder = uri_builder.path_and_query(path_and_query.clone());
        }
        return uri_builder.build().unwrap();
    }

    fn build_header_map(&self, request: &Request<Body>) -> HeaderMap<HeaderValue> {
        // Remove headers not whitelisted
        const ALLOWED_HEADERS: [&str; 4] = [
            "accept",
            "user-agent",
            "DNT",
            "X-Forwarded-For"
            // hyper::header::HOST.as_str()
            // hyper::header::ACCEPT.as_str().clone(),
            // hyper::header::USER_AGENT.as_str().clone()
        ];

        let mut filtered_headers = HeaderMap::new();
        for (header_name, header_value) in request.headers() {
            if ALLOWED_HEADERS.contains(&header_name.as_str()) {
                filtered_headers.insert(header_name, header_value.clone());
            }
        }

        // if filtered_headers.contains_key("X-Forwarded-For") {
        //     let xForwardedFor = filtered_headers.get_mut("X-Forwarded-For");
        //
        // } else {
        //     request.get
        // }


        return filtered_headers;
    }
}