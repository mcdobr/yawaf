use hyper::{Client, Request, Body, Response, HeaderMap, Uri};
use hyper::client::HttpConnector;
use hyper::http::HeaderValue;
use hyper::http::StatusCode;
use crate::waf_error::WafError;
use crate::waf::WebApplicationFirewall;
use std::net::{SocketAddr, IpAddr};
use lazy_static::lazy_static;

pub(crate) struct ReverseProxy {
    pub(crate) scheme: String,
    pub(crate) authority: String,
    pub(crate) client: Client<HttpConnector>,
    pub(crate) web_application_firewall: WebApplicationFirewall,
}

/// Part of this implementation is based on code in https://github.com/felipenoris/hyper-reverse-proxy

impl ReverseProxy {
    pub async fn handle_request(&self,
                                remote_addr: SocketAddr,
                                mut request: Request<Body>)
                                -> Result<Response<Body>, WafError>
    {
        request.extensions_mut().insert(remote_addr);
        // Rewrite the request to pass it forward to upstream servers
        *request.headers_mut() = self.whitelist_headers(&self.remove_hop_headers(request.headers()));

        // let user_ip = request.extensions().get::<SocketAddr>().unwrap().ip();
        // ReverseProxy::proxy_request_headers(&filtered_headers, user_ip);

        *request.uri_mut() = self.rewrite_uri(&request);

        log::debug!("Request == {:?} from {:?}", request, remote_addr);
        let inspected_request_result = self.web_application_firewall
            .inspect_request(request)
            .await
            .and_then(|normalized_req| {
                log::debug!("Normalized request {:?}", normalized_req);
                Ok(normalized_req)
            });

        if inspected_request_result.is_err() {
            let blocked_response = ReverseProxy::create_blocked_response();
            return Ok(blocked_response);
        }


        let received_response_result = self.client
            .request(inspected_request_result.unwrap())
            .await
            .map_err(|error| WafError::new("Unreachable origin"))
            .and_then(|response| {
                log::debug!("Received response == {:?}", response);
                Ok(response)
            });


        if received_response_result.is_err() {
            let unreachable_origin_response = Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("Could not service request"))
                .unwrap();
            return Ok(unreachable_origin_response);
        }

        let received_response = received_response_result.unwrap();

        let inspected_response_result = self.web_application_firewall
            .inspect_response(received_response)
            .await;

        let response = inspected_response_result.or(Ok(ReverseProxy::create_blocked_response()));
        return response;
    }

    fn create_blocked_response() -> Response<Body> {
        let blocked_response = Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::from("Shoo! Go away!"))
            .unwrap();
        blocked_response
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

    fn is_hop_header(&self, header_key: &str) -> bool {
        use unicase::Ascii;
        lazy_static! {
            static ref HOP_HEADERS: Vec<Ascii<&'static str>> = vec![
                Ascii::new("Connection"),
                Ascii::new("Keep-Alive"),
                Ascii::new("Proxy-Authenticate"),
                Ascii::new("Proxy-Authorization"),
                Ascii::new("Te"),
                Ascii::new("Trailers"),
                Ascii::new("Transfer-Encoding"),
                Ascii::new("Upgrade"),
            ];
        }

        return HOP_HEADERS.iter().any(|h_key| h_key == &header_key);
    }

    fn remove_hop_headers(&self, headers: &HeaderMap<HeaderValue>) -> HeaderMap<HeaderValue> {
        let mut stripped_headers = HeaderMap::new();
        for (key, value) in headers.iter() {
            if !self.is_hop_header(key.as_str()) {
                stripped_headers.insert(key.clone(), value.clone());
            }
        }
        return stripped_headers;
    }

    fn whitelist_headers(&self, headers: &HeaderMap<HeaderValue>) -> HeaderMap<HeaderValue> {
        // Remove headers not whitelisted
        const ALLOWED_HEADERS: [&str; 7] = [
            // "host",
            "content-type",
            "accept",
            "user-agent",
            "dnt",
            "x-forwarded-for",
            "x-real-ip",
            "cookie",
        ];

        let mut filtered_headers = HeaderMap::new();
        for (header_name, header_value) in headers {
            if ALLOWED_HEADERS.contains(&header_name.as_str()) {
                filtered_headers.insert(header_name, header_value.clone());
            }
        }

        return filtered_headers;
    }

    /// Adds proxy headers (e.g: X-Real-IP and X-Forwarded-For)
    fn proxy_request_headers(headers: &HeaderMap<HeaderValue>, client_ip: IpAddr) -> HeaderMap<HeaderValue> {
        let mut modified_headers = headers.clone();
        modified_headers.insert("forwarded", (client_ip.to_string() + ", 127.0.0.1").parse().unwrap());
        modified_headers.insert("x-forwarded-for", (client_ip.to_string() + ", 127.0.0.1").parse().unwrap());
        modified_headers.insert("x-real-ip", client_ip.to_string().parse().unwrap());
        return modified_headers;
    }
}