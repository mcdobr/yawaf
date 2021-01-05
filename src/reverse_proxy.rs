use hyper::{Client, Request, Body, Response, Error, HeaderMap};
use hyper::client::HttpConnector;

pub(crate) struct ReverseProxy {
    pub(crate) scheme: String,
    pub(crate) authority: String,
    pub(crate) client: Client<HttpConnector>
}

impl ReverseProxy {
    pub(crate) async fn handle_request(&self, mut request: Request<Body>) -> Result<Response<Body>, Error> {
        // Change the request's URI
        let mut uri_builder = hyper::Uri::builder()
            .scheme(&*self.scheme)
            .authority(&*self.authority);


        // Remove headers not whitelisted
        const ALLOWED_HEADERS: [&str; 3] = [
            "accept",
            "user-agent",
            "DNT",
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
        // filtered_headers.insert("host", request.uri().authority())
        *request.headers_mut() = filtered_headers;


        // Copy path and query params
        if let Some(path_and_query) = request.uri().path_and_query() {
            uri_builder = uri_builder.path_and_query(path_and_query.clone());
        }
        *request.uri_mut() = uri_builder.build().unwrap();

        log::debug!("Request == {:?}", request);
        let response = self.client.request(request).await.unwrap();
        log::debug!("Response == {:?}", response);
        return Ok(response);
    }
}