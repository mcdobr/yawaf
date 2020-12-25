use hyper::service::{make_service_fn, service_fn};
use std::convert::Infallible;
use hyper::{Request, Body, Response, Server, Client, HeaderMap};
use std::net::SocketAddr;
use hyper::client::HttpConnector;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();



    let _config : &str =
    "
hosts:
    - example.com
    - 127.0.0.1:10000

    ";

    let address = SocketAddr::from(([127, 0, 0, 1], 3030));

    let service = make_service_fn(|_| async {
        return Ok::<_, Infallible>(service_fn(handle_request));
    });

    let server = Server::bind(&address).serve(service);


    server.await?;

    return Ok(());
}

struct ReverseProxy {
    scheme: String,
    authority: String,
    client: Client<HttpConnector<hyper::client::HttpConnector>>
}


// todo: change unwraps() to log and exit
async fn handle_request(mut request: Request<Body>) -> Result<Response<Body>, Infallible> {
    // Change the request's URI
    let mut uri_builder = hyper::Uri::builder()
        .scheme("http")
        .authority("example.com");
    *request.uri_mut() = uri_builder.build().unwrap();


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


    log::debug!("Request == {:?}", request);

    // todo: change ownership such that we don't create a client for every request, but inject it somehow
    let http_connector = HttpConnector::new();
    let http_client = Client::builder().build(http_connector);
    let response = http_client.request(request).await.unwrap();
    log::debug!("Response == {:?}", response);
    return Ok(response);
}