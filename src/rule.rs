use hyper::{Request, Body};

#[derive(Clone)]
pub struct Rule {
    variables: String,
    operator: String,
    actions: String
}

impl Rule {
    pub(crate) fn matches(&self, request: &Request<Body>) -> bool {
        unimplemented!()
    }
}