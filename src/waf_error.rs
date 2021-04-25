use std::fmt::{Formatter};
use std::fmt;
use std::error::Error;

#[derive(Debug)]
pub(crate) struct WafError {
    details: String
}

impl WafError {
    pub fn new(message: &str) -> WafError {
        WafError { details: message.to_string() }
    }
}

impl fmt::Display for WafError {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.details)
    }
}

impl Error for WafError {
    fn description(&self) -> &str {
        &self.details
    }
}