use nom::IResult;
use nom::sequence::{tuple, delimited};
use nom::bytes::complete::{tag, take_until};
use nom::error::context;
use nom::character::complete::{alpha1, space0};
use nom::combinator::opt;
use libinjection::{sqli, xss};
use std::convert::identity;
use crate::rules_parser::rule::Rule;
use std::net::IpAddr;
use std::str::FromStr;
use regex::Regex;

#[derive(Clone, Debug, PartialEq)]
pub struct RuleOperator {
    pub negated: bool,
    pub operator_type: RuleOperatorType,
    pub argument: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum RuleOperatorType {
    BeginsWith,
    Contains,
    ContainsWord,
    DetectSQLi,
    DetectXSS,
    EndsWith,
    FuzzyHash,
    /// Performs numerical comparison and returns true if the input value is equal to the
    /// provided parameter. Macro expansion is performed on the parameter string before comparison.
    /// If a value is provided that cannot be converted to an integer (i.e a string)
    /// this operator will treat that value as 0.
    Equals,
    GreaterOrEqual,
    GeoLookup,
    GsbLookup,
    GreaterThan,
    InspectFile,
    IpMatch,
    IpMatchFromFile,
    LessOrEqual,
    LessThan,
    NoMatch,
    Pm,
    PmFromFile,
    Rbl,
    Rsub,
    Regex,
    StrEq,
    StrMatch,
    UnconditionalMatch,
    ValidateByteRange,
    ValidateDTD,
    ValidateHash,
    ValidateSchema,
    ValidateUrlEncoding,
    ValidateUtf8Encoding,
    VerifyCC,
    VerifyCPF,
    VerifySSN,
    Within,
}

impl std::convert::From<&str> for RuleOperatorType {
    fn from(input: &str) -> Self {
        match input {
            "beginsWith" => RuleOperatorType::BeginsWith,
            "contains" => RuleOperatorType::Contains,
            "containsWord" => RuleOperatorType::ContainsWord,
            "detectSQLi" => RuleOperatorType::DetectSQLi,
            "detectXSS" => RuleOperatorType::DetectXSS,
            "endsWith" => RuleOperatorType::EndsWith,
            "fuzzyHash" => RuleOperatorType::FuzzyHash,
            "eq" => RuleOperatorType::Equals,
            "ge" => RuleOperatorType::GreaterOrEqual,
            "geoLookup" => RuleOperatorType::GeoLookup,
            "gsbLookup" => RuleOperatorType::GsbLookup,
            "gt" => RuleOperatorType::GreaterThan,
            "inspectFile" => RuleOperatorType::InspectFile,
            "ipMatch" => RuleOperatorType::IpMatch,
            "ipMatchF" => RuleOperatorType::IpMatchFromFile,
            "ipMatchFromFile" => RuleOperatorType::IpMatchFromFile,
            "le" => RuleOperatorType::LessOrEqual,
            "lt" => RuleOperatorType::LessThan,
            "noMatch" => RuleOperatorType::NoMatch,
            "pm" => RuleOperatorType::Pm,
            "pmFromFile" => RuleOperatorType::PmFromFile,
            "rbl" => RuleOperatorType::Rbl,
            "rsub" => RuleOperatorType::Rsub,
            "rx" => RuleOperatorType::Regex,
            "streq" => RuleOperatorType::StrEq,
            "strmatch" => RuleOperatorType::StrMatch,
            "unconditionalMatch" => RuleOperatorType::UnconditionalMatch,
            "validateByteRange" => RuleOperatorType::ValidateByteRange,
            "validateDTD" => RuleOperatorType::ValidateDTD,
            "validateHash" => RuleOperatorType::ValidateHash,
            "validateSchema" => RuleOperatorType::ValidateSchema,
            "validateUrlEncoding" => RuleOperatorType::ValidateUrlEncoding,
            "validateUtf8Encoding" => RuleOperatorType::ValidateUtf8Encoding,
            "verifyCC" => RuleOperatorType::VerifyCC,
            "verifyCPF" => RuleOperatorType::VerifyCPF,
            "verifySSN" => RuleOperatorType::VerifySSN,
            "within" => RuleOperatorType::Within,
            _ => unimplemented!("operator not implemented")
        }
    }
}

pub fn parse_operator(input: &str) -> IResult<&str, RuleOperator> {
    // todo: default should be @rx
    context(
        "rule operator",
        delimited(
            tag("\""),
            tuple((
                opt(tag("!")),
                tag("@"),
                alpha1,
                space0,
                take_until("\""))
            ),
            tag("\""),
        ),
    )(input).map(|(next_input, parsing_result)| {
        let (negated_opt, _, operator_type_str, _, argument) = parsing_result;
        return (next_input,
                RuleOperator {
                    negated: negated_opt.is_some(),
                    operator_type: operator_type_str.into(),
                    argument: String::from(argument),
                }
        );
    })
}

impl Rule {
    pub fn evaluate_operation(&self, input: &str) -> bool {
        let pattern = self.operator.argument.as_str();
        let operation_result = match self.operator.operator_type {
            RuleOperatorType::BeginsWith => begins_with(input, pattern),
            RuleOperatorType::Contains => contains(input, pattern),
            RuleOperatorType::ContainsWord => unimplemented!("Not implemented yet!"),
            RuleOperatorType::DetectSQLi => detect_sqli(input),
            RuleOperatorType::DetectXSS => detect_xss(input),
            RuleOperatorType::EndsWith => ends_with(input, pattern),
            RuleOperatorType::FuzzyHash => unimplemented!("Not implemented yet!"),
            RuleOperatorType::Equals => equals(input, pattern),
            RuleOperatorType::GreaterOrEqual => greater_or_equal(input, pattern),
            RuleOperatorType::GeoLookup => unimplemented!("Not implemented yet!"),
            RuleOperatorType::GsbLookup => unimplemented!("Not implemented yet!"),
            RuleOperatorType::GreaterThan => greater_than(input, pattern),
            RuleOperatorType::InspectFile => unimplemented!("Not implemented yet!"),
            RuleOperatorType::IpMatch => ip_match(input, pattern),
            RuleOperatorType::IpMatchFromFile => unimplemented!("Not implemented yet!"),
            RuleOperatorType::LessOrEqual => less_or_equal(input, pattern),
            RuleOperatorType::LessThan => less_than(input, pattern),
            RuleOperatorType::NoMatch => no_match(),
            RuleOperatorType::Pm => unimplemented!("Not implemented yet!"),
            RuleOperatorType::PmFromFile => unimplemented!("Not implemented yet!"),
            RuleOperatorType::Rbl => unimplemented!("Not implemented yet!"),
            RuleOperatorType::Rsub => unimplemented!("Not implemented yet!"),
            RuleOperatorType::Regex => regex_match(input, pattern),
            RuleOperatorType::StrEq => str_eq(input, pattern),
            RuleOperatorType::StrMatch => str_match(input, pattern),
            RuleOperatorType::UnconditionalMatch => unconditional_match(),
            RuleOperatorType::ValidateByteRange => unimplemented!("Not implemented yet!"),
            RuleOperatorType::ValidateDTD => unimplemented!("Not implemented yet!"),
            RuleOperatorType::ValidateHash => unimplemented!("Not implemented yet!"),
            RuleOperatorType::ValidateSchema => unimplemented!("Not implemented yet!"),
            RuleOperatorType::ValidateUrlEncoding => unimplemented!("Not implemented yet!"),
            RuleOperatorType::ValidateUtf8Encoding => unimplemented!("Not implemented yet!"),
            RuleOperatorType::VerifyCC => unimplemented!("Not implemented yet!"),
            RuleOperatorType::VerifyCPF => unimplemented!("Not implemented yet!"),
            RuleOperatorType::VerifySSN => unimplemented!("Not implemented yet!"),
            RuleOperatorType::Within => unimplemented!("Not implemented yet!"),
        };
        return if self.operator.negated {
            !operation_result
        } else {
            operation_result
        };
    }
}

fn regex_match(input: &str, pattern: &str) -> bool {
    let regex = regex::Regex::new(pattern).unwrap();
    return regex.is_match(input);
}

fn detect_sqli(input: &str) -> bool {
    let (is_raw_sql_injection, _fingerprint) = sqli(input)
        .map_or((false, "abcd".to_owned()), identity);
    return is_raw_sql_injection;
}

fn detect_xss(input: &str) -> bool {
    let is_xss = xss(input).unwrap_or(false);
    return is_xss;
}

fn begins_with(input: &str, pattern: &str) -> bool {
    return input.starts_with(pattern);
}

fn contains(input: &str, pattern: &str) -> bool {
    return input.contains(pattern);
}

fn ends_with(input: &str, pattern: &str) -> bool {
    return input.ends_with(pattern);
}

fn equals(input: &str, pattern: &str) -> bool {
    let (input_numeric, pattern_numeric) = parse_numeric(input, pattern);
    return input_numeric == pattern_numeric;
}

fn greater_or_equal(input: &str, pattern: &str) -> bool {
    let (input_numeric, pattern_numeric) = parse_numeric(input, pattern);
    return input_numeric >= pattern_numeric;
}

fn greater_than(input: &str, pattern: &str) -> bool {
    let (input_numeric, pattern_numeric) = parse_numeric(input, pattern);
    return input_numeric > pattern_numeric;
}

fn ip_match(input: &str, pattern: &str) -> bool {
    let remote_ip_addr = IpAddr::from_str(input).unwrap();
    let pattern_ip_addr = IpAddr::from_str(pattern).unwrap();
    return remote_ip_addr == pattern_ip_addr;
}

fn less_or_equal(input: &str, pattern: &str) -> bool {
    let (input_numeric, pattern_numeric) = parse_numeric(input, pattern);
    return input_numeric < pattern_numeric;
}

fn less_than(input: &str, pattern: &str) -> bool {
    let (input_numeric, pattern_numeric) = parse_numeric(input, pattern);
    return input_numeric < pattern_numeric;
}

fn no_match() -> bool {
    return false;
}

fn str_eq(input: &str, pattern: &str) -> bool {
    return input == pattern;
}

/// TODO: need to check complexity of Rust stdlib implementation, will be fine for now
fn str_match(input: &str, pattern: &str) -> bool {
    return input.contains(pattern);
}

fn unconditional_match() -> bool {
    return true;
}

fn parse_numeric(input: &str, pattern: &str) -> (i32, i32) {
    let input_numeric = input.parse::<i32>().unwrap_or(0);
    let pattern_numeric = pattern.parse::<i32>().unwrap();
    (input_numeric, pattern_numeric)
}

#[test]
fn regex_should_match_modsecurity_example() {
    assert_eq!(true, regex_match("<script>alert(1);</script>", r###"(?i)<script[^>]*>[\s\S]*?"###));
    assert_eq!(true, regex_match("<sCrIpT>alert(1);</sCrIpT>", r###"(?i)<script[^>]*>[\s\S]*?"###));
    assert_eq!(true, regex_match("<scr<script>ipt>alert(1);</scr</script>ipt>", r###"(?i)<script[^>]*>[\s\S]*?"###));
}

#[test]
fn parse_operator_should_extract_operator() {
    assert_eq!(RuleOperator {
        negated: false,
        operator_type: RuleOperatorType::BeginsWith,
        argument: String::from("GET"),
    },
               parse_operator("\"@beginsWith GET\"").unwrap().1
    );


    assert_eq!(RuleOperator {
        negated: true,
        operator_type: RuleOperatorType::BeginsWith,
        argument: String::from("GET"),
    },
               parse_operator("\"!@beginsWith GET\"").unwrap().1
    );
}