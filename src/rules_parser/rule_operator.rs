use nom::IResult;
use nom::sequence::{tuple, delimited};
use nom::bytes::complete::{tag, take_until};
use nom::error::context;
use nom::character::complete::{alpha1, space0};
use nom::combinator::opt;
use libinjection::{sqli, xss};
use std::convert::identity;

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
    Eq,
    Ge,
    GeoLookup,
    GsbLookup,
    Gt,
    InspectFile,
    IpMatch,
    IpMatchF,
    IpMatchFromFile,
    Le,
    Lt,
    NoMatch,
    Pm,
    Pmf,
    PmFromFile,
    Rbl,
    Rsub,
    Rx,
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
            "eq" => RuleOperatorType::Eq,
            "ge" => RuleOperatorType::Ge,
            "geoLookup" => RuleOperatorType::GeoLookup,
            "gsbLookup" => RuleOperatorType::GsbLookup,
            "gt" => RuleOperatorType::Gt,
            "inspectFile" => RuleOperatorType::InspectFile,
            "ipMatch" => RuleOperatorType::IpMatch,
            "ipMatchF" => RuleOperatorType::IpMatchF,
            "ipMatchFromFile" => RuleOperatorType::IpMatchFromFile,
            "le" => RuleOperatorType::Le,
            "lt" => RuleOperatorType::Lt,
            "noMatch" => RuleOperatorType::NoMatch,
            "pm" => RuleOperatorType::Pm,
            "pmf" => RuleOperatorType::Pmf,
            "pmFromFile" => RuleOperatorType::PmFromFile,
            "rbl" => RuleOperatorType::Rbl,
            "rsub" => RuleOperatorType::Rsub,
            "rx" => RuleOperatorType::Rx,
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

impl RuleOperator {
    pub fn to_operation(&self) -> fn(&str) -> bool {
        let operation = match self.operator_type {
            RuleOperatorType::BeginsWith => unimplemented!("Not implemented yet!"),
            RuleOperatorType::Contains => unimplemented!("Not implemented yet!"),
            RuleOperatorType::ContainsWord => unimplemented!("Not implemented yet!"),
            RuleOperatorType::DetectSQLi => detect_sqli,
            RuleOperatorType::DetectXSS => detect_xss,
            RuleOperatorType::EndsWith => unimplemented!("Not implemented yet!"),
            RuleOperatorType::FuzzyHash => unimplemented!("Not implemented yet!"),
            RuleOperatorType::Eq => unimplemented!("Not implemented yet!"),
            RuleOperatorType::Ge => unimplemented!("Not implemented yet!"),
            RuleOperatorType::GeoLookup => unimplemented!("Not implemented yet!"),
            RuleOperatorType::GsbLookup => unimplemented!("Not implemented yet!"),
            RuleOperatorType::Gt => unimplemented!("Not implemented yet!"),
            RuleOperatorType::InspectFile => unimplemented!("Not implemented yet!"),
            RuleOperatorType::IpMatch => unimplemented!("Not implemented yet!"),
            RuleOperatorType::IpMatchF => unimplemented!("Not implemented yet!"),
            RuleOperatorType::IpMatchFromFile => unimplemented!("Not implemented yet!"),
            RuleOperatorType::Le => unimplemented!("Not implemented yet!"),
            RuleOperatorType::Lt => unimplemented!("Not implemented yet!"),
            RuleOperatorType::NoMatch => unimplemented!("Not implemented yet!"),
            RuleOperatorType::Pm => unimplemented!("Not implemented yet!"),
            RuleOperatorType::Pmf => unimplemented!("Not implemented yet!"),
            RuleOperatorType::PmFromFile => unimplemented!("Not implemented yet!"),
            RuleOperatorType::Rbl => unimplemented!("Not implemented yet!"),
            RuleOperatorType::Rsub => unimplemented!("Not implemented yet!"),
            RuleOperatorType::Rx => unimplemented!("Not implemented yet!"),
            RuleOperatorType::StrEq => unimplemented!("Not implemented yet!"),
            RuleOperatorType::StrMatch => unimplemented!("Not implemented yet!"),
            RuleOperatorType::UnconditionalMatch => unimplemented!("Not implemented yet!"),
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
        return operation;
    }
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