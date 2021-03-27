use nom::IResult;
use nom::sequence::tuple;
use nom::bytes::complete::{tag, take_until, take_while};
use nom::error::context;
use nom::character::is_alphabetic;
use nom::character::complete::{space1, alpha1};
use nom::character::complete::space0;
use nom::combinator::opt;

#[derive(Clone, Debug, PartialEq)]
pub struct RuleOperator {
    negated: bool,
    operator_type: RuleOperatorType,
    argument: String,
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
        tuple((
            tag("\""),
            opt(tag("!")),
            tag("@"),
            alpha1,
            space1,
            take_until("\"")
        )),
    )(input).map(|(next_input, parsing_result)| {
        let (_, negated_opt, _, operator_type_str, _, argument) = parsing_result;
        return (next_input,
                RuleOperator {
                    negated: negated_opt.is_some(),
                    operator_type: operator_type_str.into(),
                    argument: String::from(argument),
                }
        );
    })
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