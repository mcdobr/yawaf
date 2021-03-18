use hyper::{Request, Body};
use nom::IResult;
use crate::rule_directive::RuleDirective;
use nom::error::context;
use nom::branch::alt;
use nom::bytes::complete::tag;
use crate::rule_variable::RuleVariable;
use nom::sequence::tuple;
use nom::multi::many1;

#[derive(Clone, Debug, PartialEq)]
pub struct Rule {
    pub directive: RuleDirective,
    pub variables: Vec<RuleVariable>,
    pub operator: String,
    pub transformations: String,
    pub actions: String,
}

impl Rule {
    pub(crate) fn matches(&self, _request: &Request<Body>) -> bool {
        unimplemented!()
    }
}

// Consult https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)
fn parse_directive(input: &str) -> IResult<&str, RuleDirective> {
    context(
        "rule directive",
        alt(
            (
                tag("SecAction"),
                tag("SecDefaultAction"),
                tag("SecMarker"),
                tag("SecRule"),
                tag("SecRuleInheritance"),
                tag("SecRuleRemoveById"),
                tag("SecRuleRemoveByMsg"),
                tag("SecRuleScript"),
                tag("SecRuleUpdateActionById"),
            )
        ),
    )(input).map(|(next_input, directive_str)| (next_input, directive_str.into()))
}

fn parse_variables(input: &str) -> IResult<&str, Vec<RuleVariable>> {
    context(
        "rule variable",
        alt(
            (
                tag("REQUEST_FILENAME"),
                tag("SESSIONID"),
            )
        ),
    )(input).map(|(next_input, result)| {
        (next_input, vec![result.into()])
    })
}

fn parse_rule(input: &str) -> IResult<&str, Rule> {
    context(
        "rule",
        tuple((
            parse_directive,
            // need to handle whitespaces somehow
            parse_variables,
        )),
    )(input)
        .map(|(next_input, result)| {
            let (directive, variables) = result;
            return (next_input,
                    Rule {
                        directive,
                        variables,
                        operator: "".to_string(),
                        transformations: "".to_string(),
                        actions: "".to_string(),
                    }
            );
        })
}

#[test]
fn parse_rule_should_extract_directive() {
    assert_eq!(parse_directive("SecRule").unwrap().1, RuleDirective::SecRule)
}


#[test]
fn parse_rule_should_extract_basic_elements() {
    let raw_rule = r###"SecRule REQUEST_FILENAME "@endsWith /admin/config/development/maintenance" \
        "id:9001128,\
        phase:2,\
        pass,\
        nolog,\
        ctl:ruleRemoveById=942440,\
        ver:'OWASP_CRS/3.3.0'"
    "###;

    assert_eq!(parse_rule(raw_rule), Ok(("", Rule {
        directive: RuleDirective::SecRule,
        variables: vec![RuleVariable::RequestFilename],
        operator: "".to_string(),
        transformations: "".to_string(),
        actions: "".to_string(),
    })));
}
