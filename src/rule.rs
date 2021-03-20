use hyper::{Body, Request};
use nom::error::context;
use nom::IResult;
use nom::sequence::tuple;

use crate::{rule_directive, rule_variable};
use crate::rule_directive::RuleDirective;
use crate::rule_variable::RuleVariable;

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

fn parse_rule(input: &str) -> IResult<&str, Rule> {
    context(
        "rule",
        tuple((
            rule_directive::parse_directive,
            // need to handle whitespaces somehow
            rule_variable::parse_variables,
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
fn parse_rule_should_extract_basic_elements() {
    let raw_rule = r###"SecRule REQUEST_FILENAME "@endsWith /admin/config/development/maintenance" \
        "id:9001128,\
        phase:2,\
        pass,\
        nolog,\
        ctl:ruleRemoveById=942440,\
        ver:'OWASP_CRS/3.3.0'"
    "###;

    assert_eq!(parse_rule(raw_rule).unwrap().1,
               Rule {
                   directive: RuleDirective::SecRule,
                   variables: vec![RuleVariable::RequestFilename],
                   operator: "".to_string(),
                   transformations: "".to_string(),
                   actions: "".to_string(),
               }
    );
}
