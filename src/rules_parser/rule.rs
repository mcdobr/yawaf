use hyper::{Body, Request};
use nom::error::context;
use nom::IResult;
use nom::sequence::tuple;
use nom::character::complete::{multispace1};
use crate::rules_parser::rule_directive::RuleDirective;
use crate::rules_parser::rule_variable::RuleVariable;
use crate::rules_parser::{rule_directive, rule_variable, rule_operator, rule_action};
use crate::rules_parser::rule_operator::{RuleOperator, RuleOperatorType};
use crate::rules_parser::rule_action::{RuleAction, RuleActionType};

#[derive(Clone, Debug, PartialEq)]
pub struct Rule {
    pub directive: RuleDirective,
    pub variables: Vec<RuleVariable>,
    pub operator: RuleOperator,
    pub transformations: String,
    pub actions: Vec<RuleAction>,
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
            multispace1,
            rule_variable::parse_variables,
            multispace1,
            rule_operator::parse_operator,
            multispace1,
            rule_action::parse_actions,
        )),
    )(input)
        .map(|(next_input, result)| {
            let (directive,
                _,
                variables,
                _,
                operator,
                _,
                actions,
            ) = result;
            return (next_input,
                    Rule {
                        directive,
                        variables,
                        operator,
                        transformations: "".to_string(),
                        actions
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
    "###.replace("\\\n", " ").to_owned();

    assert_eq!(parse_rule(&*raw_rule).unwrap().1,
               Rule {
                   directive: RuleDirective::SecRule,
                   variables: vec![RuleVariable::RequestFilename],
                   operator: RuleOperator {
                       negated: false,
                       operator_type: RuleOperatorType::EndsWith,
                       argument: "/admin/config/development/maintenance".to_string(),
                   },
                   transformations: "".to_string(),
                   actions: vec![
                       RuleAction {
                           action_type: RuleActionType::Id,
                           argument: Some("9001128".to_string()),
                       },
                       RuleAction {
                           action_type: RuleActionType::Phase,
                           argument: Some("2".to_string()),
                       },
                       RuleAction {
                           action_type: RuleActionType::Pass,
                           argument: None,
                       },
                       RuleAction {
                           action_type: RuleActionType::Nolog,
                           argument: None,
                       },
                       RuleAction {
                           action_type: RuleActionType::Ctl,
                           argument: Some("ruleRemoveById=942440".to_string()),
                       },
                       RuleAction {
                           action_type: RuleActionType::Ver,
                           argument: Some("'OWASP_CRS/3.3.0'".to_string()),
                       },
                   ],
               }
    );
}
