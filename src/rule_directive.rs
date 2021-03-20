use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::error::context;
use nom::IResult;
use crate::rule_directive;

#[derive(Clone, Debug, PartialEq)]
pub enum RuleDirective {
    SecAction,
    SecDefaultAction,
    SecMarker,
    SecRule,
    SecRuleInheritance,
    SecRuleRemoveById,
    SecRuleRemoveByMsg,
    SecRuleScript,
    SecRuleUpdateActionById,
}

impl std::convert::From<&str> for RuleDirective {
    fn from(input: &str) -> Self {
        match input {
            "SecAction" => RuleDirective::SecAction,
            "SecDefaultAction" => RuleDirective::SecDefaultAction,
            "SecMarker" => RuleDirective::SecMarker,
            "SecRule" => RuleDirective::SecRule,
            "SecRuleInheritance" => RuleDirective::SecRuleInheritance,
            "SecRuleRemoveById" => RuleDirective::SecRuleRemoveById,
            "SecRuleRemoveByMsg" => RuleDirective::SecRuleRemoveByMsg,
            "SecRuleScript" => RuleDirective::SecRuleScript,
            "SecRuleUpdateActionById" => RuleDirective::SecRuleUpdateActionById,
            _ => unimplemented!("directive not implemented")
        }
    }
}

impl std::str::FromStr for RuleDirective {
    type Err = ();

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "SecAction" => Ok(RuleDirective::SecAction),
            "SecDefaultAction" => Ok(RuleDirective::SecDefaultAction),
            "SecMarker" => Ok(RuleDirective::SecMarker),
            "SecRule" => Ok(RuleDirective::SecRule),
            "SecRuleInheritance" => Ok(RuleDirective::SecRuleInheritance),
            "SecRuleRemoveById" => Ok(RuleDirective::SecRuleRemoveById),
            "SecRuleRemoveByMsg" => Ok(RuleDirective::SecRuleRemoveByMsg),
            "SecRuleScript" => Ok(RuleDirective::SecRuleScript),
            "SecRuleUpdateActionById" => Ok(RuleDirective::SecRuleUpdateActionById),
            _ => Err(())
        }
    }
}

// Consult https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)
pub fn parse_directive(input: &str) -> IResult<&str, RuleDirective> {
    context(
        "rule directive",
        alt(
            (
                tag("SecRuleUpdateActionById"),
                tag("SecRuleScript"),
                tag("SecRuleRemoveByMsg"),
                tag("SecRuleRemoveById"),
                tag("SecRuleInheritance"),
                tag("SecRule"),
                tag("SecMarker"),
                tag("SecDefaultAction"),
                tag("SecAction"),
            )
        ),
    )(input).map(|(next_input, directive_str)| (next_input, directive_str.into()))
}
  
#[test]
fn parse_rule_should_extract_directive() {
    assert_eq!(RuleDirective::SecRule, rule_directive::parse_directive("SecRule").unwrap().1);
    assert_eq!(RuleDirective::SecRuleScript,
               rule_directive::parse_directive("SecRuleScript").unwrap().1);
}
