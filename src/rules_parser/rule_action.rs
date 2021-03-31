use nom::IResult;
use nom::sequence::{tuple, separated_pair, delimited};
use nom::error::context;
use nom::character::complete::{alpha1, multispace0};
use nom::combinator::{opt};
use nom::bytes::complete::{tag, is_not};
use nom::multi::{separated_list1};

#[derive(Clone, Debug, PartialEq)]
pub struct RuleAction {
    pub action_type: RuleActionType,
    pub argument: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum RuleActionType {
    Accuracy,
    Allow,
    Append,
    AuditLog,
    Block,
    Capture,
    Chain,
    Ctl,
    Deny,
    DeprecateVar,
    Drop,
    Exec,
    ExpireVar,
    Id,
    InitCol,
    Log,
    LogData,
    Maturity,
    Msg,
    MultiMatch,
    NoAuditLog,
    Nolog,
    Pass,
    Pause,
    Phase,
    Prepend,
    Proxy,
    Redirect,
    Rev,
    SanitiseArg,
    SanitiseMatched,
    SanitiseMatchedBytes,
    SanitiseRequestHeader,
    SanitiseResponseHeader,
    Severity,
    Setuid,
    SetRsc,
    SetSid,
    SetEnv,
    SetVar,
    Skip,
    SkipAfter,
    Status,
    T,
    Tag,
    Ver,
    Xmlns,
}

impl std::convert::From<&str> for RuleActionType {
    fn from(input: &str) -> Self {
        match input {
            "accuracy" => RuleActionType::Accuracy,
            "allow" => RuleActionType::Allow,
            "append" => RuleActionType::Append,
            "auditlog" => RuleActionType::AuditLog,
            "block" => RuleActionType::Block,
            "capture" => RuleActionType::Capture,
            "chain" => RuleActionType::Chain,
            "ctl" => RuleActionType::Ctl,
            "deny" => RuleActionType::Deny,
            "deprecatevar" => RuleActionType::DeprecateVar,
            "drop" => RuleActionType::Drop,
            "exec" => RuleActionType::Exec,
            "expirevar" => RuleActionType::ExpireVar,
            "id" => RuleActionType::Id,
            "initcol" => RuleActionType::InitCol,
            "log" => RuleActionType::Log,
            "logdata" => RuleActionType::LogData,
            "maturity" => RuleActionType::Maturity,
            "msg" => RuleActionType::Msg,
            "multiMatch" => RuleActionType::MultiMatch,
            "noauditlog" => RuleActionType::NoAuditLog,
            "nolog" => RuleActionType::Nolog,
            "pass" => RuleActionType::Pass,
            "pause" => RuleActionType::Pause,
            "phase" => RuleActionType::Phase,
            "prepend" => RuleActionType::Prepend,
            "proxy" => RuleActionType::Proxy,
            "redirect" => RuleActionType::Redirect,
            "rev" => RuleActionType::Rev,
            "sanitiseArg" => RuleActionType::SanitiseArg,
            "sanitiseMatched" => RuleActionType::SanitiseMatched,
            "sanitiseMatchedBytes" => RuleActionType::SanitiseMatchedBytes,
            "sanitiseRequestHeader" => RuleActionType::SanitiseRequestHeader,
            "sanitiseResponseHeader" => RuleActionType::SanitiseResponseHeader,
            "severity" => RuleActionType::Severity,
            "setuid" => RuleActionType::Setuid,
            "setrsc" => RuleActionType::SetRsc,
            "setsid" => RuleActionType::SetSid,
            "setenv" => RuleActionType::SetEnv,
            "setvar" => RuleActionType::SetVar,
            "skip" => RuleActionType::Skip,
            "skipAfter" => RuleActionType::SkipAfter,
            "status" => RuleActionType::Status,
            "t" => RuleActionType::T,
            "tag" => RuleActionType::Tag,
            "ver" => RuleActionType::Ver,
            "xmlns" => RuleActionType::Xmlns,
            _ => unimplemented!("action not implemented")
        }
    }
}

pub fn parse_actions(input: &str) -> IResult<&str, Vec<RuleAction>> {
    context("rule action parsing",
            delimited(
                tag("\""),
                separated_list1(tuple((tag(","), multispace0)), parse_action),
                tag("\""),
            ),
    )(input).map(|(next_input, actions)| {
        return (next_input, actions);
    })
}

pub fn parse_action(input: &str) -> IResult<&str, RuleAction> {
    context("individual rule action item",
            separated_pair(alpha1,
                           opt(tag(":")),
                           opt(is_not(",\"")),
            ),
    )(input).map(|(next_input, parsing_result)| {
        let (action_type_str, argument) = parsing_result;
        return (next_input,
                RuleAction {
                    action_type: action_type_str.into(),
                    argument: argument.map(|val| val.to_string()),
                });
    })
}

#[test]
fn parse_action_should_extract_action() {
    assert_eq!(RuleAction {
        action_type: RuleActionType::Append,
        argument: Some("'<hr>Footer'".to_string()),
    }, parse_action("append:'<hr>Footer'").unwrap().1)
}

#[test]
fn parse_actions_should_extract_all_actions() {
    assert_eq!(vec![
        RuleAction {
            action_type: RuleActionType::Nolog,
            argument: None,
        },
        RuleAction {
            action_type: RuleActionType::Id,
            argument: Some("99".to_string()),
        },
        RuleAction {
            action_type: RuleActionType::Pass,
            argument: None,
        },
        RuleAction {
            action_type: RuleActionType::Append,
            argument: Some("'<hr>Footer'".to_string()),
        },
    ],
               parse_actions("\"nolog,id:99,pass,append:'<hr>Footer'\"").unwrap().1
    )
}
