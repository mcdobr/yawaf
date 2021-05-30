use hyper::{Body, Request};
use nom::error::context;
use nom::IResult;
use nom::sequence::{tuple, delimited};
use nom::character::complete::{multispace1, multispace0};
use crate::rules_parser::rule_directive::RuleDirective;
use crate::rules_parser::rule_variable::{RuleVariableType, RuleVariable};
use crate::rules_parser::{rule_directive, rule_variable, rule_operator, rule_action};
use crate::rules_parser::rule_operator::{RuleOperator, RuleOperatorType};
use crate::rules_parser::rule_action::{RuleAction, RuleActionType};
use hyper::http::uri::PathAndQuery;
use crate::rules_parser::rule_variable::RuleVariableType::RemoteAddr;
use std::net::SocketAddr;
use hyper::header::COOKIE;
use futures::Stream;
use hyper::body::Bytes;
use std::str::from_utf8;
use bytes::BytesMut;
use crate::rules_parser::rule_action::RuleActionType::T;

/// todo: is order of variables and actions relevant or should it be set instead of vec?
#[derive(Clone, Debug, PartialEq)]
pub struct Rule {
    pub directive: RuleDirective,
    pub variables: Vec<RuleVariable>,
    pub operator: RuleOperator,
    pub actions: Vec<RuleAction>,
}

impl Rule {
    pub fn matches(&self, request: &Request<Body>) -> bool {
        let transformation_actions = self.actions.clone()
            .into_iter()
            .filter(|action| action.action_type == RuleActionType::T)
            .collect::<Vec<RuleAction>>();

        let mut values: Vec<String> = self.variables.clone()
            .into_iter()
            .flat_map(|var| {
                let extracted_values = extract_from(request, &var);
                // todo: hacky for now, pass a vector with the number in string form until i can
                //  figure out how i should express this for the type system or redesign this
                match var.count {
                    true => vec![extracted_values.len().to_string()],
                    false => extracted_values,
                }
            })
            .collect();

        // apply all transformations to all extracted values
        if !transformation_actions.is_empty() {
            for value in values.iter_mut() {
                *value = value.to_lowercase();
                // match transformation_actions[0].argument.unwrap_or(String::from("none")).as_ref() {
                //     "base64Decode" => value,
                //     // "urlDecode" => *value = serde_urlencoded::from_str::<String>(value).unwrap(),
                //     "lowercase" => value.to_lowercase(),
                //     _ => value,
                // }
            }
        }

        return values
            .iter()
            .any(|str| self.evaluate_operation(str));
    }
}

fn extract_from(request: &Request<Body>, rule_var: &RuleVariable) -> Vec<String> {
    return match rule_var.variable_type {
        RuleVariableType::Args => unimplemented!("Not implemented yet!"),
        RuleVariableType::ArgsCombinedSize => unimplemented!("Not implemented yet!"),
        RuleVariableType::ArgsGet => vec![request.uri().query().unwrap_or_else(|| "").to_string()],
        RuleVariableType::ArgsGetNames => unimplemented!("Not implemented yet!"),
        RuleVariableType::ArgsNames => unimplemented!("Not implemented yet!"),
        RuleVariableType::ArgsPost => unimplemented!("Not implemented yet!"),
        RuleVariableType::ArgsPostNames => unimplemented!("Not implemented yet!"),
        RuleVariableType::AuthType => unimplemented!("Not implemented yet!"),
        RuleVariableType::Duration => unimplemented!("Not implemented yet!"),
        RuleVariableType::Env => unimplemented!("Not implemented yet!"),
        RuleVariableType::Files => unimplemented!("Not implemented yet!"),
        RuleVariableType::FilesCombinedSize => unimplemented!("Not implemented yet!"),
        RuleVariableType::FilesNames => unimplemented!("Not implemented yet!"),
        RuleVariableType::FullRequest => unimplemented!("Not implemented yet!"),
        RuleVariableType::FullRequestLength => unimplemented!("Not implemented yet!"),
        RuleVariableType::FilesSizes => unimplemented!("Not implemented yet!"),
        RuleVariableType::FilesTmpnames => unimplemented!("Not implemented yet!"),
        RuleVariableType::FilesTmpContent => unimplemented!("Not implemented yet!"),
        RuleVariableType::Geo => unimplemented!("Not implemented yet!"),
        RuleVariableType::HighestSeverity => unimplemented!("Not implemented yet!"),
        RuleVariableType::InboundDataError => unimplemented!("Not implemented yet!"),
        RuleVariableType::MatchedVar => unimplemented!("Not implemented yet!"),
        RuleVariableType::MatchedVars => unimplemented!("Not implemented yet!"),
        RuleVariableType::MatchedVarName => unimplemented!("Not implemented yet!"),
        RuleVariableType::MatchedVarsNames => unimplemented!("Not implemented yet!"),
        RuleVariableType::ModsecBuild => unimplemented!("Not implemented yet!"),
        RuleVariableType::MultipartCrlfLfLines => unimplemented!("Not implemented yet!"),
        RuleVariableType::MultipartFilename => unimplemented!("Not implemented yet!"),
        RuleVariableType::MultipartName => unimplemented!("Not implemented yet!"),
        RuleVariableType::MultipartStrictError => unimplemented!("Not implemented yet!"),
        RuleVariableType::MultipartUnmatchedBoundary => unimplemented!("Not implemented yet!"),
        RuleVariableType::OutboundDataError => unimplemented!("Not implemented yet!"),
        RuleVariableType::PathInfo => unimplemented!("Not implemented yet!"),
        RuleVariableType::PerfAll => unimplemented!("Not implemented yet!"),
        RuleVariableType::PerfCombined => unimplemented!("Not implemented yet!"),
        RuleVariableType::PerfGc => unimplemented!("Not implemented yet!"),
        RuleVariableType::PerfLogging => unimplemented!("Not implemented yet!"),
        RuleVariableType::PerfPhase1 => unimplemented!("Not implemented yet!"),
        RuleVariableType::PerfPhase2 => unimplemented!("Not implemented yet!"),
        RuleVariableType::PerfPhase3 => unimplemented!("Not implemented yet!"),
        RuleVariableType::PerfPhase4 => unimplemented!("Not implemented yet!"),
        RuleVariableType::PerfPhase5 => unimplemented!("Not implemented yet!"),
        RuleVariableType::PerfRules => unimplemented!("Not implemented yet!"),
        RuleVariableType::PerfSread => unimplemented!("Not implemented yet!"),
        RuleVariableType::PerfSwrite => unimplemented!("Not implemented yet!"),
        RuleVariableType::QueryString => unimplemented!("Not implemented yet!"),
        RuleVariableType::RemoteAddr => vec![request.extensions().get::<SocketAddr>().unwrap()
            .ip().to_string()],
        RuleVariableType::RemoteHost => unimplemented!("Not implemented yet!"),
        RuleVariableType::RemotePort => vec![request.extensions().get::<SocketAddr>().unwrap()
            .port().to_string()],
        RuleVariableType::RemoteUser => unimplemented!("Not implemented yet!"),
        RuleVariableType::ReqbodyError => unimplemented!("Not implemented yet!"),
        RuleVariableType::ReqbodyErrorMsg => unimplemented!("Not implemented yet!"),
        RuleVariableType::ReqbodyProcessor => unimplemented!("Not implemented yet!"),
        RuleVariableType::RequestBasename => unimplemented!("Not implemented yet!"),
        RuleVariableType::RequestBody => unimplemented!("Not implemented yet!"),
        RuleVariableType::RequestBodyLength => unimplemented!("Not implemented yet!"),
        RuleVariableType::RequestCookies => request.headers().get(COOKIE)
            .into_iter()
            .map(|header_value| header_value.to_str().unwrap().to_string())
            .collect::<Vec<String>>(),
        RuleVariableType::RequestCookiesNames => unimplemented!("Not implemented yet!"),
        RuleVariableType::RequestFilename => unimplemented!("Not implemented yet!"),
        RuleVariableType::RequestHeaders => request.headers()
            .iter()
            .map(|(key, value)| key.to_string() + ": " + value.to_str().unwrap_or(""))
            .collect::<Vec<String>>(),
        RuleVariableType::RequestHeadersNames => request.headers()
            .keys()
            .map(|key| key.to_string())
            .collect::<Vec<String>>(),
        RuleVariableType::RequestLine => unimplemented!("Not implemented yet!"),
        RuleVariableType::RequestMethod => vec![request.method().to_string()],
        RuleVariableType::RequestProtocol => unimplemented!("Not implemented yet!"),
        RuleVariableType::RequestUri => vec![request.uri().path_and_query()
            .map_or_else(|| "".to_string(), PathAndQuery::to_string)],
        RuleVariableType::RequestUriRaw => vec![request.uri().to_string()],
        RuleVariableType::ResponseBody => unimplemented!("Not implemented yet!"),
        RuleVariableType::ResponseContentLength => unimplemented!("Not implemented yet!"),
        RuleVariableType::ResponseContentType => unimplemented!("Not implemented yet!"),
        RuleVariableType::ResponseHeaders => unimplemented!("Not implemented yet!"),
        RuleVariableType::ResponseHeadersNames => unimplemented!("Not implemented yet!"),
        RuleVariableType::ResponseProtocol => unimplemented!("Not implemented yet!"),
        RuleVariableType::ResponseStatus => unimplemented!("Not implemented yet!"),
        RuleVariableType::Rule => unimplemented!("Not implemented yet!"),
        RuleVariableType::ScriptBasename => unimplemented!("Not implemented yet!"),
        RuleVariableType::ScriptFilename => unimplemented!("Not implemented yet!"),
        RuleVariableType::ScriptGid => unimplemented!("Not implemented yet!"),
        RuleVariableType::ScriptGroupname => unimplemented!("Not implemented yet!"),
        RuleVariableType::ScriptMode => unimplemented!("Not implemented yet!"),
        RuleVariableType::ScriptUid => unimplemented!("Not implemented yet!"),
        RuleVariableType::ScriptUsername => unimplemented!("Not implemented yet!"),
        RuleVariableType::SdbmDeleteError => unimplemented!("Not implemented yet!"),
        RuleVariableType::ServerAddr => unimplemented!("Not implemented yet!"),
        RuleVariableType::ServerName => unimplemented!("Not implemented yet!"),
        RuleVariableType::ServerPort => unimplemented!("Not implemented yet!"),
        RuleVariableType::Session => unimplemented!("Not implemented yet!"),
        RuleVariableType::Sessionid => unimplemented!("Not implemented yet!"),
        RuleVariableType::StatusLine => unimplemented!("Not implemented yet!"),
        RuleVariableType::StreamInputBody => unimplemented!("Not implemented yet!"),
        RuleVariableType::StreamOutputBody => unimplemented!("Not implemented yet!"),
        RuleVariableType::Time => unimplemented!("Not implemented yet!"),
        RuleVariableType::TimeDay => unimplemented!("Not implemented yet!"),
        RuleVariableType::TimeEpoch => unimplemented!("Not implemented yet!"),
        RuleVariableType::TimeHour => unimplemented!("Not implemented yet!"),
        RuleVariableType::TimeMin => unimplemented!("Not implemented yet!"),
        RuleVariableType::TimeMon => unimplemented!("Not implemented yet!"),
        RuleVariableType::TimeSec => unimplemented!("Not implemented yet!"),
        RuleVariableType::TimeWday => unimplemented!("Not implemented yet!"),
        RuleVariableType::TimeYear => unimplemented!("Not implemented yet!"),
        RuleVariableType::Tx => unimplemented!("Not implemented yet!"),
        RuleVariableType::UniqueId => unimplemented!("Not implemented yet!"),
        RuleVariableType::UrlencodedError => unimplemented!("Not implemented yet!"),
        RuleVariableType::Userid => unimplemented!("Not implemented yet!"),
        RuleVariableType::UseragentIp => unimplemented!("Not implemented yet!"),
        RuleVariableType::Webappid => unimplemented!("Not implemented yet!"),
        RuleVariableType::WebserverErrorLog => unimplemented!("Not implemented yet!"),
        RuleVariableType::Xml => unimplemented!("Not implemented yet!"),
    };
}

pub fn parse_rules(input: &str) -> Vec<Rule> {
    let input_with_removed_newlines = input.replace("\\\n", " ");
    let mut str = input_with_removed_newlines.as_str();
    let mut rules: Vec<Rule> = Vec::new();
    while !str.is_empty() {
        let parsing_result = parse_rule(str);
        let (next_str, rule) = parsing_result.unwrap();

        rules.push(rule);
        str = next_str;
    }
    return rules;
}

pub fn parse_rule(input: &str) -> IResult<&str, Rule> {
    context(
        "rule",
        delimited(
            multispace0,
            tuple((
                rule_directive::parse_directive,
                multispace1,
                rule_variable::parse_variables,
                multispace1,
                rule_operator::parse_operator,
                multispace1,
                rule_action::parse_actions,
            )),
            multispace0,
        ),
    )(input)
        .map(|(next_input, result)| {
            let (
                directive,
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
                        actions,
                    }
            );
        })
}

#[test]
fn parse_rules_should_parse_multiple_rules_completely() {
    let rules = parse_rules(r###"
    SecRule REMOTE_ADDR "@ipMatch 192.168.1.101" \
        "id:102,phase:1,t:none,nolog,pass,ctl:ruleEngine=off"

    SecRule REQUEST_URI "@beginsWith /index.php/component/users/" \
        "id:5,phase:1,t:none,pass,nolog,ctl:ruleRemoveTargetById=981318"
"###);

    assert_eq!(vec![
        Rule {
            directive: RuleDirective::SecRule,
            variables: vec![
                RuleVariable {
                    count: false,
                    variable_type: RuleVariableType::RemoteAddr,
                }
            ],
            operator: RuleOperator {
                negated: false,
                operator_type: RuleOperatorType::IpMatch,
                argument: "192.168.1.101".to_string(),
            },
            actions: vec![
                RuleAction {
                    action_type: RuleActionType::Id,
                    argument: Some("102".to_string()),
                },
                RuleAction {
                    action_type: RuleActionType::Phase,
                    argument: Some("1".to_string()),
                },
                RuleAction {
                    action_type: RuleActionType::T,
                    argument: Some("none".to_string()),
                },
                RuleAction {
                    action_type: RuleActionType::Nolog,
                    argument: None,
                },
                RuleAction {
                    action_type: RuleActionType::Pass,
                    argument: None,
                },
                RuleAction {
                    action_type: RuleActionType::Ctl,
                    argument: Some("ruleEngine=off".to_string()),
                },
            ],
        },
        Rule {
            directive: RuleDirective::SecRule,
            variables: vec![RuleVariable {
                count: false,
                variable_type: RuleVariableType::RequestUri,
            }],
            operator: RuleOperator {
                negated: false,
                operator_type: RuleOperatorType::BeginsWith,
                argument: "/index.php/component/users/".to_string(),
            },
            actions: vec![
                RuleAction {
                    action_type: RuleActionType::Id,
                    argument: Some("5".to_string()),
                },
                RuleAction {
                    action_type: RuleActionType::Phase,
                    argument: Some("1".to_string()),
                },
                RuleAction {
                    action_type: RuleActionType::T,
                    argument: Some("none".to_string()),
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
                    argument: Some("ruleRemoveTargetById=981318".to_string()),
                },
            ],
        }
    ], rules);
}

#[test]
fn extract_variables_should_extract_headers() {
    let request = Request::builder()
        .method("POST")
        .header("abcd", "qwerty")
        .header("ader", "<script>alert(1);</script>")
        .body(Body::empty())
        .unwrap();
    let rule = Rule {
        directive: RuleDirective::SecRule,
        variables: vec![RuleVariable {
            count: false,
            variable_type: RuleVariableType::RequestHeaders,
        }],
        operator: RuleOperator {
            negated: false,
            operator_type: RuleOperatorType::DetectXSS,
            argument: "".to_string(),
        },
        actions: vec![],
    };

    let str = extract_from(&request, &rule.variables[0]);
    println!("{:?}", str);
    assert!(!str.is_empty());
    assert!(rule.matches(&request));
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
                   variables: vec![RuleVariable {
                       count: false,
                       variable_type: RuleVariableType::RequestFilename,
                   }],
                   operator: RuleOperator {
                       negated: false,
                       operator_type: RuleOperatorType::EndsWith,
                       argument: "/admin/config/development/maintenance".to_string(),
                   },
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
