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
use hyper::http::uri::PathAndQuery;
use libinjection::sqli;

#[derive(Clone, Debug, PartialEq)]
pub struct Rule {
    pub directive: RuleDirective,
    pub variables: Vec<RuleVariable>,
    pub operator: RuleOperator,
    pub transformations: String,
    pub actions: Vec<RuleAction>,
}

impl Rule {
    pub(crate) fn matches(&self, request: &Request<Body>) -> bool {
        let values : Vec<String> = self.variables.clone()
            .into_iter()
            .map(|var| extract_from(request, var))
            .collect();
        return values
            .iter()
            .any(|str| self.operator.to_operation()(str));
    }
}

fn extract_from(request: &Request<Body>, rule_var: RuleVariable) -> String {
    return match rule_var {
        RuleVariable::Args => unimplemented!("Not implemented yet!"),
        RuleVariable::ArgsCombinedSize => unimplemented!("Not implemented yet!"),
        RuleVariable::ArgsGet => request.uri().query().unwrap_or_else(|| "").to_string(),
        RuleVariable::ArgsGetNames => unimplemented!("Not implemented yet!"),
        RuleVariable::ArgsNames => unimplemented!("Not implemented yet!"),
        RuleVariable::ArgsPost => unimplemented!("Not implemented yet!"),
        RuleVariable::ArgsPostNames => unimplemented!("Not implemented yet!"),
        RuleVariable::AuthType => unimplemented!("Not implemented yet!"),
        RuleVariable::Duration => unimplemented!("Not implemented yet!"),
        RuleVariable::Env => unimplemented!("Not implemented yet!"),
        RuleVariable::Files => unimplemented!("Not implemented yet!"),
        RuleVariable::FilesCombinedSize => unimplemented!("Not implemented yet!"),
        RuleVariable::FilesNames => unimplemented!("Not implemented yet!"),
        RuleVariable::FullRequest => unimplemented!("Not implemented yet!"),
        RuleVariable::FullRequestLength => unimplemented!("Not implemented yet!"),
        RuleVariable::FilesSizes => unimplemented!("Not implemented yet!"),
        RuleVariable::FilesTmpnames => unimplemented!("Not implemented yet!"),
        RuleVariable::FilesTmpContent => unimplemented!("Not implemented yet!"),
        RuleVariable::Geo => unimplemented!("Not implemented yet!"),
        RuleVariable::HighestSeverity => unimplemented!("Not implemented yet!"),
        RuleVariable::InboundDataError => unimplemented!("Not implemented yet!"),
        RuleVariable::MatchedVar => unimplemented!("Not implemented yet!"),
        RuleVariable::MatchedVars => unimplemented!("Not implemented yet!"),
        RuleVariable::MatchedVarName => unimplemented!("Not implemented yet!"),
        RuleVariable::MatchedVarsNames => unimplemented!("Not implemented yet!"),
        RuleVariable::ModsecBuild => unimplemented!("Not implemented yet!"),
        RuleVariable::MultipartCrlfLfLines => unimplemented!("Not implemented yet!"),
        RuleVariable::MultipartFilename => unimplemented!("Not implemented yet!"),
        RuleVariable::MultipartName => unimplemented!("Not implemented yet!"),
        RuleVariable::MultipartStrictError => unimplemented!("Not implemented yet!"),
        RuleVariable::MultipartUnmatchedBoundary => unimplemented!("Not implemented yet!"),
        RuleVariable::OutboundDataError => unimplemented!("Not implemented yet!"),
        RuleVariable::PathInfo => unimplemented!("Not implemented yet!"),
        RuleVariable::PerfAll => unimplemented!("Not implemented yet!"),
        RuleVariable::PerfCombined => unimplemented!("Not implemented yet!"),
        RuleVariable::PerfGc => unimplemented!("Not implemented yet!"),
        RuleVariable::PerfLogging => unimplemented!("Not implemented yet!"),
        RuleVariable::PerfPhase1 => unimplemented!("Not implemented yet!"),
        RuleVariable::PerfPhase2 => unimplemented!("Not implemented yet!"),
        RuleVariable::PerfPhase3 => unimplemented!("Not implemented yet!"),
        RuleVariable::PerfPhase4 => unimplemented!("Not implemented yet!"),
        RuleVariable::PerfPhase5 => unimplemented!("Not implemented yet!"),
        RuleVariable::PerfRules => unimplemented!("Not implemented yet!"),
        RuleVariable::PerfSread => unimplemented!("Not implemented yet!"),
        RuleVariable::PerfSwrite => unimplemented!("Not implemented yet!"),
        RuleVariable::QueryString => unimplemented!("Not implemented yet!"),
        RuleVariable::RemoteAddr => unimplemented!("Not implemented yet!"),
        RuleVariable::RemoteHost => unimplemented!("Not implemented yet!"),
        RuleVariable::RemotePort => unimplemented!("Not implemented yet!"),
        RuleVariable::RemoteUser => unimplemented!("Not implemented yet!"),
        RuleVariable::ReqbodyError => unimplemented!("Not implemented yet!"),
        RuleVariable::ReqbodyErrorMsg => unimplemented!("Not implemented yet!"),
        RuleVariable::ReqbodyProcessor => unimplemented!("Not implemented yet!"),
        RuleVariable::RequestBasename => unimplemented!(), //Path::new(request.uri().path()).file_name(),
        RuleVariable::RequestBody => unimplemented!("Not implemented yet!"),
        RuleVariable::RequestBodyLength => unimplemented!("Not implemented yet!"),
        RuleVariable::RequestCookies => unimplemented!("Not implemented yet!"),
        RuleVariable::RequestCookiesNames => unimplemented!("Not implemented yet!"),
        RuleVariable::RequestFilename => unimplemented!("Not implemented yet!"),
        RuleVariable::RequestHeaders => request.headers().keys().map(|key| key.as_str()).collect(),
        RuleVariable::RequestHeadersNames => unimplemented!("Not implemented yet!"),
        RuleVariable::RequestLine => unimplemented!("Not implemented yet!"),
        RuleVariable::RequestMethod => request.method().to_string(),
        RuleVariable::RequestProtocol => unimplemented!("Not implemented yet!"),
        RuleVariable::RequestUri => request.uri().path_and_query().map_or_else(|| "".to_string(), PathAndQuery::to_string),
        RuleVariable::RequestUriRaw => request.uri().to_string(),
        RuleVariable::ResponseBody => unimplemented!("Not implemented yet!"),
        RuleVariable::ResponseContentLength => unimplemented!("Not implemented yet!"),
        RuleVariable::ResponseContentType => unimplemented!("Not implemented yet!"),
        RuleVariable::ResponseHeaders => unimplemented!("Not implemented yet!"),
        RuleVariable::ResponseHeadersNames => unimplemented!("Not implemented yet!"),
        RuleVariable::ResponseProtocol => unimplemented!("Not implemented yet!"),
        RuleVariable::ResponseStatus => unimplemented!("Not implemented yet!"),
        RuleVariable::Rule => unimplemented!("Not implemented yet!"),
        RuleVariable::ScriptBasename => unimplemented!("Not implemented yet!"),
        RuleVariable::ScriptFilename => unimplemented!("Not implemented yet!"),
        RuleVariable::ScriptGid => unimplemented!("Not implemented yet!"),
        RuleVariable::ScriptGroupname => unimplemented!("Not implemented yet!"),
        RuleVariable::ScriptMode => unimplemented!("Not implemented yet!"),
        RuleVariable::ScriptUid => unimplemented!("Not implemented yet!"),
        RuleVariable::ScriptUsername => unimplemented!("Not implemented yet!"),
        RuleVariable::SdbmDeleteError => unimplemented!("Not implemented yet!"),
        RuleVariable::ServerAddr => unimplemented!("Not implemented yet!"),
        RuleVariable::ServerName => unimplemented!("Not implemented yet!"),
        RuleVariable::ServerPort => unimplemented!("Not implemented yet!"),
        RuleVariable::Session => unimplemented!("Not implemented yet!"),
        RuleVariable::Sessionid => unimplemented!("Not implemented yet!"),
        RuleVariable::StatusLine => unimplemented!("Not implemented yet!"),
        RuleVariable::StreamInputBody => unimplemented!("Not implemented yet!"),
        RuleVariable::StreamOutputBody => unimplemented!("Not implemented yet!"),
        RuleVariable::Time => unimplemented!("Not implemented yet!"),
        RuleVariable::TimeDay => unimplemented!("Not implemented yet!"),
        RuleVariable::TimeEpoch => unimplemented!("Not implemented yet!"),
        RuleVariable::TimeHour => unimplemented!("Not implemented yet!"),
        RuleVariable::TimeMin => unimplemented!("Not implemented yet!"),
        RuleVariable::TimeMon => unimplemented!("Not implemented yet!"),
        RuleVariable::TimeSec => unimplemented!("Not implemented yet!"),
        RuleVariable::TimeWday => unimplemented!("Not implemented yet!"),
        RuleVariable::TimeYear => unimplemented!("Not implemented yet!"),
        RuleVariable::Tx => unimplemented!("Not implemented yet!"),
        RuleVariable::UniqueId => unimplemented!("Not implemented yet!"),
        RuleVariable::UrlencodedError => unimplemented!("Not implemented yet!"),
        RuleVariable::Userid => unimplemented!("Not implemented yet!"),
        RuleVariable::UseragentIp => unimplemented!("Not implemented yet!"),
        RuleVariable::Webappid => unimplemented!("Not implemented yet!"),
        RuleVariable::WebserverErrorLog => unimplemented!("Not implemented yet!"),
        RuleVariable::Xml => unimplemented!("Not implemented yet!"),
    };
}


pub fn parse_rule(input: &str) -> IResult<&str, Rule> {
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
                        actions,
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
