use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::error::context;
use nom::IResult;

use strum_macros::{EnumVariantNames};
use nom::multi::separated_list0;
use nom::sequence::tuple;
use nom::combinator::opt;

#[derive(Clone, Debug, PartialEq, Eq,  EnumVariantNames, Hash)]
#[strum(serialize_all = "shouty_snake_case")]
pub enum RuleVariableType {
    Args,
    ArgsCombinedSize,
    ArgsGet,
    ArgsGetNames,
    ArgsNames,
    ArgsPost,
    ArgsPostNames,
    AuthType,
    Duration,
    Env,
    Files,
    FilesCombinedSize,
    FilesNames,
    FullRequest,
    FullRequestLength,
    FilesSizes,
    FilesTmpnames,
    FilesTmpContent,
    Geo,
    HighestSeverity,
    InboundDataError,
    MatchedVar,
    MatchedVars,
    MatchedVarName,
    MatchedVarsNames,
    ModsecBuild,
    MultipartCrlfLfLines,
    MultipartFilename,
    MultipartName,
    MultipartStrictError,
    MultipartUnmatchedBoundary,
    OutboundDataError,
    PathInfo,
    PerfAll,
    PerfCombined,
    PerfGc,
    PerfLogging,
    PerfPhase1,
    PerfPhase2,
    PerfPhase3,
    PerfPhase4,
    PerfPhase5,
    PerfRules,
    PerfSread,
    PerfSwrite,
    QueryString,
    /// This variable holds the IP address of the remote client.
    RemoteAddr,
    /// If hostname lookup is set to On, then this variable will hold
    /// the remote hostname resolved through DNS. If the directive is set to Off, this variable
    /// it will hold the remote IP address same as REMOTE_ADDR). Possible uses for this
    /// variable would be to deny known bad client hosts or network blocks,
    /// or conversely, to allow in authorized hosts.
    RemoteHost,
    /// This variable holds information on the source port that the client used when initiating the connection to our web server.
    ///
    /// E.g:  we are evaluating to see whether the REMOTE_PORT is less than 1024, which would
    /// indicate that the user is a privileged user:
    ///
    /// SecRule REMOTE_PORT "@lt 1024" "id:37"
    RemotePort,
    RemoteUser,
    ReqbodyError,
    ReqbodyErrorMsg,
    ReqbodyProcessor,
    /// This variable holds just the filename part of REQUEST_FILENAME (e.g., index.php).
    RequestBasename,
    RequestBody,
    RequestBodyLength,
    RequestCookies,
    RequestCookiesNames,
    RequestFilename,
    RequestHeaders,
    RequestHeadersNames,
    RequestLine,
    RequestMethod,
    RequestProtocol,
    /// This variable holds the full request URL including the query string
    /// data (e.g., /index.php? p=X). However, it will never contain a domain name, even if it
    /// was provided on the request line.
    RequestUri,
    RequestUriRaw,
    ResponseBody,
    ResponseContentLength,
    ResponseContentType,
    ResponseHeaders,
    ResponseHeadersNames,
    ResponseProtocol,
    ResponseStatus,
    Rule,
    ScriptBasename,
    ScriptFilename,
    ScriptGid,
    ScriptGroupname,
    ScriptMode,
    ScriptUid,
    ScriptUsername,
    SdbmDeleteError,
    ServerAddr,
    ServerName,
    ServerPort,
    Session,
    Sessionid,
    StatusLine,
    StreamInputBody,
    StreamOutputBody,
    Time,
    TimeDay,
    TimeEpoch,
    TimeHour,
    TimeMin,
    TimeMon,
    TimeSec,
    TimeWday,
    TimeYear,
    Tx,
    UniqueId,
    UrlencodedError,
    Userid,
    UseragentIp,
    Webappid,
    WebserverErrorLog,
    Xml,
}

impl std::convert::From<&str> for RuleVariableType {
    fn from(input: &str) -> Self {
        match input {
            "ARGS" => RuleVariableType::Args,
            "ARGS_COMBINED_SIZE" => RuleVariableType::ArgsCombinedSize,
            "ARGS_GET" => RuleVariableType::ArgsGet,
            "ARGS_GET_NAMES" => RuleVariableType::ArgsGetNames,
            "ARGS_NAMES" => RuleVariableType::ArgsNames,
            "ARGS_POST" => RuleVariableType::ArgsPost,
            "ARGS_POST_NAMES" => RuleVariableType::ArgsPostNames,
            "AUTH_TYPE" => RuleVariableType::AuthType,
            "DURATION" => RuleVariableType::Duration,
            "ENV" => RuleVariableType::Env,
            "FILES" => RuleVariableType::Files,
            "FILES_COMBINED_SIZE" => RuleVariableType::FilesCombinedSize,
            "FILES_NAMES" => RuleVariableType::FilesNames,
            "FULL_REQUEST" => RuleVariableType::FullRequest,
            "FULL_REQUEST_LENGTH" => RuleVariableType::FullRequestLength,
            "FILES_SIZES" => RuleVariableType::FilesSizes,
            "FILES_TMPNAMES" => RuleVariableType::FilesTmpnames,
            "FILES_TMP_CONTENT" => RuleVariableType::FilesTmpContent,
            "GEO" => RuleVariableType::Geo,
            "HIGHEST_SEVERITY" => RuleVariableType::HighestSeverity,
            "INBOUND_DATA_ERROR" => RuleVariableType::InboundDataError,
            "MATCHED_VAR" => RuleVariableType::MatchedVar,
            "MATCHED_VARS" => RuleVariableType::MatchedVars,
            "MATCHED_VAR_NAME" => RuleVariableType::MatchedVarName,
            "MATCHED_VARS_NAMES" => RuleVariableType::MatchedVarsNames,
            "MODSEC_BUILD" => RuleVariableType::ModsecBuild,
            "MULTIPART_CRLF_LF_LINES" => RuleVariableType::MultipartCrlfLfLines,
            "MULTIPART_FILENAME" => RuleVariableType::MultipartFilename,
            "MULTIPART_NAME" => RuleVariableType::MultipartName,
            "MULTIPART_STRICT_ERROR" => RuleVariableType::MultipartStrictError,
            "MULTIPART_UNMATCHED_BOUNDARY" => RuleVariableType::MultipartUnmatchedBoundary,
            "OUTBOUND_DATA_ERROR" => RuleVariableType::OutboundDataError,
            "PATH_INFO" => RuleVariableType::PathInfo,
            "PERF_ALL" => RuleVariableType::PerfAll,
            "PERF_COMBINED" => RuleVariableType::PerfCombined,
            "PERF_GC" => RuleVariableType::PerfGc,
            "PERF_LOGGING" => RuleVariableType::PerfLogging,
            "PERF_PHASE1" => RuleVariableType::PerfPhase1,
            "PERF_PHASE2" => RuleVariableType::PerfPhase2,
            "PERF_PHASE3" => RuleVariableType::PerfPhase3,
            "PERF_PHASE4" => RuleVariableType::PerfPhase4,
            "PERF_PHASE5" => RuleVariableType::PerfPhase5,
            "PERF_RULES" => RuleVariableType::PerfRules,
            "PERF_SREAD" => RuleVariableType::PerfSread,
            "PERF_SWRITE" => RuleVariableType::PerfSwrite,
            "QUERY_STRING" => RuleVariableType::QueryString,
            "REMOTE_ADDR" => RuleVariableType::RemoteAddr,
            "REMOTE_HOST" => RuleVariableType::RemoteHost,
            "REMOTE_PORT" => RuleVariableType::RemotePort,
            "REMOTE_USER" => RuleVariableType::RemoteUser,
            "REQBODY_ERROR" => RuleVariableType::ReqbodyError,
            "REQBODY_ERROR_MSG" => RuleVariableType::ReqbodyErrorMsg,
            "REQBODY_PROCESSOR" => RuleVariableType::ReqbodyProcessor,
            "REQUEST_BASENAME" => RuleVariableType::RequestBasename,
            "REQUEST_BODY" => RuleVariableType::RequestBody,
            "REQUEST_BODY_LENGTH" => RuleVariableType::RequestBodyLength,
            "REQUEST_COOKIES" => RuleVariableType::RequestCookies,
            "REQUEST_COOKIES_NAMES" => RuleVariableType::RequestCookiesNames,
            "REQUEST_FILENAME" => RuleVariableType::RequestFilename,
            "REQUEST_HEADERS" => RuleVariableType::RequestHeaders,
            "REQUEST_HEADERS_NAMES" => RuleVariableType::RequestHeadersNames,
            "REQUEST_LINE" => RuleVariableType::RequestLine,
            "REQUEST_METHOD" => RuleVariableType::RequestMethod,
            "REQUEST_PROTOCOL" => RuleVariableType::RequestProtocol,
            "REQUEST_URI" => RuleVariableType::RequestUri,
            "REQUEST_URI_RAW" => RuleVariableType::RequestUriRaw,
            "RESPONSE_BODY" => RuleVariableType::ResponseBody,
            "RESPONSE_CONTENT_LENGTH" => RuleVariableType::ResponseContentLength,
            "RESPONSE_CONTENT_TYPE" => RuleVariableType::ResponseContentType,
            "RESPONSE_HEADERS" => RuleVariableType::ResponseHeaders,
            "RESPONSE_HEADERS_NAMES" => RuleVariableType::ResponseHeadersNames,
            "RESPONSE_PROTOCOL" => RuleVariableType::ResponseProtocol,
            "RESPONSE_STATUS" => RuleVariableType::ResponseStatus,
            "RULE" => RuleVariableType::Rule,
            "SCRIPT_BASENAME" => RuleVariableType::ScriptBasename,
            "SCRIPT_FILENAME" => RuleVariableType::ScriptFilename,
            "SCRIPT_GID" => RuleVariableType::ScriptGid,
            "SCRIPT_GROUPNAME" => RuleVariableType::ScriptGroupname,
            "SCRIPT_MODE" => RuleVariableType::ScriptMode,
            "SCRIPT_UID" => RuleVariableType::ScriptUid,
            "SCRIPT_USERNAME" => RuleVariableType::ScriptUsername,
            "SDBM_DELETE_ERROR" => RuleVariableType::SdbmDeleteError,
            "SERVER_ADDR" => RuleVariableType::ServerAddr,
            "SERVER_NAME" => RuleVariableType::ServerName,
            "SERVER_PORT" => RuleVariableType::ServerPort,
            "SESSION" => RuleVariableType::Session,
            "SESSIONID" => RuleVariableType::Sessionid,
            "STATUS_LINE" => RuleVariableType::StatusLine,
            "STREAM_INPUT_BODY" => RuleVariableType::StreamInputBody,
            "STREAM_OUTPUT_BODY" => RuleVariableType::StreamOutputBody,
            "TIME" => RuleVariableType::Time,
            "TIME_DAY" => RuleVariableType::TimeDay,
            "TIME_EPOCH" => RuleVariableType::TimeEpoch,
            "TIME_HOUR" => RuleVariableType::TimeHour,
            "TIME_MIN" => RuleVariableType::TimeMin,
            "TIME_MON" => RuleVariableType::TimeMon,
            "TIME_SEC" => RuleVariableType::TimeSec,
            "TIME_WDAY" => RuleVariableType::TimeWday,
            "TIME_YEAR" => RuleVariableType::TimeYear,
            "TX" => RuleVariableType::Tx,
            "UNIQUE_ID" => RuleVariableType::UniqueId,
            "URLENCODED_ERROR" => RuleVariableType::UrlencodedError,
            "USERID" => RuleVariableType::Userid,
            "USERAGENT_IP" => RuleVariableType::UseragentIp,
            "WEBAPPID" => RuleVariableType::Webappid,
            "WEBSERVER_ERROR_LOG" => RuleVariableType::WebserverErrorLog,
            "XML" => RuleVariableType::Xml,
            _ => unimplemented!("directive not implemented")
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RuleVariable {
    pub count: bool,
    pub variable_type: RuleVariableType,
}

pub fn parse_variables(input: &str) -> IResult<&str, Vec<RuleVariable>> {
    context(
        "rule variables",
        separated_list0(tag("|"), parse_variable),
    )(input)
}

/// Parses a security rule variable.
/// Implementation note: the tags are put in reverse lexicographical order such that exact matches
/// are done, not greedy matches for variables that are a prefix of another variable.
pub fn parse_variable(input: &str) -> IResult<&str, RuleVariable> {
    context(
        "rule variable",
        tuple((
            opt(tag("&")),
            alt((
                alt((
                    tag("XML"),
                    tag("WEBSERVER_ERROR_LOG"),
                    tag("WEBAPPID"),
                    tag("USERAGENT_IP"),
                    tag("USERID"),
                    tag("URLENCODED_ERROR"),
                    tag("UNIQUE_ID"),
                    tag("TX"),
                    tag("TIME_YEAR"),
                    tag("TIME_WDAY"),
                    tag("TIME_SEC"),
                    tag("TIME_MON"),
                )),
                alt((
                    tag("TIME_MIN"),
                    tag("TIME_HOUR"),
                    tag("TIME_EPOCH"),
                    tag("TIME_DAY"),
                    tag("TIME"),
                    tag("STREAM_OUTPUT_BODY"),
                    tag("STREAM_INPUT_BODY"),
                    tag("STATUS_LINE"),
                    tag("SESSIONID"),
                    tag("SESSION"),
                    tag("SERVER_PORT"),
                    tag("SERVER_NAME"),
                )),
                alt((
                    tag("SERVER_ADDR"),
                    tag("SDBM_DELETE_ERROR"),
                    tag("SCRIPT_USERNAME"),
                    tag("SCRIPT_UID"),
                    tag("SCRIPT_MODE"),
                    tag("SCRIPT_GROUPNAME"),
                    tag("SCRIPT_GID"),
                    tag("SCRIPT_FILENAME"),
                    tag("SCRIPT_BASENAME"),
                    tag("RULE"),
                    tag("RESPONSE_STATUS"),
                    tag("RESPONSE_PROTOCOL"),
                )),
                alt((
                    tag("RESPONSE_HEADERS_NAMES"),
                    tag("RESPONSE_HEADERS"),
                    tag("RESPONSE_CONTENT_TYPE"),
                    tag("RESPONSE_CONTENT_LENGTH"),
                    tag("RESPONSE_BODY"),
                    tag("REQUEST_URI_RAW"),
                    tag("REQUEST_URI"),
                    tag("REQUEST_PROTOCOL"),
                    tag("REQUEST_METHOD"),
                    tag("REQUEST_LINE"),
                    tag("REQUEST_HEADERS_NAMES"),
                    tag("REQUEST_HEADERS"),
                )),
                alt((
                    tag("REQUEST_FILENAME"),
                    tag("REQUEST_COOKIES_NAMES"),
                    tag("REQUEST_COOKIES"),
                    tag("REQUEST_BODY_LENGTH"),
                    tag("REQUEST_BODY"),
                    tag("REQUEST_BASENAME"),
                    tag("REQBODY_PROCESSOR"),
                    tag("REQBODY_ERROR_MSG"),
                    tag("REQBODY_ERROR"),
                    tag("REMOTE_USER"),
                    tag("REMOTE_PORT"),
                    tag("REMOTE_HOST"),
                )),
                alt((
                    tag("REMOTE_ADDR"),
                    tag("QUERY_STRING"),
                    tag("PERF_SWRITE"),
                    tag("PERF_SREAD"),
                    tag("PERF_RULES"),
                    tag("PERF_PHASE5"),
                    tag("PERF_PHASE4"),
                    tag("PERF_PHASE3"),
                    tag("PERF_PHASE2"),
                    tag("PERF_PHASE1"),
                    tag("PERF_LOGGING"),
                    tag("PERF_GC"),
                )),
                alt((
                    tag("PERF_COMBINED"),
                    tag("PERF_ALL"),
                    tag("PATH_INFO"),
                    tag("OUTBOUND_DATA_ERROR"),
                    tag("MULTIPART_UNMATCHED_BOUNDARY"),
                    tag("MULTIPART_STRICT_ERROR"),
                    tag("MULTIPART_NAME"),
                    tag("MULTIPART_FILENAME"),
                    tag("MULTIPART_CRLF_LF_LINES"),
                    tag("MODSEC_BUILD"),
                    tag("MATCHED_VARS_NAMES"),
                    tag("MATCHED_VAR_NAME"),
                )),
                alt((
                    tag("MATCHED_VARS"),
                    tag("MATCHED_VAR"),
                    tag("INBOUND_DATA_ERROR"),
                    tag("HIGHEST_SEVERITY"),
                    tag("GEO"),
                    tag("FILES_TMP_CONTENT"),
                    tag("FILES_TMPNAMES"),
                    tag("FILES_SIZES"),
                    tag("FULL_REQUEST_LENGTH"),
                    tag("FULL_REQUEST"),
                    tag("FILES_NAMES"),
                    tag("FILES_COMBINED_SIZE"),
                )),
                alt((
                    tag("FILES"),
                    tag("ENV"),
                    tag("DURATION"),
                    tag("AUTH_TYPE"),
                    tag("ARGS_POST_NAMES"),
                    tag("ARGS_POST"),
                    tag("ARGS_NAMES"),
                    tag("ARGS_GET_NAMES"),
                    tag("ARGS_GET"),
                    tag("ARGS_COMBINED_SIZE"),
                    tag("ARGS"),
                )),
            )),
        )),
    )(input).map(|(next_input, result)| {
        let (count, variable_type) = result;
        (next_input, RuleVariable {
            count: match count {
                Some("&") => true,
                _ => false,
            },
            variable_type: variable_type.into(),
        })
    })
}

#[cfg(test)]
mod tests {
    use strum::VariantNames;
    use crate::rules_parser::rule_variable::{RuleVariable, RuleVariableType, parse_variable, parse_variables};

    #[test]
    fn rule_variable_enum_names_should_match_shouty_snake_case() {
        assert_eq!(RuleVariableType::VARIANTS, ["ARGS", "ARGS_COMBINED_SIZE", "ARGS_GET", "ARGS_GET_NAMES",
            "ARGS_NAMES", "ARGS_POST", "ARGS_POST_NAMES", "AUTH_TYPE", "DURATION", "ENV", "FILES",
            "FILES_COMBINED_SIZE", "FILES_NAMES", "FULL_REQUEST", "FULL_REQUEST_LENGTH", "FILES_SIZES",
            "FILES_TMPNAMES", "FILES_TMP_CONTENT", "GEO", "HIGHEST_SEVERITY", "INBOUND_DATA_ERROR",
            "MATCHED_VAR", "MATCHED_VARS", "MATCHED_VAR_NAME", "MATCHED_VARS_NAMES", "MODSEC_BUILD",
            "MULTIPART_CRLF_LF_LINES", "MULTIPART_FILENAME", "MULTIPART_NAME", "MULTIPART_STRICT_ERROR",
            "MULTIPART_UNMATCHED_BOUNDARY", "OUTBOUND_DATA_ERROR", "PATH_INFO", "PERF_ALL",
            "PERF_COMBINED", "PERF_GC", "PERF_LOGGING", "PERF_PHASE1", "PERF_PHASE2", "PERF_PHASE3",
            "PERF_PHASE4", "PERF_PHASE5", "PERF_RULES", "PERF_SREAD", "PERF_SWRITE", "QUERY_STRING",
            "REMOTE_ADDR", "REMOTE_HOST", "REMOTE_PORT", "REMOTE_USER", "REQBODY_ERROR",
            "REQBODY_ERROR_MSG", "REQBODY_PROCESSOR", "REQUEST_BASENAME", "REQUEST_BODY",
            "REQUEST_BODY_LENGTH", "REQUEST_COOKIES", "REQUEST_COOKIES_NAMES",
            "REQUEST_FILENAME", "REQUEST_HEADERS", "REQUEST_HEADERS_NAMES", "REQUEST_LINE",
            "REQUEST_METHOD", "REQUEST_PROTOCOL", "REQUEST_URI", "REQUEST_URI_RAW", "RESPONSE_BODY",
            "RESPONSE_CONTENT_LENGTH", "RESPONSE_CONTENT_TYPE", "RESPONSE_HEADERS",
            "RESPONSE_HEADERS_NAMES", "RESPONSE_PROTOCOL", "RESPONSE_STATUS", "RULE",
            "SCRIPT_BASENAME", "SCRIPT_FILENAME", "SCRIPT_GID", "SCRIPT_GROUPNAME",
            "SCRIPT_MODE", "SCRIPT_UID", "SCRIPT_USERNAME", "SDBM_DELETE_ERROR", "SERVER_ADDR",
            "SERVER_NAME", "SERVER_PORT", "SESSION", "SESSIONID", "STATUS_LINE", "STREAM_INPUT_BODY",
            "STREAM_OUTPUT_BODY", "TIME", "TIME_DAY", "TIME_EPOCH", "TIME_HOUR",
            "TIME_MIN", "TIME_MON", "TIME_SEC", "TIME_WDAY", "TIME_YEAR", "TX",
            "UNIQUE_ID", "URLENCODED_ERROR", "USERID", "USERAGENT_IP", "WEBAPPID",
            "WEBSERVER_ERROR_LOG", "XML"
        ]);
    }


    #[test]
    fn parse_variables_should_parse_one_variable() {
        assert_eq!(RuleVariable {
            count: false,
            variable_type: RuleVariableType::Args,
        }, parse_variable("ARGS").unwrap().1);
        assert_eq!(RuleVariable {
            count: false,
            variable_type: RuleVariableType::ArgsPostNames,
        }, parse_variable("ARGS_POST_NAMES").unwrap().1);

        assert_eq!(RuleVariable {
            count: false,
            variable_type: RuleVariableType::ResponseBody,
        }, parse_variable("RESPONSE_BODY").unwrap().1);
        assert_eq!(RuleVariable {
            count: false,
            variable_type: RuleVariableType::ResponseContentLength,
        }, parse_variable("RESPONSE_CONTENT_LENGTH").unwrap().1);
        assert_eq!(RuleVariable {
            count: false,
            variable_type: RuleVariableType::ResponseContentType,
        }, parse_variable("RESPONSE_CONTENT_TYPE").unwrap().1);
        assert_eq!(RuleVariable {
            count: false,
            variable_type: RuleVariableType::ResponseHeaders,
        }, parse_variable("RESPONSE_HEADERS").unwrap().1);
        assert_eq!(RuleVariable {
            count: false,
            variable_type: RuleVariableType::ResponseHeadersNames,
        },
                   parse_variable("RESPONSE_HEADERS_NAMES").unwrap().1);
        assert_eq!(RuleVariable {
            count: false,
            variable_type: RuleVariableType::ResponseProtocol,
        }, parse_variable("RESPONSE_PROTOCOL").unwrap().1);
        assert_eq!(RuleVariable {
            count: false,
            variable_type: RuleVariableType::ResponseStatus,
        }, parse_variable("RESPONSE_STATUS").unwrap().1);

        assert_eq!(RuleVariable {
            count: false,
            variable_type: RuleVariableType::Time,
        }, parse_variable("TIME").unwrap().1);
        assert_eq!(RuleVariable {
            count: false,
            variable_type: RuleVariableType::TimeDay,
        }, parse_variable("TIME_DAY").unwrap().1);
    }

    #[test]
    fn parse_variables_should_parse_multiple_variables() {
        assert_eq!(vec![
            RuleVariable {
                count: false,
                variable_type: RuleVariableType::RequestUri,
            }, RuleVariable {
                count: false,
                variable_type: RuleVariableType::RequestProtocol,
            },
        ], parse_variables("REQUEST_URI|REQUEST_PROTOCOL").unwrap().1);
        assert_eq!(vec![
            RuleVariable {
                count: false,
                variable_type: RuleVariableType::Args,
            },
            RuleVariable {
                count: false,
                variable_type: RuleVariableType::ArgsPostNames,
            }, ], parse_variables("ARGS|ARGS_POST_NAMES").unwrap().1);
    }
}