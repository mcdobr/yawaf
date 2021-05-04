use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::error::context;
use nom::IResult;

use strum_macros::{EnumVariantNames};
use strum::VariantNames;
use nom::multi::separated_list0;

#[derive(Clone, Debug, PartialEq, EnumVariantNames)]
#[strum(serialize_all = "shouty_snake_case")]
pub enum RuleVariable {
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
    FilesTempNames,
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

impl std::convert::From<&str> for RuleVariable {
    fn from(input: &str) -> Self {
        match input {
            "ARGS" => RuleVariable::Args,
            "ARGS_COMBINED_SIZE" => RuleVariable::ArgsCombinedSize,
            "ARGS_GET" => RuleVariable::ArgsGet,
            "ARGS_GET_NAMES" => RuleVariable::ArgsGetNames,
            "ARGS_NAMES" => RuleVariable::ArgsNames,
            "ARGS_POST" => RuleVariable::ArgsPost,
            "ARGS_POST_NAMES" => RuleVariable::ArgsPostNames,
            "AUTH_TYPE" => RuleVariable::AuthType,
            "DURATION" => RuleVariable::Duration,
            "ENV" => RuleVariable::Env,
            "FILES" => RuleVariable::Files,
            "FILES_COMBINED_SIZE" => RuleVariable::FilesCombinedSize,
            "FILES_NAMES" => RuleVariable::FilesNames,
            "FULL_REQUEST" => RuleVariable::FullRequest,
            "FULL_REQUEST_LENGTH" => RuleVariable::FullRequestLength,
            "FILES_SIZES" => RuleVariable::FilesSizes,
            "FILES_TMPNAMES" => RuleVariable::FilesTempNames,
            "FILES_TMP_CONTENT" => RuleVariable::FilesTmpContent,
            "GEO" => RuleVariable::Geo,
            "HIGHEST_SEVERITY" => RuleVariable::HighestSeverity,
            "INBOUND_DATA_ERROR" => RuleVariable::InboundDataError,
            "MATCHED_VAR" => RuleVariable::MatchedVar,
            "MATCHED_VARS" => RuleVariable::MatchedVars,
            "MATCHED_VAR_NAME" => RuleVariable::MatchedVarName,
            "MATCHED_VARS_NAMES" => RuleVariable::MatchedVarsNames,
            "MODSEC_BUILD" => RuleVariable::ModsecBuild,
            "MULTIPART_CRLF_LF_LINES" => RuleVariable::MultipartCrlfLfLines,
            "MULTIPART_FILENAME" => RuleVariable::MultipartFilename,
            "MULTIPART_NAME" => RuleVariable::MultipartName,
            "MULTIPART_STRICT_ERROR" => RuleVariable::MultipartStrictError,
            "MULTIPART_UNMATCHED_BOUNDARY" => RuleVariable::MultipartUnmatchedBoundary,
            "OUTBOUND_DATA_ERROR" => RuleVariable::OutboundDataError,
            "PATH_INFO" => RuleVariable::PathInfo,
            "PERF_ALL" => RuleVariable::PerfAll,
            "PERF_COMBINED" => RuleVariable::PerfCombined,
            "PERF_GC" => RuleVariable::PerfGc,
            "PERF_LOGGING" => RuleVariable::PerfLogging,
            "PERF_PHASE1" => RuleVariable::PerfPhase1,
            "PERF_PHASE2" => RuleVariable::PerfPhase2,
            "PERF_PHASE3" => RuleVariable::PerfPhase3,
            "PERF_PHASE4" => RuleVariable::PerfPhase4,
            "PERF_PHASE5" => RuleVariable::PerfPhase5,
            "PERF_RULES" => RuleVariable::PerfRules,
            "PERF_SREAD" => RuleVariable::PerfSread,
            "PERF_SWRITE" => RuleVariable::PerfSwrite,
            "QUERY_STRING" => RuleVariable::QueryString,
            "REMOTE_ADDR" => RuleVariable::RemoteAddr,
            "REMOTE_HOST" => RuleVariable::RemoteHost,
            "REMOTE_PORT" => RuleVariable::RemotePort,
            "REMOTE_USER" => RuleVariable::RemoteUser,
            "REQBODY_ERROR" => RuleVariable::ReqbodyError,
            "REQBODY_ERROR_MSG" => RuleVariable::ReqbodyErrorMsg,
            "REQBODY_PROCESSOR" => RuleVariable::ReqbodyProcessor,
            "REQUEST_BASENAME" => RuleVariable::RequestBasename,
            "REQUEST_BODY" => RuleVariable::RequestBody,
            "REQUEST_BODY_LENGTH" => RuleVariable::RequestBodyLength,
            "REQUEST_COOKIES" => RuleVariable::RequestCookies,
            "REQUEST_COOKIES_NAMES" => RuleVariable::RequestCookiesNames,
            "REQUEST_FILENAME" => RuleVariable::RequestFilename,
            "REQUEST_HEADERS" => RuleVariable::RequestHeaders,
            "REQUEST_HEADERS_NAMES" => RuleVariable::RequestHeadersNames,
            "REQUEST_LINE" => RuleVariable::RequestLine,
            "REQUEST_METHOD" => RuleVariable::RequestMethod,
            "REQUEST_PROTOCOL" => RuleVariable::RequestProtocol,
            "REQUEST_URI" => RuleVariable::RequestUri,
            "REQUEST_URI_RAW" => RuleVariable::RequestUriRaw,
            "RESPONSE_BODY" => RuleVariable::ResponseBody,
            "RESPONSE_CONTENT_LENGTH" => RuleVariable::ResponseContentLength,
            "RESPONSE_CONTENT_TYPE" => RuleVariable::ResponseContentType,
            "RESPONSE_HEADERS" => RuleVariable::ResponseHeaders,
            "RESPONSE_HEADERS_NAMES" => RuleVariable::ResponseHeadersNames,
            "RESPONSE_PROTOCOL" => RuleVariable::ResponseProtocol,
            "RESPONSE_STATUS" => RuleVariable::ResponseStatus,
            "RULE" => RuleVariable::Rule,
            "SCRIPT_BASENAME" => RuleVariable::ScriptBasename,
            "SCRIPT_FILENAME" => RuleVariable::ScriptFilename,
            "SCRIPT_GID" => RuleVariable::ScriptGid,
            "SCRIPT_GROUPNAME" => RuleVariable::ScriptGroupname,
            "SCRIPT_MODE" => RuleVariable::ScriptMode,
            "SCRIPT_UID" => RuleVariable::ScriptUid,
            "SCRIPT_USERNAME" => RuleVariable::ScriptUsername,
            "SDBM_DELETE_ERROR" => RuleVariable::SdbmDeleteError,
            "SERVER_ADDR" => RuleVariable::ServerAddr,
            "SERVER_NAME" => RuleVariable::ServerName,
            "SERVER_PORT" => RuleVariable::ServerPort,
            "SESSION" => RuleVariable::Session,
            "SESSIONID" => RuleVariable::Sessionid,
            "STATUS_LINE" => RuleVariable::StatusLine,
            "STREAM_INPUT_BODY" => RuleVariable::StreamInputBody,
            "STREAM_OUTPUT_BODY" => RuleVariable::StreamOutputBody,
            "TIME" => RuleVariable::Time,
            "TIME_DAY" => RuleVariable::TimeDay,
            "TIME_EPOCH" => RuleVariable::TimeEpoch,
            "TIME_HOUR" => RuleVariable::TimeHour,
            "TIME_MIN" => RuleVariable::TimeMin,
            "TIME_MON" => RuleVariable::TimeMon,
            "TIME_SEC" => RuleVariable::TimeSec,
            "TIME_WDAY" => RuleVariable::TimeWday,
            "TIME_YEAR" => RuleVariable::TimeYear,
            "TX" => RuleVariable::Tx,
            "UNIQUE_ID" => RuleVariable::UniqueId,
            "URLENCODED_ERROR" => RuleVariable::UrlencodedError,
            "USERID" => RuleVariable::Userid,
            "USERAGENT_IP" => RuleVariable::UseragentIp,
            "WEBAPPID" => RuleVariable::Webappid,
            "WEBSERVER_ERROR_LOG" => RuleVariable::WebserverErrorLog,
            "XML" => RuleVariable::Xml,
            _ => unimplemented!("directive not implemented")
        }
    }
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
    )(input).map(|(next_input, result)| {
        (next_input, result.into())
    })
}

#[test]
fn rule_variable_enum_names_should_match_shouty_snake_case() {
    assert_eq!(RuleVariable::VARIANTS, ["ARGS", "ARGS_COMBINED_SIZE", "ARGS_GET", "ARGS_GET_NAMES",
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
    assert_eq!(RuleVariable::Args, parse_variable("ARGS").unwrap().1);
    assert_eq!(RuleVariable::ArgsPostNames,
               parse_variable("ARGS_POST_NAMES").unwrap().1);

    assert_eq!(RuleVariable::ResponseBody, parse_variable("RESPONSE_BODY").unwrap().1);
    assert_eq!(RuleVariable::ResponseContentLength,
               parse_variable("RESPONSE_CONTENT_LENGTH").unwrap().1);
    assert_eq!(RuleVariable::ResponseContentType,
               parse_variable("RESPONSE_CONTENT_TYPE").unwrap().1);
    assert_eq!(RuleVariable::ResponseHeaders,
               parse_variable("RESPONSE_HEADERS").unwrap().1);
    assert_eq!(RuleVariable::ResponseHeadersNames,
               parse_variable("RESPONSE_HEADERS_NAMES").unwrap().1);
    assert_eq!(RuleVariable::ResponseProtocol,
               parse_variable("RESPONSE_PROTOCOL").unwrap().1);
    assert_eq!(RuleVariable::ResponseStatus,
               parse_variable("RESPONSE_STATUS").unwrap().1);

    assert_eq!(RuleVariable::Time, parse_variable("TIME").unwrap().1);
    assert_eq!(RuleVariable::TimeDay, parse_variable("TIME_DAY").unwrap().1);
}

#[test]
fn parse_variables_should_parse_multiple_variables() {
    assert_eq!(vec![RuleVariable::RequestUri, RuleVariable::RequestProtocol],
               parse_variables("REQUEST_URI|REQUEST_PROTOCOL").unwrap().1);
    assert_eq!(vec![RuleVariable::Args, RuleVariable::ArgsPostNames],
               parse_variables("ARGS|ARGS_POST_NAMES").unwrap().1);
}