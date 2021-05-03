extern crate libinjection;

use libinjection::{sqli, xss};

#[test]
fn should_detect_sql_injection() {
    let (is_sql_injection, fingerprint) = sqli("' OR '1'='1' --").unwrap();
    assert!(is_sql_injection);
    assert_eq!("s&sos", fingerprint);
}

#[test]
fn should_detect_xss() {
    let is_xss = xss(r#"<script>alert("TEST");</script>"#);
    assert!(is_xss.unwrap());
}
