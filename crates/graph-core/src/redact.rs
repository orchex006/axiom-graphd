//! Redaction of credentials, source content and absolute paths (tasks B-002 and
//! B-007; contract docs/22-OPERATIONS-AND-TROUBLESHOOTING.md).
//!
//! Redaction is applied *before* a value reaches an error, log record or support
//! bundle, so raw values never reach a sink that can be exported. The default
//! policy excludes credentials, source bodies and absolute paths.
//!
//! Credential handling is deliberately conservative: once a sensitive key or a
//! bare credential marker (`Bearer`, `token`, `secret`, ...) is seen, the rest
//! of that line is replaced. Guessing where a credential ends is how secrets
//! leak, so the scrubber refuses to guess.

/// Replacement for a redacted secret, token or credential.
pub const REDACTED: &str = "[redacted]";
/// Replacement for a redacted absolute/local path.
pub const REDACTED_PATH: &str = "[path]";

/// Detail keys an error may carry.
///
/// This is an allowlist: an arbitrary key could carry source content or a
/// credential into a diagnostic payload, so unknown keys are dropped.
pub const ALLOWED_DETAIL_KEYS: &[&str] = &[
    "actual",
    "component",
    "config_key",
    "config_source",
    "expected",
    "file_count",
    "generation",
    "job_id",
    "limit",
    "migration_name",
    "migration_version",
    "observed",
    "portable_path",
    "project_id",
    "required_version",
    "retryable",
    "rule",
    "schema",
    "solution_id",
    "sqlite_version",
    "storage_class",
    "table",
    "version",
];

/// Keys whose value is a credential and must never be recorded.
const SENSITIVE_KEYS: &[&str] = &[
    "access_key",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "conn_str",
    "connection_string",
    "connectionstring",
    "cookie",
    "credential",
    "credentials",
    "passphrase",
    "passwd",
    "password",
    "private_key",
    "pwd",
    "secret",
    "session_key",
    "token",
];

/// Bare markers that introduce a credential value.
const CREDENTIAL_MARKERS: &[&str] = &["bearer", "basic"];

/// True when an error is allowed to record `key` in its details.
#[must_use]
pub fn is_allowed_detail_key(key: &str) -> bool {
    ALLOWED_DETAIL_KEYS
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(key))
}

fn is_sensitive_key(key: &str) -> bool {
    let key = key.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-');
    SENSITIVE_KEYS
        .iter()
        .any(|sensitive| sensitive.eq_ignore_ascii_case(key))
}

/// True when the token is an absolute, UNC, device or otherwise machine-local
/// path. Used for redaction only, never as a containment test (CP-03).
#[must_use]
pub fn looks_like_absolute_path(token: &str) -> bool {
    let bytes = token.as_bytes();
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
    {
        return true;
    }
    if token.starts_with("\\\\") || token.starts_with("//") {
        return true;
    }
    if token.starts_with('/') {
        let mut segments = token.split('/');
        let _leading = segments.next();
        if let (Some(first), Some(_second)) = (segments.next(), segments.next()) {
            return !first.is_empty();
        }
    }
    false
}

fn is_jwt_like(token: &str) -> bool {
    token.starts_with("eyJ") && token.matches('.').count() >= 2 && token.len() > 20
}

fn scrub_url_userinfo(token: &str) -> Option<String> {
    let scheme_end = token.find("://")?;
    let authority_start = scheme_end + 3;
    let rest = &token[authority_start..];
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let at = authority.find('@')?;
    let mut scrubbed = String::with_capacity(token.len());
    scrubbed.push_str(&token[..authority_start]);
    scrubbed.push_str(REDACTED);
    scrubbed.push_str(&authority[at..]);
    scrubbed.push_str(&rest[authority_end..]);
    Some(scrubbed)
}

fn is_credential_marker(token: &str) -> bool {
    let bare = token.trim_end_matches(':');
    is_sensitive_key(bare)
        || CREDENTIAL_MARKERS
            .iter()
            .any(|marker| marker.eq_ignore_ascii_case(bare))
}

/// Redact credentials and absolute paths from arbitrary diagnostic text.
///
/// Whitespace between tokens is preserved except that once a credential marker
/// is found the remainder of the line is replaced by [`REDACTED`].
#[must_use]
pub fn scrub(input: &str) -> String {
    if input.contains("PRIVATE KEY") {
        return REDACTED.to_string();
    }
    let mut out = String::with_capacity(input.len());
    let mut remainder = input;
    while !remainder.is_empty() {
        let split_at = remainder
            .find(char::is_whitespace)
            .unwrap_or(remainder.len());
        let token = &remainder[..split_at];

        if let Some(eq) = token.find('=') {
            let key = &token[..eq];
            if is_sensitive_key(key) {
                out.push_str(key);
                out.push_str("=[redacted]");
                remainder = &remainder[split_at..];
                let ws_end = remainder
                    .find(|c: char| !c.is_whitespace())
                    .unwrap_or(remainder.len());
                out.push_str(&remainder[..ws_end]);
                remainder = &remainder[ws_end..];
                continue;
            }
        }

        if is_credential_marker(token) {
            out.push_str(token);
            out.push(' ');
            out.push_str(REDACTED);
            return out;
        }

        if is_jwt_like(token) {
            out.push_str(REDACTED);
        } else if let Some(scrubbed) = scrub_url_userinfo(token) {
            out.push_str(&scrubbed);
        } else if looks_like_absolute_path(token) {
            out.push_str(REDACTED_PATH);
        } else {
            out.push_str(token);
        }

        remainder = &remainder[split_at..];
        let ws_end = remainder
            .find(|c: char| !c.is_whitespace())
            .unwrap_or(remainder.len());
        out.push_str(&remainder[..ws_end]);
        remainder = &remainder[ws_end..];
    }
    out
}

/// Scrub a value bound for a support bundle or exported evidence file.
#[must_use]
pub fn scrub_for_export(input: &str) -> String {
    scrub(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assignment_secrets_are_redacted() {
        assert_eq!(scrub("token=abc123"), "token=[redacted]");
        assert_eq!(scrub("api_key=abc123"), "api_key=[redacted]");
        assert_eq!(scrub("PASSWORD=hunter2"), "PASSWORD=[redacted]");
        assert_eq!(
            scrub("token=abc123 later prose"),
            "token=[redacted] later prose"
        );
        assert!(!scrub("token=abc123 later prose").contains("abc123"));
    }

    #[test]
    fn colon_form_drops_the_rest_of_the_line() {
        let scrubbed = scrub("connection_string: Server=x;Password=y");
        assert_eq!(scrubbed, "connection_string: [redacted]");
        assert!(!scrubbed.contains("Server=x"));
        assert!(!scrubbed.contains("Password=y"));
    }

    #[test]
    fn bearer_values_never_survive() {
        let scrubbed = scrub("Authorization: Bearer abc.def.ghi");
        assert_eq!(scrubbed, "Authorization: [redacted]");
        assert!(!scrubbed.contains("abc.def.ghi"));
        let bare = scrub("Bearer abcdef.ghijkl.mnopqr again");
        assert_eq!(bare, "Bearer [redacted]");
        assert!(!bare.contains("abcdef.ghijkl.mnopqr"));
    }

    #[test]
    fn credential_bearing_urls_are_redacted() {
        let scrubbed = scrub("https://user:pa55@example.test/graph");
        assert_eq!(scrubbed, "https://[redacted]@example.test/graph");
        assert!(!scrubbed.contains("pa55"));
    }

    #[test]
    fn absolute_paths_are_redacted() {
        assert_eq!(scrub(r"C:\Users\me\repo\src\a.cs"), REDACTED_PATH);
        assert_eq!(scrub("/home/me/repo/src/a.cs"), REDACTED_PATH);
        assert_eq!(scrub(r"\\server\share\a.cs"), REDACTED_PATH);
        assert_eq!(scrub("see /tmp/a/b here"), "see [path] here");
        // A single-segment slash token is not a machine path.
        assert_eq!(scrub("/health"), "/health");
    }

    #[test]
    fn jwt_and_pem_material_are_redacted() {
        assert_eq!(
            scrub("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"),
            REDACTED
        );
        let pem = "-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----";
        assert_eq!(scrub(pem), REDACTED);
    }

    #[test]
    fn thai_text_and_plain_words_survive() {
        let text = "ตรวจพบไฟล์ 3 ไฟล์ในโปรเจกต์ graph-core";
        assert_eq!(scrub(text), text);
    }

    #[test]
    fn scrubbing_is_idempotent() {
        let once = scrub("token=abc /home/me/x C:\\Users\\me\\y https://a:b@c.test/d");
        assert_eq!(scrub(&once), once);
        let marker = scrub("Authorization: Bearer zzz");
        assert_eq!(scrub(&marker), marker);
    }

    #[test]
    fn detail_key_allowlist_is_explicit() {
        assert!(is_allowed_detail_key("job_id"));
        assert!(is_allowed_detail_key("JOB_ID"));
        assert!(!is_allowed_detail_key("source_body"));
        assert!(!is_allowed_detail_key("token"));
        for key in ALLOWED_DETAIL_KEYS {
            assert!(
                !is_sensitive_key(key),
                "allowlisted key {key} looks sensitive"
            );
        }
    }
}
