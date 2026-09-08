use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use crate::engine::Analyzer;
use crate::request::NormalizedAnalysisRequest;
use fat_core::artifacts::ArtifactKind;
use fat_core::finding::{Finding, FindingSeverity, FindingSubject};
use fat_plugin_api::{
    AnalysisResult, AnalysisTrigger, AnalyzerClass, ArtifactInputRef, PluginDescriptor,
    PluginTrustTier,
};
use regex::Regex;

/// Maximum length of a matched snippet carried in finding titles/metadata.
const SNIPPET_MAX_CHARS: usize = 80;

/// Exact username/password combos that indicate unchanged factory defaults.
const DEFAULT_CREDENTIALS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("root", "root"),
    ("root", ""),
    ("support", "support"),
    ("user", "user"),
    ("1234", "1234"),
    ("administrator", "administrator"),
];

/// Bare lines that are unambiguous usernames even though they are common words.
const KNOWN_BARE_USERNAMES: &[&str] = &[
    "admin",
    "administrator",
    "root",
    "support",
    "user",
    "login",
    "username",
];

/// English words that frequently follow "password" in prose; they never look
/// like a credential value, so space-separated assignments with these values
/// are treated as documentation rather than secrets.
const PROSE_VALUE_STOPWORDS: &[&str] = &[
    "a", "all", "also", "an", "and", "any", "are", "as", "at", "be", "been", "both", "but", "by",
    "can", "cannot", "could", "default", "did", "do", "does", "done", "down", "during", "each",
    "else", "enter", "entered", "entering", "every", "example", "field", "fields", "file", "for",
    "from", "had", "has", "have", "here", "his", "how", "if", "in", "input", "into", "is", "it",
    "its", "line", "may", "might", "more", "most", "must", "name", "new", "no", "none", "not",
    "note", "of", "off", "old", "on", "one", "only", "optional", "or", "other", "our", "out",
    "over", "per", "please", "policy", "prompt", "prompts", "required", "same", "see", "set",
    "sets", "shall", "should", "since", "some", "string", "strings", "test", "than", "that", "the",
    "their", "them", "then", "there", "these", "they", "this", "to", "type", "typed", "under",
    "up", "use", "used", "user", "users", "using", "value", "values", "via", "was", "we", "were",
    "what", "when", "where", "which", "while", "who", "why", "will", "with", "would", "you",
    "your",
];

#[derive(Debug, Default)]
pub struct CredentialStaticAnalyzer;

/// Credential shapes this analyzer recognizes in static artifact text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CredentialCategory {
    PrivateKey,
    Certificate,
    AwsAccessKey,
    ApiKey,
    SecretToken,
    DefaultCredential,
    AdjacentPair,
    PasswordAssignment,
}

impl CredentialCategory {
    fn slug(self) -> &'static str {
        match self {
            Self::PrivateKey => "pem-private-key",
            Self::Certificate => "certificate",
            Self::AwsAccessKey => "aws-access-key",
            Self::ApiKey => "api-key",
            Self::SecretToken => "secret-token",
            Self::DefaultCredential => "default-credential",
            Self::AdjacentPair => "adjacent-credential-pair",
            Self::PasswordAssignment => "password-assignment",
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::PrivateKey => "PEM private key embedded in static artifact",
            Self::Certificate => "PEM certificate embedded in static artifact",
            Self::AwsAccessKey => "AWS access key id embedded in static artifact",
            Self::ApiKey => "API key assignment in static artifact",
            Self::SecretToken => "Secret or bearer token assignment in static artifact",
            Self::DefaultCredential => "Known default credential pair in static artifact",
            Self::AdjacentPair => "Adjacent username/password pair in static artifact",
            Self::PasswordAssignment => "Hardcoded password assignment in static artifact",
        }
    }

    fn severity(self) -> FindingSeverity {
        match self {
            Self::PrivateKey | Self::AwsAccessKey | Self::ApiKey | Self::DefaultCredential => {
                FindingSeverity::High
            }
            Self::Certificate
            | Self::SecretToken
            | Self::AdjacentPair
            | Self::PasswordAssignment => FindingSeverity::Medium,
        }
    }
}

struct CompiledPatterns {
    private_key: Regex,
    certificate: Regex,
    aws_access_key: Regex,
    api_key: Regex,
    secret_token: Regex,
    bearer_token: Regex,
    authorization_bearer: Regex,
    password_keyword: Regex,
    username_value: Regex,
}

fn patterns() -> &'static CompiledPatterns {
    static PATTERNS: LazyLock<CompiledPatterns> = LazyLock::new(|| {
        CompiledPatterns {
        private_key: Regex::new(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----")
            .expect("valid private key pattern"),
        certificate: Regex::new(r"-----BEGIN CERTIFICATE-----").expect("valid certificate pattern"),
        aws_access_key: Regex::new(r"AKIA[0-9A-Z]{16}").expect("valid AWS key pattern"),
        api_key: Regex::new(r#"(?i)api[_-]?key\s*[=:]\s*['"]?([A-Za-z0-9_-]{16,})"#)
            .expect("valid api key pattern"),
        secret_token: Regex::new(r#"(?i)secret[_-]?token\s*[=:]\s*['"]?([A-Za-z0-9_-]{16,})"#)
            .expect("valid secret token pattern"),
        bearer_token: Regex::new(r#"(?i)bearer[_-]?token\s*[=:]\s*['"]?([A-Za-z0-9_.-]{16,})"#)
            .expect("valid bearer token pattern"),
        authorization_bearer: Regex::new(
            r#"(?i)authorization\s*[=:]\s*bearer\s+['"]?([A-Za-z0-9_.-]{16,})"#,
        )
        .expect("valid authorization bearer pattern"),
        password_keyword: Regex::new(
            r"(?i)(?:^|[^A-Za-z0-9])(password|passwd|pwd|pass)[^A-Za-z0-9]",
        )
        .expect("valid password keyword pattern"),
        username_value: Regex::new(
            r#"(?i)\b(?:user(?:name)?|login|account|acct|email|usr)\s*[=:]\s*['"]?([A-Za-z0-9._@-]+)"#,
        )
        .expect("valid username pattern"),
    }
    });
    &PATTERNS
}

impl Analyzer for CredentialStaticAnalyzer {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor::new(
            "credential-static",
            "Credential Static",
            AnalyzerClass::Static,
            PluginTrustTier::FirstParty,
        )
        .with_supported_triggers(vec![AnalysisTrigger::AnalysisRequested])
        .with_supported_artifacts(vec![ArtifactInputRef::optional(ArtifactKind::Analysis)])
    }

    fn analyze(&self, request: &NormalizedAnalysisRequest) -> AnalysisResult {
        let mut findings = Vec::new();
        let mut ids_per_category: BTreeMap<CredentialCategory, usize> = BTreeMap::new();
        for artifact in &request.artifact_documents {
            let Some(text) = artifact.text_content.as_deref() else {
                continue;
            };
            let hits = scan_text(text);
            if hits.is_empty() {
                continue;
            }
            let rel_path = artifact
                .rel_path
                .clone()
                .unwrap_or_else(|| artifact.subkind.clone());
            for (category, values) in hits {
                let occurrence = ids_per_category.entry(category).or_insert(0);
                *occurrence += 1;
                let base = format!("credential-static-{}", category.slug());
                let id = if *occurrence == 1 {
                    base
                } else {
                    format!("{base}-{occurrence}")
                };
                let mut metadata = BTreeMap::new();
                metadata.insert("matches".to_string(), join_matches(&values));
                findings.push(
                    Finding::new(
                        id,
                        format!("{} ({})", category.title(), truncate_snippet(&rel_path)),
                        category.severity(),
                        FindingSubject::File {
                            rel_path: rel_path.clone(),
                        },
                    )
                    .with_plugin_id("credential-static")
                    .with_evidence_artifact_ids(vec![artifact.artifact_id.clone()])
                    .with_metadata(metadata),
                );
            }
        }
        AnalysisResult {
            findings,
            diagnostics: Vec::new(),
            produced_artifacts: Vec::new(),
            produced_artifact_ids: Vec::new(),
        }
    }
}

/// Scans artifact text for credential shapes, returning distinct matched
/// snippets per category so each category yields one deduplicated finding.
fn scan_text(text: &str) -> BTreeMap<CredentialCategory, BTreeSet<String>> {
    let mut hits: BTreeMap<CredentialCategory, BTreeSet<String>> = BTreeMap::new();
    let compiled = patterns();
    for matched in compiled.private_key.find_iter(text) {
        insert_match(&mut hits, CredentialCategory::PrivateKey, matched.as_str());
    }
    for matched in compiled.certificate.find_iter(text) {
        insert_match(&mut hits, CredentialCategory::Certificate, matched.as_str());
    }
    for matched in compiled.aws_access_key.find_iter(text) {
        insert_match(
            &mut hits,
            CredentialCategory::AwsAccessKey,
            matched.as_str(),
        );
    }
    for matched in compiled
        .secret_token
        .find_iter(text)
        .chain(compiled.bearer_token.find_iter(text))
        .chain(compiled.authorization_bearer.find_iter(text))
    {
        insert_match(&mut hits, CredentialCategory::SecretToken, matched.as_str());
    }
    // The API-key regex is its own High-severity category; keep it distinct.
    for matched in compiled.api_key.find_iter(text) {
        insert_match(&mut hits, CredentialCategory::ApiKey, matched.as_str());
    }
    scan_line_credentials(text, &mut hits);
    hits
}

fn insert_match(
    hits: &mut BTreeMap<CredentialCategory, BTreeSet<String>>,
    category: CredentialCategory,
    snippet: &str,
) {
    hits.entry(category)
        .or_default()
        .insert(truncate_snippet(snippet));
}

/// Line-oriented detection of password assignments, adjacent
/// username/password pairs, and known default credentials.
fn scan_line_credentials(text: &str, hits: &mut BTreeMap<CredentialCategory, BTreeSet<String>>) {
    let compiled = patterns();
    let lines: Vec<&str> = text.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        for keyword in compiled.password_keyword.captures_iter(line) {
            let rest = &line[keyword.get(1).expect("keyword group").end()..];
            let Some((raw_value, space_separated)) = parse_assignment_value(rest) else {
                continue;
            };
            if space_separated && is_prose_value(&raw_value) {
                continue;
            }
            let value = clean_value(&raw_value);
            let username =
                username_for_assignment(&lines, index, keyword.get(0).expect("match").start());
            if value.is_empty() {
                if let Some(user) = username {
                    if DEFAULT_CREDENTIALS.contains(&(user.as_str(), "")) {
                        insert_match(
                            hits,
                            CredentialCategory::DefaultCredential,
                            &format!("{user} / <empty password>"),
                        );
                    }
                }
                continue;
            }
            if let Some(user) = username {
                if DEFAULT_CREDENTIALS.contains(&(user.as_str(), value.as_str())) {
                    insert_match(
                        hits,
                        CredentialCategory::DefaultCredential,
                        &format!("{user} / {value}"),
                    );
                    continue;
                }
                insert_match(
                    hits,
                    CredentialCategory::AdjacentPair,
                    &format!("{user} / {value}"),
                );
            }
            insert_match(hits, CredentialCategory::PasswordAssignment, line.trim());
        }
    }
}

/// Parses the text following a password keyword into an assigned value.
/// Returns the raw value and whether it was space-separated rather than
/// attached with `=` or `:`.
fn parse_assignment_value(rest: &str) -> Option<(String, bool)> {
    let trimmed = rest.trim_start();
    if let Some(after) = trimmed.strip_prefix(['=', ':']) {
        return Some((after.trim().to_string(), false));
    }
    if trimmed.len() < rest.len() {
        let token = trimmed.split_whitespace().next()?;
        return Some((token.to_string(), true));
    }
    None
}

/// Space-separated values that are just English words are prose, not secrets.
fn is_prose_value(value: &str) -> bool {
    value.contains(['=', ':'])
        || PROSE_VALUE_STOPWORDS.contains(&value.to_ascii_lowercase().as_str())
}

fn clean_value(value: &str) -> String {
    value
        .trim_matches(|c| c == '"' || c == '\'')
        .trim_end_matches(['.', ',', ';'])
        .to_string()
}

/// Looks for a username on the same line (before the password keyword) or on
/// one of the two preceding lines.
fn username_for_assignment(lines: &[&str], index: usize, keyword_start: usize) -> Option<String> {
    username_from_line(&lines[index][..keyword_start]).or_else(|| {
        lines[..index]
            .iter()
            .rev()
            .take(2)
            .find_map(|line| username_from_line(line))
    })
}

fn username_from_line(line: &str) -> Option<String> {
    let compiled = patterns();
    if let Some(caps) = compiled.username_value.captures(line) {
        return Some(caps[1].to_string());
    }
    let bare = line.trim();
    if bare.is_empty()
        || bare.contains(char::is_whitespace)
        || !bare.starts_with(|c: char| c.is_ascii_alphanumeric())
        || !bare.ends_with(|c: char| c.is_ascii_alphanumeric())
        || !bare
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | '-'))
    {
        return None;
    }
    let lower = bare.to_ascii_lowercase();
    if KNOWN_BARE_USERNAMES.contains(&lower.as_str())
        || !PROSE_VALUE_STOPWORDS.contains(&lower.as_str())
    {
        return Some(bare.to_string());
    }
    None
}

fn truncate_snippet(snippet: &str) -> String {
    if snippet.chars().count() <= SNIPPET_MAX_CHARS {
        return snippet.to_string();
    }
    let truncated: String = snippet.chars().take(SNIPPET_MAX_CHARS).collect();
    format!("{truncated}…")
}

fn join_matches(values: &BTreeSet<String>) -> String {
    values
        .iter()
        .map(|value| truncate_snippet(value))
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::ArtifactDocument;
    use fat_plugin_api::{AnalysisTrigger, ArtifactScope};

    fn artifact_document(id: &str, rel_path: &str, text: &str) -> ArtifactDocument {
        ArtifactDocument::new(
            id,
            ArtifactKind::Analysis,
            ArtifactScope::Target,
            "text",
            Some(rel_path.to_string()),
            "text/plain",
            Some(text.to_string()),
        )
    }

    fn analyze_documents(documents: Vec<ArtifactDocument>) -> AnalysisResult {
        let request = NormalizedAnalysisRequest::new(
            AnalysisTrigger::AnalysisRequested,
            "project-test",
            "target-test",
        )
        .with_artifact_documents(documents);
        CredentialStaticAnalyzer.analyze(&request)
    }

    fn finding_ids(result: &AnalysisResult) -> Vec<&str> {
        result.findings.iter().map(|f| f.id.as_str()).collect()
    }

    #[test]
    fn pem_private_key_yields_single_high_finding() {
        let result = analyze_documents(vec![artifact_document(
            "art-key-1",
            "etc/dropbear/dropbear_rsa_host_key",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7nJb\n-----END RSA PRIVATE KEY-----\n",
        )]);
        assert_eq!(result.findings.len(), 1);
        let finding = &result.findings[0];
        assert_eq!(finding.id, "credential-static-pem-private-key");
        assert_eq!(finding.severity, FindingSeverity::High);
        assert_eq!(finding.plugin_id.as_deref(), Some("credential-static"));
        assert_eq!(finding.evidence_artifact_ids, vec!["art-key-1"]);
        assert!(matches!(
            &finding.subject,
            FindingSubject::File { rel_path } if rel_path == "etc/dropbear/dropbear_rsa_host_key"
        ));
    }

    #[test]
    fn default_credential_pair_detected_and_prose_only_password_is_quiet() {
        let default_cred = analyze_documents(vec![artifact_document(
            "art-cred-1",
            "etc/default.cfg",
            "admin\npassword: admin\n",
        )]);
        assert_eq!(default_cred.findings.len(), 1);
        assert_eq!(
            default_cred.findings[0].id,
            "credential-static-default-credential"
        );
        assert_eq!(default_cred.findings[0].severity, FindingSeverity::High);

        let adjacent = analyze_documents(vec![artifact_document(
            "art-cred-2",
            "etc/app.conf",
            "deploy\npassword: s3cret-value\n",
        )]);
        assert_eq!(
            finding_ids(&adjacent),
            vec![
                "credential-static-adjacent-credential-pair",
                "credential-static-password-assignment",
            ]
        );
        assert!(adjacent
            .findings
            .iter()
            .all(|f| f.severity == FindingSeverity::Medium));

        let clean = analyze_documents(vec![artifact_document(
            "art-plain-1",
            "README.txt",
            "The password policy requires rotation every 90 days. Passwords are stored in a vault.\n",
        )]);
        assert!(clean.findings.is_empty());
    }

    #[test]
    fn cloud_tokens_detected_and_identical_matches_deduplicated() {
        let text = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\nregion = us-east-1\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\napi_key = 'ABCDEFGHIJKLMNOPQR'\n";
        let result = analyze_documents(vec![artifact_document("art-cloud-1", "etc/aws.env", text)]);
        assert_eq!(
            finding_ids(&result),
            vec![
                "credential-static-aws-access-key",
                "credential-static-api-key",
            ]
        );
        assert_eq!(result.findings[0].severity, FindingSeverity::High);
        assert_eq!(result.findings[1].severity, FindingSeverity::High);
        assert!(result.findings[0].metadata.contains_key("matches"));
    }

    #[test]
    fn certificate_yields_medium_finding() {
        let result = analyze_documents(vec![artifact_document(
            "art-cert-1",
            "etc/cert.pem",
            "-----BEGIN CERTIFICATE-----\nMIIDdTCCAl2gAwIBAgIU\n-----END CERTIFICATE-----\n",
        )]);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].id, "credential-static-certificate");
        assert_eq!(result.findings[0].severity, FindingSeverity::Medium);
    }

    #[test]
    fn standalone_password_assignment_reports_single_medium_finding() {
        let result = analyze_documents(vec![artifact_document(
            "art-cred-3",
            "etc/config/system",
            "default_password=admin\n",
        )]);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(
            result.findings[0].id,
            "credential-static-password-assignment"
        );
        assert_eq!(result.findings[0].severity, FindingSeverity::Medium);
        assert_eq!(result.findings[0].evidence_artifact_ids, vec!["art-cred-3"]);
    }
}
