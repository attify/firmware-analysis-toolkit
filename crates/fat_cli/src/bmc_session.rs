//! Bounded Redfish session/role experiment against an owned BMC runtime.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process::Command;

use fat_core::artifacts::ArtifactKind;
use fat_core::runs::RunStatus;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::debug_cmd::{load_context, write_runtime_json_artifact, DynResult};

const SESSIONS: &str = "/redfish/v1/SessionService/Sessions";
const ACCOUNTS: &str = "/redfish/v1/AccountService/Accounts";
const MANAGERS: &str = "/redfish/v1/Managers";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Credentials {
    username: String,
    password: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    admin: Credentials,
    reader: Credentials,
    reader_account: String,
    target_account: String,
    target_username: String,
}
impl Fixture {
    fn validate(&self) -> Result<(), String> {
        let names = [
            &self.admin.username,
            &self.reader.username,
            &self.target_username,
        ];
        if names.iter().any(|s| !component(s))
            || names[0] == names[1]
            || names[0] == names[2]
            || names[1] == names[2]
            || !resource_path(&self.reader_account, ACCOUNTS)
            || !resource_path(&self.target_account, ACCOUNTS)
            || self.reader_account == self.target_account
            || [&self.admin.password, &self.reader.password]
                .iter()
                .any(|p| p.is_empty() || p.len() > 1024)
        {
            return Err("fixture requires distinct admin, ReadOnly reader and disposable target accounts, direct account paths, and nonempty passwords".into());
        }
        Ok(())
    }
}

struct Response {
    status: u16,
    body: Value,
    token: Option<String>,
    location: Option<String>,
    etag: Option<String>,
}
trait Transport {
    fn request(
        &mut self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
        etag: Option<&str>,
    ) -> Result<Response, String>;
}
struct Session {
    token: String,
    path: String,
}
#[derive(Debug, Serialize)]
struct Check {
    step: String,
    status: Option<u16>,
    passed: bool,
    enabled: Option<bool>,
}
#[derive(Debug, Serialize)]
struct SessionReport {
    schema_version: &'static str,
    passed: bool,
    checks: Vec<Check>,
    failure: Option<String>,
    cleanup_passed: bool,
}
fn check(
    report: &mut SessionReport,
    name: &str,
    response: &Response,
    passed: bool,
) -> Result<(), String> {
    report.checks.push(Check {
        step: name.into(),
        status: Some(response.status),
        passed,
        enabled: response.body["Enabled"].as_bool(),
    });
    if passed {
        Ok(())
    } else {
        Err(format!("{name} failed"))
    }
}
fn request(
    t: &mut impl Transport,
    r: &mut SessionReport,
    name: &str,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&Value>,
    etag: Option<&str>,
) -> Result<Response, String> {
    t.request(method, path, token, body, etag).map_err(|_| {
        r.checks.push(Check {
            step: name.into(),
            status: None,
            passed: false,
            enabled: None,
        });
        format!("{name}: transport or response validation failed")
    })
}
fn login(
    t: &mut impl Transport,
    report: &mut SessionReport,
    name: &str,
    c: &Credentials,
    sessions: &mut Vec<Session>,
) -> Result<usize, String> {
    let response = match request(
        t,
        report,
        name,
        "POST",
        SESSIONS,
        None,
        Some(&json!({"UserName":c.username,"Password":c.password})),
        None,
    ) {
        Ok(response) => response,
        Err(error) => {
            report.cleanup_passed = false;
            return Err(error);
        }
    };
    // Register a safe cleanup handle before evaluating the response's user identity.
    let handle = response
        .token
        .as_ref()
        .zip(response.location.as_ref())
        .filter(|(token, path)| header_value(token) && resource_path(path, SESSIONS));
    let index = sessions.len();
    if let Some((token, path)) = handle {
        sessions.push(Session {
            token: token.clone(),
            path: path.clone(),
        });
    } else {
        report.cleanup_passed = false;
    }
    check(
        report,
        name,
        &response,
        response.status == 201 && handle.is_some() && response.body["UserName"] == c.username,
    )?;
    Ok(index)
}
fn account(response: &Response, username: &str) -> bool {
    response.status == 200
        && response.body["UserName"] == username
        && response.body["RoleId"] == "ReadOnly"
        && response.body["Enabled"].is_boolean()
}
fn account_unchanged(before: &Value, after: &Value) -> bool {
    [
        "UserName",
        "RoleId",
        "Enabled",
        "Locked",
        "PasswordChangeRequired",
    ]
    .iter()
    .all(|k| before[k] == after[k])
}
fn success(status: u16) -> bool {
    matches!(status, 200 | 204)
}

fn exercise(fixture: &Fixture, t: &mut impl Transport) -> SessionReport {
    let mut report = SessionReport {
        schema_version: "bmc-session/v1",
        passed: false,
        checks: vec![],
        failure: None,
        cleanup_passed: true,
    };
    let mut sessions = vec![];
    let mut before: Option<Value> = None;
    let mut mutation_attempted = false;
    let outcome = (|| -> Result<(), String> {
        fixture.validate()?;
        let admin = login(t, &mut report, "admin-login", &fixture.admin, &mut sessions)?;
        let reader_state = request(
            t,
            &mut report,
            "reader-precondition",
            "GET",
            &fixture.reader_account,
            Some(&sessions[admin].token),
            None,
            None,
        )?;
        check(
            &mut report,
            "reader-precondition",
            &reader_state,
            account(&reader_state, &fixture.reader.username)
                && reader_state.body["Enabled"] == true
                && reader_state.body["Locked"] != true
                && reader_state.body["PasswordChangeRequired"] != true,
        )?;
        let target = request(
            t,
            &mut report,
            "target-before",
            "GET",
            &fixture.target_account,
            Some(&sessions[admin].token),
            None,
            None,
        )?;
        check(
            &mut report,
            "target-before",
            &target,
            account(&target, &fixture.target_username) && target.body["Enabled"] == true,
        )?;
        before = Some(target.body.clone());
        let reader = login(
            t,
            &mut report,
            "reader-login",
            &fixture.reader,
            &mut sessions,
        )?;
        let anonymous = request(
            t,
            &mut report,
            "anonymous-read",
            "GET",
            MANAGERS,
            None,
            None,
            None,
        )?;
        check(
            &mut report,
            "anonymous-read",
            &anonymous,
            anonymous.status == 401,
        )?;
        let read = request(
            t,
            &mut report,
            "reader-read",
            "GET",
            MANAGERS,
            Some(&sessions[reader].token),
            None,
            None,
        )?;
        check(
            &mut report,
            "reader-read",
            &read,
            read.status == 200
                && read.body["@odata.id"]
                    .as_str()
                    .is_some_and(|v| v.trim_end_matches('/') == MANAGERS)
                && read.body["Members"].is_array(),
        )?;
        mutation_attempted = true;
        let denied = request(
            t,
            &mut report,
            "reader-forbidden-patch",
            "PATCH",
            &fixture.target_account,
            Some(&sessions[reader].token),
            Some(&json!({"Enabled":false})),
            target.etag.as_deref().or(Some("*")),
        )?;
        check(
            &mut report,
            "reader-forbidden-patch",
            &denied,
            denied.status == 403,
        )?;
        let unchanged = request(
            t,
            &mut report,
            "target-after-denial",
            "GET",
            &fixture.target_account,
            Some(&sessions[admin].token),
            None,
            None,
        )?;
        check(
            &mut report,
            "target-after-denial",
            &unchanged,
            unchanged.status == 200 && account_unchanged(&target.body, &unchanged.body),
        )?;
        let positive = request(
            t,
            &mut report,
            "admin-positive-patch",
            "PATCH",
            &fixture.target_account,
            Some(&sessions[admin].token),
            Some(&json!({"Enabled":false})),
            unchanged.etag.as_deref().or(Some("*")),
        )?;
        check(
            &mut report,
            "admin-positive-patch",
            &positive,
            success(positive.status),
        )?;
        let changed = request(
            t,
            &mut report,
            "target-after-admin",
            "GET",
            &fixture.target_account,
            Some(&sessions[admin].token),
            None,
            None,
        )?;
        check(
            &mut report,
            "target-after-admin",
            &changed,
            account(&changed, &fixture.target_username) && changed.body["Enabled"] == false,
        )?;
        let logout = request(
            t,
            &mut report,
            "reader-logout",
            "DELETE",
            &sessions[reader].path,
            Some(&sessions[reader].token),
            None,
            None,
        )?;
        check(
            &mut report,
            "reader-logout",
            &logout,
            success(logout.status),
        )?;
        let stale = request(
            t,
            &mut report,
            "stale-token-read",
            "GET",
            MANAGERS,
            Some(&sessions[reader].token),
            None,
            None,
        )?;
        check(&mut report, "stale-token-read", &stale, stale.status == 401)?;
        Ok(())
    })();
    report.failure = outcome.err();
    // Even a timed-out PATCH can have changed state: restore before deleting admin's session.
    if mutation_attempted {
        let restored = (|| -> Result<(), String> {
            let admin = sessions.first().ok_or("admin session missing")?;
            let current = request(
                t,
                &mut report,
                "cleanup-target-read",
                "GET",
                &fixture.target_account,
                Some(&admin.token),
                None,
                None,
            )?;
            check(
                &mut report,
                "cleanup-target-read",
                &current,
                account(&current, &fixture.target_username),
            )?;
            let restore = request(
                t,
                &mut report,
                "target-restore",
                "PATCH",
                &fixture.target_account,
                Some(&admin.token),
                Some(&json!({"Enabled":true})),
                current.etag.as_deref().or(Some("*")),
            )?;
            check(
                &mut report,
                "target-restore",
                &restore,
                success(restore.status),
            )?;
            let state = request(
                t,
                &mut report,
                "target-restored",
                "GET",
                &fixture.target_account,
                Some(&admin.token),
                None,
                None,
            )?;
            check(
                &mut report,
                "target-restored",
                &state,
                state.status == 200
                    && before
                        .as_ref()
                        .is_some_and(|b| account_unchanged(b, &state.body)),
            )
        })();
        if restored.is_err() {
            report.cleanup_passed = false;
        }
    }
    // Successful logout was already measured. Retry failed logout and all other created sessions.
    let reader_logged_out = report
        .checks
        .iter()
        .any(|c| c.step == "stale-token-read" && c.passed);
    for (i, session) in sessions.iter().enumerate().rev() {
        if i == 1 && reader_logged_out {
            continue;
        }
        let name = if i == 0 {
            "admin-cleanup"
        } else {
            "reader-cleanup"
        };
        match request(
            t,
            &mut report,
            name,
            "DELETE",
            &session.path,
            Some(&sessions[0].token),
            None,
            None,
        ) {
            Ok(response) => {
                if check(
                    &mut report,
                    name,
                    &response,
                    success(response.status) || response.status == 404,
                )
                .is_err()
                {
                    report.cleanup_passed = false;
                }
            }
            Err(_) => report.cleanup_passed = false,
        }
        let verify_name = format!("{name}-revocation");
        match request(
            t,
            &mut report,
            &verify_name,
            "GET",
            MANAGERS,
            Some(&session.token),
            None,
            None,
        ) {
            Ok(response) => {
                if check(&mut report, &verify_name, &response, response.status == 401).is_err() {
                    report.cleanup_passed = false;
                }
            }
            Err(_) => report.cleanup_passed = false,
        }
    }
    report.passed = report.failure.is_none() && report.cleanup_passed;
    report
}
fn component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}
fn resource_path(path: &str, collection: &str) -> bool {
    path.strip_prefix(collection)
        .and_then(|s| s.strip_prefix('/'))
        .is_some_and(component)
}
fn header_value(v: &str) -> bool {
    !v.is_empty() && v.len() <= 8192 && v.bytes().all(|b| (32..=126).contains(&b))
}

struct Curl {
    origin: String,
}
impl Transport for Curl {
    fn request(
        &mut self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
        etag: Option<&str>,
    ) -> Result<Response, String> {
        if !(path == SESSIONS
            || path == MANAGERS
            || resource_path(path, ACCOUNTS)
            || resource_path(path, SESSIONS))
        {
            return Err("unsupported resource path".into());
        }
        if token.into_iter().chain(etag).any(|v| !header_value(v)) {
            return Err("invalid header value".into());
        }
        let result = (|| -> DynResult<Response> {
            let mut request_headers = tempfile::NamedTempFile::new()?;
            writeln!(request_headers, "Content-Type: application/json")?;
            if let Some(token) = token {
                writeln!(request_headers, "X-Auth-Token: {token}")?;
            }
            if let Some(etag) = etag {
                writeln!(request_headers, "If-Match: {etag}")?;
            }
            let mut payload = tempfile::NamedTempFile::new()?;
            if let Some(body) = body {
                serde_json::to_writer(&mut payload, body)?;
            }
            let response_headers = tempfile::NamedTempFile::new()?;
            let response_body = tempfile::NamedTempFile::new()?;
            let mut command = Command::new("curl");
            command
                .args([
                    "-q",
                    "--silent",
                    "--insecure",
                    "--noproxy",
                    "*",
                    "--proto",
                    "=https",
                    "--connect-timeout",
                    "3",
                    "--max-time",
                    "20",
                    "--max-filesize",
                    "262144",
                    "--request",
                    method,
                    "--header",
                ])
                .arg(format!("@{}", request_headers.path().display()))
                .arg("--dump-header")
                .arg(response_headers.path())
                .arg("--output")
                .arg(response_body.path())
                .args(["--write-out", "%{http_code}"]);
            if body.is_some() {
                command
                    .arg("--data-binary")
                    .arg(format!("@{}", payload.path().display()));
            }
            let output = command.arg(format!("{}{path}", self.origin)).output()?;
            if !output.status.success() {
                return Err("HTTPS request failed".into());
            }
            let status = String::from_utf8(output.stdout)?.parse::<u16>()?;
            let headers = read_bounded(response_headers.path(), 65536)?;
            let header = |key: &str| -> Option<String> {
                String::from_utf8_lossy(&headers)
                    .lines()
                    .rev()
                    .find_map(|l| {
                        l.split_once(':')
                            .filter(|(k, _)| k.eq_ignore_ascii_case(key))
                            .map(|(_, v)| v.trim().to_string())
                    })
            };
            let bytes = read_bounded(response_body.path(), 262144)?;
            Ok(Response {
                status,
                body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
                token: header("X-Auth-Token"),
                location: header("Location"),
                etag: header("ETag"),
            })
        })();
        result.map_err(|_| "HTTPS request or response validation failed".into())
    }
}
fn read_bounded(path: &Path, limit: u64) -> DynResult<Vec<u8>> {
    let mut bytes = vec![];
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err("file exceeds size limit".into());
    }
    Ok(bytes)
}
pub fn run(
    project: &Path,
    session_id: Option<&str>,
    fixture_path: &Path,
    allow_mutation: bool,
    json_output: bool,
) -> DynResult<()> {
    if !allow_mutation {
        return Err("this experiment temporarily disables the disposable target account; pass --allow-account-mutation".into());
    }
    let fixture: Fixture = serde_json::from_slice(&read_bounded(fixture_path, 65536)?)
        .map_err(|_| "invalid credentials fixture JSON")?;
    fixture.validate()?;
    let context = load_context(project, session_id)?;
    if context.view.run.status != RunStatus::Running
        || context.view.run.backend_driver != "qemu-direct"
    {
        return Err("requires a running native BMC session".into());
    }
    let endpoint = context
        .view
        .run
        .active_endpoints
        .iter()
        .find(|e| e.name == "bmc-redfish" && e.host == "127.0.0.1" && e.target_port == Some(443))
        .ok_or("active BMC HTTPS endpoint is unavailable")?;
    let origin = format!("https://127.0.0.1:{}", endpoint.port);
    let report = exercise(
        &fixture,
        &mut Curl {
            origin: origin.clone(),
        },
    );
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let artifact = json!({"session_id":context.view.session.session_id,"run_id":context.view.run.run_id,"origin":origin,"checked_at_unix":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),"tls_certificate_verified":false,"accounts":{"reader":fixture.reader_account,"target":fixture.target_account,"reader_username":fixture.reader.username,"target_username":fixture.target_username},"scope":"ReadOnly cross-account Enabled mutation and session lifecycle","result":report});
    let text = serde_json::to_string_pretty(&artifact)?;
    write_runtime_json_artifact(
        &context.store,
        &context.project,
        &context.view.session.session_id,
        &context.view.run.run_id,
        ArtifactKind::RuntimeDebug,
        &format!("bmc-session-report-{stamp}"),
        "fat debug redfish-session",
        "Redfish session and role experiment",
        "debug",
        &context.view.run.backend_driver,
        context.view.run.substrate_kind,
        &text,
    )?;
    if json_output {
        println!("{text}");
    } else {
        for check in &report.checks {
            println!(
                "{}: {} (HTTP {})",
                check.step,
                if check.passed { "pass" } else { "FAIL" },
                check.status.map_or("unavailable".into(), |v| v.to_string())
            );
        }
        println!(
            "target/session cleanup: {}",
            if report.cleanup_passed {
                "pass"
            } else {
                "FAILED — inspect the guest before continuing"
            }
        );
    }
    if report.passed {
        Ok(())
    } else {
        Err("Redfish session/role experiment failed; see bmc-session-report artifact".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct Fake {
        enabled: bool,
        expired: bool,
        deny: bool,
        stale_accepted: bool,
        fail_positive_read: bool,
        changed: bool,
        uncertain_login: bool,
        unsafe_session_location: bool,
        deleted: Vec<String>,
        requests: Vec<(String, String)>,
    }
    impl Default for Fake {
        fn default() -> Self {
            Self {
                enabled: true,
                expired: false,
                deny: true,
                stale_accepted: false,
                fail_positive_read: false,
                changed: false,
                uncertain_login: false,
                unsafe_session_location: false,
                deleted: vec![],
                requests: vec![],
            }
        }
    }
    impl Transport for Fake {
        fn request(
            &mut self,
            method: &str,
            path: &str,
            token: Option<&str>,
            body: Option<&serde_json::Value>,
            _etag: Option<&str>,
        ) -> Result<Response, String> {
            self.requests.push((method.into(), path.into()));
            let mut response = Response {
                status: 200,
                body: json!({}),
                token: None,
                location: None,
                etag: Some("\"version\"".into()),
            };
            if method == "POST" {
                if self.uncertain_login {
                    return Err("response lost after creating session".into());
                }
                let user = body.unwrap()["UserName"].as_str().unwrap();
                response.status = 201;
                response.token = Some(format!("SECRET-{user}"));
                response.location = Some(format!("{SESSIONS}/{user}"));
                if self.unsafe_session_location {
                    response.location = Some("https://other-host/session/1".into());
                }
                response.body = json!({"UserName":user});
            } else if method == "DELETE" {
                self.deleted.push(path.into());
                response.status = 204;
            } else if path == MANAGERS {
                response.status = if self.expired && token == Some("SECRET-reader") {
                    403
                } else if token.is_none()
                    || (!self.stale_accepted
                        && token.is_some_and(|token| {
                            self.deleted.iter().any(|p| {
                                p == &format!(
                                    "{SESSIONS}/{}",
                                    token.strip_prefix("SECRET-").unwrap_or("")
                                )
                            })
                        }))
                {
                    401
                } else {
                    200
                };
                response.body = json!({"@odata.id":MANAGERS,"Members":[]});
            } else if path.ends_with("/reader") {
                response.body = json!({"UserName":"reader","RoleId":"ReadOnly","Enabled":true,"Locked":false,"PasswordChangeRequired":self.expired});
            } else if method == "PATCH" {
                if token == Some("SECRET-reader") && self.deny {
                    response.status = 403;
                } else {
                    self.enabled = body.unwrap()["Enabled"].as_bool().unwrap();
                    self.changed = true;
                    response.status = 204;
                }
            } else {
                if self.fail_positive_read && self.changed && !self.enabled {
                    self.fail_positive_read = false;
                    return Err("transport failed".into());
                }
                response.body = json!({"UserName":"target","RoleId":"ReadOnly","Enabled":self.enabled,"Locked":false});
            }
            Ok(response)
        }
    }
    fn fixture() -> Fixture {
        serde_json::from_value(json!({
            "admin":{"username":"admin","password":"ADMIN-PASSWORD"},
            "reader":{"username":"reader","password":"READER-PASSWORD"},
            "reader_account":"/redfish/v1/AccountService/Accounts/reader",
            "target_account":"/redfish/v1/AccountService/Accounts/target",
            "target_username":"target"
        }))
        .unwrap()
    }
    #[test]
    fn lifecycle_requires_denial_state_positive_control_and_revocation() {
        let mut fake = Fake::default();
        let report = exercise(&fixture(), &mut fake);
        assert!(report.passed, "{report:?}");
        assert!(fake.enabled);
        assert_eq!(fake.deleted.len(), 2);
        let text = serde_json::to_string(&report).unwrap();
        for secret in ["SECRET-", "ADMIN-PASSWORD", "READER-PASSWORD"] {
            assert!(!text.contains(secret));
        }
    }
    #[test]
    fn password_change_gate_does_not_pass_as_role_denial() {
        let mut fake = Fake {
            expired: true,
            ..Fake::default()
        };
        assert!(!exercise(&fixture(), &mut fake).passed);
        assert!(!fake.requests.iter().any(|(m, _)| m == "PATCH"));
        assert_eq!(fake.deleted.len(), 1);
    }
    #[test]
    fn forbidden_change_is_failure_and_restored() {
        let mut fake = Fake {
            deny: false,
            ..Fake::default()
        };
        assert!(!exercise(&fixture(), &mut fake).passed);
        assert!(fake.enabled);
        assert_eq!(fake.deleted.len(), 2);
    }
    #[test]
    fn transport_error_after_mutation_still_restores_and_logs_out() {
        let mut fake = Fake {
            fail_positive_read: true,
            ..Fake::default()
        };
        assert!(!exercise(&fixture(), &mut fake).passed);
        assert!(fake.enabled);
        assert_eq!(fake.deleted.len(), 2);
    }
    #[test]
    fn accepting_old_token_is_failure() {
        let mut fake = Fake {
            stale_accepted: true,
            ..Fake::default()
        };
        let report = exercise(&fixture(), &mut fake);
        assert!(!report.passed);
        assert!(!report.cleanup_passed);
    }
    #[test]
    fn unknown_or_unsafe_session_handle_cannot_claim_cleanup() {
        for mut fake in [
            Fake {
                uncertain_login: true,
                ..Fake::default()
            },
            Fake {
                unsafe_session_location: true,
                ..Fake::default()
            },
        ] {
            let report = exercise(&fixture(), &mut fake);
            assert!(!report.passed);
            assert!(!report.cleanup_passed);
            assert!(fake.deleted.is_empty());
            assert!(!fake.requests.iter().any(|(m, _)| m == "PATCH"));
        }
    }
    #[test]
    fn only_direct_resource_paths_are_accepted() {
        for p in [
            "https://evil/redfish/v1/SessionService/Sessions/a",
            "//evil/a",
            "/redfish/v1/SessionService/Sessions/../a",
            "/redfish/v1/SessionService/Sessions/a?x=1",
            "/redfish/v1/SessionService/Sessions/a%2fb",
            "/redfish/v1/SessionService/Sessions/a\r\nX:b",
        ] {
            assert!(!resource_path(p, SESSIONS), "{p}");
        }
        assert!(resource_path(
            "/redfish/v1/SessionService/Sessions/a_B-12",
            SESSIONS
        ));
    }
}
