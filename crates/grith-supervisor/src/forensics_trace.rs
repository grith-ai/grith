// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::interceptor::{SyscallEvent, SyscallKind};
use crate::process_tree::ProcessTree;
use grith_proxy::types::ToolCallType;

/// Structured subject extracted from a syscall or tool-call event.
///
/// Provides the typed fields the audit pipeline needs to classify findings
/// into remote-overlay-eligible vs bundled-change-required vs manual-review.
#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct TraceSubject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_canonical: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spawn_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spawn_argv: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_query_type: Option<String>,
}

impl TraceSubject {
    /// Extract subject from a raw syscall kind.
    pub(crate) fn from_syscall_kind(kind: &SyscallKind) -> Self {
        let mut s = Self::default();
        match kind {
            SyscallKind::FileOpen { path, flags } => {
                use crate::interceptor::OpenFlags;
                s.event_kind = Some(
                    if matches!(flags, OpenFlags::ReadOnly) {
                        "FileRead"
                    } else {
                        "FileWrite"
                    }
                    .into(),
                );
                s.path = Some(path.clone());
                s.path_canonical = std::fs::canonicalize(path)
                    .ok()
                    .and_then(|p| p.to_str().map(String::from));
            }
            SyscallKind::FileWrite { path, .. } => {
                s.event_kind = Some("FileWrite".into());
                if let Some(p) = path {
                    s.path = Some(p.clone());
                }
            }
            SyscallKind::FileRead { path, .. } => {
                s.event_kind = Some("FileRead".into());
                if let Some(p) = path {
                    s.path = Some(p.clone());
                }
            }
            SyscallKind::FileDelete { path } => {
                s.event_kind = Some("FileDelete".into());
                s.path = Some(path.clone());
            }
            SyscallKind::FileRename { old_path, new_path } => {
                s.event_kind = Some("FileRename".into());
                s.path = Some(old_path.clone());
                s.path_canonical = Some(new_path.clone());
            }
            SyscallKind::FileChmod { path, .. } => {
                s.event_kind = Some("FileChmod".into());
                s.path = Some(path.clone());
            }
            SyscallKind::DirCreate { path, .. } => {
                s.event_kind = Some("DirCreate".into());
                s.path = Some(path.clone());
            }
            SyscallKind::DirList { path } => {
                s.event_kind = Some("DirList".into());
                s.path = Some(path.clone());
            }
            SyscallKind::ProcessExec { path, args } => {
                s.event_kind = Some("ProcessSpawn".into());
                s.spawn_path = Some(path.clone());
                s.spawn_argv = Some(args.clone());
            }
            SyscallKind::NetConnect { address, port, .. } => {
                s.event_kind = Some("NetConnect".into());
                s.address = Some(address.clone());
                s.port = Some(*port);
            }
            SyscallKind::NetBind { address, port, .. } => {
                s.event_kind = Some("NetListen".into());
                s.listen_address = Some(address.clone());
                s.listen_port = Some(*port);
            }
            SyscallKind::NetSendTo { address, port } => {
                s.event_kind = Some("NetConnect".into());
                s.address = Some(address.clone());
                s.port = Some(*port);
            }
            _ => {}
        }
        s
    }

    /// Extract subject from a proxy ToolCallType.
    pub(crate) fn from_tool_call_type(tct: &ToolCallType) -> Self {
        let mut s = Self::default();
        match tct {
            ToolCallType::FileRead { path } => {
                s.event_kind = Some("FileRead".into());
                s.path = Some(path.clone());
            }
            ToolCallType::FileWrite { path, .. } => {
                s.event_kind = Some("FileWrite".into());
                s.path = Some(path.clone());
            }
            ToolCallType::FileAppend { path } => {
                s.event_kind = Some("FileWrite".into());
                s.path = Some(path.clone());
            }
            ToolCallType::FileDelete { path } => {
                s.event_kind = Some("FileDelete".into());
                s.path = Some(path.clone());
            }
            ToolCallType::FileRename {
                old_path, new_path, ..
            } => {
                s.event_kind = Some("FileRename".into());
                s.path = Some(old_path.clone());
                s.path_canonical = Some(new_path.clone());
            }
            ToolCallType::FileChmod { path, .. } => {
                s.event_kind = Some("FileChmod".into());
                s.path = Some(path.clone());
            }
            ToolCallType::DirCreate { path } => {
                s.event_kind = Some("DirCreate".into());
                s.path = Some(path.clone());
            }
            ToolCallType::DirList { path } => {
                s.event_kind = Some("DirList".into());
                s.path = Some(path.clone());
            }
            ToolCallType::ProcessSpawn { command, args } => {
                s.event_kind = Some("ProcessSpawn".into());
                s.spawn_path = Some(command.clone());
                s.spawn_argv = Some(args.clone());
            }
            ToolCallType::ShellExec { command, args } => {
                s.event_kind = Some("ProcessSpawn".into());
                s.spawn_path = Some(command.clone());
                s.spawn_argv = Some(args.clone());
            }
            ToolCallType::NetConnect { address, port } => {
                s.event_kind = Some("NetConnect".into());
                s.address = Some(address.clone());
                s.port = Some(*port);
            }
            ToolCallType::NetListen { address, port } => {
                s.event_kind = Some("NetListen".into());
                s.listen_address = Some(address.clone());
                s.listen_port = Some(*port);
            }
            ToolCallType::DnsQuery { domain, query_type } => {
                s.event_kind = Some("DnsQuery".into());
                s.dns_name = Some(domain.clone());
                s.dns_query_type = Some(query_type.clone());
            }
            ToolCallType::HttpRequest { url, .. } => {
                s.event_kind = Some("HttpRequest".into());
                s.address = Some(url.clone());
            }
            // PR 6 Phase B: category-2 syscalls.
            ToolCallType::OwnershipChange { target, .. } => {
                s.event_kind = Some("OwnershipChange".into());
                s.path = Some(target.clone());
            }
            ToolCallType::FilesystemMutation { target, .. } => {
                s.event_kind = Some("FilesystemMutation".into());
                s.path = Some(target.clone());
            }
            ToolCallType::CrossProcessAccess { .. } => {
                s.event_kind = Some("CrossProcessAccess".into());
            }
            ToolCallType::NamespaceOp { .. } => {
                s.event_kind = Some("NamespaceOp".into());
            }
        }
        s
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ForensicsTraceSink {
    writer: Arc<Mutex<std::io::BufWriter<std::fs::File>>>,
}

impl ForensicsTraceSink {
    pub(crate) fn new(path: &std::path::Path) -> crate::error::Result<Self> {
        let file = std::fs::File::create(path).map_err(|e| {
            crate::error::Error::ConfigError(format!(
                "failed to open forensics trace file '{}': {e}",
                path.display()
            ))
        })?;
        Ok(Self {
            writer: Arc::new(Mutex::new(std::io::BufWriter::new(file))),
        })
    }

    pub(crate) fn capture_syscall(
        &self,
        event_id: Uuid,
        session_id: Uuid,
        root_pid: u32,
        process_tree: &ProcessTree,
        event: &SyscallEvent,
    ) {
        let snapshot = ProcessSnapshot::capture(event.pid, process_tree);
        let subject = TraceSubject::from_syscall_kind(&event.kind);
        let record = ForensicsTraceRecord {
            event_id,
            timestamp: event.timestamp,
            session_id,
            root_pid,
            pid: event.pid,
            tid: event.tid,
            ppid: snapshot.ppid,
            stage: "captured",
            decision: None,
            score: None,
            decision_reason: None,
            raw_syscall_nr: event.raw_syscall_nr,
            raw_syscall_kind: format!("{:?}", event.kind),
            tool_call_type: None,
            exe_path: snapshot.exe_path,
            exe_canonical_path: snapshot.exe_canonical_path,
            argv: snapshot.argv,
            cwd: snapshot.cwd,
            comm: snapshot.comm,
            env: snapshot.env,
            subject,
        };
        self.write_record(&record);
    }

    pub(crate) fn record_stage(
        &self,
        event_id: Uuid,
        session_id: Uuid,
        root_pid: u32,
        process_tree: &ProcessTree,
        pid: u32,
        call_type: Option<&grith_proxy::types::ToolCallType>,
        stage: &'static str,
        decision: Option<&str>,
        score: Option<f64>,
        decision_reason: Option<&str>,
    ) {
        let snapshot = ProcessSnapshot::capture(pid, process_tree);
        let subject = call_type
            .map(TraceSubject::from_tool_call_type)
            .unwrap_or_default();
        let record = ForensicsTraceRecord {
            event_id,
            timestamp: Utc::now(),
            session_id,
            root_pid,
            pid,
            tid: pid,
            ppid: snapshot.ppid,
            stage,
            decision: decision.map(String::from),
            score,
            decision_reason: decision_reason.map(String::from),
            raw_syscall_nr: 0,
            raw_syscall_kind: String::new(),
            tool_call_type: call_type.map(|ct| ct.to_string()),
            exe_path: snapshot.exe_path,
            exe_canonical_path: snapshot.exe_canonical_path,
            argv: snapshot.argv,
            cwd: snapshot.cwd,
            comm: snapshot.comm,
            env: snapshot.env,
            subject,
        };
        self.write_record(&record);
    }

    pub(crate) fn capture_dns_query(
        &self,
        event_id: Uuid,
        session_id: Uuid,
        root_pid: u32,
        process_tree: &ProcessTree,
        pid: u32,
        call_type: &grith_proxy::types::ToolCallType,
    ) {
        self.record_stage(
            event_id,
            session_id,
            root_pid,
            process_tree,
            pid,
            Some(call_type),
            "captured",
            None,
            None,
            None,
        );
    }

    fn write_record(&self, record: &ForensicsTraceRecord) {
        if let Ok(mut writer) = self.writer.lock() {
            if let Ok(line) = serde_json::to_string(record) {
                let _ = writeln!(writer, "{line}");
                let _ = writer.flush();
            }
        }
    }
}

#[derive(Serialize)]
struct ForensicsTraceRecord {
    event_id: Uuid,
    timestamp: DateTime<Utc>,
    session_id: Uuid,
    root_pid: u32,
    pid: u32,
    tid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    ppid: Option<u32>,
    stage: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decision_reason: Option<String>,
    raw_syscall_nr: i64,
    raw_syscall_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exe_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exe_canonical_path: Option<String>,
    argv: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comm: Option<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    env: BTreeMap<String, String>,
    /// Structured subject fields for the audit pipeline.
    #[serde(flatten)]
    subject: TraceSubject,
}

struct ProcessSnapshot {
    ppid: Option<u32>,
    exe_path: Option<String>,
    exe_canonical_path: Option<String>,
    argv: Vec<String>,
    cwd: Option<String>,
    comm: Option<String>,
    env: BTreeMap<String, String>,
}

impl ProcessSnapshot {
    fn capture(pid: u32, process_tree: &ProcessTree) -> Self {
        let proc_info = process_tree.get(pid);
        let ppid = proc_info.map(|p| p.parent_pid).filter(|ppid| *ppid != 0);
        let argv = read_cmdline(pid)
            .or_else(|| proc_info.map(|p| p.args.clone()))
            .unwrap_or_default();
        let comm = proc_info.map(|p| p.command.clone());
        let exe_path = read_link(format!("/proc/{pid}/exe"));
        let exe_canonical_path = exe_path
            .as_ref()
            .and_then(|p| std::fs::canonicalize(p).ok())
            .and_then(|p| p.to_str().map(String::from));
        let cwd = read_link(format!("/proc/{pid}/cwd"));
        let env = read_selected_environ(pid);

        Self {
            ppid,
            exe_path,
            exe_canonical_path,
            argv,
            cwd,
            comm,
            env,
        }
    }
}

fn read_link(path: String) -> Option<String> {
    std::fs::read_link(path)
        .ok()
        .and_then(|p| p.to_str().map(String::from))
}

fn read_cmdline(pid: u32) -> Option<Vec<String>> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let args: Vec<String> = raw
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .filter_map(|s| std::str::from_utf8(s).ok().map(String::from))
        .collect();
    Some(args)
}

/// The allow-list of environment variable names captured in forensic traces.
/// Intentionally limited to avoid leaking secrets.
const ALLOWED_ENV_KEYS: &[&str] = &[
    "PATH",
    "HOME",
    "SSH_AUTH_SOCK",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
];

/// Prefix for additional captured env vars (e.g. CLAUDE_CODE_VERSION).
const ALLOWED_ENV_PREFIX: &str = "CLAUDE_";

fn read_selected_environ(pid: u32) -> BTreeMap<String, String> {
    let mut selected = BTreeMap::new();
    let Ok(raw) = std::fs::read(format!("/proc/{pid}/environ")) else {
        return selected;
    };

    for entry in raw.split(|b| *b == 0).filter(|s| !s.is_empty()) {
        let Ok(kv) = std::str::from_utf8(entry) else {
            continue;
        };
        let Some((key, value)) = kv.split_once('=') else {
            continue;
        };
        if ALLOWED_ENV_KEYS.contains(&key) || key.starts_with(ALLOWED_ENV_PREFIX) {
            selected.insert(key.to_string(), value.to_string());
        }
    }

    selected
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::NamedTempFile;

    #[test]
    fn test_trace_file_creation() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let sink = ForensicsTraceSink::new(&path);
        assert!(sink.is_ok(), "should create trace file: {sink:?}");
    }

    #[test]
    fn test_trace_file_fail_closed_on_bad_path() {
        let result = ForensicsTraceSink::new(std::path::Path::new(
            "/nonexistent-dir-grith-test/trace.jsonl",
        ));
        assert!(result.is_err(), "should fail on invalid path");
    }

    #[test]
    fn test_trace_record_serializes_as_jsonl() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let sink = ForensicsTraceSink::new(&path).unwrap();

        let record = ForensicsTraceRecord {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            session_id: Uuid::new_v4(),
            root_pid: 1000,
            pid: 1001,
            tid: 1001,
            ppid: Some(1000),
            stage: "captured",
            decision: None,
            score: None,
            decision_reason: None,
            raw_syscall_nr: 257,
            raw_syscall_kind: "FileOpen { path: \"/tmp/test\", flags: ReadOnly }".into(),
            tool_call_type: Some("FileRead(/tmp/test)".into()),
            exe_path: Some("/usr/bin/cat".into()),
            exe_canonical_path: Some("/usr/bin/cat".into()),
            argv: vec!["cat".into(), "/tmp/test".into()],
            cwd: Some("/home/user".into()),
            comm: Some("cat".into()),
            env: BTreeMap::new(),
            subject: TraceSubject::default(),
        };
        sink.write_record(&record);

        // Read back and verify it's valid JSON
        let mut content = String::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        let lines: Vec<&str> = content.trim().lines().collect();
        assert_eq!(lines.len(), 1, "should be exactly 1 JSONL line");

        let parsed: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed["stage"], "captured");
        assert_eq!(parsed["pid"], 1001);
        assert_eq!(parsed["ppid"], 1000);
        assert_eq!(parsed["root_pid"], 1000);
        assert!(parsed["event_id"].is_string());
        assert!(parsed["timestamp"].is_string());
        assert_eq!(parsed["exe_path"], "/usr/bin/cat");
        assert_eq!(parsed["argv"][0], "cat");
    }

    #[test]
    fn test_trace_record_stage_with_decision() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let sink = ForensicsTraceSink::new(&path).unwrap();

        let record = ForensicsTraceRecord {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            session_id: Uuid::new_v4(),
            root_pid: 100,
            pid: 101,
            tid: 101,
            ppid: Some(100),
            stage: "proxy_scored",
            decision: Some("deny".into()),
            score: Some(8.5),
            decision_reason: Some("ssh-private-key".into()),
            raw_syscall_nr: 0,
            raw_syscall_kind: String::new(),
            tool_call_type: Some("FileRead(/home/user/.ssh/id_rsa)".into()),
            exe_path: None,
            exe_canonical_path: None,
            argv: vec![],
            cwd: None,
            comm: None,
            env: BTreeMap::new(),
            subject: TraceSubject::default(),
        };
        sink.write_record(&record);

        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(parsed["stage"], "proxy_scored");
        assert_eq!(parsed["decision"], "deny");
        assert_eq!(parsed["score"], 8.5);
        assert_eq!(parsed["decision_reason"], "ssh-private-key");
    }

    #[test]
    fn test_trace_omits_empty_optional_fields() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let sink = ForensicsTraceSink::new(&path).unwrap();

        let record = ForensicsTraceRecord {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            session_id: Uuid::new_v4(),
            root_pid: 100,
            pid: 100,
            tid: 100,
            ppid: None,
            stage: "captured",
            decision: None,
            score: None,
            decision_reason: None,
            raw_syscall_nr: 59,
            raw_syscall_kind: "ProcessExec".into(),
            tool_call_type: None,
            exe_path: None,
            exe_canonical_path: None,
            argv: vec![],
            cwd: None,
            comm: None,
            env: BTreeMap::new(),
            subject: TraceSubject::default(),
        };
        sink.write_record(&record);

        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        // Optional fields should not appear in output
        assert!(parsed.get("ppid").is_none());
        assert!(parsed.get("decision").is_none());
        assert!(parsed.get("score").is_none());
        assert!(parsed.get("tool_call_type").is_none());
        assert!(parsed.get("exe_path").is_none());
        assert!(parsed.get("env").is_none()); // empty BTreeMap should be omitted
    }

    #[test]
    fn test_env_allowlist_only_captures_selected_keys() {
        // The allow list should be strict — no secrets like API keys
        assert!(ALLOWED_ENV_KEYS.contains(&"PATH"));
        assert!(ALLOWED_ENV_KEYS.contains(&"HOME"));
        assert!(ALLOWED_ENV_KEYS.contains(&"SSH_AUTH_SOCK"));
        assert!(ALLOWED_ENV_KEYS.contains(&"GIT_SSH"));
        assert!(ALLOWED_ENV_KEYS.contains(&"GIT_SSH_COMMAND"));
        // Should NOT include sensitive vars
        assert!(!ALLOWED_ENV_KEYS.contains(&"AWS_SECRET_ACCESS_KEY"));
        assert!(!ALLOWED_ENV_KEYS.contains(&"ANTHROPIC_API_KEY"));
        assert!(!ALLOWED_ENV_KEYS.contains(&"OPENAI_API_KEY"));
        // CLAUDE_ prefix is allowed
        assert!("CLAUDE_CODE_VERSION".starts_with(ALLOWED_ENV_PREFIX));
    }

    #[test]
    fn test_multiple_records_produce_valid_jsonl() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let sink = ForensicsTraceSink::new(&path).unwrap();

        for i in 0..5 {
            let record = ForensicsTraceRecord {
                event_id: Uuid::new_v4(),
                timestamp: Utc::now(),
                session_id: Uuid::new_v4(),
                root_pid: 100,
                pid: 100 + i,
                tid: 100 + i,
                ppid: Some(100),
                stage: "captured",
                decision: None,
                score: None,
                decision_reason: None,
                raw_syscall_nr: 257,
                raw_syscall_kind: "FileOpen".into(),
                tool_call_type: None,
                exe_path: None,
                exe_canonical_path: None,
                argv: vec![],
                cwd: None,
                comm: None,
                env: BTreeMap::new(),
                subject: TraceSubject::default(),
            };
            sink.write_record(&record);
        }

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.trim().lines().collect();
        assert_eq!(lines.len(), 5, "should have 5 JSONL lines");
        // Every line should be valid JSON
        for (i, line) in lines.iter().enumerate() {
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(line);
            assert!(parsed.is_ok(), "line {i} should be valid JSON: {line}");
        }
    }

    // ── TraceSubject extraction ───────────────────────────────────

    #[test]
    fn trace_subject_from_file_open_readonly() {
        use crate::interceptor::{OpenFlags, SyscallKind};
        let kind = SyscallKind::FileOpen {
            path: "/tmp/test.txt".into(),
            flags: OpenFlags::ReadOnly,
        };
        let subject = TraceSubject::from_syscall_kind(&kind);
        assert_eq!(subject.event_kind.as_deref(), Some("FileRead"));
        assert_eq!(subject.path.as_deref(), Some("/tmp/test.txt"));
        assert!(subject.address.is_none());
    }

    #[test]
    fn trace_subject_from_net_connect() {
        use crate::interceptor::{NetProtocol, SyscallKind};
        let kind = SyscallKind::NetConnect {
            address: "93.184.216.34".into(),
            port: 443,
            protocol: NetProtocol::Tcp,
        };
        let subject = TraceSubject::from_syscall_kind(&kind);
        assert_eq!(subject.event_kind.as_deref(), Some("NetConnect"));
        assert_eq!(subject.address.as_deref(), Some("93.184.216.34"));
        assert_eq!(subject.port, Some(443));
        assert!(subject.path.is_none());
    }

    #[test]
    fn trace_subject_from_process_exec() {
        use crate::interceptor::SyscallKind;
        let kind = SyscallKind::ProcessExec {
            path: "/usr/bin/git".into(),
            args: vec!["git".into(), "status".into()],
        };
        let subject = TraceSubject::from_syscall_kind(&kind);
        assert_eq!(subject.event_kind.as_deref(), Some("ProcessSpawn"));
        assert_eq!(subject.spawn_path.as_deref(), Some("/usr/bin/git"));
        assert_eq!(
            subject.spawn_argv,
            Some(vec!["git".to_string(), "status".to_string()])
        );
    }

    #[test]
    fn trace_subject_from_tool_call_type_dns() {
        let tct = ToolCallType::DnsQuery {
            domain: "example.com".into(),
            query_type: "A".into(),
        };
        let subject = TraceSubject::from_tool_call_type(&tct);
        assert_eq!(subject.event_kind.as_deref(), Some("DnsQuery"));
        assert_eq!(subject.dns_name.as_deref(), Some("example.com"));
        assert_eq!(subject.dns_query_type.as_deref(), Some("A"));
    }

    #[test]
    fn trace_subject_default_is_all_none() {
        let subject = TraceSubject::default();
        let json = serde_json::to_value(&subject).unwrap();
        // All fields should be absent (all None, all skip_serializing_if).
        assert!(json.as_object().unwrap().is_empty());
    }

    #[test]
    fn trace_subject_flattened_into_record() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let sink = ForensicsTraceSink::new(&path).unwrap();

        let record = ForensicsTraceRecord {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            session_id: Uuid::new_v4(),
            root_pid: 100,
            pid: 101,
            tid: 101,
            ppid: None,
            stage: "captured",
            decision: None,
            score: None,
            decision_reason: None,
            raw_syscall_nr: 257,
            raw_syscall_kind: "FileOpen".into(),
            tool_call_type: None,
            exe_path: None,
            exe_canonical_path: None,
            argv: vec![],
            cwd: None,
            comm: None,
            env: BTreeMap::new(),
            subject: TraceSubject {
                event_kind: Some("FileRead".into()),
                path: Some("/tmp/data.json".into()),
                ..Default::default()
            },
        };
        sink.write_record(&record);

        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        // Subject fields should appear at top level (flattened).
        assert_eq!(parsed["event_kind"], "FileRead");
        assert_eq!(parsed["path"], "/tmp/data.json");
        // Non-set subject fields should be absent.
        assert!(parsed.get("domain").is_none());
        assert!(parsed.get("address").is_none());
    }
}
