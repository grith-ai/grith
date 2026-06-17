// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Supervisor integration tests.
//!
//! Tests the supervisor subsystem's interaction with the security proxy,
//! including syscall-to-ToolCallType mapping, proxy evaluation of supervisor
//! events, session management, profile detection, and the process tree.

use grith_supervisor::config::SupervisorConfig;
use grith_supervisor::interceptor::{NetProtocol, OpenFlags, SyscallKind};
use grith_supervisor::process_tree::ProcessTree;
use grith_supervisor::profiles::SupervisorProfile;
use grith_supervisor::supervisor::{SessionStats, SupervisorRegistry, SupervisorSession};
use grith_supervisor::syscall_map;
use grith_tests::{make_tool_call_context, TestFixtures, ToolCallType};

// ---------------------------------------------------------------------------
// Syscall-to-ToolCallType mapping → proxy evaluation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn supervisor_file_read_through_proxy() {
    let fixtures = TestFixtures::new();
    let kind = SyscallKind::FileOpen {
        path: "/tmp/safe.txt".into(),
        flags: OpenFlags::ReadOnly,
    };
    let call_type = syscall_map::to_tool_call_type(&kind).expect("should map to ToolCallType");
    let ctx = make_tool_call_context(call_type, serde_json::json!({}));
    let decision = fixtures.proxy.evaluate(&ctx).await;
    assert!(decision.is_allowed(), "safe file read should be allowed");
}

#[tokio::test]
async fn supervisor_ssh_key_read_flagged() {
    let fixtures = TestFixtures::new();
    let kind = SyscallKind::FileOpen {
        path: "/home/user/.ssh/id_rsa".into(),
        flags: OpenFlags::ReadOnly,
    };
    let call_type = syscall_map::to_tool_call_type(&kind).expect("should map to ToolCallType");
    let ctx = make_tool_call_context(call_type, serde_json::json!({}));
    let decision = fixtures.proxy.evaluate(&ctx).await;
    assert!(
        decision.composite_score > 0.0,
        "SSH key access should produce non-zero score, got {}",
        decision.composite_score
    );
}

#[tokio::test]
async fn supervisor_file_write_through_proxy() {
    let fixtures = TestFixtures::new();
    let kind = SyscallKind::FileOpen {
        path: "/tmp/output.txt".into(),
        flags: OpenFlags::WriteOnly,
    };
    let call_type = syscall_map::to_tool_call_type(&kind).expect("should map");
    match &call_type {
        ToolCallType::FileWrite { path, .. } => assert_eq!(path, "/tmp/output.txt"),
        other => panic!("expected FileWrite, got {other:?}"),
    }
    let ctx = make_tool_call_context(call_type, serde_json::json!({}));
    let decision = fixtures.proxy.evaluate(&ctx).await;
    // Safe path write should be allowed
    assert!(decision.is_allowed());
}

#[tokio::test]
async fn supervisor_dangerous_exec_flagged() {
    let kind = SyscallKind::ProcessExec {
        path: "/usr/bin/sudo".into(),
        args: vec!["sudo".into(), "rm".into(), "-rf".into(), "/".into()],
    };
    let call_type = syscall_map::to_tool_call_type(&kind).expect("should map");
    match &call_type {
        ToolCallType::ProcessSpawn { command, .. } => assert!(command.contains("sudo")),
        other => panic!("expected ProcessSpawn, got {other:?}"),
    }
}

#[tokio::test]
async fn supervisor_net_connect_maps_correctly() {
    let fixtures = TestFixtures::new();
    let kind = SyscallKind::NetConnect {
        address: "evil.com".into(),
        port: 443,
        protocol: NetProtocol::Tcp,
    };
    let call_type = syscall_map::to_tool_call_type(&kind).expect("should map");
    match &call_type {
        ToolCallType::NetConnect { address, port } => {
            assert_eq!(address, "evil.com");
            assert_eq!(*port, 443);
        }
        other => panic!("expected NetConnect, got {other:?}"),
    }
    let ctx = make_tool_call_context(call_type, serde_json::json!({}));
    let _decision = fixtures.proxy.evaluate(&ctx).await;
}

// ---------------------------------------------------------------------------
// Noise filtering
// ---------------------------------------------------------------------------

#[test]
fn noise_paths_are_filtered() {
    let noise_paths = vec![
        "/proc/self/maps",
        "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq",
        "/dev/null",
        "/dev/urandom",
        "/dev/tty",
        "/tmp/.tmp_abc123",
    ];
    for path in &noise_paths {
        assert!(
            syscall_map::is_noise_path(path),
            "{path} should be classified as noise"
        );
    }
}

#[test]
fn regular_paths_are_not_noise() {
    let regular_paths = vec![
        "/home/user/project/src/main.rs",
        "/usr/bin/git",
        "/home/user/.ssh/id_rsa",
    ];
    for path in &regular_paths {
        assert!(
            !syscall_map::is_noise_path(path),
            "{path} should NOT be classified as noise"
        );
    }
}

#[test]
fn fork_and_pipe_are_filtered_by_mapping() {
    assert!(
        syscall_map::to_tool_call_type(&SyscallKind::ProcessFork { child_pid: 42 }).is_none(),
        "ProcessFork should be filtered (no ToolCallType)"
    );
    assert!(
        syscall_map::to_tool_call_type(&SyscallKind::PipeCreate).is_none(),
        "PipeCreate should be filtered"
    );
    assert!(
        syscall_map::to_tool_call_type(&SyscallKind::SocketPair).is_none(),
        "SocketPair should be filtered"
    );
}

// ---------------------------------------------------------------------------
// Session management
// ---------------------------------------------------------------------------

#[test]
fn registry_lifecycle() {
    let config = SupervisorConfig::default();
    let mut registry = SupervisorRegistry::new(config);

    // Start empty
    assert_eq!(registry.count(), 0);
    assert!(registry.list().is_empty());

    // Register a session
    let session = SupervisorSession::new("claude-code", 1234);
    let id = session.id;
    registry.register(session).unwrap();
    assert_eq!(registry.count(), 1);

    // Get session
    let s = registry.get(&id).unwrap();
    assert_eq!(s.tool_name, "claude-code");
    assert_eq!(s.root_pid, 1234);

    // Update stats
    let s = registry.get_mut(&id).unwrap();
    s.stats.total_intercepted = 100;
    s.stats.total_allowed = 90;
    s.stats.total_denied = 5;
    s.stats.total_queued = 3;
    s.stats.total_filtered_noise = 2;

    // List reflects updates
    let list = registry.list();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].stats.total_intercepted, 100);

    // Remove
    let removed = registry.remove(&id).unwrap();
    assert_eq!(removed.tool_name, "claude-code");
    assert_eq!(registry.count(), 0);
}

#[test]
fn registry_enforces_concurrency_limit() {
    let config = SupervisorConfig {
        max_concurrent_sessions: 2,
        ..SupervisorConfig::default()
    };
    let mut registry = SupervisorRegistry::new(config);

    registry.register(SupervisorSession::new("a", 1)).unwrap();
    registry.register(SupervisorSession::new("b", 2)).unwrap();

    let result = registry.register(SupervisorSession::new("c", 3));
    assert!(result.is_err(), "should reject 3rd session at limit of 2");
}

#[test]
fn session_stats_tracking() {
    let mut stats = SessionStats::default();
    assert_eq!(stats.total_intercepted, 0);

    // Simulate a series of events
    stats.total_intercepted = 50;
    stats.total_allowed = 40;
    stats.total_queued = 5;
    stats.total_denied = 3;
    stats.total_filtered_noise = 2;

    // Verify stats are correct
    assert_eq!(
        stats.total_allowed + stats.total_queued + stats.total_denied + stats.total_filtered_noise,
        50,
        "stats should sum to total intercepted"
    );

    // Verify serialization roundtrip
    let json = serde_json::to_string(&stats).unwrap();
    let deserialized: SessionStats = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.total_intercepted, 50);
}

// ---------------------------------------------------------------------------
// Process tree
// ---------------------------------------------------------------------------

#[test]
fn process_tree_tracks_children() {
    let mut tree = ProcessTree::new(100, "test-tool");

    // Root exists
    assert!(tree.all_pids().contains(&100));

    // Add children
    tree.add_child(100, 101, "child-1").unwrap();
    tree.add_child(100, 102, "child-2").unwrap();
    tree.add_child(101, 103, "grandchild-1").unwrap();

    assert_eq!(tree.all_pids().len(), 4);
    assert_eq!(tree.children_of(100).len(), 2);
    assert_eq!(tree.children_of(101).len(), 1);
}

#[test]
fn process_tree_freeze_thaw() {
    let mut tree = ProcessTree::new(100, "test");
    tree.add_child(100, 101, "child").unwrap();
    tree.add_child(101, 102, "grandchild").unwrap();

    // Freeze subtree from 100
    tree.freeze_tree(100).unwrap();
    assert!(tree.is_frozen(100));
    assert!(tree.is_frozen(101));
    assert!(tree.is_frozen(102));

    // Thaw subtree
    tree.thaw_tree(100).unwrap();
    assert!(!tree.is_frozen(100));
    assert!(!tree.is_frozen(101));
    assert!(!tree.is_frozen(102));
}

// ---------------------------------------------------------------------------
// Profile detection
// ---------------------------------------------------------------------------

#[test]
fn profile_detection_for_known_tools() {
    assert_eq!(
        SupervisorProfile::detect_profile("claude"),
        Some("claude-code".into())
    );
    assert_eq!(
        SupervisorProfile::detect_profile("claude-code"),
        Some("claude-code".into())
    );
    assert_eq!(
        SupervisorProfile::detect_profile("/usr/local/bin/claude"),
        Some("claude-code".into())
    );
    assert_eq!(
        SupervisorProfile::detect_profile("codex"),
        Some("codex".into())
    );
    assert_eq!(
        SupervisorProfile::detect_profile("aider"),
        Some("aider".into())
    );
}

#[test]
fn profile_detection_unknown_tool() {
    assert_eq!(SupervisorProfile::detect_profile("unknown-tool"), None);
    assert_eq!(SupervisorProfile::detect_profile("vim"), None);
}

#[test]
fn toml_profiles_have_allowlists() {
    let profiles = SupervisorProfile::load_from_config().unwrap();
    assert!(
        profiles.len() >= 4,
        "profiles.toml should have at least 4 profiles"
    );

    for profile in &profiles {
        // Every profile should have a non-empty name
        assert!(!profile.name.is_empty());
        // Allowlist entries should be producible
        let _entries = profile.to_allowlist_entries();
    }
}

// ---------------------------------------------------------------------------
// New ToolCallType variants through proxy
// ---------------------------------------------------------------------------

#[tokio::test]
async fn new_tool_call_types_evaluate_through_proxy() {
    let fixtures = TestFixtures::new();

    // FileRename
    let ctx = make_tool_call_context(
        ToolCallType::FileRename {
            old_path: "/tmp/a.txt".into(),
            new_path: "/tmp/b.txt".into(),
        },
        serde_json::json!({}),
    );
    let decision = fixtures.proxy.evaluate(&ctx).await;
    assert!(decision.is_allowed(), "safe rename should be allowed");

    // FileChmod
    let ctx = make_tool_call_context(
        ToolCallType::FileChmod {
            path: "/tmp/script.sh".into(),
            mode: 0o755,
        },
        serde_json::json!({}),
    );
    let _decision = fixtures.proxy.evaluate(&ctx).await;

    // DirCreate
    let ctx = make_tool_call_context(
        ToolCallType::DirCreate {
            path: "/tmp/newdir".into(),
        },
        serde_json::json!({}),
    );
    let decision = fixtures.proxy.evaluate(&ctx).await;
    assert!(decision.is_allowed(), "safe dir create should be allowed");

    // NetConnect
    let ctx = make_tool_call_context(
        ToolCallType::NetConnect {
            address: "localhost".into(),
            port: 8080,
        },
        serde_json::json!({}),
    );
    let _decision = fixtures.proxy.evaluate(&ctx).await;

    // NetListen
    let ctx = make_tool_call_context(
        ToolCallType::NetListen {
            address: "0.0.0.0".into(),
            port: 3000,
        },
        serde_json::json!({}),
    );
    let _decision = fixtures.proxy.evaluate(&ctx).await;

    // ProcessSpawn
    let ctx = make_tool_call_context(
        ToolCallType::ProcessSpawn {
            command: "ls".into(),
            args: vec!["-la".into()],
        },
        serde_json::json!({}),
    );
    let _decision = fixtures.proxy.evaluate(&ctx).await;
}

// ---------------------------------------------------------------------------
// Supervisor config conversion
// ---------------------------------------------------------------------------

#[test]
fn supervisor_config_defaults_are_sane() {
    let config = SupervisorConfig::default();
    assert!(config.enabled);
    assert!(config.default_profile.is_empty());
    assert_eq!(config.freeze_timeout_seconds, 300);
    assert!(config.max_concurrent_sessions > 0);
    assert!(config.pty_forwarding);
}

#[test]
fn supervisor_config_toml_roundtrip() {
    let config = SupervisorConfig::default();
    let toml_str = toml::to_string(&config).unwrap();
    let parsed: SupervisorConfig = toml::from_str(&toml_str).unwrap();
    assert_eq!(parsed.enabled, config.enabled);
    assert_eq!(parsed.default_profile, config.default_profile);
    assert_eq!(parsed.freeze_timeout_seconds, config.freeze_timeout_seconds);
    assert_eq!(
        parsed.max_concurrent_sessions,
        config.max_concurrent_sessions
    );
}

// ---------------------------------------------------------------------------
// Full syscall mapping coverage
// ---------------------------------------------------------------------------

#[test]
fn all_security_relevant_syscalls_map_or_filter() {
    let test_cases: Vec<(SyscallKind, Option<&str>)> = vec![
        (
            SyscallKind::FileOpen {
                path: "/etc/passwd".into(),
                flags: OpenFlags::ReadOnly,
            },
            Some("FileRead"),
        ),
        (
            SyscallKind::FileOpen {
                path: "/tmp/out".into(),
                flags: OpenFlags::WriteOnly,
            },
            Some("FileWrite"),
        ),
        (
            SyscallKind::FileOpen {
                path: "/tmp/log".into(),
                flags: OpenFlags::Append,
            },
            Some("FileAppend"),
        ),
        (
            SyscallKind::FileRead {
                fd: 3,
                path: Some("/etc/hosts".into()),
            },
            Some("FileRead"),
        ),
        (
            SyscallKind::FileRead { fd: 3, path: None },
            None, // No path → filtered
        ),
        (
            SyscallKind::FileWrite {
                fd: 4,
                path: Some("/tmp/data".into()),
            },
            Some("FileWrite"),
        ),
        (
            SyscallKind::FileDelete {
                path: "/tmp/old".into(),
            },
            Some("FileDelete"),
        ),
        (
            SyscallKind::FileRename {
                old_path: "/a".into(),
                new_path: "/b".into(),
            },
            Some("FileRename"),
        ),
        (
            SyscallKind::FileChmod {
                path: "/tmp/x".into(),
                mode: 0o755,
            },
            Some("FileChmod"),
        ),
        (
            SyscallKind::DirCreate {
                path: "/tmp/d".into(),
                mode: 0o755,
            },
            Some("DirCreate"),
        ),
        (
            SyscallKind::DirList {
                path: "/tmp".into(),
            },
            Some("DirList"),
        ),
        (
            SyscallKind::ProcessExec {
                path: "/bin/ls".into(),
                args: vec!["ls".into()],
            },
            Some("ProcessSpawn"),
        ),
        (
            SyscallKind::ProcessFork { child_pid: 42 },
            None, // Filtered
        ),
        (
            SyscallKind::NetConnect {
                address: "1.2.3.4".into(),
                port: 80,
                protocol: NetProtocol::Tcp,
            },
            Some("NetConnect"),
        ),
        (
            SyscallKind::NetBind {
                address: "0.0.0.0".into(),
                port: 8080,
                protocol: NetProtocol::Tcp,
                sockaddr_ptr: None,
                addrlen: None,
            },
            Some("NetListen"),
        ),
        (SyscallKind::PipeCreate, None),
        (SyscallKind::SocketPair, None),
        (
            SyscallKind::NetSendTo {
                address: "1.2.3.4".into(),
                port: 53,
            },
            None, // Filtered for now
        ),
    ];

    for (kind, expected_type) in test_cases {
        let result = syscall_map::to_tool_call_type(&kind);
        match expected_type {
            Some(type_name) => {
                let ct = result
                    .unwrap_or_else(|| panic!("{kind:?} should map to ToolCallType::{type_name}"));
                let ct_str = format!("{ct:?}");
                assert!(
                    ct_str.starts_with(type_name),
                    "{kind:?}: expected {type_name}, got {ct_str}"
                );
            }
            None => {
                assert!(
                    result.is_none(),
                    "{kind:?} should be filtered, but got {result:?}"
                );
            }
        }
    }
}
