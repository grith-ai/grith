//! Go-live review round 2 — a supervised process must not be able to escape
//! interception by installing its own seccomp filter.
//!
//! `SECCOMP_RET_USER_NOTIF` (0x7fc00000) out-ranks grith's
//! `SECCOMP_RET_TRACE` (0x7ff00000) in seccomp action precedence, so a tracee
//! that adds a `NEW_LISTENER` filter and answers its own notifications with
//! `USER_NOTIF_FLAG_CONTINUE` runs syscalls grith never sees. grith denies the
//! `NEW_LISTENER` install; without a listener fd the escape cannot be built.
//!
//! Drives the FULL supervisor loop (the deny lives in `event_handler`, above
//! the interceptor), so it needs a tracer slot — skips when already traced.

#![cfg(target_os = "linux")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// Serialise the ptrace tests in this binary: cargo runs test functions in a
/// binary concurrently, and two supervised-process loops competing for CPU and
/// tracer slots time each other out. Every other ptrace test file uses the
/// same pattern.
fn test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn already_traced() -> bool {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("TracerPid:"))
                .map(|v| v.trim() != "0")
        })
        .unwrap_or(false)
}

fn compile(dir: &Path, name: &str, source: &str) -> PathBuf {
    let src = dir.join(format!("{name}.c"));
    let bin = dir.join(name);
    fs::write(&src, source).expect("write source");
    let out = Command::new("cc")
        .args(["-O0", "-pthread", "-o"])
        .arg(&bin)
        .arg(&src)
        .output()
        .expect("spawn cc");
    assert!(
        out.status.success(),
        "cc failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    bin
}

/// The exploit: install an own `USER_NOTIF` filter for `openat`, a sibling
/// thread answers with `FLAG_CONTINUE`, then open the target. Writes the
/// resulting fd (or the negative errno from a blocked listener install) to
/// argv[1].
const BYPASS_SRC: &str = r#"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static int listener = -1;

static struct sock_filter prog[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 257, 0, 1),   /* openat */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};

static void *supervisor(void *arg) {
    (void)arg;
    for (;;) {
        struct seccomp_notif req;
        memset(&req, 0, sizeof(req));
        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) break;
        struct seccomp_notif_resp resp;
        memset(&resp, 0, sizeof(resp));
        resp.id = req.id;
        resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &resp);
    }
    return NULL;
}

int main(int argc, char **argv) {
    (void)prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    struct sock_fprog fprog = { .len = sizeof(prog)/sizeof(prog[0]), .filter = prog };
    listener = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                       SECCOMP_FILTER_FLAG_NEW_LISTENER, &fprog);

    long result;
    if (listener < 0) {
        /* Install blocked — the bypass could not be built. Report -errno. */
        result = -errno;
    } else {
        pthread_t t;
        pthread_create(&t, NULL, supervisor, NULL);
        const char *target = argc > 2 ? argv[2] : "/etc/hostname";
        result = syscall(SYS_openat, AT_FDCWD, target, O_RDONLY);
        if (result >= 0) close(result);
    }

    if (argc > 1) {
        FILE *f = fopen(argv[1], "w");
        if (f) { fprintf(f, "%ld\n", result); fclose(f); }
    }
    return 0;
}
"#;

/// Run `binary args` through the full supervisor loop with an all-allow proxy,
/// returning the session's (allowed, denied) counts.
async fn run_full_loop(binary: &Path, args: &[String]) -> (u64, u64) {
    use grith_proxy::engine::SecurityProxy;
    use grith_proxy::filters::FilterRegistry;
    use grith_proxy::meta_rules::MetaRuleEngine;
    use grith_proxy::scoring::ScoringConfig;
    use tokio::sync::broadcast;

    let mut interceptor: Box<dyn grith_supervisor::interceptor::SyscallInterceptor> =
        grith_supervisor::platform::create_interceptor().unwrap();
    let pid = interceptor
        .spawn_supervised(binary.to_str().unwrap(), args, &[])
        .await
        .expect("spawn_supervised failed");

    let proxy = Arc::new(SecurityProxy::new(
        FilterRegistry::new(),
        ScoringConfig {
            auto_allow_threshold: 3.0,
            auto_deny_threshold: 8.0,
        },
        MetaRuleEngine::new(vec![]),
    ));
    let mut session = grith_supervisor::supervisor::SupervisorSession::new("bypass", pid);
    let audit_storage = Arc::new(std::sync::Mutex::new(
        grith_audit::AuditStorage::open_in_memory().unwrap(),
    ));
    let audit_sink: Arc<dyn grith_supervisor::AuditSink> =
        Arc::new(grith_supervisor::StorageAuditSink::new(audit_storage));
    let digest_queue = Arc::new(grith_digest::queue::DigestQueue::open_in_memory().unwrap());
    let digest_store: Arc<dyn grith_supervisor::DigestStore> =
        Arc::new(grith_supervisor::LocalDigestStore::new(digest_queue));
    let dlp_redactor = grith_proxy::filters::dlp_gate::DlpRedactor::with_defaults();
    let correlation_tracker = Arc::new(grith_audit::CorrelationTracker::with_defaults());
    let containment_tracker =
        Arc::new(grith_proxy::filters::session_containment::ContainmentTracker::with_defaults());
    let config = grith_supervisor::config::SupervisorConfig::default();
    let (_shutdown_tx, shutdown_rx) = broadcast::channel(1);

    let result = tokio::time::timeout(
        Duration::from_secs(45),
        grith_supervisor::supervisor::run_supervisor_loop(
            &mut interceptor,
            &mut session,
            proxy,
            audit_sink,
            digest_store,
            &dlp_redactor,
            correlation_tracker,
            containment_tracker,
            &config,
            shutdown_rx,
            None,
            None,
            None,
            &[],
            std::collections::HashSet::new(),
            None,
            None,
            None,
            None,
            None,
        ),
    )
    .await;
    result
        .expect("supervisor loop timed out")
        .expect("loop err");

    (session.stats.total_allowed, session.stats.total_denied)
}

/// The load-bearing test: the bypass must not open the file. With grith's
/// default config the NEW_LISTENER install is denied, so the helper cannot
/// even build its notifier and reports a negative errno; the open never runs.
#[test]
fn self_seccomp_notify_bypass_is_blocked() {
    if already_traced() {
        eprintln!("SKIP self_seccomp_notify_bypass_is_blocked: process already traced");
        return;
    }
    let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
    let temp = tempfile::tempdir().unwrap();
    let secret = temp.path().join("id_rsa");
    fs::write(&secret, "-----BEGIN OPENSSH PRIVATE KEY-----\n").unwrap();
    let result_path = temp.path().join("bypass_result");
    let bin = compile(temp.path(), "notif_bypass", BYPASS_SRC);

    let args = vec![
        result_path.to_str().unwrap().to_owned(),
        secret.to_str().unwrap().to_owned(),
    ];

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (_allowed, denied) = rt.block_on(run_full_loop(&bin, &args));

    let raw: i64 = fs::read_to_string(&result_path)
        .expect("result file missing")
        .trim()
        .parse()
        .expect("result not an integer");

    eprintln!("[test] helper reported raw={raw}, session denied={denied}");
    // A non-negative value is a file descriptor — the key was opened through
    // the tracee's own notifier, i.e. the bypass worked. grith's deny seeds
    // -EPERM (-1) as the return of the intercepted seccomp() call, so the
    // helper's NEW_LISTENER install fails with -1 and it never opens the key.
    assert_eq!(
        raw, -1,
        "expected grith to deny the NEW_LISTENER install with EPERM (-1); a          non-negative value is the opened fd (bypass worked), another negative          value is an unrelated failure"
    );
    let _ = denied;
}

/// Negative control: a plain seccomp filter (no NEW_LISTENER) is NOT the
/// escape and must still install, or grith would break bwrap / Chrome /
/// Node sandboxes. The helper installs an ALLOW-everything filter and reports
/// the install result.
const PLAIN_SRC: &str = r####"
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static struct sock_filter prog[] = {
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};

int main(int argc, char **argv) {
    (void)prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    struct sock_fprog fprog = { .len = 1, .filter = prog };
    long r = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &fprog);
    long result = (r < 0) ? -errno : r;
    if (argc > 1) {
        FILE *f = fopen(argv[1], "w");
        if (f) { fprintf(f, "%ld\n", result); fclose(f); }
    }
    return 0;
}
"####;

#[test]
fn plain_self_seccomp_filter_is_allowed() {
    if already_traced() {
        eprintln!("SKIP plain_self_seccomp_filter_is_allowed: process already traced");
        return;
    }
    let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
    let temp = tempfile::tempdir().unwrap();
    let result_path = temp.path().join("plain_result");
    let bin = compile(temp.path(), "plain_filter", PLAIN_SRC);
    let args = vec![result_path.to_str().unwrap().to_owned()];

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _ = rt.block_on(run_full_loop(&bin, &args));

    let raw: i64 = fs::read_to_string(&result_path)
        .expect("result file missing")
        .trim()
        .parse()
        .expect("result not an integer");
    // 0 = success. A plain filter grants no authority — denying it would break
    // every sandbox that self-filters.
    assert_eq!(
        raw, 0,
        "a plain (non-listener) seccomp filter must still install; got {raw}"
    );
}
