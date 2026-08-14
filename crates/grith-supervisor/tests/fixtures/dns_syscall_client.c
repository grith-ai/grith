// SPDX-License-Identifier: MPL-2.0
// Deterministic syscall-shape fixture for Linux DNS inspection.
//
// Build:
//   cc -O2 -Wall -Wextra -pthread dns_syscall_client.c -o dns_syscall_client
// Run against a test resolver:
//   ./dns_syscall_client MODE 127.0.0.1 53 fixture.test
//
// MODE is one of:
//   connected-sendto, unconnected-sendto, sendmsg, sendmmsg,
//   cross-thread, connect-write-race, connected-read, connected-write-read,
//   connected-writev-readv, connected-send-recv,
//   connected-sendmsg-null-recvmsg, repeated-queries, reconnect,
//   af-unspec-disconnect, dup-alias, close-reuse,
//   explicit-destination-connected, tcp53
//
// `reconnect` and `explicit-destination-connected` accept an optional second
// resolver:
//   ./dns_syscall_client MODE RESOLVER PORT DOMAIN SECOND_RESOLVER SECOND_PORT

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

struct fixture {
    int fd;
    struct sockaddr_storage resolver;
    socklen_t resolver_len;
    struct sockaddr_storage second_resolver;
    socklen_t second_resolver_len;
    uint8_t query[512];
    size_t query_len;
};

static int parse_endpoint(const char *address, const char *port_text,
                          struct sockaddr_storage *storage,
                          socklen_t *storage_len) {
    unsigned long raw_port = strtoul(port_text, NULL, 10);
    if (raw_port > UINT16_MAX) return -1;
    uint16_t port = htons((uint16_t)raw_port);

    struct sockaddr_in *ipv4 = (struct sockaddr_in *)storage;
    memset(storage, 0, sizeof(*storage));
    if (inet_pton(AF_INET, address, &ipv4->sin_addr) == 1) {
        ipv4->sin_family = AF_INET;
        ipv4->sin_port = port;
        *storage_len = sizeof(*ipv4);
        return 0;
    }

    struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)storage;
    memset(storage, 0, sizeof(*storage));
    if (inet_pton(AF_INET6, address, &ipv6->sin6_addr) == 1) {
        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_port = port;
        *storage_len = sizeof(*ipv6);
        return 0;
    }
    return -1;
}

static size_t make_query(uint8_t *out, size_t cap, const char *domain,
                         uint16_t id, uint16_t qtype) {
    if (cap < 17) return 0;
    memset(out, 0, cap);
    out[0] = (uint8_t)(id >> 8);
    out[1] = (uint8_t)id;
    out[2] = 1; /* recursion desired */
    out[5] = 1; /* QDCOUNT */
    size_t at = 12;
    const char *label = domain;
    while (*label) {
        const char *dot = strchr(label, '.');
        size_t len = dot ? (size_t)(dot - label) : strlen(label);
        if (len == 0 || len > 63 || at + len + 5 > cap) return 0;
        out[at++] = (uint8_t)len;
        memcpy(out + at, label, len);
        at += len;
        if (!dot) break;
        label = dot + 1;
    }
    out[at++] = 0;
    out[at++] = (uint8_t)(qtype >> 8);
    out[at++] = (uint8_t)qtype;
    out[at++] = 0;
    out[at++] = 1; /* IN */
    return at;
}

static int receive_from(int fd) {
    uint8_t response[4096];
    ssize_t n = recvfrom(fd, response, sizeof(response), 0, NULL, NULL);
    return n > 0 ? 0 : -1;
}

static int connected_sendto(struct fixture *f) {
    if (connect(f->fd, (struct sockaddr *)&f->resolver, f->resolver_len))
        return -1;
    if (sendto(f->fd, f->query, f->query_len, 0, NULL, 0) < 0) return -1;
    return receive_from(f->fd);
}

static int unconnected_sendto(struct fixture *f) {
    if (sendto(f->fd, f->query, f->query_len, 0,
               (struct sockaddr *)&f->resolver, f->resolver_len) < 0)
        return -1;
    return receive_from(f->fd);
}

static int message_pair(struct fixture *f) {
    struct iovec send_iov = {.iov_base = f->query, .iov_len = f->query_len};
    struct msghdr send_hdr = {0};
    send_hdr.msg_name = &f->resolver;
    send_hdr.msg_namelen = f->resolver_len;
    send_hdr.msg_iov = &send_iov;
    send_hdr.msg_iovlen = 1;
    if (sendmsg(f->fd, &send_hdr, 0) < 0) return -1;

    uint8_t response[4096];
    struct iovec recv_iov = {.iov_base = response, .iov_len = sizeof(response)};
    struct msghdr recv_hdr = {0};
    recv_hdr.msg_iov = &recv_iov;
    recv_hdr.msg_iovlen = 1;
    return recvmsg(f->fd, &recv_hdr, 0) > 0 ? 0 : -1;
}

static int message_batch(struct fixture *f, const char *domain) {
    uint8_t second[512];
    size_t second_len = make_query(second, sizeof(second), domain, 0x7102, 28);
    struct iovec send_iov[2] = {
        {.iov_base = f->query, .iov_len = f->query_len},
        {.iov_base = second, .iov_len = second_len},
    };
    struct mmsghdr sends[2] = {0};
    for (size_t i = 0; i < 2; i++) {
        sends[i].msg_hdr.msg_name = &f->resolver;
        sends[i].msg_hdr.msg_namelen = f->resolver_len;
        sends[i].msg_hdr.msg_iov = &send_iov[i];
        sends[i].msg_hdr.msg_iovlen = 1;
    }
    if (sendmmsg(f->fd, sends, 2, 0) != 2) return -1;

    uint8_t responses[2][4096];
    struct iovec recv_iov[2];
    struct mmsghdr recvs[2] = {0};
    for (size_t i = 0; i < 2; i++) {
        recv_iov[i].iov_base = responses[i];
        recv_iov[i].iov_len = sizeof(responses[i]);
        recvs[i].msg_hdr.msg_iov = &recv_iov[i];
        recvs[i].msg_hdr.msg_iovlen = 1;
    }
    return recvmmsg(f->fd, recvs, 2, 0, NULL) > 0 ? 0 : -1;
}

static void *thread_io(void *arg) {
    struct fixture *f = arg;
    uint8_t response[4096];
    int result = 0;
    if (write(f->fd, f->query, f->query_len) < 0 ||
        read(f->fd, response, sizeof(response)) <= 0)
        result = -1;
    return (void *)(intptr_t)result;
}

static int cross_thread(struct fixture *f) {
    if (connect(f->fd, (struct sockaddr *)&f->resolver, f->resolver_len))
        return -1;
    pthread_t thread;
    if (pthread_create(&thread, NULL, thread_io, f)) return -1;
    void *result = NULL;
    if (pthread_join(thread, &result)) return -1;
    return (int)(intptr_t)result;
}

struct connect_write_race {
    struct fixture *fixture;
    atomic_bool start;
};

static void *racing_thread_io(void *arg) {
    struct connect_write_race *race = arg;
    struct fixture *f = race->fixture;
    uint8_t response[4096];

    while (!atomic_load_explicit(&race->start, memory_order_acquire))
        sched_yield();

    /*
     * Retry until TID A's connect has reached the kernel. Under ptrace this
     * deliberately lets TID B issue untrapped writes while TID A is stopped at
     * connect exit and the route is still pending registration.
     */
    for (size_t attempt = 0; attempt < 1000000; attempt++) {
        ssize_t sent = write(f->fd, f->query, f->query_len);
        if (sent == (ssize_t)f->query_len)
            return (void *)(intptr_t)(
                read(f->fd, response, sizeof(response)) > 0 ? 0 : -1);
        if (sent >= 0 ||
            (errno != EDESTADDRREQ && errno != ENOTCONN && errno != EAGAIN &&
             errno != EINTR))
            return (void *)(intptr_t)-1;
        sched_yield();
    }
    errno = ETIMEDOUT;
    return (void *)(intptr_t)-1;
}

static int connect_write_race(struct fixture *f) {
    struct connect_write_race race = {
        .fixture = f,
        .start = ATOMIC_VAR_INIT(false),
    };
    pthread_t thread;
    if (pthread_create(&thread, NULL, racing_thread_io, &race)) return -1;
    atomic_store_explicit(&race.start, true, memory_order_release);

    int connect_result =
        connect(f->fd, (struct sockaddr *)&f->resolver, f->resolver_len);
    void *thread_result = NULL;
    if (pthread_join(thread, &thread_result)) return -1;
    if (connect_result != 0) return -1;
    return (int)(intptr_t)thread_result;
}

static int connected_read(struct fixture *f) {
    uint8_t response[4096];
    if (connect(f->fd, (struct sockaddr *)&f->resolver, f->resolver_len))
        return -1;
    if (send(f->fd, f->query, f->query_len, 0) < 0) return -1;
    return read(f->fd, response, sizeof(response)) > 0 ? 0 : -1;
}

static int connected_write_read(struct fixture *f) {
    uint8_t response[4096];
    if (connect(f->fd, (struct sockaddr *)&f->resolver, f->resolver_len))
        return -1;
    if (write(f->fd, f->query, f->query_len) < 0) return -1;
    return read(f->fd, response, sizeof(response)) > 0 ? 0 : -1;
}

static int connected_writev_readv(struct fixture *f) {
    uint8_t response[4096];
    size_t split = f->query_len / 2;
    struct iovec send_iov[2] = {
        {.iov_base = f->query, .iov_len = split},
        {.iov_base = f->query + split, .iov_len = f->query_len - split},
    };
    struct iovec recv_iov[2] = {
        {.iov_base = response, .iov_len = sizeof(response) / 2},
        {
            .iov_base = response + sizeof(response) / 2,
            .iov_len = sizeof(response) / 2,
        },
    };
    if (connect(f->fd, (struct sockaddr *)&f->resolver, f->resolver_len))
        return -1;
    if (writev(f->fd, send_iov, 2) < 0) return -1;
    return readv(f->fd, recv_iov, 2) > 0 ? 0 : -1;
}

static int connected_send_recv(struct fixture *f) {
    uint8_t response[4096];
    if (connect(f->fd, (struct sockaddr *)&f->resolver, f->resolver_len))
        return -1;
    if (send(f->fd, f->query, f->query_len, 0) < 0) return -1;
    return recv(f->fd, response, sizeof(response), 0) > 0 ? 0 : -1;
}

static int connected_sendmsg_null(struct fixture *f) {
    struct iovec send_iov = {.iov_base = f->query, .iov_len = f->query_len};
    struct msghdr send_hdr = {0};
    send_hdr.msg_iov = &send_iov;
    send_hdr.msg_iovlen = 1;

    uint8_t response[4096];
    struct iovec recv_iov = {.iov_base = response, .iov_len = sizeof(response)};
    struct msghdr recv_hdr = {0};
    recv_hdr.msg_iov = &recv_iov;
    recv_hdr.msg_iovlen = 1;

    if (connect(f->fd, (struct sockaddr *)&f->resolver, f->resolver_len))
        return -1;
    if (sendmsg(f->fd, &send_hdr, 0) < 0) return -1;
    return recvmsg(f->fd, &recv_hdr, 0) > 0 ? 0 : -1;
}

static int repeated_queries(struct fixture *f, const char *domain) {
    uint8_t second[512];
    uint8_t response[4096];
    size_t second_len = make_query(second, sizeof(second), domain, 0x7102, 28);
    if (!second_len) return -1;
    if (connect(f->fd, (struct sockaddr *)&f->resolver, f->resolver_len))
        return -1;
    if (write(f->fd, f->query, f->query_len) < 0) return -1;
    if (read(f->fd, response, sizeof(response)) <= 0) return -1;
    if (write(f->fd, second, second_len) < 0) return -1;
    return read(f->fd, response, sizeof(response)) > 0 ? 0 : -1;
}

static int reconnect_socket(struct fixture *f) {
    uint8_t response[4096];
    if (connect(f->fd, (struct sockaddr *)&f->resolver, f->resolver_len))
        return -1;
    if (connect(f->fd, (struct sockaddr *)&f->second_resolver,
                f->second_resolver_len))
        return -1;
    if (write(f->fd, f->query, f->query_len) < 0) return -1;
    return read(f->fd, response, sizeof(response)) > 0 ? 0 : -1;
}

static int disconnect_unspec(struct fixture *f) {
    struct sockaddr disconnected = {0};
    struct sockaddr_storage peer = {0};
    socklen_t peer_len = sizeof(peer);
    disconnected.sa_family = AF_UNSPEC;
    if (connect(f->fd, (struct sockaddr *)&f->resolver, f->resolver_len))
        return -1;
    if (connect(f->fd, &disconnected, sizeof(disconnected))) return -1;
    errno = 0;
    if (getpeername(f->fd, (struct sockaddr *)&peer, &peer_len) == 0)
        return -1;
    return errno == ENOTCONN ? 0 : -1;
}

static int dup_alias(struct fixture *f) {
    uint8_t response[4096];
    if (connect(f->fd, (struct sockaddr *)&f->resolver, f->resolver_len))
        return -1;
    int alias = dup(f->fd);
    if (alias < 0) return -1;
    int result = 0;
    if (write(alias, f->query, f->query_len) < 0 ||
        read(alias, response, sizeof(response)) <= 0)
        result = -1;
    if (close(alias) != 0) result = -1;
    return result;
}

static int close_reuse(struct fixture *f) {
    int reused_fd = f->fd;
    if (close(f->fd) != 0) return -1;

    int replacement = socket(f->resolver.ss_family, SOCK_DGRAM, 0);
    if (replacement < 0) return -1;
    if (replacement != reused_fd) {
        if (dup2(replacement, reused_fd) < 0) {
            close(replacement);
            return -1;
        }
        if (close(replacement) != 0) return -1;
    }
    f->fd = reused_fd;
    return unconnected_sendto(f);
}

static int explicit_destination_connected(struct fixture *f) {
    if (connect(f->fd, (struct sockaddr *)&f->resolver, f->resolver_len))
        return -1;
    return sendto(f->fd, f->query, f->query_len, 0,
                  (struct sockaddr *)&f->second_resolver,
                  f->second_resolver_len) >= 0
               ? 0
               : -1;
}

static int tcp53(struct fixture *f) {
    int fd = socket(f->resolver.ss_family, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int result =
        connect(fd, (struct sockaddr *)&f->resolver, f->resolver_len);
    int saved_errno = errno;
    if (close(fd) != 0 && result == 0) return -1;
    errno = saved_errno;
    return result;
}

int main(int argc, char **argv) {
    if (argc != 5 && argc != 7) {
        fprintf(stderr,
                "usage: %s MODE RESOLVER PORT DOMAIN "
                "[SECOND_RESOLVER SECOND_PORT]\n",
                argv[0]);
        return 2;
    }
    struct fixture f = {0};
    if (parse_endpoint(argv[2], argv[3], &f.resolver, &f.resolver_len))
        return 2;
    f.fd = socket(f.resolver.ss_family, SOCK_DGRAM, 0);
    if (f.fd < 0)
        return 2;
    f.query_len = make_query(f.query, sizeof(f.query), argv[4], 0x7101, 1);
    if (!f.query_len) return 2;
    f.second_resolver = f.resolver;
    f.second_resolver_len = f.resolver_len;
    if (argc == 7) {
        if (parse_endpoint(argv[5], argv[6], &f.second_resolver,
                           &f.second_resolver_len) ||
            f.second_resolver.ss_family != f.resolver.ss_family)
            return 2;
    }

    int result;
    if (!strcmp(argv[1], "connected-sendto"))
        result = connected_sendto(&f);
    else if (!strcmp(argv[1], "unconnected-sendto"))
        result = unconnected_sendto(&f);
    else if (!strcmp(argv[1], "sendmsg"))
        result = message_pair(&f);
    else if (!strcmp(argv[1], "sendmmsg"))
        result = message_batch(&f, argv[4]);
    else if (!strcmp(argv[1], "cross-thread"))
        result = cross_thread(&f);
    else if (!strcmp(argv[1], "connect-write-race"))
        result = connect_write_race(&f);
    else if (!strcmp(argv[1], "connected-read"))
        result = connected_read(&f);
    else if (!strcmp(argv[1], "connected-write-read"))
        result = connected_write_read(&f);
    else if (!strcmp(argv[1], "connected-writev-readv"))
        result = connected_writev_readv(&f);
    else if (!strcmp(argv[1], "connected-send-recv"))
        result = connected_send_recv(&f);
    else if (!strcmp(argv[1], "connected-sendmsg-null-recvmsg") ||
             !strcmp(argv[1], "connected-sendmsg-null"))
        result = connected_sendmsg_null(&f);
    else if (!strcmp(argv[1], "repeated-queries"))
        result = repeated_queries(&f, argv[4]);
    else if (!strcmp(argv[1], "reconnect"))
        result = reconnect_socket(&f);
    else if (!strcmp(argv[1], "af-unspec-disconnect") ||
             !strcmp(argv[1], "disconnect-unspec"))
        result = disconnect_unspec(&f);
    else if (!strcmp(argv[1], "dup-alias"))
        result = dup_alias(&f);
    else if (!strcmp(argv[1], "close-reuse"))
        result = close_reuse(&f);
    else if (!strcmp(argv[1], "explicit-destination-connected"))
        result = explicit_destination_connected(&f);
    else if (!strcmp(argv[1], "tcp53"))
        result = tcp53(&f);
    else
        result = -1;

    if (result) perror("dns fixture");
    close(f.fd);
    return result ? 1 : 0;
}
