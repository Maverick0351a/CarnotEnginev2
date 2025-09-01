// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// v7.2 — BPF-side correlation, SNI capture, cgroup_id, SSL*→fd mapping

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_SNI 128

struct hs_state_t {
    u64 ts_ns;
    u64 ssl_ptr;
    char sni[MAX_SNI];
    bool sni_set;
    int  nid_group;              // negotiated group NID (best-effort)
    int  last_shared_group_n;    // last n seen for SSL_get_shared_group
};

struct hs_event_t {
    u32 pid;
    u32 tid;
    u64 ts_ns;
    u64 cgroup_id;
    char comm[16];
    u64 ssl_ptr;
    int  success; // >0 ok
    int  fd;      // -1 if unknown
    char sni[MAX_SNI];
    int  nid_group;  // OpenSSL group NID (best-effort)
    int  nid_cipher; // OpenSSL cipher NID (best-effort)
};

// TID keyed state during handshake
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct hs_state_t);
    __uint(max_entries, 16384);
} hs_state SEC(".maps");

// SSL* → fd mapping
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, int);
    __uint(max_entries, 16384);
} ssl_to_fd SEC(".maps");

// Ring buffer for completed handshake events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Helpers
static __always_inline u32 get_tid() { return (u32)bpf_get_current_pid_tgid(); }
static __always_inline u32 get_pid() { return (u32)(bpf_get_current_pid_tgid() >> 32); }

// --- Probes ---

// int SSL_set_fd(SSL *ssl, int fd);
SEC("uprobe/SSL_set_fd")
int BPF_KPROBE(SSL_set_fd_enter, void *ssl, int fd) {
    u64 key = (u64)ssl;
    bpf_map_update_elem(&ssl_to_fd, &key, &fd, BPF_ANY);
    return 0;
}

// int SSL_do_handshake(SSL *ssl);
SEC("uprobe/SSL_do_handshake")
int BPF_KPROBE(SSL_do_handshake_enter, void *ssl) {
    u32 tid = get_tid();
    struct hs_state_t st = {};
    st.ts_ns = bpf_ktime_get_ns();
    st.ssl_ptr = (u64)ssl;
    st.nid_group = 0;
    st.last_shared_group_n = -1;
    bpf_map_update_elem(&hs_state, &tid, &st, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_do_handshake")
int BPF_KRETPROBE(SSL_do_handshake_exit, int ret) {
    u32 tid = get_tid();
    struct hs_state_t *st = bpf_map_lookup_elem(&hs_state, &tid);
    if (!st) return 0;

    struct hs_event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&hs_state, &tid);
        return 0;
    }

    e->pid = get_pid();
    e->tid = tid;
    e->ts_ns = bpf_ktime_get_ns();
    e->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->ssl_ptr = st->ssl_ptr;
    e->success = ret;

    // Negotiated params (best-effort)
    e->nid_group = st->nid_group; // 0 if unknown
    e->nid_cipher = 0;            // left unset in this scaffold

    __builtin_memset(e->sni, 0, sizeof(e->sni));
    if (st->sni_set) {
        __builtin_memcpy(e->sni, st->sni, sizeof(e->sni));
    }
    int *fdp = bpf_map_lookup_elem(&ssl_to_fd, &st->ssl_ptr);
    e->fd = fdp ? *fdp : -1;

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&hs_state, &tid);
    return 0;
}

// long SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg);
// Heuristic: capture SNI when cmd matches TLSEXT_HOST_NAME related control
// We avoid hardcoding constants; we only try to read parg as char* if non-NULL.
SEC("uprobe/SSL_ctrl")
int BPF_KPROBE(SSL_ctrl_enter, void *ssl, int cmd, long larg, void *parg) {
    if (!parg) return 0;
    u32 tid = get_tid();
    struct hs_state_t *st = bpf_map_lookup_elem(&hs_state, &tid);
    if (!st) return 0;

    char buf[MAX_SNI] = {};
    long n = bpf_probe_read_user_str(buf, sizeof(buf), parg);
    if (n > 1) {
        __builtin_memcpy(st->sni, buf, sizeof(st->sni));
        st->sni_set = true;
        bpf_map_update_elem(&hs_state, &tid, st, BPF_ANY);
    }
    return 0;
}

// int BIO_set_conn_hostname(BIO *b, const char *name);
SEC("uprobe/BIO_set_conn_hostname")
int BPF_KPROBE(BIO_set_conn_hostname_enter, void *bio, const char *name) {
    if (!name) return 0;
    u32 tid = get_tid();
    struct hs_state_t st_init = {};
    struct hs_state_t *st = bpf_map_lookup_elem(&hs_state, &tid);
    if (!st) {
        st_init.ts_ns = bpf_ktime_get_ns();
        st_init.ssl_ptr = 0;
        bpf_map_update_elem(&hs_state, &tid, &st_init, BPF_ANY);
        st = &st_init; // NOTE: local copy; we will update map again below
    }
    char buf[MAX_SNI] = {};
    long n = bpf_probe_read_user_str(buf, sizeof(buf), name);
    if (n > 1) {
        struct hs_state_t *st2 = bpf_map_lookup_elem(&hs_state, &tid);
        if (st2) {
            __builtin_memcpy(st2->sni, buf, sizeof(st2->sni));
            st2->sni_set = true;
            bpf_map_update_elem(&hs_state, &tid, st2, BPF_ANY);
        }
    }
    return 0;
}

// int SSL_get_shared_group(const SSL *ssl, int n);
SEC("uprobe/SSL_get_shared_group")
int BPF_KPROBE(SSL_get_shared_group_enter, void *ssl, int n) {
    u32 tid = get_tid();
    struct hs_state_t st_init = {};
    struct hs_state_t *st = bpf_map_lookup_elem(&hs_state, &tid);
    if (!st) {
        st_init.ts_ns = bpf_ktime_get_ns();
        st_init.ssl_ptr = (u64)ssl;
        st_init.last_shared_group_n = n;
        bpf_map_update_elem(&hs_state, &tid, &st_init, BPF_ANY);
    } else {
        st->last_shared_group_n = n;
        bpf_map_update_elem(&hs_state, &tid, st, BPF_ANY);
    }
    return 0;
}

SEC("uretprobe/SSL_get_shared_group")
int BPF_KRETPROBE(SSL_get_shared_group_exit, int ret) {
    u32 tid = get_tid();
    struct hs_state_t *st = bpf_map_lookup_elem(&hs_state, &tid);
    if (!st) return 0;
    // When n == 0, ret is the negotiated group NID (>0)
    if (st->last_shared_group_n == 0 && ret > 0) {
        st->nid_group = ret;
        bpf_map_update_elem(&hs_state, &tid, st, BPF_ANY);
    }
    return 0;
}
