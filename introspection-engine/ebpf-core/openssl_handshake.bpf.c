// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// v7.2 — BPF-side correlation, SNI capture, cgroup_id, SSL*→fd mapping

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_SNI 256

struct hs_state_t {
    u64 ts_ns;
    u64 ssl_ptr;
    char sni[MAX_SNI];
    int  sni_len;
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

// --- Minimal OpenSSL forward-decls for CO-RE field access (best-effort) ---
// These mirror a tiny subset of OpenSSL 1.1.1 / 3.x structures used only for
// reading negotiated cipher (tmp.new_cipher->id) and group (tmp.group_id).
// Layout may differ across distros; preserve_access_index enables CO-RE
// relocation so unsupported builds simply yield zero values.
struct ssl_cipher_st { unsigned long id; } __attribute__((preserve_access_index));
struct ssl3_tmp_st {
    struct ssl_cipher_st *new_cipher;
    unsigned short group_id; // For TLS 1.3 key_share (if present)
} __attribute__((preserve_access_index));
struct ssl3_state_st { struct ssl3_tmp_st tmp; } __attribute__((preserve_access_index));
struct ssl_st { struct ssl3_state_st *s3; } __attribute__((preserve_access_index));

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
    // 1. Start with any values collected via helper probes.
    e->nid_group = st->nid_group; // may be 0
    e->nid_cipher = 0;

    // 2. CO-RE read of ssl->s3->tmp.new_cipher->id & group_id if ssl_ptr known.
    if (st->ssl_ptr != 0) {
        struct ssl_st *ssl = (struct ssl_st *) (unsigned long) st->ssl_ptr;
        struct ssl3_state_st *s3_ptr = 0;
        // Read s3 pointer
        if (bpf_core_read_user(&s3_ptr, sizeof(s3_ptr), &ssl->s3) == 0 && s3_ptr) {
            struct ssl3_tmp_st tmp_local = {};
            if (bpf_core_read_user(&tmp_local, sizeof(tmp_local), &s3_ptr->tmp) == 0) {
                // group_id (OpenSSL keeps this in tmp during TLS 1.3 handshake)
                if (e->nid_group == 0 && tmp_local.group_id > 0)
                    e->nid_group = (int)tmp_local.group_id;
                // new_cipher pointer
                struct ssl_cipher_st *ciph_ptr = tmp_local.new_cipher;
                if (ciph_ptr) {
                    unsigned long cipher_id = 0;
                    if (bpf_core_read_user(&cipher_id, sizeof(cipher_id), &ciph_ptr->id) == 0) {
                        // TLS cipher suite IDs occupy lower 16 bits of OpenSSL internal id
                        int c_id16 = (int)(cipher_id & 0xFFFF);
                        if (c_id16 > 0)
                            e->nid_cipher = c_id16;
                    }
                }
            }
        }
    }

    __builtin_memset(e->sni, 0, sizeof(e->sni));
    if (st->sni_set && st->sni_len > 0) {
        int cplen = st->sni_len;
        if (cplen > MAX_SNI - 1) cplen = MAX_SNI - 1;
        bpf_probe_read_kernel(e->sni, cplen, st->sni);
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

    long n = bpf_probe_read_user_str(st->sni, sizeof(st->sni), parg);
    if (n > 1) {
        int len = (int)(n - 1); // exclude trailing NUL
        if (len > MAX_SNI - 1) len = MAX_SNI - 1;
        st->sni_len = len;
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
    }
    struct hs_state_t *st2 = bpf_map_lookup_elem(&hs_state, &tid);
    if (!st2) return 0;
    long n = bpf_probe_read_user_str(st2->sni, sizeof(st2->sni), name);
    if (n > 1) {
        int len = (int)(n - 1);
        if (len > MAX_SNI - 1) len = MAX_SNI - 1;
        st2->sni_len = len;
        st2->sni_set = true;
        bpf_map_update_elem(&hs_state, &tid, st2, BPF_ANY);
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
