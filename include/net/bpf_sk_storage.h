/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NET_BPF_SK_STORAGE_H
#define _NET_BPF_SK_STORAGE_H

struct sock;

#ifdef CONFIG_CGROUP_BPF
void bpf_sk_storage_free(struct sock *sk);
extern const struct bpf_func_proto bpf_sk_storage_get_proto;
extern const struct bpf_func_proto bpf_sk_storage_delete_proto;
#else
static inline void bpf_sk_storage_free(struct sock *sk) {}
#endif

#endif
