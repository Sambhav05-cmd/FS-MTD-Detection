#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "read_common.h"

// Intentionally scoped to one held-open fixture and one live process.
// Counts permission checks, not general logical reads or completed bytes.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct read_config);
} read_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct read_counts);
} counts SEC(".maps");

SEC("lsm/file_permission")
int BPF_PROG(check_read, struct file *file, int mask, int ret)
{
    if (ret)
        return ret;
    if (!(mask & 4)) // MAY_READ
        return 0;
    __u32 zero = 0;
    struct read_config *cfg = bpf_map_lookup_elem(&read_cfg, &zero);
    if (!cfg || cfg->tgid != (__u32)(bpf_get_current_pid_tgid() >> 32))
        return 0;
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode || BPF_CORE_READ(inode, i_ino) != cfg->inode)
        return 0;
    __u32 dev = BPF_CORE_READ(inode, i_sb, s_dev);
    if ((dev >> 20) != cfg->dev_major || (dev & 0xfffff) != cfg->dev_minor)
        return 0;
    struct read_counts *stat = bpf_map_lookup_elem(&counts, &zero);
    if (cfg->deny) {
        if (stat) __sync_fetch_and_add(&stat->denied, 1);
        return -13; // EACCES; no userspace round trip.
    }
    if (stat) __sync_fetch_and_add(&stat->allowed, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
