// SPDX-License-Identifier: GPL-2.0
// ZeroCore Agent — eBPF Kernel-Space Probe
// Attaches to vfs_write and execve via kprobes.
// Uses BTF + CO-RE: compiles once, runs on any kernel 5.8+
// Emits ProcessFileEvent structs to a ring buffer consumed by userspace.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
#define MAX_PATH_LEN   256
#define MAX_COMM_LEN   16
#define MAX_ARGS_LEN   128
#define EVENT_VFS_WRITE 1
#define EVENT_EXECVE    2

// ---------------------------------------------------------------------------
// Shared event struct — written to ring buffer, read by Go userspace
// ---------------------------------------------------------------------------
struct process_file_event {
    __u32 event_type;           // EVENT_VFS_WRITE or EVENT_EXECVE
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char  comm[MAX_COMM_LEN];   // process name (e.g. "python3")
    char  file_path[MAX_PATH_LEN];
    char  args[MAX_ARGS_LEN];   // argv[0..n] space-joined (execve only)
};

// Force BTF export of the struct so Go can access it via CO-RE
struct process_file_event *unused __attribute__((unused));

// ---------------------------------------------------------------------------
// Ring buffer map — lock-free, variable-length, preferred over perf_event_array
// ---------------------------------------------------------------------------
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024); // 4 MB ring buffer
} events SEC(".maps");

// ---------------------------------------------------------------------------
// Per-CPU scratch map to stash file path across kprobe/kretprobe boundary
// ---------------------------------------------------------------------------
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct process_file_event);
} scratch SEC(".maps");

// ---------------------------------------------------------------------------
// Helper: populate process metadata from current task_struct
// ---------------------------------------------------------------------------
static __always_inline void fill_process_info(struct process_file_event *ev)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    ev->pid  = bpf_get_current_pid_tgid() >> 32;
    ev->uid  = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ev->gid  = bpf_get_current_uid_gid() >> 32;
    ev->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(ev->comm, sizeof(ev->comm));
}

// ---------------------------------------------------------------------------
// Helper: resolve dentry → full path into buffer
// Uses bpf_d_path which requires a valid path struct pointer.
// ---------------------------------------------------------------------------
static __always_inline int fill_file_path(struct file *file,
                                           struct process_file_event *ev)
{
    if (!file)
        return -1;

    struct path f_path = BPF_CORE_READ(file, f_path);
    int ret = bpf_d_path(&f_path, ev->file_path, sizeof(ev->file_path));
    return ret;
}

// ---------------------------------------------------------------------------
// kprobe: vfs_write(struct file *file, const char __user *buf,
//                   size_t count, loff_t *pos)
//
// Fires on every kernel write — we filter to regular files only.
// ---------------------------------------------------------------------------
SEC("kprobe/vfs_write")
int BPF_KPROBE(kprobe_vfs_write, struct file *file)
{
    // Filter: only regular files (not sockets, pipes, etc.)
    umode_t mode = BPF_CORE_READ(file, f_inode, i_mode);
    if (!S_ISREG(mode))
        return 0;

    // Reserve ring buffer slot
    struct process_file_event *ev =
        bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->event_type = EVENT_VFS_WRITE;
    fill_process_info(ev);

    int ret = fill_file_path(file, ev);
    if (ret < 0) {
        // Path resolution failed — emit with empty path rather than drop
        ev->file_path[0] = '\0';
    }

    ev->args[0] = '\0'; // args not applicable for write events

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// ---------------------------------------------------------------------------
// tracepoint: sys_enter_execve
// Captures argv[0] + argv[1] for process launch context.
// Using raw tracepoint for lower overhead than kprobe on execve.
// ---------------------------------------------------------------------------
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct process_file_event *ev =
        bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->event_type = EVENT_EXECVE;
    fill_process_info(ev);

    // Read filename (argv[0]) from userspace pointer
    const char __user *filename = (const char __user *)ctx->args[0];
    bpf_probe_read_user_str(ev->file_path, sizeof(ev->file_path), filename);

    // Read argv array: args[1] is char __user * __user *
    const char __user *const __user *argv =
        (const char __user *const __user *)ctx->args[1];

    // Collect up to 3 argv entries into ev->args (space-separated)
    char arg[32];
    int  offset = 0;

    #pragma unroll
    for (int i = 0; i < 3; i++) {
        const char __user *argp = NULL;
        if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) < 0)
            break;
        if (!argp)
            break;
        int n = bpf_probe_read_user_str(arg, sizeof(arg), argp);
        if (n <= 0)
            break;
        if (offset + n < MAX_ARGS_LEN) {
            bpf_probe_read_kernel(ev->args + offset, n, arg);
            offset += n - 1; // overwrite null terminator with space
            if (i < 2 && offset < MAX_ARGS_LEN - 1)
                ev->args[offset++] = ' ';
        }
    }
    ev->args[offset < MAX_ARGS_LEN ? offset : MAX_ARGS_LEN - 1] = '\0';

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
