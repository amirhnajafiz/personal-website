#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/bpf.h>
#include <linux/limits.h>
#include <linux/binfmts.h>
#include <net/sock.h>
#include <bcc/proto.h>

// event is a custom struct that ebpf_program is using to transmit
// its logs to the script program.
struct event
{
    u32 pid;
    u32 uid;
    u32 ip;
    u64 timestamp;
    u64 inode_number;
    char command[TASK_COMM_LEN];
    char filename[NAME_MAX];
    char syscall[16];
    char action[16];
};

// string_t is a custom string type to use in BPF maps.
typedef char string_t[256];

// defining BPF maps
BPF_PERF_OUTPUT(events); // events

BPF_HASH(tmp_inode, u32, u64);          // directory inode
BPF_HASH(blocked_ips, u32, u8, 1024);   // ip address
BPF_HASH(string_map, u32, string_t, 1); // execute path

// string_compare is a custom function to compare two strings.
static inline int string_compare(const char *s1, const char *s2, size_t n)
{
    while (n-- > 0)
    {
        if (*s1 != *s2)
        {
            return (*s1 < *s2) ? -1 : 1;
        }

        if (*s1 == '\0')
        {
            return 0;
        }

        s1++;
        s2++;
    }

    return 0;
}

// LSM probe for inode_create to block file creation in a specific directory.
LSM_PROBE(inode_create, struct inode *dir, struct dentry *dentry, umode_t mode)
{
    struct event data = {};

    // getting the pid, uid, and ts
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data.timestamp = bpf_ktime_get_ns();

    bpf_get_current_comm(&data.command, sizeof(data.command));
    bpf_probe_read_kernel_str(&data.filename, sizeof(data.filename), dentry->d_name.name);

    data.inode_number = dir->i_ino;

    __builtin_memcpy(data.action, "allow", sizeof("allow"));
    __builtin_memcpy(data.syscall, "open", sizeof("open"));

    // get the inode from BPF map and compare to the file inode
    u32 key = 0;
    u64 *tmp_inode_ptr = tmp_inode.lookup(&key);
    if (tmp_inode_ptr)
    {
        u64 tmp_inode_num = *tmp_inode_ptr;

        if (data.inode_number == tmp_inode_num)
        {
            __builtin_memcpy(data.action, "denied", sizeof("denied"));

            // submit an event
            events.perf_submit(ctx, &data, sizeof(data));
            return -EPERM;
        }
    }

    // submit an event
    if (data.pid > 0)
    {
        events.perf_submit(ctx, &data, sizeof(data));
    }

    return 0;
}

// LSM probe for bprm_check_security to block execution of a specific file.
LSM_PROBE(bprm_check_security, struct linux_binprm *bprm)
{
    struct event data = {};

    // getting the pid, uid, and ts
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data.timestamp = bpf_ktime_get_ns();

    bpf_get_current_comm(&data.command, sizeof(data.command));

    // set default action and syscall
    __builtin_memcpy(data.action, "allow", sizeof("allow"));
    __builtin_memcpy(data.syscall, "exec", sizeof("exec"));
    __builtin_memcpy(data.filename, data.command, sizeof(data.command));

    bpf_probe_read_str(data.filename, sizeof(data.filename), bprm->filename);

    // get the target command
    u32 key = 1;
    string_t *string = string_map.lookup(&key);

    if (string && string_compare(data.filename, (const char *)string, sizeof(data.filename)) == 0)
    {
        __builtin_memcpy(data.action, "denied", sizeof("denied"));

        events.perf_submit(ctx, &data, sizeof(data));
        return -EPERM;
    }

    if (data.pid > 0)
    {
        events.perf_submit(ctx, &data, sizeof(data));
    }

    return 0;
}

// LSM probe on socket_connect to block connections to a specific IP.
LSM_PROBE(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    struct event data = {};

    // getting the pid, uid, and ts
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data.timestamp = bpf_ktime_get_ns();

    if (address->sa_family != AF_INET)
        return 0;

    __builtin_memcpy(data.action, "allow", sizeof("allow"));
    __builtin_memcpy(data.syscall, "connect", sizeof("connect"));

    // get the target IP address
    struct sockaddr_in *addr = (struct sockaddr_in *)address;
    u32 ip = bpf_ntohl(addr->sin_addr.s_addr);
    data.ip = ip;

    // check to see if the ip is blocked or not
    u8 *blocked = blocked_ips.lookup(&ip);
    if (blocked)
    {
        __builtin_memcpy(data.action, "denied", sizeof("denied"));

        events.perf_submit(ctx, &data, sizeof(data));
        return -EPERM;
    }

    if (data.pid > 0)
    {
        events.perf_submit(ctx, &data, sizeof(data));
    }

    return 0;
}

// LSM probe on socket_connect to block connections from a specific IP.
LSM_PROBE(socket_accept, struct socket *sock, struct socket *newsock)
{
    struct event data = {};

    // getting the pid, uid, and ts
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data.timestamp = bpf_ktime_get_ns();

    struct sock *sk = sock->sk;
    if (!sk)
        return 0;

    __builtin_memcpy(data.action, "allow", sizeof("allow"));
    __builtin_memcpy(data.syscall, "accept", sizeof("accept"));

    // get the target IP address
    u32 ip = bpf_ntohl(sk->__sk_common.skc_rcv_saddr);
    data.ip = ip;

    // check to see if the ip is blocked or not
    u8 *blocked = blocked_ips.lookup(&ip);
    if (blocked)
    {
        __builtin_memcpy(data.action, "denied", sizeof("denied"));

        events.perf_submit(ctx, &data, sizeof(data));
        return -EPERM;
    }

    if (data.pid > 0)
    {
        events.perf_submit(ctx, &data, sizeof(data));
    }

    return 0;
}
