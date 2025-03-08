# eBPF Program

This eBPF (Extended Berkeley Packet Filter) program is developed using the BCC (BPF Compiler Collection) and Linux Security Module (LSM) probes. To execute the program, run the following command:

```bash
sudo python3 script.py
```

For better logging, you can redirect the output to a file using:

```bash
sudo python3 script.py > logs.output.txt
```

Press `Ctrl+C` to exit and detach the program.

## Functionality

The program loads kernel code from the file `ebpf_program.c` into a BPF instance and attaches four LSM probes to perform the following tasks:

1. **Block File Creation:** A probe on `inode_create` is utilized to prevent the creation of files within a specified directory.
2. **Block Command Execution:** A probe on `bprm_check_security` is employed to restrict the execution of a particular command.
3. **Block Network Connections:** Probes on both `socket_connect` and `socket_accept` are implemented to prevent connections to and from a specified IP address.

### Blocking File Creation

To block file creation in a specific directory, the program passes the inode (obtained by running the `__get_directory_inode` function in `script.py`) using a BPF map to the LSM probe with the following signature:

```c
LSM_PROBE(inode_create, struct inode *dir, struct dentry *dentry, umode_t mode)
```

Each time a file creation is attempted, this hook checks the inodes and blocks any that are directed to the target directory.

### Blocking Command Execution

To prevent the execution of specific commands, the program passes the command string via a BPF map to a LSM probe defined as follows:

```c
LSM_PROBE(bprm_check_security, struct linux_binprm *bprm)
```

Whenever a command execution is initiated, this hook verifies the filename against the specified command and blocks it if there is a match.

### Blocking Network Connections

To block network connections, IP addresses are converted to a 32-bit unsigned integer format using the following code:

```python
ip_int = struct.unpack("!I", socket.inet_aton(TARGET_IPA))[0]
bpf["blocked_ips"][ctypes.c_uint32(ip_int)] = ctypes.c_ubyte(1)
```

This program uses two LSM probes for this purpose:

```c
LSM_PROBE(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
LSM_PROBE(socket_accept, struct socket *sock, struct socket *newsock)
```

When a connection or acceptance event occurs, the program checks the IP addresses against the specified targets. If a match is found, the connection is blocked.

## Kernel-Level Details

The user-level Python application utilizes three BPF hash maps to send information about the directory inode, IP address, and file path of the executed command to the kernel program. Additionally, the kernel program employs `BPF_PERF_OUTPUT` to send events back to the user-level application. The structure of these events is defined as follows:

```c
struct event
{
    u32 pid;               // Process ID
    u32 uid;               // User ID
    u32 ip;                // IP address
    u64 timestamp;         // Event timestamp
    u64 inode_number;      // Inode number of the file
    char command[TASK_COMM_LEN]; // Command name
    char filename[NAME_MAX]; // Filename being accessed
    char syscall[16];      // System call name
    char action[16];       // Action taken (allowed or denied)
};
```

## User-Level Implementation

In the user-level program, a `while` loop continuously calls `perf_buffer_poll` to retrieve events from the performance buffer and invokes the `print_event` callback function.

```python
# Load the kernel code from ebpf_program.c to attach kprobes
with open(PROGRAM_PATH, "r") as file:
    bpf_program = file.read()

# Initialize BPF
bpf = BPF(text=bpf_program)

# Additional setup code goes here...

# Open the performance buffer for events
bpf["events"].open_perf_buffer(print_event)

while True:
    try:
        bpf.perf_buffer_poll()  # Poll for events
    except KeyboardInterrupt:
        print("Detaching...")
        break
```

In the `print_event` callback function, the program captures events and calculates the timestamp based on the system's boot time. Events are printed for incoming actions. For IP address events, a helper function, `__ip_to_string`, converts the IP address from a 32-bit unsigned integer to a human-readable string format.

For other events, the program checks the `inode_number` field. If it contains a valid value, it uses the `__find_directory_by_inode` helper function to retrieve the absolute path of the file.

The program specifies target variables in lines 50 to 53 to indicate which actions to block:

```python
# Initialize target variables
TARGET_DIR = "/home/sekar/Desktop"  # Block file creation in this directory
TARGET_EXE = "/bin/nc"               # Block execution of this command
TARGET_IPA = "142.251.41.14"         # Block connections to and from this IP address
```

To determine the inode of files, the program sets the `INODE_START_PATH` variable in line 58 to specify the starting directory for inode checks, reducing the overhead of searching through directory names.

```python
INODE_START_PATH = "/home/sekar/Desktop"  # Starting point for inode checks
```

## Logging Output

To execute the program, you may adjust the specified variables as necessary. It is advisable to redirect the program's output to a log file. The output will be formatted as follows:

```txt
Blocker program running, press Ctrl+C to exit and detach.

Timestamp                     PID     UID     System Call    Action   Path/IP
2024-10-30 14:45:44.943664    12494   0       exec           allow    /usr/bin/ischroot
2024-10-30 14:45:45.455794    12495   0       exec           allow    /usr/bin/dpkg
2024-10-30 14:45:45.497490    12496   0       exec           allow    /usr/bin/dpkg
2024-10-30 14:45:45.517889    12497   0       exec           allow    /usr/bin/dpkg
2024-10-30 14:45:45.562129    12498   0       exec           allow    /usr/bin/dpkg
2024-10-30 14:46:07.039886    12813   1000    open           denied   /home/sekar/Desktop/file
2024-10-30 14:46:13.971619    12899   0       exec           allow    /bin/sh
2024-10-30 14:46:14.133565    12903   1000    exec           denied   /bin/nc
2024-10-30 14:46:37.438751    13247   1000    exec           allow    /usr/bin/wget
2024-10-30 14:46:37.457748    13247   1000    connect        denied   142.251.41.14
2024-10-30 14:46:39.452597    13255   1000    exec           allow    /bin/sh
2024-10-30 14:46:39.458687    13256   1000    exec           allow    /usr/bin/ps
```

This output provides a detailed log of the events processed by the program, including timestamps, process IDs, user IDs, system calls executed, actions taken (either allowed or denied), and the relevant paths or IP addresses involved.
