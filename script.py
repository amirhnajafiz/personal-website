from bcc import BPF
import ctypes

import time
import socket
import struct
import os
import subprocess
from datetime import datetime



# helper functions ======================
# ip to string convertion (u32 -> string)
def __ip_to_string(ip):
    # extract each byte by shifting and masking
    bytes = [
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF,
    ]

    # join the bytes with dots to form the IP address
    return ".".join(str(byte) for byte in bytes)

# get the inode number for /tmp directory
def __get_directory_inode(directory):
    result = subprocess.run(['stat', '-c', '%i', directory], stdout=subprocess.PIPE)
    return int(result.stdout.decode().strip())

# find directory by its inode
def __find_directory_by_inode(inode, start_path):
    try:
        # use find command to locate the directory
        cmd = f"find {start_path} -inum {inode} -type d -print -quit"
        result = subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=2)
        
        if result.returncode == 0 and result.stdout:
            return result.stdout.strip()
        else:
            return ""
    except subprocess.TimeoutExpired:
        return ""
    except subprocess.CalledProcessError as e:
        return ""



# initialize target variables
TARGET_DIR = "/home/sekar/Desktop" # block file creation in `/tmp` directory
TARGET_EXE = "/bin/nc" # block execution of `/bin/nc`
TARGET_IPA = "142.251.41.14" # block connections from and to `<ip address>`

# global variables
PROGRAM_PATH = "ebpf_program.c"
IP_SYSCALLS = ["connect", "accept"]
INODE_START_PATH = "/home/sekar/Desktop"



if __name__ == "__main__":
    # ebpf_program.c is the kernel code that we load in our script to attach kprobes
    with open(PROGRAM_PATH, "r") as file:
        bpf_program = file.read()

    # initialize BPF
    bpf = BPF(text=bpf_program)

    # initialize BPF maps
    # inode
    key = ctypes.c_uint32(0)
    value = ctypes.c_uint64(__get_directory_inode(TARGET_DIR))
    bpf["tmp_inode"][key] = value

    # exec file path
    key = ctypes.c_uint32(1)
    value = ctypes.create_string_buffer(TARGET_EXE.encode(), 256)
    bpf["string_map"][key] = value

    # ip address
    ip_int = struct.unpack("!I", socket.inet_aton(TARGET_IPA))[0]
    bpf["blocked_ips"][ctypes.c_uint32(ip_int)] = ctypes.c_ubyte(1)

    # set the system boot time to use for timestamp
    boot_time = time.clock_gettime(time.CLOCK_BOOTTIME)

    print("blocker program running, press Ctrl+C to exit and detach.")
    print("\nTimestamp\t\t\tPID\tUID\tSystem Call\tAction\tPath/IP")

    # polling loop to periodically print syscall events to process them
    def print_event(cpu, data, size):
        # get event
        event = bpf["events"].event(data)

        # calculate timestamp
        time_since_boot = time.time() - boot_time
        timestamp_sec = event.timestamp / 1e9
        wall_clock_time = time_since_boot + timestamp_sec
        datetime_obj = datetime.fromtimestamp(wall_clock_time)

        if event.syscall.decode('utf-8') in IP_SYSCALLS: # processing socket syscalls
            print(f"{datetime_obj}\t{event.pid}\t{event.uid}\t{event.syscall.decode('utf-8')}\t\t{event.action.decode('utf-8')}\t{__ip_to_string(event.ip)}")
        else:
            filename = event.filename.decode('utf-8')

            # check if the event has inode_number
            if event.inode_number > 0:
                # find the directory name by inode
                dname = __find_directory_by_inode(event.inode_number, INODE_START_PATH)
                if not filename.startswith(dname):
                    filename = dname + "/" + filename
            
            print(f"{datetime_obj}\t{event.pid}\t{event.uid}\t{event.syscall.decode('utf-8')}\t\t{event.action.decode('utf-8')}\t{filename}")

    # loop with callback to print_event to process events
    bpf["events"].open_perf_buffer(print_event)
    while True:
        try:
            bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            print("detaching ...")
            break

