# Modified version of nfsslower.py originally authored by Samuel Nair (31-Aug-2017)
# Original script available at: https://github.com/iovisor/bcc/blob/master/tools/nfsslower.py

from __future__ import print_function
from bcc import BPF
from time import strftime

from prometheus_client import Gauge, start_http_server, Histogram
import socket

node_name = socket.gethostname()

read_bytes_metric = Gauge('nfs_read_bytes', 'NFS file read bytes per node', ['node_name'])
write_bytes_metric = Gauge('nfs_write_bytes', 'NFS file write bytes per node', ['node_name'])

read_latency_metric = Histogram('nfs_read_latency', 'NFS file read latency', buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0], labelnames=['node_name'])
write_latency_metric = Histogram('nfs_write_latency', 'NFS file write latency', buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0], labelnames=['node_name'])
open_latency_metric = Histogram('nfs_open_latency', 'NFS file open latency', buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0], labelnames=['node_name'])

start_http_server(8000)


bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/nfs_fs.h>

#define TRACE_READ 0
#define TRACE_WRITE 1
#define TRACE_OPEN 2
#define TRACE_GETATTR 3

struct event {
    u64 timestamp;
    u64 file_offset;
    struct file *file_ptr;
    struct dentry *dentry_ptr;
};

struct export_data {
    u64 timestamp;
    u8 event_type;
    u64 size;
    u64 file_offset;
    u64 delta;
    u32 pid;
    char task[TASK_COMM_LEN];
    char file[DNAME_INLINE_LEN];
};

BPF_HASH(entry_record, u64, struct event);
BPF_PERF_OUTPUT(events);

int trace_read_and_write_entry(struct pt_regs *ctx, struct kiocb *iocb, struct iov_iter *data) {
    
    // get pid from bpf helper function
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    // store file ptr and timestamp by pid_tgid
    struct event curr_event = {};
    curr_event.timestamp = bpf_ktime_get_ns();
    curr_event.file_ptr = iocb->ki_filp;
    curr_event.dentry_ptr = NULL;
    curr_event.file_offset = iocb->ki_pos;

    if (curr_event.file_ptr)
        entry_record.update(&pid_tgid, &curr_event);

    return 0;
}

int trace_file_open_entry (struct pt_regs *ctx, struct inode *inode, struct file *filep) {
    
    // get pid from bpf helper function
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    // store file ptr and timestamp by pid_tgid
    struct event curr_event = {};
    curr_event.timestamp = bpf_ktime_get_ns();
    curr_event.file_ptr = filep;
    curr_event.dentry_ptr = NULL;
    curr_event.file_offset = 0;
    
    if (curr_event.file_ptr)
        entry_record.update(&pid_tgid, &curr_event);
    
    return 0;
}

int trace_getattr_entry(struct pt_regs *ctx, struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat) {
    
    // get pid from bpf helper function
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    // store dentry ptr and timestamp by pid_tgid
    struct event curr_event = {};
    curr_event.timestamp = bpf_ktime_get_ns();
    curr_event.file_ptr = NULL;
    curr_event.dentry_ptr = dentry;
    curr_event.file_offset = 0;
    
    if (curr_event.dentry_ptr)
        entry_record.update(&pid_tgid, &curr_event);

    return 0;
}


static int trace_exit(struct pt_regs *ctx, int type) {
    
    // get pid from bpf helper function
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    struct event *prev_event;
    prev_event = entry_record.lookup(&pid_tgid);
    if (prev_event == 0) {
        // missed the event entry or filtered
        return 0;
    }
    entry_record.delete(&pid_tgid);

    // calculate delta in milli seconds
    u64 curr_timestamp = bpf_ktime_get_ns();
    u64 delta = (curr_timestamp - prev_event->timestamp) / 1000;

    // populate output struct
    struct export_data data = {};
    data.event_type = type;
    data.delta = delta;
    data.pid = pid;
    data.timestamp = curr_timestamp / 1000;
    data.file_offset = prev_event->file_offset;
    bpf_get_current_comm(&data.task, sizeof(data.task));
    data.size = PT_REGS_RC(ctx);
    
    // copy value of dentry for getting ptr to quick string (qstr)
    struct dentry *de = NULL;
    if(type == TRACE_GETATTR) {
        bpf_probe_read_kernel(&de, sizeof(de), &prev_event->dentry_ptr);
    } else {
        bpf_probe_read_kernel(&de, sizeof(de), &prev_event->file_ptr->f_path.dentry);
    }

    struct qstr qs = {};
    bpf_probe_read_kernel(&qs, sizeof(qs), (void *)&de->d_name);
    if (qs.len == 0)
        return 0;
    
    // copy file name from qstr ptr's attribute name
    bpf_probe_read_kernel(&data.file, sizeof(data.file), (void *)qs.name);
    
    // export data
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


int trace_read_return(struct pt_regs *ctx){
    return trace_exit(ctx, TRACE_READ);
}

int trace_write_return(struct pt_regs *ctx){
    return trace_exit(ctx, TRACE_WRITE);
}

int trace_file_open_return(struct pt_regs *ctx){
    return trace_exit(ctx, TRACE_OPEN);
}

int trace_getattr_return(struct pt_regs *ctx){
    return trace_exit(ctx, TRACE_GETATTR);
}
"""

# process output events
def print_event(cpu, data, size):
    event = b["events"].event(data)

    event_type = ''
    if event.event_type == 0:
        event_type = 'R'
        if event.size != 0:
            read_bytes_metric.labels(node_name).set(event.size)
        if float(event.delta)/1000 > 0.001:
            read_latency_metric.labels(node_name).observe(float(event.delta)/1000)
    
    elif event.event_type == 1:
        event_type = 'W'
        if event.size != 0:
            write_bytes_metric.labels(node_name).set(event.size)
        if float(event.delta)/1000 > 0.001:
            write_latency_metric.labels(node_name).observe(float(event.delta)/1000)

    elif event.event_type == 2:
        event_type = 'O'
        if float(event.delta)/1000 > 0.001:
            open_latency_metric.labels(node_name).observe(float(event.delta)/1000)

    elif event.event_type == 3:
        event_type = 'G'
        return

    print("%-8s %-14.14s %-6s %1s %-7s %-8d %7.2f %s" %
          (strftime("%H:%M:%S"),
           event.task.decode('utf-8', 'replace'),
           event.pid,
           event_type,
           event.size,
           event.file_offset / 1024,
           float(event.delta) / 1000,
           event.file.decode('utf-8', 'replace')))


# cflag to supress the warning on kernels after linux-5.18
b = BPF(text=bpf_text, cflags=["-Wno-tautological-constant-out-of-range-compare"])

# attach kprobe - before the target function
b.attach_kprobe(event="nfs_file_read", fn_name="trace_read_and_write_entry")
b.attach_kprobe(event="nfs_file_write", fn_name="trace_read_and_write_entry")
b.attach_kprobe(event="nfs_file_open", fn_name="trace_file_open_entry")
b.attach_kprobe(event="nfs_getattr", fn_name="trace_getattr_entry")

# attach kretprobe - after the target function
b.attach_kretprobe(event="nfs_file_read", fn_name="trace_read_return")
b.attach_kretprobe(event="nfs_file_write", fn_name="trace_write_return")
b.attach_kretprobe(event="nfs_file_open", fn_name="trace_file_open_return")
b.attach_kretprobe(event="nfs_getattr", fn_name="trace_getattr_return")

# check for nfs4, if yes attach the kprobe and kretprobe
if BPF.get_kprobe_functions(b'nfs4_file_open'):
    b.attach_kprobe(event="nfs4_file_open", fn_name="trace_file_open_entry")
    b.attach_kretprobe(event="nfs4_file_open", fn_name="trace_file_open_return")

print("Tracing NFS operations ... ctrl-c to quit")
print("%-8s %-14s %-6s %1s %-7s %-8s %7s %s" % ("TIME", "COMM", "PID", "T", "BYTES", "OFF_KB", "LAT(ms)", "FILENAME"))

b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
