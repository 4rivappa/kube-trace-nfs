from bcc import BPF

bpf_object = BPF(text='int kprobe__sys_clone(void *ctx) { bpf_trace_printk("Hello, World!\\n"); return 0; }')
bpf_object.trace_print()