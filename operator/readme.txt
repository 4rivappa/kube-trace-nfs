nfsslower tool (from bcc)

         __         _                        
  _ __  / _|___ ___| | _____      _____ _ __ 
 | '_ \| |_/ __/ __| |/ _ \ \ /\ / / _ \ '__|
 | | | |  _\__ \__ \ | (_) \ V  V /  __/ |   
 |_| |_|_| |___/___/_|\___/ \_/\_/ \___|_|   
                                             

BPF code

    ----
    
    bpf_get_current_pid_tgid function (no Params)
        
        used to get the details of processor id and thread group id
        when processor starts, it has an initial thread (this is the first thread of this new thread group)
        thread group id is same as the processor id, with which this thread group is being created

    ----

    bpf_ktime_get_ns function (no Params)
    
        this is a bpf helper function, to return the number of nanoseconds it elapsed from the start of the system
    
    ----
    
    trace_rw_entry has three inputs pt_regs, kiocb, iov_iter
        
        Parameters
            kiocb -> kernal I/O control block
                (https://sourcegraph.com/github.com/torvalds/linux@13a2e429f644691fca70049ea1c75f135957c788/-/blob/include/linux/fs.h?L364)
            pt_regs -> processor registers
            iov_iter -> interface for iterating over scatter-gather I/O vectors
    
        Values Utilized
            ki_filp (kiocb) -> pointer pointing to the struct 'file' (refer above link)
            ki_pos (kiocb) -> this is a type of loff_t, used to present file offsets and sizes (offset into file)
    
    ----
    
    trace_exit function
        
        Parameters
            pt_regs -> processor registers
            type -> type of event (read, write, getattr ...)
        
        Notable units
            PT_REGS_RC -> macro to get - return value stored in 'rc' register of pt_regs
            dentry -> directory entry - data structure used to represent entries in kernel's directory cache (part of virtual file system VFS)
                (https://sourcegraph.com/github.com/torvalds/linux@13a2e429f644691fca70049ea1c75f135957c788/-/blob/include/linux/dcache.h?L82)
                in the current nfs context, only the 'getattr' events have dentry values (from dcache.h)
            qs -> this is type of 'qstr' struct - we can observe, qs is being extracted from dentry's 'd_name' property, which is of type qstr struct
                (https://sourcegraph.com/github.com/torvalds/linux@13a2e429f644691fca70049ea1c75f135957c788/-/blob/include/linux/dcache.h?L49)
                qstr stands for quick string, which stores two parameters - name and the hash of the string !

    ----
    
    bpf_probe_read_kernel function
    
        Parameters
            destination buffer -> dest memory space, to copy the kernel data structure to
            source addr -> kernel datastructure to copy from
        
        Usage
            used to safely copy the kernel memory space's data structure to bpf's level memory space (without modifying the source kernel's space)

    ----
    
    bpf_get_current_comm function
        
        bpf helper function to get the current command
    
    ----
