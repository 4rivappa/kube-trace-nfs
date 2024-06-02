# Kube Trace NFS

![image](https://github.com/4rivappa/kube-trace-nfs/assets/114223788/3e67ef41-13ca-424a-8c1c-e5fb0cc7ee26)

## Overview

Kube Trace NFS is designed to **observe NFS connections in a Kubernetes cluster** by collecting telemetry data from a node-level **eBPF program**, utilizing the BCC tool. Inspired by the `nfsslower` tool and other **BCC utilities**, this application focuses specifically on NFS operations such as **reads, writes, opens, and getattrs**.

Currently, the application collects **node-level metrics**, with **pod-level metrics** and the ranking of the **most accessed files** planned for upcoming versions. Collected data can be **exported to monitoring tools** like Prometheus and **visualized on platforms** such as Grafana. This comprehensive data provides valuable insights into how NFS traffic is distributed across the cluster.

## Motivation

Many cloud providers offer **storage through NFS protocol**, which can be attached to **Kubernetes clusters via CSI** (Container Storage Interface). However, the monitoring provided by storage providers often **aggregates data for all NFS client connections**. This aggregation makes it **difficult to isolate and monitor specific connections** and their operations such as reads, writes, and getattrs to the NFS server. This project **addresses this challenge** by offering detailed **telemetry data of NFS requests** from clients to the server, facilitating both node-level and pod-level analysis. Leveraging Prometheus and Grafana, this data **enables comprehensive analysis of NFS traffic**, empowering users to gain valuable insights into their cluster's NFS interactions.

## Features

- **[eBPF](https://ebpf.io/what-is-ebpf#what-is-ebpf)-based** efficient and low-overhead monitoring
- Provide **byte throughput** metrics for read/write operations
- **Latency and occurrence rate** of read, write, open, and getattr operations
- Potential for metrics related to **IOPS and file-level access**

## Architecture

![image](https://github.com/4rivappa/kube-trace-nfs/assets/114223788/7f87e006-0965-4363-986e-2fddd77f8304)

> K (Kernel): kprobe, eBPF program

> U (User space): kube-trace-nfs, nfs-client, other pods

The `nfs client` establishes a connection with the `nfs server` to furnish storage for pods, a process routed through kernel programs. `kube-trace-nfs` attaches `eBPF program` to nfs `kprobes` to capture metrics concerning events occurring within nfs clients. These metrics are stored in **eBPF maps** and undergo processing for event analysis. Events involving read, write, open, and getattr operations are forwarded to the user space component `kube-trace-nfs`. Subsequently, these values are exported to **Prometheus**, from where the data can be leveraged in various visualization tools such as **Grafana**.


