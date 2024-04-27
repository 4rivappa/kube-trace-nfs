Trace NFS traffic

  _          _            _                               __     
 | | ___   _| |__   ___  | |_ _ __ __ _  ___ ___   _ __  / _|___ 
 | |/ / | | | '_ \ / _ \ | __| '__/ _` |/ __/ _ \ | '_ \| |_/ __|
 |   <| |_| | |_) |  __/ | |_| | | (_| | (_|  __/ | | | |  _\__ \
 |_|\_\\__,_|_.__/ \___|  \__|_|  \__,_|\___\___| |_| |_|_| |___/
                                                                

This application is designed to assist in pinpointing causes of spikes in NFS (Network File System) traffic within the cluster
It can be accomplished by collecting and analyzing telemetry data of NFS operations collected through eBPF (https://ebpf.io/) 

specifically focusing on:
    Reads, Writes, Opens, GetAttrs

Collected data can be exported to monitoring tools (Prometheus) and visualized on various platforms (like Grafana)

This comprehensive data allows for analysis at both the node and pod levels, 
providing valuable insights into how NFS traffic is distributed across the cluster

Additionally, the application aims to provide a ranking of files that have experienced the most traffic, 
further aiding in the identification of potential bottlenecks

----

config to deploy operator as a daemonset

    deployment.yaml
        config to create daemonset, which includes init container to install linux headers
