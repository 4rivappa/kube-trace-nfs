Setup NFS traffic to EFS (Elastic File System)

  _              __  __ _         __                    __     
 | |_ _ __ __ _ / _|/ _(_) ___   / _| ___  _ __    ___ / _|___ 
 | __| '__/ _` | |_| |_| |/ __| | |_ / _ \| '__|  / _ \ |_/ __|
 | |_| | | (_| |  _|  _| | (__  |  _| (_) | |    |  __/  _\__ \
  \__|_|  \__,_|_| |_| |_|\___| |_|  \___/|_|     \___|_| |___/
                                                               

Helper scripts to setup basic traffic to and fro on AWS - EFS

    storage-class.yaml
        config to create storage class in cluster for specific efs mount
    
    persistent-volume.yaml
        config to create persistent volume from storage class
        * replace the <fs-id> with appropriate volumeHandler value of EFS
    
    efs-traffic.yaml
        config file to load efs-traffic deployment into cluster
        mount efs drive to pods from persistent volume claim
    
    command: kubectl apply -f file-name