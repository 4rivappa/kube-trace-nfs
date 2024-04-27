Setup kubernetes cluster using eksctl

       _             _   _ 
   ___| | _____  ___| |_| |
  / _ \ |/ / __|/ __| __| |
 |  __/   <\__ \ (__| |_| |
  \___|_|\_\___/\___|\__|_|
                           

using eksctl to setup cluster on aws

    config.yaml
        config file for cluster
    
    install-eksctl.sh
        installation script for eksctl

---
    
steps to configure CSI on eks cluster

    - configure IAM OIDC provider for cluster
        link: https://docs.aws.amazon.com/eks/latest/userguide/enable-iam-roles-for-service-accounts.html
    
    - setting up CSI driver
        link: https://docs.aws.amazon.com/eks/latest/userguide/efs-csi.html

    - installing efs-csi-driver
        setup driver from EKS add-ons, by using above created OIDC role