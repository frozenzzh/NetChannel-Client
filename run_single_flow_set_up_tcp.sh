sudo sysctl  net.nd.nd_default_sche_policy=0
sudo sysctl  net.nd.num_thpt_channels=1
sudo sysctl  net.nd.nd_num_dc_thread=1
sudo ethtool -G ens2f0 rx 1024
sudo sysctl  net.nd.wmem_default=3289600
sudo sysctl  net.nd.rmem_default=3000000
sudo sysctl -w net.ipv4.tcp_rmem='4096 131072 6291456'
