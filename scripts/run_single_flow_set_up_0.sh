iface=${1:-ens2f0}
sudo sysctl  net.nd.nd_default_sche_policy=0
sudo sysctl  net.nd.num_thpt_channels=1
sudo sysctl  net.nd.nd_num_dc_thread=0
sudo ethtool -G $iface rx 256
sudo sysctl  net.nd.wmem_default=3289600
sudo sysctl  net.nd.rmem_default=3000000
sudo sysctl -w net.ipv4.tcp_rmem='4096 131072 3000000'
sudo ethtool -K $iface tso on gso on gro on lro off
sudo ifconfig $iface mtu 9000
