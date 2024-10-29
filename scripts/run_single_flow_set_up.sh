iface=${1:-ens2f0}
sudo sysctl  net.nd.nd_default_sche_policy=0
sudo sysctl  net.nd.num_thpt_channels=1
sudo sysctl  net.nd.nd_num_dc_thread=4
sudo ethtool -G $iface rx 256
sudo sysctl net.nd.nd_ldcopy_tx_inflight_thre=91457280
sudo sysctl net.nd.nd_ldcopy_min_thre=0
sudo sysctl  net.nd.wmem_default=31457280
sudo sysctl  net.nd.rmem_default=31457280
sudo sysctl -w net.ipv4.tcp_rmem='4096 131072 3000000'
sudo ethtool -K $iface tso on gso on gro on lro off
sudo ifconfig $iface mtu 9000

sudo ~/NetChannel/scripts/enable_arfs.sh $iface
