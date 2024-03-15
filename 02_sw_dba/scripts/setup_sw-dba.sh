#
# 
echo 4 > /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages
mkdir -p /mnt/huge_1GB
mount -t hugetlbfs -o pagesize=1G none /mnt/huge_1GB

#
tibit_int=ens4f0
ctrl_int=ens1f1 # 0000:10:00.1
traf_int=ens1f0 # 0000:10:00.0
#
ctrl_businfo=$(ethtool -i $ctrl_int |grep bus-info | awk '{print $2'})

traf_businfo=$(ethtool -i $traf_int |grep bus-info | awk '{print $2'})

echo $ctrl_businfo
echo $traf_businfo

# Check if ctrl_businfo is set and non-empty
if [ -n "$ctrl_businfo" ]; then
    dpdk-devbind.py -b vfio-pci $ctrl_businfo
else
    echo "Control bus info is not set."
fi

# Check if traf_businfo is set and non-empty
if [ -n "$traf_businfo" ]; then
    dpdk-devbind.py -b vfio-pci $traf_businfo
else
    echo "Traffic bus info is not set."
fi

ethtool -L $tibit_int combined 2
ifconfig $tibit_int promisc up
ifconfig $tibit_int mtu 3000
ethtool -K $tibit_int rxhash on
