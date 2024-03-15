#
# 
echo 4 > /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages
mkdir -p /mnt/huge_1GB
mount -t hugetlbfs -o pagesize=1G none /mnt/huge_1GB

#
tibit_int=eno7
ctrl_int=eno6 # 0000:b7:00.1
traf_int=eno4 # 0000:67:00.3
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
ethtool -K $tibit_int rxhash on
