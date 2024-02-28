#
# 
echo 4 > /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages
#
tibit_int=eno7
#
ctrl_businfo=$(ethtool -i $ctrl_int |grep bus-info | awk '{print $2'})

echo $ctrl_businfo

# Check if ctrl_businfo is set and non-empty
if [ -n "$ctrl_businfo" ]; then
    dpdk-devbind.py -b vfio-pci $ctrl_businfo
else
    echo "Control bus info is not set."
fi

ethtool -L $tibit_int combined 2
ifconfig $tibit_int promisc up
ethtool -K $tibit_int rxhash on
