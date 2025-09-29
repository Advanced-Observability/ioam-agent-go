#!/bin/bash

# Script to test IOAM with fake network created using network namespaces

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root."
  exit
fi

# Remove namespaces
cleanup()
{
  ip netns delete encap || true
  ip netns delete transit || true
  ip netns delete decap || true
}

echo "Cleaning everything up..."
cleanup
echo -e "Done cleaning.\n"

echo "Adding network namespaces..."
ip netns add encap
ip netns add transit
ip netns add decap
echo -e "Done adding namespaces.\n"

echo "Listing network namespaces..."
ip netns list
echo -e "Done listing.\n"

echo "Creating links..."
# encap <-> transit link
ip link add ioam-veth-encap netns encap type veth peer ioam-veth-t-e netns transit

# transit <-> decap link
ip link add ioam-veth-decap netns decap type veth peer ioam-veth-t-d netns transit
echo -e "Done creating links.\n"

echo "Renaming interfaces..."
# rename links: encap (veth0) <-> (veth0) transit (veth1) <-> (veth0) decap
ip -netns encap link set ioam-veth-encap name veth0
ip -netns decap link set ioam-veth-decap name veth0
ip -netns transit link set ioam-veth-t-e name veth0
ip -netns transit link set ioam-veth-t-d name veth1
echo -e "Done renaming interfaces.\n"

echo "Setting IPv6 addresses..."
# db01::1/64 <-> db01::2/64 | db02::2/64 <-> db02::1/64
ip -netns encap addr add db01::1/64 dev veth0
ip -netns transit addr add db01::2/64 dev veth0
ip -netns transit addr add db02::2/64 dev veth1
ip -netns decap addr add db02::1/64 dev veth0
echo -e "Done setting addresses.\n"

echo "Turning interfaces up..."
ip -netns encap link set veth0 up
ip -netns transit link set veth0 up
ip -netns transit link set veth1 up
ip -netns decap link set veth0 up
echo -e "Done turning interfaces up\n"

echo "Turning loopback interfaces up..."
ip -netns encap link set lo up
ip -netns transit link set lo up
ip -netns transit link set lo up
ip -netns decap link set lo up
echo -e "Done turning loopback interfaces up\n"

echo "Setting routes..."
#ip -netns encap route add db02::/64 via db01::2 dev veth0
ip -netns encap route add db02::/64 encap ioam6 mode inline trace prealloc type 0xf6e000 ns 123 size 96 via db01::2 dev veth0
ip -netns decap route add db01::/64 via db02::2 dev veth0
echo -e "Done set routes\n"

echo "Setting forwarding on transit node..."
ip netns exec transit sysctl -w net.ipv6.conf.all.forwarding=1
echo -e "Done setting forwarding on transit.\n"

echo "Sysctl on encap..."
ip netns exec encap sysctl -w net.ipv6.ioam6_id=1
ip netns exec encap sysctl -w net.ipv6.ioam6_id_wide=1
ip netns exec encap sysctl -w net.ipv6.conf.veth0.ioam6_enabled=1
ip netns exec encap sysctl -w net.ipv6.conf.veth0.ioam6_id=1
ip netns exec encap sysctl -w net.ipv6.conf.veth0.ioam6_id_wide=1
ip -netns encap ioam namespace add 123 data 12345678 wide deadcafedeadcafe

echo "Sysctl on transit..."
ip netns exec transit sysctl -w net.ipv6.ioam6_id=2
ip netns exec transit sysctl -w net.ipv6.ioam6_id_wide=2
ip netns exec transit sysctl -w net.ipv6.conf.veth0.ioam6_enabled=1
ip netns exec transit sysctl -w net.ipv6.conf.veth0.ioam6_id=2
ip netns exec transit sysctl -w net.ipv6.conf.veth0.ioam6_id_wide=2
ip netns exec transit sysctl -w net.ipv6.conf.veth1.ioam6_enabled=1
ip netns exec transit sysctl -w net.ipv6.conf.veth1.ioam6_id=2
ip netns exec transit sysctl -w net.ipv6.conf.veth1.ioam6_id_wide=2
ip -netns transit ioam namespace add 123 data 12345678 wide deadcafedeadcafe

echo "Sysctl on decap..."
ip netns exec decap sysctl -w net.ipv6.ioam6_id=3
ip netns exec decap sysctl -w net.ipv6.ioam6_id_wide=3
ip netns exec decap sysctl -w net.ipv6.conf.veth0.ioam6_enabled=1
ip netns exec decap sysctl -w net.ipv6.conf.veth0.ioam6_id=3
ip netns exec decap sysctl -w net.ipv6.conf.veth0.ioam6_id_wide=3
ip -netns decap ioam namespace add 123 data 12345678 wide deadcafedeadcafe

echo -e "\nSleeping for 2 seconds..."
sleep 2

echo -e "\n\n** TESTING **"
#sudo ip netns exec encap ping -c 1 db01::1
#sudo ip netns exec encap ping -c 1 db01::2
ip netns exec encap ping db02::1
#sudo ip netns exec encap ping -c 1 db02::2
echo -e "\n\n** DONE **\n\n"
