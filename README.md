Prevent libvirtd from adding iptables rules by calling /sbin/iptables or
/sbin/ip6tables. Let it call "iptables --version" though.

Compile with: gcc -shared -ldl -fPIC no-iptables.c -o no-iptables.so

If needed, add -DNOIPTABLES_DEBUG

Usage: LD_PRELOAD=/path/to/no-iptables.so libvirtd
