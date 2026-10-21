#!/bin/sh
set -eu
# This network namespace is shared only by the two decoys.
# Reply packets to inbound sessions are allowed. New outbound TCP, UDP and
# loopback sessions (including DNS/callbacks/SSH forwarding) are denied.
iptables -P OUTPUT DROP
iptables -F OUTPUT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# IPv6 is disabled by the service sysctl; assert that before declaring ready.
test "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" = 1
exec sleep infinity
