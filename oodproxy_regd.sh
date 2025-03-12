#!/bin/bash


# Wait for the job script to write to the fd that signals registration is ready
head -c 1 <&0 >/dev/null

# This isn't the prettiest. Currently we grab the hostname, hostname -f, and all global IPs.
# Maybe we shouldn't bother with IPs?
#hosts="$(hostname) $(hostname -f) $(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | tr '\n' ' ')"
hosts="$(hostname) $(hostname -f)"

# Grab the list of IP:ports that are being listened on. lsof prefixes the relevant lines with "n".
# "*" is what you will usually see for the IP, but maybe there are reasons for someone to bind to a specific "global" IP?
# I couldn't find a way to only include global scope entries with lsof, so we'll do a crude mechanism to exclude the 127/8 and 169.254/16 ranges.
# I debated also adding support for IPv6 but decided against it for now. If this is desirable, you should just be able to stop limiting it to IPv4.
ports=$(lsof -wa -i tcp -i udp +sTCP:LISTEN +i4 -Pnp $(cat /sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)/cgroup.procs |paste -sd ,) -F n | awk '$1 ~ /^n/ && $1 !~ /^n127|^n169\.254/ { print; }' | sort -u | tr '\n' ' ')

# Add an entry per host and port combination. "*" expands it to write an entry per host for that port.
for p in $ports
do
	ip=$(sed -e 's/^n//' -e 's/:[^:]*$//' <<<"$p")
	port=$(awk -F: '{print $NF}' <<<"$p")

	if [[ "$ip" == "*" ]]
	then
		for host in $hosts
		do
			echo "$host:$port"
		done
	else
		echo "$ip:$port"
	fi
done
