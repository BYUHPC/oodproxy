# Proxy Server Script and Configuration

The proxy server for BYU's OODProxy needs to be installed on a system that
meets three different criteria:
1. Accessible externally
2. Can connect to compute nodes
3. Mounts a shared file system also accessible on OOD servers and cluster nodes

The proxy server can be hosted on OOD servers, reverse proxy servers, or
any other servers that meet the above criteria.

There are two critical files:
- `proxy_server/config/stunnel.conf`
- `bin/handle_incoming_stunnel_fd`

One is the stunnel configuration and the other is a script that is run by
stunnel.

systemd files are:
- `/usr/lib/systemd/system/stunnel-oodproxy@.service`
- `/usr/lib/systemd/system/stunnel-oodproxy.socket`

Examples are included.
