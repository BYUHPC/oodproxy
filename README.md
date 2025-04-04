# oodproxy
BYU's oodproxy is a system designed to provide secure port forwarding for jobs running on a Slurm cluster. It enables users to access network ports open on a compute node, which are typically isolated from direct user access.

This allows a native VNC or RDP client running on a desktop to have a secure, direct connection all the way to a VNC server, [Gnome RDP server](https://gitlab.gnome.org/GNOME/gnome-remote-desktop), or [Windows VM](https://github.com/BYUHPC/7lbd) running in a job.

See the wiki for instructions: https://github.com/BYUHPC/oodproxy/wiki
