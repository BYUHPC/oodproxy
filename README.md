# oodproxy
BYU's oodproxy is a system designed to provide secure port forwarding for jobs running on a Slurm cluster. It enables users to access network ports open on a compute node, which are typically isolated from direct user access.

See the wiki for instructions: https://github.com/BYUHPC/oodproxy/wiki

Files are divided among the following directories:
- `client` - code for desktop/laptops to launch the VNC/RDP client program
- `compute_node/spank_oodproxy` - Slurm SPANK plugin to generate TLS certs and create allowed_destinations (see https://github.com/BYUHPC/oodproxy/wiki/spank_oodproxy)
- `ood_web` - code and configs to be run from the main OnDemand web server(s) (Apache)
- `proxy_server` - the OODProxy server setup itself
