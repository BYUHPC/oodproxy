all:
	gcc -I/usr/local/src/slurm -fPIC -shared -lcap -o spank_oodproxy.so spank_oodproxy.c

install: all
	@echo "You need to manually copy the spank_oodproxy.so file to /apps/slurm/SLURMVERSION/lib/slurm/"
	@exit 1
