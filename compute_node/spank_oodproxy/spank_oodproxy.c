/*
* Author: Ryan Cox
* 
* Copyright (C) 2025, Brigham Young University
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, see
* <https://www.gnu.org/licenses/>.
*
*
* Compile with: gcc -I/usr/local/src/slurm -fPIC -shared -lcap -o spank_oodproxy{.so,.c}
*
*/

#define _GNU_SOURCE
#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <slurm/spank.h>
#include <stdbool.h>
#include <limits.h>

#include <sys/stat.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/syscall.h>

/* For dropping privs */
#include <grp.h>
#include <sys/capability.h>
#include <pwd.h>

/* Plugin identifier */
#define SPANK_MODULE_NAME_LC "spank_oodproxy"

/* Environment variable names */
#define ENVVAR_NAME_REG_READY_FD "OODPROXY_REG_READY_FD" /* File descriptor to which the job writes when ports are open */
#define ENVVAR_NAME_OODPROXY_DIR "OODPROXY_DIR" /* Directory where certificates are stored */

#define ALLOWED_DESTINATIONS_FILENAME "allowed_destinations" /* Filename for storing allowed host:port combinations */

/* String size constants */
#define UINT32_STR_SIZE 12           /* Size for uint32 string representations (includes sign for safety) */
#define ENVVAR_VALUE_MAXLEN 128      /* Maximum length for environment variable values */
#define PATH_MAXLEN 4096             /* Maximum length for file paths */

/*
 * Syscall definitions for pidfd functionality
 * These are used for race-free process management of the registration daemon
 * As of the time of this writing, pidfd_open, et al. do not have a wrapper
 */
#if defined(__x86_64__)
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif
#elif defined(__aarch64__)
/* Add ARM64 syscall numbers if needed */
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif
#else
#error "Architecture not supported"
#endif

#ifndef P_PIDFD
#define P_PIDFD 3
#endif


/* Macros for pidfd operations not currently provided by libc */
#ifndef pidfd_open
#define pidfd_open(pid, flags) syscall(SYS_pidfd_open, (pid), (flags))
#endif

#ifndef pidfd_send_signal
#define pidfd_send_signal(pidfd, sig, info, flags) \
    syscall(SYS_pidfd_send_signal, (pidfd), (sig), (info), (flags))
#endif

/* Register the SPANK plugin */
SPANK_PLUGIN(SPANK_MODULE_NAME_LC, 1);

/* Function prototypes */
static int _spank_opt_process(int val, const char *optarg, int remote);
int _drop_privs(uid_t job_uid, gid_t job_gid);

/* Global variables */
static bool spank_plugin_active = false;
static int opt_fd_count = -1;
static int allowed_destinations_fd = -1;
static char allowed_destinations_path[PATH_MAXLEN];
int regd_pidfd = -1;

/* Configuration parameters from plugstack.conf */
static char *PATH_envstr = NULL;
static char *registration_daemon_path = NULL;
static char *oodproxy_root_dir = NULL;
static char *gencerts_path = NULL;
static gid_t webserver_gid = -1;

/* Directory structure paths */
static char uid_dir[PATH_MAXLEN], job_dir[PATH_MAXLEN];

/* Define command line options for sbatch */
struct spank_option spank_opts[] =
{
	{
		"oodproxy-register",
		"1",
		"Internal use only.",
		1,
		0,
		(spank_opt_cb_f) _spank_opt_process
	},
	SPANK_OPTIONS_TABLE_END
};

/*
 * User initialization function - called for each task after privileges are dropped
 * Not currently used, but required by SPANK API
 */
int slurm_spank_user_init (spank_t sp, int argc, char **argv) {
	return 0;
}

/*
 * Drop privileges from root to the job user
 * This ensures that child processes run with the correct permissions
 *
 * Args:
 *   job_uid: uid drop to
 *   job_gid: gid to drop to
 *
 * Returns:
 *   ESPANK_SUCCESS on success, ESPANK_ERROR on failure
 */
int _drop_privs(uid_t job_uid, gid_t job_gid) {
	struct passwd *pw;
	cap_t caps;
	int retval;

	/* Get the passwd entry for the user */
	pw = getpwuid(job_uid);
	if (!pw) {
		slurm_error(SPANK_MODULE_NAME_LC ": getpwuid: %m");
		return ESPANK_ERROR;
	}

	/* Initialize supplementary groups for the user */
	retval = initgroups(pw->pw_name, job_gid);
	if (retval) {
		slurm_error(SPANK_MODULE_NAME_LC ": initgroups: %m");
		return ESPANK_ERROR;
	}

	/* Set real, effective, and saved group IDs */
	retval = setresgid(job_gid, job_gid, job_gid);
	if (retval) {
		slurm_error(SPANK_MODULE_NAME_LC ": setresgid: %m");
		return ESPANK_ERROR;
	}

	/* Set real, effective, and saved user IDs */
	retval = setresuid(job_uid, job_uid, job_uid);
	if (retval) {
		slurm_error(SPANK_MODULE_NAME_LC ": setresuid: %m");
		return ESPANK_ERROR;
	}

	/* Drop all capabilities */
	caps = cap_init();
	if (!caps) {
		slurm_error(SPANK_MODULE_NAME_LC ": cap_init: %m");
		return ESPANK_ERROR;
	}

	retval = cap_set_proc(caps);
	if (retval) {
		slurm_error(SPANK_MODULE_NAME_LC ": cap_set_proc: %m");
		cap_free(caps);
		return ESPANK_ERROR;
	}

	retval = cap_free(caps);
	if (retval) {
		slurm_error(SPANK_MODULE_NAME_LC ": cap_free: %m");
		return ESPANK_ERROR;
	}

	return ESPANK_SUCCESS;
}

/*
 * Task initialization function (privileged) - called for each task before it is started
 * This is where most of the plugin's work happens:
 * - Create directories
 * - Generate certificates
 * - Launch the registration daemon
 *
 * Args:
 *   sp: SPANK handle
 *   argc: Number of plugin arguments
 *   argv: Plugin arguments
 *
 * Returns:
 *   ESPANK_SUCCESS on success, ESPANK_ERROR on failure
 */
int slurm_spank_task_init_privileged (spank_t sp, int argc, char **argv) {
	pid_t child;
	int status, retval, envvar_idx, actual_fd_count = 0;
	spank_err_t rc;
	int pipefd[2];
	uid_t job_uid;
	gid_t job_gid;
	u_int32_t job_id;

	if (!spank_plugin_active) {
		return 0;
	}

	/* Only execute in the remote (slurmstepd) context */
	if (!spank_remote(sp))
		return 0;

	if (spank_context() != S_CTX_REMOTE)
		return 0;

	slurm_info(SPANK_MODULE_NAME_LC ": slurm_spank_task_init_privileged running");

	/* Create user directory if it doesn't exist */
	retval = mkdir(uid_dir, 0750);
	if (retval != 0 && errno != EEXIST) {
		slurm_error("error: Could not mkdir %s: %m", uid_dir);
		return ESPANK_ERROR;
	}

	/* Set ownership of user directory */
	retval = chown(uid_dir, getuid(), webserver_gid);
	if (retval) {
		slurm_error("error: Could not chown %s: %m", uid_dir);
		return ESPANK_ERROR;
	}

	/* Create job directory if it doesn't exist */
	retval = mkdir(job_dir, 0750);
	if (retval != 0 && errno != EEXIST) {
		slurm_error("error: Could not mkdir %s: %m", job_dir);
		return ESPANK_ERROR;
	}

	/* Set ownership of job directory */
	retval = chown(job_dir, getuid(), webserver_gid);
	if (retval) {
		slurm_error("error: Could not chown %s: %m", job_dir);
		return ESPANK_ERROR;
	}

	/* Get job information from SPANK */
	spank_get_item(sp, S_JOB_ID, &job_id);
	spank_get_item(sp, S_JOB_UID, &job_uid);
	spank_get_item(sp, S_JOB_GID, &job_gid);

	/*
	 * Create temporary directory for certificates
	 * I'm not entirely sure that TMPDIR can be trusted here if it is set.  Is there a way for a user to
	 * set it maliciously? Let's just use /tmp and let someone patch it if they want configurability (sorry).
	 */
	char oodproxy_cert_dir_template[64] = "/tmp/.oodproxy-XXXXXX";
	char *oodproxy_cert_dir;

	oodproxy_cert_dir = mkdtemp(oodproxy_cert_dir_template);
	if (oodproxy_cert_dir == NULL) {
		slurm_error("error: Could not mkdtemp with template '%s': %m", oodproxy_cert_dir_template);
		return ESPANK_ERROR;
	}

	/* Prepare environment variables for certificate generation */
	char oodproxy_cert_dir_envstr[ENVVAR_VALUE_MAXLEN];
	snprintf(oodproxy_cert_dir_envstr, ENVVAR_VALUE_MAXLEN, "%s=%s", ENVVAR_NAME_OODPROXY_DIR, oodproxy_cert_dir);

	char job_uid_envstr[ENVVAR_VALUE_MAXLEN], job_gid_envstr[ENVVAR_VALUE_MAXLEN], job_id_envstr[ENVVAR_VALUE_MAXLEN];
	snprintf(job_uid_envstr, ENVVAR_VALUE_MAXLEN, "SLURM_JOB_UID=%u", job_uid);
	snprintf(job_gid_envstr, ENVVAR_VALUE_MAXLEN, "SLURM_JOB_GID=%u", job_gid);
	snprintf(job_id_envstr, ENVVAR_VALUE_MAXLEN, "SLURM_JOB_ID=%u", job_id);

	/* Set the OODPROXY_DIR environment variable for the job */
	spank_setenv(sp, ENVVAR_NAME_OODPROXY_DIR, oodproxy_cert_dir, 1);
        setenv(ENVVAR_NAME_OODPROXY_DIR, oodproxy_cert_dir, 1);

	/* Fork and execute the certificate generation script */
	child = fork();
	if (child == 0) {
		/* Child. Close all unnecessary file descriptors */
		int fdlimit = (int)sysconf(_SC_OPEN_MAX);
		for (int i = 3; i < fdlimit; i++) {
			close(i);
		}

		/* Change to job directory before running cert generation */
		retval = chdir(job_dir);
		if (retval) {
			slurm_error("Could not chdir to '%s' for launching cert creation");
			exit(1);
		}

		/* Execute certificate generation script */
		char *gencerts_argv[] = { "bash", gencerts_path, "create", NULL };
		char *exec_env[] = { PATH_envstr, job_uid_envstr, job_gid_envstr, job_id_envstr, oodproxy_cert_dir_envstr, NULL };
		execve("/bin/bash", gencerts_argv, exec_env);

		/* Should never reach here */
		slurm_error("execve failed: %m");
		exit(1);
	}

	/* Parent process waits for certificate generation to complete */
	if (waitpid(child, &status, 0) == -1) {
		slurm_error("waitpid on %s fork: %m", gencerts_path);
		return ESPANK_ERROR;
	} else {
		if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
			slurm_error("%s exited with non-zero status: %d\n", gencerts_path, WEXITSTATUS(status));
			return ESPANK_ERROR;
		} else if (WIFSIGNALED(status)) {
			slurm_error("%s was terminated by signal: %d\n", gencerts_path, WTERMSIG(status));
			return ESPANK_ERROR;
		}
	}

	/* Create the allowed_destinations file and leave it open for the registration daemon */
	allowed_destinations_fd = open(allowed_destinations_path, O_WRONLY | O_CREAT | O_EXCL | O_SYNC, 0640);
	if (allowed_destinations_fd < 0) {
		slurm_error("Could not create %s for writing: %m", allowed_destinations_path);
		return ESPANK_ERROR;
	} else {
		slurm_info(SPANK_MODULE_NAME_LC ": Created %s for writing at fd %d. Success.", allowed_destinations_path, allowed_destinations_fd);
	}

	/* Set proper ownership on the allowed_destinations file */
	retval = fchown(allowed_destinations_fd, getuid(), webserver_gid);
	if (retval) {
		slurm_error("error: Could not fchown %s: %m", allowed_destinations_path);
		return ESPANK_ERROR;
	}

	/* Create a pipe for communication with the registration daemon */
	retval = pipe(pipefd);
	if (retval) {
		slurm_error("error: Could not create pipe: %m");
		return ESPANK_ERROR;
	}

	/* Fork and execute the registration daemon script */
	child = fork();
	if (child == 0) {
		/* Child. Drop privileges to job user */
		_drop_privs(job_uid, job_gid);

		/* Close all unnecessary file descriptors, keeping only pipe and allowed_destinations file */
		int fdlimit = (int)sysconf(_SC_OPEN_MAX);
		for (int i = 0; i < fdlimit; i++) {
			if (i != pipefd[0] && i != allowed_destinations_fd) {
				close(i);
			}
		}

		/* Set up standard I/O for the registration daemon */
		dup2(pipefd[0], 0); /* Read pipe becomes stdin */
		close(pipefd[0]);
		dup2(allowed_destinations_fd, 1); /* allowed_destinations file becomes stdout */
		close(allowed_destinations_fd);

		/* Execute registration daemon with proper environment */
		char *registration_daemon_argv[] = { "bash", registration_daemon_path, NULL };
		char *exec_env[] = { PATH_envstr, NULL };
		execve("/bin/bash", registration_daemon_argv, exec_env);

		/* Should never reach here */
		slurm_error("execve failed: %m"); // should never get here
		exit(1);
	} else {
		/* Parent. Obtain a pidfd for the registration daemon, allowing for race-free process management.
		 * pidfd_open is guaranteed to be race-free according to pidfd_open(2) as long as we follow certain rules,
		 * which we do */
		regd_pidfd = pidfd_open(child, 0);
		if (regd_pidfd < 0) {
			slurm_error("pidfd_open on registration daemon pid %d failed: %m");
			return ESPANK_ERROR;
		}
	}

	/* Parent no longer needs these file descriptors */
	close(pipefd[0]);
	close(allowed_destinations_fd);

	slurm_debug(SPANK_MODULE_NAME_LC ": forked %s as pid %d", registration_daemon_path, child);

	/* Export the file descriptor to the job environment for signaling readiness */
	char regfd_str[10];
	snprintf(regfd_str, 10, "%d", pipefd[1]);
        spank_setenv(sp, ENVVAR_NAME_REG_READY_FD, regfd_str, 1);
        setenv(ENVVAR_NAME_REG_READY_FD, regfd_str, 1);

	return ESPANK_SUCCESS;
}

/*
 * Task initialization function - called for each task after it begins execution
 * Currently not doing much, but kept for future expansion
 *
 * Args:
 *   sp: SPANK handle
 *   argc: Number of plugin arguments
 *   argv: Plugin arguments
 *
 * Returns:
 *   ESPANK_SUCCESS on success, ESPANK_ERROR on failure
 */
int slurm_spank_task_init (spank_t sp, int argc, char **argv) {
	int retval = 0;
	if (!spank_plugin_active) {
		return 0;
	}

	/* only work on the remote side */
	if (!spank_remote(sp))
		return 0;

	/* only work on the "remote" (meaning slurmstepd) context */
	if (spank_context() != S_CTX_REMOTE)
		return 0;

	slurm_info(SPANK_MODULE_NAME_LC ": slurm_spank_task_init running as uid %u from pid %d", getuid(), getpid());
	return retval;
}

/*
 * Task exit function - called for each task as it exits
 * Handles cleanup of certificates and registration daemon
 *
 * Args:
 *   sp: SPANK handle
 *   argc: Number of plugin arguments
 *   argv: Plugin arguments
 *
 * Returns:
 *   ESPANK_SUCCESS on success, ESPANK_ERROR on failure
 */
int slurm_spank_task_exit (spank_t sp, int argc, char **argv) {
	pid_t child;
	int status, retval;
	spank_err_t rc = ESPANK_SUCCESS;
	uid_t job_uid;
	gid_t job_gid;
	u_int32_t job_id;

	if (!spank_plugin_active) {
		goto cleanup;
	}

	/* Only execute in the remote (slurmstepd) context */
	if (!spank_remote(sp)) {
		goto cleanup;
	}

	if (spank_context() != S_CTX_REMOTE) {
		goto cleanup;
	}

	/* Kill the registration daemon if it's alive so that it closes the allowed_destinations_path file.
	 * Error checking should not be needed because it should either be dead, this should kill it, or
	 * there's really not much we can do about it anyway. */
	if (regd_pidfd > -1) {
		pidfd_send_signal(regd_pidfd, SIGKILL, NULL, 0);
		waitid(P_PIDFD, regd_pidfd, NULL, WEXITED);
	}

	/* Remove the allowed_destinations file */
	retval = unlink(allowed_destinations_path);
	if (retval) {
		slurm_error("Could not unlink '%s': %m", allowed_destinations_path);
		/* not returning an error since this is not really a fatal condition */
	}

	/* Fork and execute the certificate cleanup script */
	child = fork();
	if (child == 0) {
		/* Child. Close all unnecessary file descriptors. */
		int fdlimit = (int)sysconf(_SC_OPEN_MAX);
		for (int i = 3; i < fdlimit; i++) {
			close(i);
		}

		/* Change to job directory before running cleanup */
		retval = chdir(job_dir);
		if (retval) {
			slurm_error("Could not chdir to '%s' for launching cert destruction");
			exit(1);
		}

		/* Execute certificate cleanup script */
		char *gencerts_argv[] = { "bash", gencerts_path, "destroy", NULL };
		char *exec_env[] = { PATH_envstr, NULL };
		execve("/bin/bash", gencerts_argv, exec_env);

		/* Should never reach here */
		slurm_error("execve failed: %m"); // should never get here
		exit(1);
	}

	/* Parent waits for certificate cleanup to complete */
	if (waitpid(child, &status, 0) == -1) {
		slurm_error("waitpid on %s fork: %m", gencerts_path);
	} else {
		if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
			slurm_error("%s exited with non-zero status: %d\n", gencerts_path, WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			slurm_error("%s was terminated by signal: %d\n", gencerts_path, WTERMSIG(status));
		}
	}

	/* This is here for a very annoying reason. If the registration daemon was never talked to and thus never exited,
	 * it will be holding an open file descriptor for the allowed_destinations_path file.  At this point, we already
	 * killed it AND waited for it, but NFS has not necessarily removed its .nfs file inside the directory. This
	 * typically solves the problem but I would love to hear if there's a better way. Please let me know. In my
	 * testing I am getting <= 5 tries at 50000 microseconds apart over NFS. */
	int i = 0;
	while ( (retval = rmdir(job_dir)) && i < 100 ) {
		usleep(50000);
		i++;
	}

	/* Log directory contents if removal failed */
/*	if (retval) {
		slurm_error("rmdir '%s' failed: %m", job_dir);
		DIR *dir;
		struct dirent *entry;

		dir = opendir(job_dir);
		if (dir) {
			while ((entry = readdir(dir)) != NULL) {
				slurm_error("  file in dir: %s", entry->d_name);
			}
			closedir(dir);
		} else {
			slurm_error("  failed to open dir for listing: %m");
		}
	}
*/

cleanup:
/*	if (opt_options) {
		free(opt_options);
	}*/
	return rc;
}

/*
 * Plugin exit function - called when the plugin itself is unloaded
 * Currently not used, but required by SPANK API
 */
int slurm_spank_exit (spank_t sp, int argc, char **argv) {
	return ESPANK_SUCCESS;
}

/*
 * Process command-line option values
 * Validates the oodproxy-register option value
 *
 * Args:
 *   val: Option identifier
 *   optarg: Option argument value
 *   remote: Whether option was specified remotely
 *
 * Returns:
 *   ESPANK_SUCCESS on success, ESPANK_ERROR on failure
 */
static int _spank_opt_process(int val, const char *optarg, int remote)
{
	spank_err_t err;
	int value = -1;

	/* Parse and validate the option value */
	value = atoi(optarg);
	if (value == 1) {
		spank_plugin_active = true;
		return ESPANK_SUCCESS;
	} else {
		slurm_error("spank_oodproxy: parameter must be set to 1");
		return ESPANK_ERROR;
	}
}

/*
 * Parse a plugin argument from plugstack.conf
 * Handles configuration parameters like registration_daemon, oodproxy_root, etc.
 *
 * Args:
 *   arg: Argument string from plugstack.conf
 *
 * Returns:
 *   ESPANK_SUCCESS on success, ESPANK_ERROR on failure
 */
spank_err_t _parse_spank_arg(char *arg) {
	if (!strncmp("registration_daemon=", arg, 20)) {
		registration_daemon_path = arg+20;
	} else if (!strncmp("oodproxy_root=", arg, 14)) {
		oodproxy_root_dir = arg+14;
	} else if (!strncmp("gencerts=", arg, 9)) {
		gencerts_path = arg+9;
	} else if (!strncmp("PATH=", arg, 5)) {
		/* As a shortcut, include the PATH= in this since it is fed straight to execve */
		PATH_envstr = arg;
	} else if (!strncmp("webserver_gid=", arg, 14)) {
		char *endptr;
		/* Parse GID value from number or group name */
		long gid = strtol(arg+14, &endptr, 10);
		if (*endptr == '\0' && gid >= 0 && gid <= UINT_MAX) {
			/* Valid numeric GID */
			webserver_gid = (gid_t)gid;
		} else {
			/* Try looking up group name */
			struct group *gr = getgrnam(arg+14);
			if (gr) {
				webserver_gid = gr->gr_gid;
			} else {
				slurm_error(SPANK_MODULE_NAME_LC ": invalid webserver_gid value '%s'", arg+14);
				return ESPANK_ERROR;
			}
		}
	} else {
		 slurm_info(SPANK_MODULE_NAME_LC ": unknown plugin parameter '%s' from plugstack.conf", arg);
		return ESPANK_ERROR;
	}
	return ESPANK_SUCCESS;
}

/*
 * Plugin initialization function - called when the plugin is loaded
 * Handles option registration and configuration parsing
 *
 * Args:
 *   sp: SPANK handle
 *   argc: Number of plugin arguments
 *   argv: Plugin arguments
 *
 * Returns:
 *   ESPANK_SUCCESS on success, ESPANK_ERROR on failure
 */
int slurm_spank_init (spank_t sp, int argc, char **argv) {
	int i;
	spank_err_t rc = ESPANK_SUCCESS;
	uid_t job_uid;
	gid_t job_gid;
	u_int32_t job_id;

	/* Register command-line options */
	for (i = 0; spank_opts[i].name; i++) {
		if ((rc = spank_option_register(sp, &spank_opts[i])) != ESPANK_SUCCESS) {
			slurm_error("spank_option_register: error registering %s: %s", spank_opts[i].name, spank_strerror(rc));
			break;
		}
	}

	/* Parse plugin arguments from plugstack.conf */
	for (i = 0; i < argc; i++) {
		_parse_spank_arg(argv[i]);
	}

	/* Verify all required parameters are set */
	if (spank_plugin_active && (registration_daemon_path == NULL || webserver_gid == -1 ||
				oodproxy_root_dir == NULL || gencerts_path == NULL || PATH_envstr == NULL)) {
		slurm_error("registration_daemon, webserver_gid, oodproxy_root, gencerts, and PATH are mandatory arguments");
		return ESPANK_ERROR;
	}

	/* Get job information from SPANK */
	spank_get_item(sp, S_JOB_ID, &job_id);
	spank_get_item(sp, S_JOB_UID, &job_uid);
	spank_get_item(sp, S_JOB_GID, &job_gid);

	/* Construct paths for directories and files */
	snprintf(uid_dir, PATH_MAXLEN, "%s/%d", oodproxy_root_dir, job_uid);
	snprintf(job_dir, PATH_MAXLEN, "%s/%d", uid_dir, job_id);
	snprintf(allowed_destinations_path, PATH_MAXLEN, "%s/%s", job_dir, ALLOWED_DESTINATIONS_FILENAME);

	return rc;
}
