/*
 * This file is part of the osnmpd project (https://github.com/verrio/osnmpd).
 * Copyright (C) 2016 Olivier Verriest
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <poll.h>
#include <fcntl.h>
#include <time.h>
#include <dirent.h>
#include <dlfcn.h>
#include <limits.h>
#include <regex.h>

#include "config.h"
#ifdef WITH_SMARTCARD_SUPPORT
#include <openssl/engine.h>
#endif
#include "snmp-agent/agent-incoming.h"
#include "snmp-agent/agent-notification.h"
#include "snmp-agent/agent-notification-log.h"
#include "snmp-agent/agent-ctl.h"
#include "snmp-agent/agent-config.h"
#include "snmp-agent/agent-cache.h"
#include "snmp-agent/mib-tree.h"

#define FD_CTL      0
#define FD_INCOMING 1
#define FD_OUTGOING 2

#define POLL_EVENT  (POLLIN | POLLERR | POLL_HUP | POLLNVAL)

/* indicates if debug logging is enabled */
static int debug_logging = 0;

/* PID file */
static const char *pid_file = SNMPD_RUN_PATH "osnmpd.pid";

/* plugin directory */
static const char *plugin_dir = PLUGIN_DIR;

/* indicates if process is finished */
static int finished = 0;

/* poll descriptors */
static struct pollfd fds[3];

/* timeout on poll */
int timeout_msecs = -1;

/* handle incoming requests */
static void accept_loop()
{
    struct timespec start;
    struct timespec end;

    syslog(LOG_DEBUG, "entering accept loop");

    while (!finished) {
        if (clock_gettime(CLOCK_MONOTONIC, &start)) {
            syslog(LOG_ERR, "failed to get start time : %s", strerror(errno));
            return;
        }

        int fd_len = fds[FD_INCOMING].fd == -1 ? 1 :
                (fds[FD_OUTGOING].fd == -1 ? 2 : 3);

        if (poll(fds, fd_len, timeout_msecs) < 0) {
            if (errno == EINTR) {
                finished = 1;
            } else {
                syslog(LOG_ERR, "failed to fetch next event : %s", strerror(errno));
                break;
            }
        }

        /* handle control requests */
        if (fds[FD_CTL].revents & POLL_EVENT) {
            handle_ctl_request();
        }

        /* handle incoming requests */
        if (fds[FD_INCOMING].revents & POLL_EVENT) {
            handle_request();
        }

        int remaining = 0;
        if (timeout_msecs != -1) {
            if (clock_gettime(CLOCK_MONOTONIC, &end)) {
                syslog(LOG_ERR, "failed to get end time : %s", strerror(errno));
                return;
            }
            remaining = timeout_msecs - 1000 * (end.tv_sec - start.tv_sec)
                    - (end.tv_nsec - start.tv_nsec) / 1000000;
            if (remaining <= 0) {
                syslog(LOG_DEBUG, "notification timeout reached");
                remaining = -1;
            }
            timeout_msecs = remaining;
        }

        /* handle traps */
        if ((fds[FD_OUTGOING].fd != -1 && (fds[FD_OUTGOING].revents & POLL_EVENT))
            || remaining < 0) {
            handle_incoming_notification();
        }
    }

    syslog(LOG_DEBUG, "accept loop finished");
}

static int load_plugins(void)
{
    if (access(plugin_dir, R_OK | X_OK)) {
        syslog(LOG_WARNING, "plugin directory not accessible : %s", strerror(errno));
        return -1;
    }

    DIR *dir;
    dir = opendir(plugin_dir);
    if (dir == NULL) {
        syslog(LOG_WARNING, "failed to open plugin dir : %s", strerror(errno));
        return -1;
    }

    regex_t plugin_reg;
    if (regcomp(&plugin_reg, "libsnmp-mib.*\\.so.*", REG_NOSUB)) {
        return -1;
    }

    struct dirent *plugin;
    while ((plugin = readdir(dir)) != NULL) {
        if (regexec(&plugin_reg, plugin->d_name, 0, NULL, 0) == REG_NOMATCH) {
            syslog(LOG_DEBUG, "ignoring file %s", plugin->d_name);
            continue;
        }

        char full_path[PATH_MAX + 1];
        strcpy(full_path, plugin_dir);
        strcat(full_path, "/");
        strcat(full_path, plugin->d_name);

        char resolved[PATH_MAX + 1];
        if (realpath(full_path, resolved) == NULL) {
            syslog(LOG_ERR, "failed to resolve plugin %s : %s", plugin->d_name, strerror(errno));
            continue;
        }

        syslog(LOG_DEBUG, "loading plugin %s", resolved);
        if (!dlopen(resolved, RTLD_NOW)) {
            syslog(LOG_WARNING, "failed to load plugin %s : %s", plugin->d_name, dlerror());
        }
    }

    regfree(&plugin_reg);
    closedir(dir);
    return 0;
}

/* perform graceful shutdown */
static void handle_signal(int signal)
{
    finished = 1;
}

/* prints a help message to the user; this function never returns */
static void usage(void)
{
    fprintf(stderr, "usage: snmpd [-qfdv] [-c <config-file>] [-p <plugin-dir>]\n");
    exit(EXIT_SUCCESS);
}

static void init_run_dir(void)
{
    struct stat rundir;
    if (stat(SNMPD_RUN_PATH, &rundir) == -1) {
        if(ENOENT != errno) {
            goto failed;
        }
    } else if (!S_ISDIR(rundir.st_mode)) {
        if (remove(SNMPD_RUN_PATH) == -1) {
            goto failed;
        }
    } else {
        goto set_permissions;
    }

    if (mkdir(SNMPD_RUN_PATH, 0775) == -1) {
        goto failed;
    }

set_permissions:
    if (get_agent_uid() != -1 && get_agent_gid() != -1 &&
        chown(SNMPD_RUN_PATH, get_agent_uid(), get_agent_gid()) == -1) {
        goto failed;
    }

    return;
failed:
    syslog(LOG_ERR, "failed to initialise runtime directory : %s", strerror(errno));
}

static void create_pid_file(void)
{
    int mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;
    int f = open(pid_file, O_RDWR | O_CREAT, mode);
    if (f == -1) {
        goto failed;
    }

    char pid[16];
    snprintf(pid, sizeof(pid), "%u\n", getpid());
    ssize_t size = write(f, pid, strlen(pid) + 1);
    if (size < 0) {
        goto failed;
    }
    close(f);
    chmod(pid_file, mode);
    return;

failed:
    if (f != -1) {
        close(f);
    }
    syslog(LOG_ERR, "failed to create PID file : %s", strerror(errno));
}

static void remove_pid_file(void)
{
    if (remove(pid_file) != 0) {
        syslog(LOG_ERR, "failed to remove PID file : %s", strerror(errno));
    }
}

void set_debug_logging(int enabled)
{
    debug_logging = enabled ? 1 : 0;
    setlogmask(LOG_UPTO(enabled ? LOG_DEBUG : LOG_INFO));
}

int debug_logging_enabled(void)
{
    return debug_logging;
}

int main(int argc, char **argv)
{
    int daemonize = 1;
    int log_level = LOG_INFO;
    int opt;
    while ((opt = getopt(argc, argv, "c:fvqdh?p:")) != -1) {
        switch (opt) {
            case 'c': {
                set_config_file(optarg);
                break;
            }

            case 'p': {
                plugin_dir = optarg;
                break;
            }

            case 'f': {
                daemonize = 0;
                break;
            }

            case 'v': {
                fprintf(stderr, "%s\n", PACKAGE_STRING);
                exit(0);
            }

            case 'q': {
                log_level = LOG_WARNING;
                break;
            }

            case 'd': {
                debug_logging = 1;
                log_level = LOG_DEBUG;
                struct rlimit core_limits;
                core_limits.rlim_cur = RLIM_INFINITY;
                core_limits.rlim_max = RLIM_INFINITY;
                setrlimit(RLIMIT_CORE, &core_limits);
                break;
            }

            default: {
                usage();
                break;
            }
        }
    }

    if (getuid() != 0) {
        fprintf(stderr, "run as root.\n");
        exit(EXIT_FAILURE);
    }

    setlogmask(LOG_UPTO(log_level));
    openlog(PACKAGE_NAME, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_DAEMON);
    init_crypto();

    if (load_configuration() == -1) {
        syslog(LOG_ERR, "failed to load SNMP agent configuration.");
    }
    if (init_cache() == -1) {
        syslog(LOG_ERR, "failed to initialise SNMP agent cache.");
    }

    if (daemonize) {
        signal(SIGCHLD, SIG_IGN);
        int pid = fork();

        if (pid < 0)
            goto daemonize_failed;
        else if (pid > 0)
            /* exit parent */
            exit(EXIT_SUCCESS);

        /* new session leader */
        if (setsid() < 0)
            goto daemonize_failed;

        pid = fork();
        if (pid < 0)
            goto daemonize_failed;
        else if (pid > 0)
            /* exit parent */
            exit(EXIT_SUCCESS);

        umask(0);
        char *work_dir = get_cache_dir();
        if (work_dir == NULL)
            work_dir = "/tmp";
        if (chdir(work_dir) == -1)
            goto daemonize_failed;

        /* redirect stdio */
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        open("/dev/null", O_RDWR);
        if (dup(0) == -1 || dup(0) == -1) {
            syslog(LOG_ERR, "failed to reroute stdin/out : %s.", strerror(errno));
        }

        create_pid_file();
        goto daemonize_completed;

        daemonize_failed: syslog(LOG_ERR, "failed to daemonize : %s.", strerror(errno));
        exit(EXIT_FAILURE);
    } else {
        umask(0);
    }
    daemonize_completed: ;

    /* set signal handler */
    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sa.sa_flags = 0; /* no SA_RESTART */
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGTERM, &sa, NULL) == -1 || sigaction(SIGINT, &sa, NULL) == -1) {
        syslog(LOG_ERR, "failed to register signal handler : %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    init_run_dir();
    if (init_ctl_handler(&fds[FD_CTL]) == -1) {
        syslog(LOG_ERR, "failed to initialise control socket : %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (init_incoming_handler(&fds[FD_INCOMING])) {
        /* run control socket regardless: allow reconfiguration */
        fds[FD_INCOMING].fd = -1;
    }
    if (init_notification_handler(&fds[FD_OUTGOING], &timeout_msecs)) {
        fds[FD_OUTGOING].fd = -1;
    }
    if (init_mib_tree()) {
        syslog(LOG_ERR, "failed to initialise MIB tree");
    }
    if (load_plugins()) {
        syslog(LOG_ERR, "failed to load plugins");
    }
    if (init_trap_log()) {
        syslog(LOG_ERR, "failed to initialise trap log");
    }

    /* drop privileges after creating queues and sockets */
    if (getuid() == 0 && get_agent_uid() != -1 && get_agent_gid() != -1) {
        if (setgid(get_agent_gid()) != 0) {
            syslog(LOG_ERR, "unable to drop group privileges : %s", strerror(errno));
        }
        if (setuid(get_agent_uid()) != 0) {
            syslog(LOG_ERR, "unable to drop user privileges : %s", strerror(errno));
        }
    }

    accept_loop();

    finish_incoming_handler();
    finish_notification_handler();
    finish_trap_log();
    finish_ctl_handler();
    finish_cache();
    finish_mib_tree();
    finish_crypto();
    remove_pid_file();
    closelog();

    exit(EXIT_SUCCESS);
}
