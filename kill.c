// SPDX-License-Identifier: MIT

/* Kill the most memory-hungy process */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h> /* Definition of SYS_* constants */
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "globals.h"
#include "kill.h"
#include "meminfo.h"
#include "msg.h"

// Processes matching "--prefer REGEX" get ADJ_PREFER added to their oom_score_adj
// when computing their badness. This is the weight --prefer had against
// oom_score upstream.
#define ADJ_PREFER 300
// Processes matching "--avoid REGEX" get ADJ_AVOID added to their oom_score_adj
#define ADJ_AVOID -300

// Processes matching "--prefer REGEX" get VMRSS_PREFER added to their VmRSSkiB
#define VMRSS_PREFER 3145728
// Processes matching "--avoid REGEX" get VMRSS_AVOID added to their VmRSSkiB
#define VMRSS_AVOID -3145728

// Buffer size for UID/GID/PID string conversion
#define UID_BUFSIZ 128
// At most 1 notification per second when --dryrun is active
#define NOTIFY_RATELIMIT 1

// Wait for at most this amount of milliseconds when invoking the pre-hook (otherwise
// when the pre-hook gets spawned, it doesn't have time to act)
#define PREHOOK_STARTUP_SLEEP_MS 200

static bool isnumeric(char* str)
{
    int i = 0;

    // Empty string is not numeric
    if (str[0] == 0)
        return false;

    while (1) {
        if (str[i] == 0) // End of string
            return true;

        if (isdigit(str[i]) == 0)
            return false;

        i++;
    }
}

#ifndef SYS_pidfd_open
// It's 434 on all architectures except Alpha. Sorry, Alpha users.
#warning SYS_pidfd_open is not defined. Assuming 434.
#define SYS_pidfd_open 434
#endif

static int pidfd_open(pid_t pid, unsigned int flags)
{
    return (int)syscall(SYS_pidfd_open, pid, flags);
}

#ifndef SYS_process_mrelease
// It's 448 on all architectures except Alpha. Sorry, Alpha users.
#warning SYS_process_mrelease is not defined. Assuming 448.
#define SYS_process_mrelease 448
#endif

static int process_mrelease(int pidfd, unsigned int flags) {
    return (int)syscall(SYS_process_mrelease, pidfd, flags);
}

static void notify_spawn_subprocess(const poll_loop_args_t* args, const char* script, char* const argv[], const procinfo_t* victim, int timeout_ms)
{
    // Prevent our SIGCHLD handler from reaping
    // children before we can
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGCHLD);
    sigprocmask(SIG_BLOCK, &set, NULL);

    pid_t pid1 = fork();

    if (pid1 == -1) {
        warn("%s: fork error: %s\n", __func__, strerror(errno));
        goto out_unblock;
    } else if (pid1 != 0) {
        // we are the parent
        int pidfd = pidfd_open(pid1, 0);
        if (pidfd == -1) {
            warn("%s: pidfd_open error: %s\n", __func__, strerror(errno));
            goto out_unblock;
        }
        struct pollfd pollfd = { 0 };
        pollfd.fd = pidfd;
        pollfd.events = POLLIN;

        int ready = poll(&pollfd, 1, timeout_ms);
        if (ready == -1) {
            warn("%s: poll error: %s\n", __func__, strerror(errno));
        } else if (ready == 0) {
            // child is still running. Ignore unless a timeout was set.
            if (timeout_ms > 0)
                warn("%s: timeout waiting for process %s\n", __func__, script);
        } else {
            // child has exited
            int ret = 0, wstatus = 0;
            ret = waitpid(pid1, &wstatus, WNOHANG);
            if (ret <= 0) {
                warn("%s: waitpid error: %s\n", __func__, strerror(errno));
            } else {
                if (WIFEXITED(wstatus)) {
                    debug("%s: child exited, status=%d\n", __func__, WEXITSTATUS(wstatus));
                } else if (WIFSIGNALED(wstatus)) {
                    debug("%s: child killed by signal %d\n", __func__, WTERMSIG(wstatus));
                } else {
                    warn("%s: unknown child status 0x%x\n", __func__, wstatus);
                }
            }
        }
        close(pidfd);
out_unblock:
        sigprocmask(SIG_UNBLOCK, &set, NULL);
        return;
    }

    // we are the child
    sigprocmask(SIG_UNBLOCK, &set, NULL);

    if (victim) {
        char pid_str[UID_BUFSIZ] = { 0 };
        char uid_str[UID_BUFSIZ] = { 0 };

        snprintf(pid_str, UID_BUFSIZ, "%d", victim->pid);
        snprintf(uid_str, UID_BUFSIZ, "%d", victim->uid);

        setenv("EARLYOOM_PID", pid_str, 1);
        setenv("EARLYOOM_UID", uid_str, 1);
        setenv("EARLYOOM_NAME", victim->name, 1);
        setenv("EARLYOOM_CMDLINE", victim->cmdline, 1);

        char num_str[UID_BUFSIZ] = { 0 };
        if (victim->oom_score_adj != PROCINFO_FIELD_NOT_SET) {
            snprintf(num_str, UID_BUFSIZ, "%d", victim->oom_score_adj);
            setenv("EARLYOOM_OOM_SCORE_ADJ", num_str, 1);
        }
        snprintf(num_str, UID_BUFSIZ, "%lld", victim->badness_kib);
        setenv("EARLYOOM_BADNESS_KIB", num_str, 1);
        snprintf(num_str, UID_BUFSIZ, "%lld", victim->VmRSSkiB);
        setenv("EARLYOOM_VMRSS_KIB", num_str, 1);
        if (args) {
            setenv("EARLYOOM_ORDERING", ordering_name(args->ordering), 1);
        }
    }

    debug("%s: exec %s\n", __func__, script);
    execv(script, argv);
    warn("%s: exec %s failed: %s\n", __func__, script, strerror(errno));
    exit(1);
}

// "-n" option
static void notify_dbus(const char* body)
{
    char body2[1024] = "string:";
    if (body != NULL) {
        snprintf(body2, sizeof(body2), "string:%s", body);
    }

    // Complete command line looks like this:
    // dbus-send --system / net.nuetzlich.SystemNotifications.Notify 'string:earlyoom' 'string:and body text'
    char* const argv[] = {
        "dbus-send",
        "--system",
        "/",
        "net.nuetzlich.SystemNotifications.Notify",
        "string:earlyoom",
        body2,
        NULL
    };
    const char* dbus_send_path = "/usr/bin/dbus-send";
    notify_spawn_subprocess(NULL, dbus_send_path, argv, NULL, 0);
}

// "-N" option
static void notify_ext(const poll_loop_args_t* args, char* const script, const procinfo_t* victim)
{
    char* const argv[] = {
        script,
        NULL
    };
    notify_spawn_subprocess(args, script, argv, victim, 0);
}

static void notify_process_killed(const poll_loop_args_t* args, const procinfo_t* victim)
{
    // Dry run can cause the notify function to be called on each poll as
    // nothing is immediately done to change the situation we don't know how
    // heavy the notify script is so avoid spamming it
    if (args->dryrun) {
        static struct timespec prev_notify = { 0 };
        struct timespec cur_time = { 0 };

        int ret = clock_gettime(CLOCK_MONOTONIC, &cur_time);
        if (ret == -1) {
            warn("%s: clock_gettime failed: %s\n", __func__, strerror(errno));
            return;
        }
        // Ignores nanoseconds, but good enough here
        if (cur_time.tv_sec - prev_notify.tv_sec < NOTIFY_RATELIMIT) {
            // Too soon
            debug("%s: rate limit hit, skipping notifications this time\n", __func__);
            return;
        }
        prev_notify = cur_time;
    }

    if (args->notify) {
        char notif_args[PATH_MAX + 1000];
        snprintf(notif_args, sizeof(notif_args),
            "Low memory! Killing process %d %s", victim->pid, victim->name);
        notify_dbus(notif_args);
    }
    if (args->notify_ext) {
        notify_ext(args, args->notify_ext, victim);
    }
}

// "-P" option
static void kill_process_prehook(const poll_loop_args_t* args, const procinfo_t* victim)
{
    char* const argv[] = {
        args->kill_process_prehook,
        NULL,
    };
    notify_spawn_subprocess(args, args->kill_process_prehook, argv, victim, PREHOOK_STARTUP_SLEEP_MS);
}

// kill_release kills a process and calls process_mrelease to
// release the memory as quickly as possible.
//
// See https://lwn.net/Articles/864184/ for details on process_mrelease.
int kill_release(const pid_t pid, const int pidfd, const int sig)
{
    int res = kill(pid, sig);
    if (res != 0) {
        return res;
    }
    // Can't do process_mrelease without a pidfd.
    if (pidfd < 0) {
        return 0;
    }

    res = process_mrelease(pidfd, 0);
    if (res != 0) {
        warn("%s: pid=%d: process_mrelease pidfd=%d failed: %s\n", __func__, pid, pidfd, strerror(errno));
    } else {
        info("%s: pid=%d: process_mrelease pidfd=%d success\n", __func__, pid, pidfd);
    }

    // Return 0 regardless of process_mrelease outcome
    return 0;
}

/*
 * Send the selected signal to "pid" and wait for the process to exit
 * (max 10 seconds)
 */
int kill_wait(const poll_loop_args_t* args, pid_t pid, int sig)
{
    const unsigned poll_ms = 100;
    int pidfd = -1;

    if (args->dryrun && sig != 0) {
        warn("dryrun, not actually sending any signal\n");
        return 0;
    }

    if (args->kill_process_group) {
        int res = getpgid(pid);
        if (res < 0) {
            return res;
        }
        pid = -res;
        warn("killing whole process group %d (-g flag is active)\n", res);
    }

    // Open the pidfd *before* calling kill().
    if (!args->kill_process_group && sig != 0) {
        pidfd = pidfd_open(pid, 0);
        if (pidfd < 0) {
            warn("%s pid %d: error opening pidfd: %s\n", __func__, pid, strerror(errno));
        }
    }

    int res = kill_release(pid, pidfd, sig);
    if (res != 0) {
        goto out_close;
    }

    /* signal 0 does not kill the process. Don't wait for it to exit */
    if (sig == 0) {
        goto out_close;
    }

    struct timespec t0 = { 0 };
    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (unsigned i = 0; i < 100; i++) {
        struct timespec t1 = { 0 };
        clock_gettime(CLOCK_MONOTONIC, &t1);
        float secs = (float)(t1.tv_sec - t0.tv_sec) + (float)(t1.tv_nsec - t0.tv_nsec) / (float)1e9;

        // We have sent SIGTERM but now have dropped below SIGKILL limits.
        // Escalate to SIGKILL.
        if (sig != SIGKILL) {
            meminfo_t m = parse_meminfo();
            print_mem_stats(debug, m);
            if (m.MemAvailablePercent <= args->mem_kill_percent && m.SwapFreePercent <= args->swap_kill_percent) {
                sig = SIGKILL;
                warn("escalating to SIGKILL after %.3f seconds\n", secs);
                res = kill_release(pid, pidfd, sig);
                if (res != 0) {
                    goto out_close;
                }
            }
        } else if (enable_debug) {
            meminfo_t m = parse_meminfo();
            print_mem_stats(info, m);
        }
        if (!is_alive(pid)) {
            warn("process %d exited after %.3f seconds\n", pid, secs);
            goto out_close;
        }
        struct timespec req = { .tv_sec = (time_t)(poll_ms / 1000), .tv_nsec = (poll_ms % 1000) * 1000000 };
        nanosleep(&req, NULL);
    }

    res = -1;
    errno = ETIME;
    warn("process %d did not exit\n", pid);

out_close:
    if (pidfd >= 0) {
        int saved_errno = errno;
        if (close(pidfd)) {
            warn("%s pid %d: error closing pidfd %d: %s\n", __func__, pid, pidfd, strerror(errno));
        }
        errno = saved_errno;
    }
    return res;
}

const char* ordering_name(ordering_t ordering)
{
    switch (ordering) {
    case ORDERING_KERNEL_BADNESS:
        return "kernel_badness";
    case ORDERING_RSS_FALLBACK:
        return "rss_fallback";
    case ORDERING_SORT_BY_RSS:
        return "sort_by_rss";
    }
    return "?";
}

// select_ordering is the startup self-check: it reads every input the kernel
// badness needs, for earlyoom's own process. If any of them cannot be read,
// the badness cannot be computed for anyone, so victims are chosen by RSS
// alone. This never exits: under a supervisor, a restart loop would leave the
// machine with no early shedding at all.
ordering_t select_ordering(const meminfo_t* m)
{
    bool ok = true;
    const int self = getpid();

    int adj = 0;
    int res = get_oom_score_adj(self, &adj);
    if (res < 0) {
        warn("ERROR: self-check: could not read %s/%d/oom_score_adj: %s\n", procdir_path, self, strerror(-res));
        ok = false;
    }
    pid_status_t status = { 0 };
    if (!parse_proc_pid_status(&status, self)) {
        warn("ERROR: self-check: could not read or parse %s/%d/status\n", procdir_path, self);
        ok = false;
    } else if (!status.has_VmRSS) {
        warn("ERROR: self-check: %s/%d/status has no VmRSS line\n", procdir_path, self);
        ok = false;
    }
    if (m->MemTotalKiB <= 0) {
        warn("ERROR: self-check: MemTotal in %s/meminfo is %lld\n", procdir_path, m->MemTotalKiB);
        ok = false;
    }
    if (!ok) {
        warn("ERROR: self-check failed, falling back to RSS-only victim ordering (oom_score_adj is ignored)\n");
        return ORDERING_RSS_FALLBACK;
    }
    return ORDERING_KERNEL_BADNESS;
}

// adj_kib converts oom_score_adj points into KiB of badness the way the
// kernel's oom_badness() does: one point is worth 1/1000 of RAM plus swap.
static long long adj_kib(const meminfo_t* m, long long adj)
{
    return adj * (m->MemTotalKiB + m->SwapTotalKiB) / 1000;
}

// read_mm_status fills `out` from the mm of `pid`, finding it the way the
// kernel's find_lock_task_mm() does: the thread-group leader's, or, when the
// leader has exited (a zombie main thread), any live thread's. Returns false
// if the process is gone or has no mm at all, which is what makes a kernel
// thread. This holds inside a pid namespace, where pid 2 and its children are
// ordinary processes.
static bool read_mm_status(int pid, pid_status_t* out)
{
    if (!parse_proc_pid_status(out, pid)) {
        return false;
    }
    if (out->has_VmRSS) {
        return true;
    }
    // Room for procdir_path, the task directory and a d_name.
    char path[2 * PATH_LEN] = { 0 };
    snprintf(path, sizeof(path), "%s/%d/task", procdir_path, pid);
    DIR* taskdir = opendir(path);
    if (taskdir == NULL) {
        return false;
    }
    bool found = false;
    struct dirent* d = NULL;
    while ((d = readdir(taskdir)) != NULL) {
        if (!isnumeric(d->d_name)) {
            continue;
        }
        snprintf(path, sizeof(path), "%s/%d/task/%s/status", procdir_path, pid, d->d_name);
        if (parse_proc_pid_status_path(out, path) && out->has_VmRSS) {
            found = true;
            break;
        }
    }
    closedir(taskdir);
    return found;
}

// is_larger finds out if the process with pid `cur->pid` is a better victim
// than our current `victim`.
// In the process, it fills the `cur` structure.
//
// The score is the kernel's oom_badness() (mm/oom_kill.c), in KiB:
//
//   badness = VmRSS + VmSwap + VmPTE + oom_score_adj * (MemTotal + SwapTotal) / 1000
//
// It is computed here instead of read from /proc/$pid/oom_score because
// gVisor serves oom_score as a constant 0, which would reduce the choice to
// largest RSS and ignore oom_score_adj. On a Linux kernel it reproduces the
// kernel's own ordering.
bool is_larger(const poll_loop_args_t* args, const meminfo_t* m, const procinfo_t* victim, procinfo_t* cur)
{
    if (cur->pid == 1) {
        // Let's not kill init (the kernel's is_global_init()). Inside a
        // container, this is the container's init.
        return false;
    }
    if (cur->pid == getpid()) {
        return false;
    }

    // Ignore processes owned by root user?
    if (args->ignore_root_user) {
        int res = get_uid(cur->pid);
        if (res < 0) {
            debug("%s: pid %d: error reading uid: %s\n", __func__, cur->pid, strerror(-res));
            return false;
        }
        cur->uid = res;

        if (cur->uid == 0) {
            return false;
        }
    }

    if (args->ordering == ORDERING_RSS_FALLBACK) {
        // /proc/$pid/status failed the self-check, so use the rss from
        // /proc/$pid/stat, like upstream. A process without memory (a kernel
        // thread) has nothing to free.
        bool res = parse_proc_pid_stat(&cur->stat, cur->pid);
        if (!res) {
            debug("%s: pid %d: error reading stat\n", __func__, cur->pid);
            return false;
        }
        const long page_size = sysconf(_SC_PAGESIZE);
        cur->VmRSSkiB = cur->stat.rss * page_size / 1024;
        if (cur->VmRSSkiB == 0) {
            return false;
        }
    } else {
        pid_status_t status = { 0 };
        if (!read_mm_status(cur->pid, &status)) {
            // Gone, or a kernel thread.
            return false;
        }
        cur->VmRSSkiB = status.VmRSSkiB;
        cur->VmSwapkiB = status.VmSwapkiB;
        cur->VmPTEkiB = status.VmPTEkiB;
    }

    {
        int adj = 0;
        int res = get_oom_score_adj(cur->pid, &adj);
        if (res < 0) {
            debug("%s: pid %d: error reading oom_score_adj: %s\n", __func__, cur->pid, strerror(-res));
            // The badness needs it. The RSS orderings do not, and in the
            // fallback it may be unreadable for everyone.
            if (args->ordering == ORDERING_KERNEL_BADNESS) {
                return false;
            }
        } else {
            cur->oom_score_adj = adj;
        }
    }
    // Skip processes with oom_score_adj = -1000, like the
    // kernel oom killer would.
    if (cur->oom_score_adj == -1000) {
        return false;
    }

    int bonus_adj = 0;
    if ((args->prefer_regex || args->avoid_regex || args->ignore_regex)) {
        int res = get_comm(cur->pid, cur->name, sizeof(cur->name));
        if (res < 0) {
            debug("%s: pid %d: error reading process name: %s\n", __func__, cur->pid, strerror(-res));
            return false;
        }
        if (args->prefer_regex && regexec(args->prefer_regex, cur->name, (size_t)0, NULL, 0) == 0) {
            bonus_adj += ADJ_PREFER;
        }
        if (args->avoid_regex && regexec(args->avoid_regex, cur->name, (size_t)0, NULL, 0) == 0) {
            bonus_adj += ADJ_AVOID;
        }
        if (args->ignore_regex && regexec(args->ignore_regex, cur->name, (size_t)0, NULL, 0) == 0) {
            return false;
        }
    }

    if (args->ordering == ORDERING_KERNEL_BADNESS) {
        cur->badness_kib = cur->VmRSSkiB + cur->VmSwapkiB + cur->VmPTEkiB
            + adj_kib(m, (long long)cur->oom_score_adj + bonus_adj);
    } else {
        // The RSS orderings keep upstream's fixed --prefer/--avoid bonus of
        // 3 GiB: in the fallback, MemTotal may be the input that failed.
        long long bonus_kib = 0;
        if (bonus_adj > 0) {
            bonus_kib = VMRSS_PREFER;
        } else if (bonus_adj < 0) {
            bonus_kib = VMRSS_AVOID;
        }
        cur->badness_kib = cur->VmRSSkiB + bonus_kib;
    }

    if (cur->badness_kib < victim->badness_kib) {
        return false;
    }
    // Tie-break on RSS.
    if (cur->badness_kib == victim->badness_kib && cur->VmRSSkiB <= victim->VmRSSkiB) {
        return false;
    }
    return true;
}

// Fill the fields in `cur` that are not required for the kill decision.
// Used to log details about the selected process.
void fill_informative_fields(procinfo_t* cur)
{
    if (strlen(cur->name) == 0) {
        int res = get_comm(cur->pid, cur->name, sizeof(cur->name));
        if (res < 0) {
            debug("%s: pid %d: error reading process name: %s\n", __func__, cur->pid, strerror(-res));
        }
    }
    if (strlen(cur->cmdline) == 0) {
        int res = get_cmdline(cur->pid, cur->cmdline, sizeof(cur->cmdline));
        if (res < 0) {
            debug("%s: pid %d: error reading process cmdline: %s\n", __func__, cur->pid, strerror(-res));
        }
    }
    if (cur->uid == PROCINFO_FIELD_NOT_SET) {
        int res = get_uid(cur->pid);
        if (res < 0) {
            debug("%s: pid %d: error reading uid: %s\n", __func__, cur->pid, strerror(-res));
        } else {
            cur->uid = res;
        }
    }
    // Not used for the decision, but worth logging: gVisor serves a
    // constant 0 here.
    if (cur->oom_score == PROCINFO_FIELD_NOT_SET) {
        int res = get_oom_score(cur->pid);
        if (res < 0) {
            debug("%s: pid %d: error reading oom_score: %s\n", __func__, cur->pid, strerror(-res));
        } else {
            cur->oom_score = res;
        }
    }
}

// debug_print_procinfo pretty-prints the process information in `cur`.
void debug_print_procinfo(procinfo_t* cur)
{
    if (!enable_debug) {
        return;
    }
    fill_informative_fields(cur);
    debug("%5d %11lld %7lld %5d %13d \"%s\"",
        cur->pid, cur->badness_kib, cur->VmRSSkiB, cur->uid, cur->oom_score_adj, cur->name);
}

void debug_print_procinfo_header()
{
    debug("  PID BADNESSkiB  RSSkiB   UID OOM_SCORE_ADJ  COMM\n");
}

/*
 * Find the process with the largest badness (see is_larger()).
 */
procinfo_t find_largest_process(const poll_loop_args_t* args, const meminfo_t* m)
{
    DIR* procdir = opendir(procdir_path);
    if (procdir == NULL) {
        fatal(5, "%s: could not open /proc: %s", __func__, strerror(errno));
    }

    struct timespec t0 = { 0 }, t1 = { 0 };
    if (enable_debug) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
    }

    debug_print_procinfo_header();

    const procinfo_t empty_procinfo = {
        .pid = PROCINFO_FIELD_NOT_SET,
        .uid = PROCINFO_FIELD_NOT_SET,
        .oom_score = PROCINFO_FIELD_NOT_SET,
        .oom_score_adj = PROCINFO_FIELD_NOT_SET,
        .VmRSSkiB = PROCINFO_FIELD_NOT_SET,
        // Badness can be negative (oom_score_adj < 0), so anything beats this.
        .badness_kib = LLONG_MIN,
        /* omitted fields are set to zero */
    };

    procinfo_t victim = empty_procinfo;
    while (1) {
        errno = 0;
        struct dirent* d = readdir(procdir);
        if (d == NULL) {
            if (errno != 0)
                warn("%s: readdir error: %s", __func__, strerror(errno));
            break;
        }

        // proc contains lots of directories not related to processes,
        // skip them
        if (!isnumeric(d->d_name))
            continue;

        procinfo_t cur = empty_procinfo;
        cur.pid = (int)strtol(d->d_name, NULL, 10);

        bool larger = is_larger(args, m, &victim, &cur);

        debug_print_procinfo(&cur);

        if (larger) {
            debug(" <--- new victim\n");
            victim = cur;
        } else {
            debug("\n");
        }
    }
    closedir(procdir);

    if (enable_debug) {
        clock_gettime(CLOCK_MONOTONIC, &t1);
        long delta = (t1.tv_sec - t0.tv_sec) * 1000000 + (t1.tv_nsec - t0.tv_nsec) / 1000;
        debug("selecting victim took %ld.%03ld ms\n", delta / 1000, delta % 1000);
    }

    if (victim.pid >= 0) {
        // We will pretty-print the victim later, so get all the info.
        fill_informative_fields(&victim);
    }

    return victim;
}

/*
 * Kill the victim process, wait for it to exit, send a gui notification
 * (if enabled).
 */
void kill_process(const poll_loop_args_t* args, int sig, const procinfo_t* victim)
{
    if (victim->pid <= 0) {
        warn("Could not find a process to kill. Sleeping 1 second.\n");
        if (args->notify) {
            notify_dbus("Error: Could not find a process to kill. Sleeping 1 second.");
        }
        sleep(1);
        return;
    }

    char* sig_name = "?";
    if (sig == SIGTERM) {
        sig_name = "SIGTERM";
    } else if (sig == SIGKILL) {
        sig_name = "SIGKILL";
    } else if (sig == 0) {
        sig_name = "0 (no-op signal)";
    }
    // sig == 0 is used as a self-test during startup. Don't notify the user.
    if (sig != 0 || enable_debug) {
        if (sig != 0 && args->ordering == ORDERING_RSS_FALLBACK) {
            warn("ERROR: victim chosen by RSS alone (ordering rss_fallback): the startup self-check could not read the badness inputs\n");
        }
        warn("sending %s to process %d uid %d \"%s\": oom_score %d, oom_score_adj %d, badness %lld KiB, VmRSS %lld MiB, ordering %s, cmdline \"%s\"\n",
            sig_name, victim->pid, victim->uid, victim->name, victim->oom_score, victim->oom_score_adj, victim->badness_kib,
            victim->VmRSSkiB / 1024, ordering_name(args->ordering), victim->cmdline);
    }

    // Invoke program BEFORE killing a process. There is a small risk that there
    // is not enough memory to spawn it, warn; and a brief period of waiting to
    // let the program be able to start and do something meaningful.
    if (sig != 0 && args->kill_process_prehook) {
        debug("going to invoke program before killing: %s\n", args->kill_process_prehook);
        kill_process_prehook(args, victim);
    }

    int res = kill_wait(args, victim->pid, sig);
    int saved_errno = errno;

    // Send the GUI notification AFTER killing a process. This makes it more likely
    // that there is enough memory to spawn the notification helper.
    if (sig != 0) {
        notify_process_killed(args, victim);
    }

    if (sig == 0) {
        return;
    }

    if (res != 0) {
        warn("kill failed: %s\n", strerror(saved_errno));
        if (args->notify) {
            notify_dbus("Error: Failed to kill process");
        }
        // Killing the process may have failed because we are not running as root.
        // In that case, trying again in 100ms will just yield the same error.
        // Throttle ourselves to not spam the log.
        if (saved_errno == EPERM) {
            warn("sleeping 1 second\n");
            sleep(1);
        }
    }
}
