/* SPDX-License-Identifier: MIT */
#ifndef PROC_PID_H
#define PROC_PID_H

#include <stdbool.h>

typedef struct {
    char state;
    int ppid;
    long num_threads;
    long rss;
} pid_stat_t;

// The memory counters from /proc/$pid/status, in KiB. A missing VmSwap or
// VmPTE line reads as 0 (gVisor serves neither). A missing VmRSS line means
// the task has no mm: a kernel thread, or a zombie thread-group leader.
typedef struct {
    bool has_VmRSS;
    long long VmRSSkiB;
    long long VmSwapkiB;
    long long VmPTEkiB;
} pid_status_t;

bool parse_proc_pid_stat_buf(pid_stat_t* out, char* buf);
bool parse_proc_pid_stat(pid_stat_t* out, int pid);
bool parse_proc_pid_status_buf(pid_status_t* out, const char* buf);
bool parse_proc_pid_status(pid_status_t* out, int pid);
bool parse_proc_pid_status_path(pid_status_t* out, const char* path);

#endif
