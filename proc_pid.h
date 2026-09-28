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
// gVisor instead prints every Vm* line as 0 for a task without an mm, so a
// VmSize of 0 means the same thing there (see status_has_mm()).
typedef struct {
    bool has_VmRSS;
    // Linux prints RssAnon (4.5+) for a task with an mm; gVisor never does.
    bool has_RssAnon;
    long long VmRSSkiB;
    long long VmSwapkiB;
    long long VmPTEkiB;
    bool has_VmSize;
    long long VmSizekiB;
    // The Threads line, or 0 when there is none
    long long threads;
} pid_status_t;

bool status_has_mm(const pid_status_t* status);

bool parse_proc_pid_stat_buf(pid_stat_t* out, char* buf);
bool parse_proc_pid_stat(pid_stat_t* out, int pid);
bool parse_proc_pid_status_buf(pid_status_t* out, const char* buf);
bool parse_proc_pid_status(pid_status_t* out, int pid);
bool parse_proc_pid_status_path(pid_status_t* out, const char* path);
bool parse_proc_pid_smaps_anon_path(long long* out, const char* path);
bool parse_proc_pid_smaps_anon(long long* out, int pid);

#endif
