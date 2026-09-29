/* SPDX-License-Identifier: MIT */
#ifndef MEMINFO_H
#define MEMINFO_H

#define PATH_LEN 256

#include "proc_pid.h"
#include <stdbool.h>

typedef struct {
    // Values from /proc/meminfo, in KiB
    long long MemTotalKiB;
    long long MemAvailableKiB;
    long long SwapTotalKiB;
    long long SwapFreeKiB;
    long long AnonPagesKiB;
    // Calculated values
    // UserMemTotalKiB = MemAvailableKiB + AnonPagesKiB.
    // Represents the total amount of memory that may be used by user processes.
    long long UserMemTotalKiB;
    // Calculated percentages
    double MemAvailablePercent; // percent of total memory that is available
    double SwapFreePercent; // percent of total swap that is free
    // True when MemAvailableKiB, UserMemTotalKiB and MemAvailablePercent come
    // from the --host-meminfo file, because it reported less headroom than
    // /proc/meminfo. MemTotalKiB always stays the /proc/meminfo value.
    bool host_limited;
} meminfo_t;

// A --host-meminfo file older than this is ignored: whatever writes it has
// stopped, and its last numbers no longer describe the machine.
#define HOST_MEMINFO_MAX_AGE_S 5

typedef enum {
    // The host reported less headroom than /proc/meminfo, and `m` now holds it
    HOST_MEMINFO_APPLIED = 0,
    // The host reported at least as much headroom, and `m` is unchanged
    HOST_MEMINFO_NOT_LOWER,
    // The file is missing or unreadable
    HOST_MEMINFO_MISSING,
    // A MemTotal, MemAvailable or Timestamp line is missing or out of range
    HOST_MEMINFO_INVALID,
    // Timestamp is more than HOST_MEMINFO_MAX_AGE_S seconds old
    HOST_MEMINFO_STALE,
} host_meminfo_result_t;

host_meminfo_result_t apply_host_meminfo(meminfo_t* m, const char* buf, long long now_s);
const char* host_meminfo_result_name(host_meminfo_result_t res);

typedef struct procinfo {
    int pid;
    int uid;
    int oom_score;
    int oom_score_adj;
    long long VmRSSkiB;
    long long VmSwapkiB;
    long long VmPTEkiB;
    // The kernel's oom_badness() in KiB, see is_larger()
    long long badness_kib;
    // The resident memory the badness counts, in KiB: VmRSSkiB, or the
    // smaps Anonymous total (see rss_source_t)
    long long badness_rss_kib;
    pid_stat_t stat;
    char name[PATH_LEN];
    char cmdline[PATH_LEN];
} procinfo_t;

// placeholder value for numeric fields
#define PROCINFO_FIELD_NOT_SET -9999

meminfo_t parse_meminfo();
bool is_alive(int pid);
void print_mem_stats(int (*out_func)(const char* fmt, ...), const meminfo_t m);
int get_oom_score(int pid);
int get_oom_score_adj(const int pid, int* out);
int get_comm(int pid, char* out, size_t outlen);
int get_uid(int pid);
int get_cmdline(int pid, char* out, size_t outlen);

#endif
