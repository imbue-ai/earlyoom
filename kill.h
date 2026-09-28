/* SPDX-License-Identifier: MIT */
#ifndef KILL_H
#define KILL_H

#include <regex.h>
#include <stdbool.h>

#include "meminfo.h"

// How the victim is chosen. See select_ordering() and is_larger().
typedef enum {
    // The kernel's oom_badness(), computed from oom_score_adj and the
    // memory counters in /proc/$pid/status
    ORDERING_KERNEL_BADNESS = 0,
    // Upstream earlyoom's ordering (oom_score, or rss with --sort-by-rss),
    // because the startup self-check could not read an input of the badness
    ORDERING_UPSTREAM_FALLBACK,
    // Upstream earlyoom's --sort-by-rss ordering, because it was passed
    ORDERING_SORT_BY_RSS,
} ordering_t;

// Where the badness reads a process's resident memory from. See
// select_rss_source() in kill.c.
typedef enum {
    // VmRSS in /proc/$pid/status, as the kernel's oom_badness() counts it
    RSS_SOURCE_VMRSS = 0,
    // The Anonymous lines of /proc/$pid/smaps. gVisor's VmRSS counts every
    // page of each range it has mapped, not the pages that were touched:
    // anonymous memory in 2 MiB-aligned blocks and a mapped file in full.
    RSS_SOURCE_SMAPS_ANONYMOUS,
} rss_source_t;

typedef struct {
    /* if the available memory AND swap goes below these percentages,
     * we start killing processes */
    double mem_term_percent;
    double mem_kill_percent;
    double swap_term_percent;
    double swap_kill_percent;
    /* send d-bus notifications? */
    bool notify;
    /* Path to script for programmatic notifications after killing (or NULL) */
    char* notify_ext;
    /* Path to script/binary for to execute before killing (or NULL) */
    char* kill_process_prehook;
    /* kill all processes within a process group */
    bool kill_process_group;
    /* do not kill processes owned by root */
    bool ignore_root_user;
    /* find process with the largest rss */
    bool sort_by_rss;
    /* prefer/avoid killing these processes. NULL = no-op. */
    regex_t* prefer_regex;
    regex_t* avoid_regex;
    /* will ignore these processes. NULL = no-op. */
    regex_t* ignore_regex;
    /* memory report interval, in milliseconds */
    int report_interval_ms;
    /* Flag --dryrun was passed */
    bool dryrun;
    /* how the victim is chosen */
    ordering_t ordering;
    /* where ORDERING_KERNEL_BADNESS reads resident memory from */
    rss_source_t rss_source;
} poll_loop_args_t;

void kill_process(const poll_loop_args_t* args, int sig, const procinfo_t* victim);
procinfo_t find_largest_process(const poll_loop_args_t* args, const meminfo_t* m);
bool is_larger(const poll_loop_args_t* args, const meminfo_t* m, const procinfo_t* victim, procinfo_t* cur);
ordering_t select_ordering(const meminfo_t* m, rss_source_t* rss_source);
const char* ordering_name(ordering_t ordering);
const char* rss_source_name(rss_source_t rss_source);

#endif
