/* SPDX-License-Identifier: MIT */
#ifndef HOST_RECLAIM_H
#define HOST_RECLAIM_H

#include <stdbool.h>
#include <stddef.h>

// How long earlyoom waits for the answer to a reclaim request before it goes
// on to shed a process. The VM-side publisher looks for requests every 250 ms
// and a round of reclaim takes up to about a second.
#define HOST_RECLAIM_WAIT_MS 1500
// How often the answer file is checked while waiting.
#define HOST_RECLAIM_POLL_MS 50
// At most one request in this long, so a host that keeps answering without
// freeing anything costs a shed only one wait.
#define HOST_RECLAIM_MIN_INTERVAL_MS 2000

typedef enum {
    // The host answered; its outcome is in the outcome buffer
    HOST_RECLAIM_ANSWERED = 0,
    // No request was written or no answer came in time; the reason is in the outcome buffer
    HOST_RECLAIM_FAILED,
    // Not asked: the last request was under HOST_RECLAIM_MIN_INTERVAL_MS ago
    HOST_RECLAIM_SKIPPED,
} host_reclaim_result_t;

long long parse_host_reclaim_answer(const char* buf, char* outcome, size_t outcome_size);
host_reclaim_result_t ask_host_reclaim(char* outcome, size_t outcome_size, long long* waited_ms);

#endif
