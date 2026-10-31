// SPDX-License-Identifier: MIT

/* --host-reclaim-request and --host-reclaim-result: before earlyoom sheds a
 * process because the host-published headroom is low, it asks the host that
 * publishes it to reclaim the sandbox's cold file cache, which the sandbox
 * cannot drop itself (gVisor has no drop_caches), and waits for the answer.
 *
 * The request file holds a sequence number, raised on every ask. The answer
 * file, written by the host after it has republished the headroom, holds
 *
 *   Sequence: <the sequence number it answers>
 *   Outcome:  <how the reclaim round ended>
 *   Timestamp: <unix seconds>
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "globals.h"
#include "host_reclaim.h"
#include "msg.h"

static long long monotonic_ms(void)
{
    struct timespec ts = { 0 };
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* A sequence number above any an earlier earlyoom wrote: the wall clock in
 * milliseconds, or one more than the last if the clock has not moved on. */
static long long next_sequence(void)
{
    static long long last = 0;
    struct timespec ts = { 0 };
    clock_gettime(CLOCK_REALTIME, &ts);
    long long now = (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    last = now > last ? now : last + 1;
    return last;
}

/* Writes the request in place, at a fixed width, so the file keeps one inode:
 * gVisor's gofer keeps an entry for every distinct inode the sandbox makes. */
static bool write_request(long long sequence)
{
    char buf[32];
    int len = snprintf(buf, sizeof(buf), "%20lld\n", sequence);
    int fd = open(host_reclaim_request_path, O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0) {
        return false;
    }
    bool ok = pwrite(fd, buf, (size_t)len, 0) == len && ftruncate(fd, len) == 0;
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return ok;
}

/* The sequence number an answer (in buf) is for, with its outcome copied into
 * `outcome`, or -1 if buf is not a complete answer. */
long long parse_host_reclaim_answer(const char* buf, char* outcome, size_t outcome_size)
{
    const char* sequence_field = strstr(buf, "Sequence:");
    const char* outcome_field = strstr(buf, "Outcome:");
    if (sequence_field == NULL || outcome_field == NULL || outcome_size == 0) {
        return -1;
    }
    sequence_field += strlen("Sequence:");
    char* end = NULL;
    long long sequence = strtoll(sequence_field, &end, 10);
    if (end == sequence_field || sequence <= 0) {
        return -1;
    }
    outcome_field += strlen("Outcome:");
    outcome_field += strspn(outcome_field, " ");
    size_t len = strcspn(outcome_field, "\n");
    if (outcome_field[len] != '\n') {
        // Cut short: the line has no end yet.
        return -1;
    }
    while (len > 0 && outcome_field[len - 1] == ' ') {
        len--;
    }
    if (len >= outcome_size) {
        len = outcome_size - 1;
    }
    memcpy(outcome, outcome_field, len);
    outcome[len] = '\0';
    return sequence;
}

static long long read_answer(char* outcome, size_t outcome_size)
{
    char buf[256] = { 0 };
    FILE* f = fopen(host_reclaim_result_path, "r");
    if (f == NULL) {
        return -1;
    }
    size_t len = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[len] = '\0';
    return parse_host_reclaim_answer(buf, outcome, outcome_size);
}

/* Asks the host to reclaim and waits up to HOST_RECLAIM_WAIT_MS for its
 * answer, setting `waited_ms`. Once it is answered the caller rereads the
 * headroom, which the host republished before answering. */
host_reclaim_result_t ask_host_reclaim(char* outcome, size_t outcome_size, long long* waited_ms)
{
    static long long last_ask_ms = -HOST_RECLAIM_MIN_INTERVAL_MS;
    long long start_ms = monotonic_ms();
    *waited_ms = 0;
    if (start_ms - last_ask_ms < HOST_RECLAIM_MIN_INTERVAL_MS) {
        return HOST_RECLAIM_SKIPPED;
    }
    last_ask_ms = start_ms;
    long long sequence = next_sequence();
    if (!write_request(sequence)) {
        snprintf(outcome, outcome_size, "request failed: %s", strerror(errno));
        return HOST_RECLAIM_FAILED;
    }
    while ((*waited_ms = monotonic_ms() - start_ms) < HOST_RECLAIM_WAIT_MS) {
        struct timespec req = { .tv_sec = 0, .tv_nsec = HOST_RECLAIM_POLL_MS * 1000000L };
        while (nanosleep(&req, &req) == -1 && errno == EINTR)
            ;
        if (read_answer(outcome, outcome_size) == sequence) {
            *waited_ms = monotonic_ms() - start_ms;
            return HOST_RECLAIM_ANSWERED;
        }
    }
    snprintf(outcome, outcome_size, "no answer within %d ms", HOST_RECLAIM_WAIT_MS);
    return HOST_RECLAIM_FAILED;
}
