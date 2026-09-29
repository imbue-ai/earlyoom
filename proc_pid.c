#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "globals.h"
#include "msg.h"
#include "proc_pid.h"

// Parse a buffer that contains the text from /proc/$pid/stat. Example:
// $ cat /proc/self/stat
// 551716 (cat) R 551087 551716 551087 34816 551716 4194304 94 0 0 0 0 0 0 0 20 0 1 0 5017160 227065856 448 18446744073709551615 94898152189952 94898152206609 140721104501216 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 94898152221328 94898152222824 94898185641984 140721104505828 140721104505848 140721104505848 140721104510955 0
bool parse_proc_pid_stat_buf(pid_stat_t* out, char* buf)
{
    char* closing_bracket = strrchr(buf, ')');
    if (!closing_bracket) {
        return false;
    }
    // If the string ends (i.e. has a null byte) after the closing bracket: bail out.
    if (!closing_bracket[1]) {
        return false;
    }
    // Because of the check above, there must be at least one more byte at
    // closing_bracket[2] (possibly a null byte, but sscanf will handle that).
    char* state_field = &closing_bracket[2];
    int ret = sscanf(state_field,
        "%c " // state
        "%d %*d %*d %*d %*d " // ppid, pgrp, sid, tty_nr, tty_pgrp
        "%*u %*u %*u %*u %*u " // flags, min_flt, cmin_flt, maj_flt, cmaj_flt
        "%*u %*u %*u %*u " // utime, stime, cutime, cstime
        "%*d %*d " // priority, nice
        "%ld " // num_threads
        "%*d %*d %*d" // itrealvalue, starttime, vsize
        "%ld ", // rss
        &out->state,
        &out->ppid,
        &out->num_threads,
        &out->rss);
    if (ret != 4) {
        return false;
    };
    return true;
};

// Read and parse /proc/$pid/stat. Returns true on success, false on error.
bool parse_proc_pid_stat(pid_stat_t* out, int pid)
{
    // Largest /proc/*/stat file here is 363 bytes acc. to:
    //   wc -c /proc/*/stat | sort
    // 512 seems safe given that we only need the first 20 fields.
    char buf[512] = { 0 };

    // Read /proc/$pid/stat
    snprintf(buf, sizeof(buf), "%s/%d/stat", procdir_path, pid);
    FILE* f = fopen(buf, "r");
    if (f == NULL) {
        // Process is gone - good.
        return false;
    }
    memset(buf, 0, sizeof(buf));

    // File content looks like this:
    // 10751 (cat) R 2663 10751 2663[...]
    // File may be bigger than 256 bytes, but we only need the first 20 or so.
    int len = (int)fread(buf, 1, sizeof(buf) - 1, f);
    bool read_error = ferror(f) || len == 0;
    fclose(f);
    if (read_error) {
        warn("%s: fread failed: %s\n", __func__, strerror(errno));
        return false;
    }
    // Terminate string at end of data
    buf[len] = 0;
    return parse_proc_pid_stat_buf(out, buf);
}

// Find the line of a /proc/$pid/status buffer that starts with `name`
// (example: "VmRSS:") and return a pointer just past the name, or NULL if
// there is no such line. The name must start a line, so that "VmRSS:" cannot
// match inside another field.
static const char* status_field(const char* buf, const char* name)
{
    size_t name_len = strlen(name);
    const char* line = buf;
    while (*line) {
        if (strncmp(line, name, name_len) == 0) {
            return line + name_len;
        }
        line = strchr(line, '\n');
        if (line == NULL) {
            return NULL;
        }
        line++;
    }
    return NULL;
}

// Parse the KiB value of the `name` line into `out`. An absent line leaves
// `out` untouched and returns true; a line that does not hold a number
// returns false.
static bool parse_status_field_kib(const char* buf, const char* name, bool* present, long long* out)
{
    const char* val = status_field(buf, name);
    *present = val != NULL;
    if (val == NULL) {
        return true;
    }
    char* end = NULL;
    errno = 0;
    long long parsed = strtoll(val, &end, 10);
    if (errno != 0 || end == val) {
        return false;
    }
    *out = parsed;
    return true;
}

// Parse a buffer that contains the text from /proc/$pid/status. Example
// excerpt:
//   VmSize:	   20480 kB
//   VmRSS:	    8240 kB
//   RssAnon:	    6120 kB
//   VmPTE:	      64 kB
//   VmSwap:	       0 kB
//   Threads:	1
// Returns false if one of these lines is present but does not parse.
bool parse_proc_pid_status_buf(pid_status_t* out, const char* buf)
{
    pid_status_t res = { 0 };
    bool present = false;
    if (!parse_status_field_kib(buf, "VmRSS:", &res.has_VmRSS, &res.VmRSSkiB)) {
        return false;
    }
    long long rss_anon = 0;
    if (!parse_status_field_kib(buf, "RssAnon:", &res.has_RssAnon, &rss_anon)) {
        return false;
    }
    if (!parse_status_field_kib(buf, "VmSwap:", &present, &res.VmSwapkiB)) {
        return false;
    }
    if (!parse_status_field_kib(buf, "VmPTE:", &present, &res.VmPTEkiB)) {
        return false;
    }
    if (!parse_status_field_kib(buf, "VmSize:", &res.has_VmSize, &res.VmSizekiB)) {
        return false;
    }
    if (!parse_status_field_kib(buf, "Threads:", &present, &res.threads)) {
        return false;
    }
    *out = res;
    return true;
}

// status_has_mm reports whether the task behind `status` still has an mm.
// Linux omits the Vm* lines for a task without one. gVisor prints them all
// as 0 instead: for a zombie, and also for a task that is still exiting,
// because it releases the mm before the task turns into a zombie. A live
// task always maps something (its stack, the vDSO), so its VmSize is never 0.
bool status_has_mm(const pid_status_t* status)
{
    if (!status->has_VmRSS) {
        return false;
    }
    return !(status->has_VmSize && status->VmSizekiB == 0);
}

// Read and parse the status file at `path`. Returns true on success, false
// on error (usually: the process is gone).
bool parse_proc_pid_status_path(pid_status_t* out, const char* path)
{
    // A real /proc/$pid/status is about 1.5 KiB.
    char buf[4096] = { 0 };
    FILE* f = fopen(path, "r");
    if (f == NULL) {
        return false;
    }
    size_t len = fread(buf, 1, sizeof(buf) - 1, f);
    bool read_error = ferror(f) || len == 0;
    fclose(f);
    if (read_error) {
        return false;
    }
    buf[len] = 0;
    return parse_proc_pid_status_buf(out, buf);
}

// Read and parse /proc/$pid/status. Returns true on success, false on error.
bool parse_proc_pid_status(pid_status_t* out, int pid)
{
    char path[256] = { 0 };
    snprintf(path, sizeof(path), "%s/%d/status", procdir_path, pid);
    return parse_proc_pid_status_path(out, path);
}

// Sum the Anonymous lines of the smaps file at `path` into `out`, in KiB.
// Returns false if the file cannot be read or a line does not parse (usually:
// the process is gone).
bool parse_proc_pid_smaps_anon_path(long long* out, const char* path)
{
    FILE* f = fopen(path, "r");
    if (f == NULL) {
        return false;
    }
    // A mapping's header line can be longer than the buffer (it ends in a
    // path). Only a chunk that starts a line may be taken for a field.
    char buf[512];
    bool at_line_start = true;
    bool ok = true;
    long long sum = 0;
    const char name[] = "Anonymous:";
    while (fgets(buf, sizeof(buf), f) != NULL) {
        bool starts_line = at_line_start;
        at_line_start = strchr(buf, '\n') != NULL;
        if (!starts_line || strncmp(buf, name, sizeof(name) - 1) != 0) {
            continue;
        }
        char* end = NULL;
        errno = 0;
        long long val = strtoll(buf + sizeof(name) - 1, &end, 10);
        if (errno != 0 || end == buf + sizeof(name) - 1) {
            ok = false;
            break;
        }
        sum += val;
    }
    if (ferror(f)) {
        ok = false;
    }
    fclose(f);
    if (ok) {
        *out = sum;
    }
    return ok;
}

// Sum the Anonymous lines of /proc/$pid/smaps, see
// parse_proc_pid_smaps_anon_path().
bool parse_proc_pid_smaps_anon(long long* out, int pid)
{
    char path[256] = { 0 };
    snprintf(path, sizeof(path), "%s/%d/smaps", procdir_path, pid);
    return parse_proc_pid_smaps_anon_path(out, path);
}
