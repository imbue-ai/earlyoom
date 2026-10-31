/* SPDX-License-Identifier: MIT */
#ifndef GLOBALS_H
#define GLOBALS_H

extern int enable_debug;

extern char* procdir_path;

// --host-meminfo: the file that reports the enforcing memory limit from
// outside a sandbox, or NULL. See apply_host_meminfo().
extern char* host_meminfo_path;

// --host-reclaim-request and --host-reclaim-result: where earlyoom asks the
// host to reclaim the sandbox's cold cache before shedding, and where the host
// answers, or NULL. See host_reclaim.c.
extern char* host_reclaim_request_path;
extern char* host_reclaim_result_path;

#endif
