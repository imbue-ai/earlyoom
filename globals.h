/* SPDX-License-Identifier: MIT */
#ifndef GLOBALS_H
#define GLOBALS_H

extern int enable_debug;

extern char* procdir_path;

// --host-meminfo: the file that reports the enforcing memory limit from
// outside a sandbox, or NULL. See apply_host_meminfo().
extern char* host_meminfo_path;

#endif
