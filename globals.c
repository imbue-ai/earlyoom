#include <stddef.h>

int enable_debug = 0;

// This variable exists so the tests can point
// it to a mockup proc dir
char* procdir_path = "/proc";

// --host-meminfo, see globals.h
char* host_meminfo_path = NULL;

// --host-reclaim-request and --host-reclaim-result, see globals.h
char* host_reclaim_request_path = NULL;
char* host_reclaim_result_path = NULL;
