#include <stddef.h>

int enable_debug = 0;

// This variable exists so the tests can point
// it to a mockup proc dir
char* procdir_path = "/proc";

// --host-meminfo, see globals.h
char* host_meminfo_path = NULL;
