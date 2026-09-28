package earlyoom_testsuite

import (
	"fmt"
	"strings"
	"unsafe"
)

// #cgo CFLAGS: -std=gnu99 -DCGO
// #include <limits.h>
// #include <regex.h>
// #include <signal.h>
// #include <stdlib.h>
// #include "meminfo.h"
// #include "kill.h"
// #include "msg.h"
// #include "globals.h"
// #include "proc_pid.h"
import "C"

func init() {
	C.enable_debug = 1
}

func enable_debug(state bool) (oldState bool) {
	if C.enable_debug == 1 {
		oldState = true
	}
	if state {
		C.enable_debug = 1
	} else {
		C.enable_debug = 0
	}
	return
}

func parse_term_kill_tuple(optarg string, upper_limit int) (error, float64, float64) {
	cs := C.CString(optarg)
	tuple := C.parse_term_kill_tuple(cs, C.longlong(upper_limit))
	errmsg := C.GoString(&(tuple.err[0]))
	if len(errmsg) > 0 {
		return fmt.Errorf(errmsg), 0, 0
	}
	return nil, float64(tuple.term), float64(tuple.kill)
}

func is_alive(pid int) bool {
	res := C.is_alive(C.int(pid))
	return bool(res)
}

func fix_truncated_utf8(str string) string {
	cstr := C.CString(str)
	C.fix_truncated_utf8(cstr)
	return C.GoString(cstr)
}

func parse_meminfo() C.meminfo_t {
	return C.parse_meminfo()
}

const (
	orderingKernelBadness    = C.ORDERING_KERNEL_BADNESS
	orderingUpstreamFallback = C.ORDERING_UPSTREAM_FALLBACK
	orderingSortByRss        = C.ORDERING_SORT_BY_RSS
)

// Wrapper so _test.go code can create a poll_loop_args_t
// struct. _test.go code cannot use C.
func poll_loop_args_t(ordering C.ordering_t) (args C.poll_loop_args_t) {
	args.ordering = ordering
	args.sort_by_rss = C.bool(ordering == C.ORDERING_SORT_BY_RSS)
	return
}

// compileRegex returns a regex_t for --prefer/--avoid/--ignore. It is never
// freed; the tests are short-lived.
func compileRegex(pattern string) *C.regex_t {
	re := (*C.regex_t)(C.malloc(C.size_t(unsafe.Sizeof(C.regex_t{}))))
	cpattern := C.CString(pattern)
	defer C.free(unsafe.Pointer(cpattern))
	if C.regcomp(re, cpattern, C.REG_EXTENDED|C.REG_NOSUB) != 0 {
		panic("regcomp failed: " + pattern)
	}
	return re
}

func setPrefer(args *C.poll_loop_args_t, pattern string) {
	args.prefer_regex = compileRegex(pattern)
}

func setAvoid(args *C.poll_loop_args_t, pattern string) {
	args.avoid_regex = compileRegex(pattern)
}

func meminfo_t(memTotalKiB int64, swapTotalKiB int64) (m C.meminfo_t) {
	m.MemTotalKiB = C.longlong(memTotalKiB)
	m.SwapTotalKiB = C.longlong(swapTotalKiB)
	return
}

func procinfo_t() C.procinfo_t {
	return C.procinfo_t{}
}

// emptyVictim mirrors the initial victim of find_largest_process().
func emptyVictim() (p C.procinfo_t) {
	p.pid = C.PROCINFO_FIELD_NOT_SET
	p.uid = C.PROCINFO_FIELD_NOT_SET
	p.oom_score = C.PROCINFO_FIELD_NOT_SET
	p.oom_score_adj = C.PROCINFO_FIELD_NOT_SET
	p.VmRSSkiB = C.PROCINFO_FIELD_NOT_SET
	p.badness_kib = C.LLONG_MIN
	return
}

// candidate runs is_larger() against an empty victim, which fills in the
// process's badness from the mock /proc. It reports whether the process is
// eligible at all.
func candidate(args *C.poll_loop_args_t, m *C.meminfo_t, proc mockProcProcess) (C.procinfo_t, bool) {
	empty := emptyVictim()
	cur := emptyVictim()
	cur.pid = C.int(proc.pid)
	eligible := bool(C.is_larger(args, m, &empty, &cur))
	return cur, eligible
}

func is_larger(args *C.poll_loop_args_t, m *C.meminfo_t, victim mockProcProcess, cur mockProcProcess) bool {
	cVictim, _ := candidate(args, m, victim)
	cCur := emptyVictim()
	cCur.pid = C.int(cur.pid)
	return bool(C.is_larger(args, m, &cVictim, &cCur))
}

// badness returns the badness is_larger() computes for `proc`.
func badness(args *C.poll_loop_args_t, m *C.meminfo_t, proc mockProcProcess) int64 {
	cur, _ := candidate(args, m, proc)
	return int64(cur.badness_kib)
}

type victimInfo struct {
	pid         int
	badnessKiB  int64
	oomScoreAdj int
	vmRssKiB    int64
	oomScore    int
}

func find_largest_process_with(args *C.poll_loop_args_t, m *C.meminfo_t) victimInfo {
	v := C.find_largest_process(args, m)
	return victimInfo{
		pid:         int(v.pid),
		badnessKiB:  int64(v.badness_kib),
		oomScoreAdj: int(v.oom_score_adj),
		vmRssKiB:    int64(v.VmRSSkiB),
		oomScore:    int(v.oom_score),
	}
}

func find_largest_process() {
	var args C.poll_loop_args_t
	m := C.parse_meminfo()
	C.find_largest_process(&args, &m)
}

func kill_process() {
	var args C.poll_loop_args_t
	var victim C.procinfo_t
	victim.pid = 1
	C.kill_process(&args, 0, &victim)
}

// kill_process_dryrun_notify runs a dry-run SIGTERM "kill" of `victim` with
// `script` as the -N hook, so the hook runs without anything being killed.
func kill_process_dryrun_notify(ordering C.ordering_t, script string, victim victimInfo, name string) {
	args := poll_loop_args_t(ordering)
	args.dryrun = true
	args.notify_ext = C.CString(script)
	var v C.procinfo_t
	v.pid = C.int(victim.pid)
	v.uid = 1000
	v.oom_score_adj = C.int(victim.oomScoreAdj)
	v.badness_kib = C.longlong(victim.badnessKiB)
	v.VmRSSkiB = C.longlong(victim.vmRssKiB)
	for i, b := range []byte(name) {
		v.name[i] = C.char(b)
		v.cmdline[i] = C.char(b)
	}
	C.kill_process(&args, C.SIGTERM, &v)
}

func select_ordering(m *C.meminfo_t) C.ordering_t {
	return C.select_ordering(m)
}

func ordering_name(o C.ordering_t) string {
	return C.GoString(C.ordering_name(o))
}

func get_oom_score(pid int) int {
	return int(C.get_oom_score(C.int(pid)))
}

func get_oom_score_adj(pid int, out *int) int {
	var out2 C.int
	res := C.get_oom_score_adj(C.int(pid), &out2)
	*out = int(out2)
	return int(res)
}

func get_comm(pid int) (int, string) {
	cstr := C.CString(strings.Repeat("\000", 256))
	res := C.get_comm(C.int(pid), cstr, 256)
	return int(res), C.GoString(cstr)
}

func get_cmdline(pid int) (int, string) {
	cstr := C.CString(strings.Repeat("\000", 256))
	res := C.get_cmdline(C.int(pid), cstr, 256)
	return int(res), C.GoString(cstr)
}

func procdir_path(str string) string {
	if str != "" {
		cstr := C.CString(str)
		C.procdir_path = cstr
	}
	return C.GoString(C.procdir_path)
}

func parse_proc_pid_stat_buf(buf string) (res bool, out C.pid_stat_t) {
	cbuf := C.CString(buf)
	res = bool(C.parse_proc_pid_stat_buf(&out, cbuf))
	return res, out
}

func parse_proc_pid_stat(pid int) (res bool, out C.pid_stat_t) {
	res = bool(C.parse_proc_pid_stat(&out, C.int(pid)))
	return res, out
}

func parse_proc_pid_status_buf(buf string) (res bool, out C.pid_status_t) {
	cbuf := C.CString(buf)
	defer C.free(unsafe.Pointer(cbuf))
	res = bool(C.parse_proc_pid_status_buf(&out, cbuf))
	return res, out
}

func status_has_mm(buf string) bool {
	ok, status := parse_proc_pid_status_buf(buf)
	return ok && bool(C.status_has_mm(&status))
}

// sandboxMeminfo is a meminfo_t as parse_meminfo() fills it from a sandbox's
// own /proc/meminfo.
func sandboxMeminfo(memTotalKiB, availKiB, userTotalKiB int64) (m C.meminfo_t) {
	m.MemTotalKiB = C.longlong(memTotalKiB)
	m.MemAvailableKiB = C.longlong(availKiB)
	m.UserMemTotalKiB = C.longlong(userTotalKiB)
	m.MemAvailablePercent = C.double(float64(availKiB) * 100 / float64(userTotalKiB))
	return
}

type hostMeminfoResult = C.host_meminfo_result_t

const (
	hostMeminfoApplied   = C.HOST_MEMINFO_APPLIED
	hostMeminfoNotLower  = C.HOST_MEMINFO_NOT_LOWER
	hostMeminfoInvalid   = C.HOST_MEMINFO_INVALID
	hostMeminfoStale     = C.HOST_MEMINFO_STALE
	hostMeminfoMaxAgeSec = C.HOST_MEMINFO_MAX_AGE_S
)

func apply_host_meminfo(m *C.meminfo_t, buf string, nowSec int64) hostMeminfoResult {
	cbuf := C.CString(buf)
	defer C.free(unsafe.Pointer(cbuf))
	return C.apply_host_meminfo(m, cbuf, C.longlong(nowSec))
}

func host_meminfo_result_name(res hostMeminfoResult) string {
	return C.GoString(C.host_meminfo_result_name(res))
}

func parse_proc_pid_status(pid int) (res bool, out C.pid_status_t) {
	res = bool(C.parse_proc_pid_status(&out, C.int(pid)))
	return res, out
}
