package earlyoom_testsuite

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	linuxproc "github.com/c9s/goprocinfo/linux"
)

// On Fedora 31 (Linux 5.4), /proc/sys/kernel/pid_max = 4194304.
// It's very unlikely that INT32_MAX will be a valid pid anytime soon.
const INT32_MAX = 2147483647
const ENOENT = 2

func TestParseTuple(t *testing.T) {
	tcs := []struct {
		arg        string
		limit      int
		shouldFail bool
		term       float64
		kill       float64
	}{
		{arg: "2,1", limit: 100, term: 2, kill: 1},
		{arg: "20,10", limit: 100, term: 20, kill: 10},
		{arg: "30", limit: 100, term: 30, kill: 15},
		{arg: "30", limit: 20, shouldFail: true},
		// https://github.com/rfjakob/earlyoom/issues/97
		{arg: "22[,20]", limit: 100, shouldFail: true},
		{arg: "220[,160]", limit: 300, shouldFail: true},
		{arg: "180[,170]", limit: 300, shouldFail: true},
		{arg: "5,0", limit: 100, term: 5, kill: 0},
		{arg: "5,9", limit: 100, term: 9, kill: 9},
		{arg: "0,5", limit: 100, term: 5, kill: 5},
		// TERM value is set to KILL value when it is below TERM
		{arg: "4,5", limit: 100, term: 5, kill: 5},
		{arg: "0", limit: 100, shouldFail: true},
		{arg: "0,0", limit: 100, shouldFail: true},
		// Floating point values
		{arg: "4.0,2.0", limit: 100, term: 4, kill: 2},
		{arg: "4,0,2,0", limit: 100, shouldFail: true},
		{arg: "3.1415,2.7182", limit: 100, term: 3.1415, kill: 2.7182},
		{arg: "3.1415", limit: 100, term: 3.1415, kill: 3.1415 / 2},
		{arg: "1." + strings.Repeat("123", 100), limit: 100, shouldFail: true},
		// Leading garbage
		{arg: "x1,x2", limit: 100, shouldFail: true},
		{arg: "1,x2", limit: 100, shouldFail: true},
		// Trailing garbage
		{arg: "1x,2x", limit: 100, shouldFail: true},
		{arg: "1.1.", limit: 100, shouldFail: true},
		{arg: "1,2..", limit: 100, shouldFail: true},
	}
	for _, tc := range tcs {
		err, term, kill := parse_term_kill_tuple(tc.arg, tc.limit)
		hasFailed := (err != nil)
		if tc.shouldFail != hasFailed {
			t.Errorf("case %v: hasFailed=%v", tc, hasFailed)
			continue
		}
		if term != tc.term {
			t.Errorf("case %v: term=%v", tc, term)
		}
		if kill != tc.kill {
			t.Errorf("case %v: kill=%v", tc, kill)
		}
	}
}

func TestIsAlive(t *testing.T) {
	tcs := []struct {
		pid int
		res bool
	}{
		{os.Getpid(), true},
		{1, true},
		{999999, false},
		{0, false},
	}
	for _, tc := range tcs {
		if res := is_alive(tc.pid); res != tc.res {
			t.Errorf("pid %d: expected %v, got %v", tc.pid, tc.res, res)
		}
	}
}

func TestIsAliveMock(t *testing.T) {
	mockProcdir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatal(err)
	}
	procdir_path(mockProcdir)
	defer procdir_path("/proc")

	if err := os.Mkdir(mockProcdir+"/100", 0700); err != nil {
		t.Fatal(err)
	}

	statString := func(comm string, state string) string {
		template := "144815 (%s) %s 17620 144815 144815 34817 247882 4194304 20170 1855121 1 3321 28 46 3646 3366 20 0 1 0 10798280 237576192 1065 18446744073709551615 94174652813312 94174653706789 140724247111872 0 0 0 65536 3686404 1266761467 0 0 0 17 0 0 0 9 0 0 94174653946928 94174653994640 94174663303168 140724247119367 140724247119377 140724247119377 140724247121902 0"
		return fmt.Sprintf(template, comm, state)
	}
	testCases := []struct {
		content string
		res     bool
	}{
		{statString("bash", "R"), true}, // full string from actual system
		{statString("bash", "Z"), false},
		// hostile process names that try to fake "I am dead"
		{statString("foo) Z ", "R"), true},
		{statString("foo) Z", "R"), true},
		{statString("foo)Z ", "R"), true},
		{statString("foo)\nZ\n", "R"), true},
		{statString("foo)\tZ\t", "R"), true},
		{statString("foo)  Z  ", "R"), true},
		// Actual stat string from https://github.com/rfjakob/zombiemem
		{"777295 (zombiemem) Z 773303 777295 773303 34817 777295 4227084 262246 0 1 0 18 49 0 0 20 0 2 0 8669053 0 0 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0 0 0 0 0 0 0 0 0", true},
	}

	for _, tc := range testCases {
		statFile := mockProcdir + "/100/stat"
		if err := ioutil.WriteFile(statFile, []byte(tc.content), 0600); err != nil {
			t.Fatal(err)
		}
		if is_alive(100) != tc.res {
			t.Errorf("have=%v, want=%v for /proc/100/stat=%q", is_alive(100), tc.res, tc.content)
		}
	}
}

func Test_fix_truncated_utf8(t *testing.T) {
	// From https://gist.github.com/w-vi/67fe49106c62421992a2
	str := "___😀∮ E⋅da = Q,  n → ∞, 𐍈∑ f(i) = ∏ g(i)"
	// a range loop will split at runes - we *want* broken utf8 so use raw
	// counter.
	for i := 3; i < len(str); i++ {
		truncated := str[:i]
		fixed := fix_truncated_utf8(truncated)
		if len(fixed) < 3 {
			t.Fatalf("truncated: %q", fixed)
		}
		if !utf8.Valid([]byte(fixed)) {
			t.Errorf("Invalid utf8: %q", fixed)
		}
	}
}

func Test_get_oom_score(t *testing.T) {
	res := get_oom_score(os.Getpid())
	// On systems with a lot of RAM, our process may actually have a score of
	// zero. At least check that get_oom_score did not return an error.
	if res < 0 {
		t.Error(res)
	}
	res = get_oom_score(INT32_MAX)
	if res != -ENOENT {
		t.Errorf("want %d, but have %d", syscall.ENOENT, res)
	}
}

func Test_get_comm(t *testing.T) {
	pid := os.Getpid()
	res, comm := get_comm(pid)
	if res != 0 {
		t.Fatalf("error %d", res)
	}
	if len(comm) == 0 {
		t.Fatalf("empty process name %q", comm)
	}
	t.Logf("process name %q", comm)
	// Error case
	res, comm = get_comm(INT32_MAX)
	if res != -ENOENT {
		t.Fail()
	}
	if comm != "" {
		t.Fail()
	}
}

func Test_get_cmdline(t *testing.T) {
	pid := os.Getpid()
	res, comm := get_cmdline(pid)
	if res != 0 {
		t.Fatalf("error %d", res)
	}
	if len(comm) == 0 {
		t.Fatalf("empty process cmdline %q", comm)
	}
	t.Logf("process cmdline %q", comm)
	// Error case
	res, comm = get_cmdline(INT32_MAX)
	if res != -ENOENT {
		t.Fail()
	}
	if comm != "" {
		t.Fail()
	}
}

func Test_parse_proc_pid_stat_buf(t *testing.T) {
	should_error_out := []string{
		"",
		"x",
		"\000\000\000",
		")",
	}
	for _, v := range should_error_out {
		res, _ := parse_proc_pid_stat_buf(v)
		if res {
			t.Errorf("Should have errored out at %q", v)
		}
	}
}

func Test_parse_proc_pid_stat_1(t *testing.T) {
	stat, err := linuxproc.ReadProcessStat("/proc/1/stat")
	if err != nil {
		t.Fatal(err)
	}

	res, have := parse_proc_pid_stat(1)
	if !res {
		t.Fatal(res)
	}

	want := have
	want.state = _Ctype_char(stat.State[0])
	want.ppid = _Ctype_int(stat.Ppid)
	want.num_threads = _Ctype_long(stat.NumThreads)
	want.rss = _Ctype_long(stat.Rss)

	if have != want {
		t.Errorf("\nhave=%#v\nwant=%#v", have, want)
	}
}

func Test_parse_proc_pid_stat_Mock(t *testing.T) {
	mockProcdir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatal(err)
	}
	procdir_path(mockProcdir)
	defer procdir_path("/proc")

	if err := os.Mkdir(mockProcdir+"/100", 0700); err != nil {
		t.Fatal(err)
	}

	// Real /proc/pid/stat string for gnome-shell
	template := "549077 (%s) S 547891 549077 549077 0 -1 4194560 245592 104 342 5 108521 28953 0 1 20 0 23 0 4816953 5260238848 65528 18446744073709551615 94179647238144 94179647245825 140730757359824 0 0 0 0 16781312 17656 0 0 0 17 1 0 0 0 0 0 94179647252976 94179647254904 94179672109056 140730757367876 140730757367897 140730757367897 140730757369827 0"
	content := []string{
		fmt.Sprintf(template, "gnome-shell"),
		fmt.Sprintf(template, ""),
		fmt.Sprintf(template, ": - )"),
		fmt.Sprintf(template, "()()()())))(((()))()()"),
		fmt.Sprintf(template, "   \n\n    "),
	}

	// Stupid hack to get a C.pid_stat_t
	_, want := parse_proc_pid_stat(1)
	want.state = 'S'
	want.ppid = 547891
	want.num_threads = 23
	want.rss = 65528

	for _, c := range content {
		statFile := mockProcdir + "/100/stat"
		if err := ioutil.WriteFile(statFile, []byte(c), 0600); err != nil {
			t.Fatal(err)
		}
		res, have := parse_proc_pid_stat(100)
		if !res {
			t.Errorf("parse_proc_pid_stat returned %v", res)
		}
		if have != want {
			t.Errorf("/proc/100/stat=%q:\nhave=%#v\nwant=%#v", c, have, want)
		}
	}
}

// permute_is_larger checks is_larger() against every pair of `procs`, which
// must be listed from the best victim candidate's opposite (smallest) to the
// best victim (largest).
func permute_is_larger(t *testing.T, args *_Ctype_poll_loop_args_t, m *_Ctype_meminfo_t, procs []mockProcProcess) {
	for i := range procs {
		for j := range procs {
			// If the entry is later in the list, is_larger should return true.
			want := j > i
			have := is_larger(args, m, procs[i], procs[j])
			if want != have {
				t.Errorf("j%d/pid%d larger than i%d/pid%d? want=%v have=%v (badness %d vs %d)",
					j, procs[j].pid, i, procs[i].pid, want, have,
					badness(args, m, procs[j]), badness(args, m, procs[i]))
			}
		}
	}
}

// One oom_score_adj point is worth (MemTotal + SwapTotal) / 1000 KiB. With
// these totals that is exactly 1000 KiB.
const testMemTotalKiB = 1000000

// The adj term dominates RSS within the MemTotal/1000 exchange rate, and a
// large enough RSS gap still wins, like the kernel's soft steer.
func Test_is_larger_adj_beats_rss(t *testing.T) {
	procs := []mockProcProcess{
		// smallest
		{pid: 100, oom_score_adj: 0, VmRSSkiB: 50000},     // 50000
		{pid: 101, oom_score_adj: 100, VmRSSkiB: 1000},    // 101000
		{pid: 102, oom_score_adj: 100, VmRSSkiB: 2000},    // 102000
		{pid: 103, oom_score_adj: -500, VmRSSkiB: 999000}, // 499000
		{pid: 104, oom_score_adj: 900, VmRSSkiB: 1000},    // 901000
		{pid: 105, oom_score_adj: 0, VmRSSkiB: 950000},    // 950000
		// largest
	}
	mockProc(t, procs)
	defer procdir_path("/proc")

	args := poll_loop_args_t(orderingKernelBadness)
	m := meminfo_t(testMemTotalKiB, 0)
	permute_is_larger(t, &args, &m, procs)

	if have := badness(&args, &m, procs[3]); have != 499000 {
		t.Errorf("pid 103: badness want=499000 have=%d", have)
	}
}

// gVisor serves oom_score as a constant 0 and has no VmSwap/VmPTE lines. The
// order must still follow oom_score_adj. This is the bug the fork fixes:
// upstream fell back to largest RSS here.
func Test_is_larger_gvisor_zero_oom_score(t *testing.T) {
	procs := []mockProcProcess{
		// smallest
		{pid: 100, oom_score_adj: 25, VmRSSkiB: 400000, gvisor: true},  // a chat: 425000
		{pid: 101, oom_score_adj: 500, VmRSSkiB: 100000, gvisor: true}, // a worker: 600000
		{pid: 102, oom_score_adj: 900, VmRSSkiB: 20000, gvisor: true},  // pytest: 920000
		{pid: 103, oom_score_adj: 1000, VmRSSkiB: 5000, gvisor: true},  // chromium: 1005000
		// largest
	}
	mockProc(t, procs)
	defer procdir_path("/proc")

	args := poll_loop_args_t(orderingKernelBadness)
	m := meminfo_t(testMemTotalKiB, 0)
	permute_is_larger(t, &args, &m, procs)

	v := find_largest_process_with(&args, &m)
	if v.pid != 103 {
		t.Errorf("victim want=103 have=%d", v.pid)
	}
	if v.oomScore != 0 {
		t.Errorf("victim oom_score want=0 have=%d", v.oomScore)
	}
}

// VmSwap and VmPTE count like RSS, and SwapTotal scales the adj term.
func Test_is_larger_swap_terms(t *testing.T) {
	procs := []mockProcProcess{
		{pid: 100, VmRSSkiB: 15000},
		{pid: 101, VmRSSkiB: 1000, oom_score_adj: 10},
		{pid: 102, VmRSSkiB: 1000, VmSwapkiB: 30000},
		{pid: 103, VmRSSkiB: 1000, VmPTEkiB: 40000},
	}
	mockProc(t, procs)
	defer procdir_path("/proc")

	args := poll_loop_args_t(orderingKernelBadness)

	noSwap := meminfo_t(testMemTotalKiB, 0)
	// 15000, 11000, 31000, 41000
	permute_is_larger(t, &args, &noSwap, []mockProcProcess{procs[1], procs[0], procs[2], procs[3]})

	// With as much swap as RAM, one adj point is worth 2000 KiB:
	// 15000, 21000, 31000, 41000
	withSwap := meminfo_t(testMemTotalKiB, testMemTotalKiB)
	permute_is_larger(t, &args, &withSwap, procs)
}

// --prefer and --avoid are worth +-300 oom_score_adj points.
func Test_is_larger_prefer_avoid(t *testing.T) {
	procs := []mockProcProcess{
		// smallest
		{pid: 100, comm: "sshd", VmRSSkiB: 200000},                    // 200000 - 300000
		{pid: 101, comm: "foo", VmRSSkiB: 1000},                       // 1000
		{pid: 102, comm: "foo", VmRSSkiB: 1000, oom_score_adj: 250},   // 251000
		{pid: 103, comm: "chrome", VmRSSkiB: 1000},                    // 301000
		{pid: 104, comm: "foo", VmRSSkiB: 1000, oom_score_adj: 301},   // 302000
		{pid: 105, comm: "sshd", VmRSSkiB: 1000, oom_score_adj: 1000}, // 701000
		// largest
	}
	mockProc(t, procs)
	defer procdir_path("/proc")

	args := poll_loop_args_t(orderingKernelBadness)
	setPrefer(&args, "^chrome$")
	setAvoid(&args, "^sshd$")
	m := meminfo_t(testMemTotalKiB, 0)
	permute_is_larger(t, &args, &m, procs)

	if have := badness(&args, &m, procs[0]); have != -100000 {
		t.Errorf("avoided sshd: badness want=-100000 have=%d", have)
	}
}

// A process at oom_score_adj -1000 is never picked, even when it is the only
// candidate.
func Test_is_larger_skips_adj_minus_1000(t *testing.T) {
	procs := []mockProcProcess{
		{pid: 100, VmRSSkiB: 900000, oom_score_adj: -1000},
	}
	mockProc(t, procs)
	defer procdir_path("/proc")

	args := poll_loop_args_t(orderingKernelBadness)
	// Even a --prefer bonus does not make it eligible.
	setPrefer(&args, ".")
	m := meminfo_t(testMemTotalKiB, 0)
	if _, eligible := candidate(&args, &m, procs[0]); eligible {
		t.Error("pid at oom_score_adj -1000 is eligible")
	}
	if v := find_largest_process_with(&args, &m); v.pid > 0 {
		t.Errorf("want no victim, have pid %d", v.pid)
	}
}

// Inside a pid namespace, pid 2 and its children are ordinary processes.
// Only a process without an mm (no VmRSS line) is a kernel thread, and pid 1
// is init.
func Test_is_larger_kernel_threads(t *testing.T) {
	procs := []mockProcProcess{
		{pid: 1, VmRSSkiB: 500000},
		{pid: 2, VmRSSkiB: 5000},
		{pid: 60, ppid: 2, VmRSSkiB: 6000},
		{pid: 70, noMm: true, oom_score_adj: 1000},
	}
	mockProc(t, procs)
	defer procdir_path("/proc")

	args := poll_loop_args_t(orderingKernelBadness)
	m := meminfo_t(testMemTotalKiB, 0)
	for _, tc := range []struct {
		pid      int
		eligible bool
	}{{1, false}, {2, true}, {60, true}, {70, false}} {
		var proc mockProcProcess
		for _, p := range procs {
			if p.pid == tc.pid {
				proc = p
			}
		}
		if _, have := candidate(&args, &m, proc); have != tc.eligible {
			t.Errorf("pid %d: eligible want=%v have=%v", tc.pid, tc.eligible, have)
		}
	}
	if v := find_largest_process_with(&args, &m); v.pid != 60 {
		t.Errorf("victim want=60 have=%d", v.pid)
	}
}

// A zombie main thread has no mm of its own; like the kernel's
// find_lock_task_mm(), its memory is found through a live thread.
func Test_is_larger_zombie_main_thread(t *testing.T) {
	procs := []mockProcProcess{
		{pid: 100, VmRSSkiB: 5000},
		{pid: 200, zombieLeader: true, VmRSSkiB: 800000},
	}
	mockProc(t, procs)
	defer procdir_path("/proc")

	args := poll_loop_args_t(orderingKernelBadness)
	m := meminfo_t(testMemTotalKiB, 0)
	v := find_largest_process_with(&args, &m)
	if v.pid != 200 || v.vmRssKiB != 800000 {
		t.Errorf("victim want=200 with 800000 KiB, have=%d with %d KiB", v.pid, v.vmRssKiB)
	}
}

// gVisor prints every Vm* line as 0 for a task without an mm instead of
// omitting them. A single-threaded zombie or exiting task frees nothing when
// killed, so it must not be chosen however high its oom_score_adj: choosing
// it made earlyoom signal the same dead pid in a loop while memory ran out.
// A zombie leader whose other threads still run is kept, on its adj alone,
// because gVisor cannot list its task directory to find their memory.
func Test_is_larger_gvisor_task_without_mm(t *testing.T) {
	procs := []mockProcProcess{
		{pid: 100, oom_score_adj: 0, VmRSSkiB: 50000, gvisor: true},
		{pid: 200, oom_score_adj: 931, state: "Z", gvisorNoMm: true},
		{pid: 300, oom_score_adj: 931, state: "R", gvisorNoMm: true},
		{pid: 400, oom_score_adj: 500, state: "Z", num_threads: 2, gvisorNoMm: true},
	}
	mockProc(t, procs)
	defer procdir_path("/proc")

	m := meminfo_t(testMemTotalKiB, 0)
	for _, rssSource := range []_Ctype_rss_source_t{rssSourceVmrss, rssSourceSmapsAnonymous} {
		t.Run(rss_source_name(rssSource), func(t *testing.T) {
			args := badness_poll_loop_args_t(rssSource)
			for _, tc := range []struct {
				proc     mockProcProcess
				eligible bool
			}{{procs[0], true}, {procs[1], false}, {procs[2], false}, {procs[3], true}} {
				if _, have := candidate(&args, &m, tc.proc); have != tc.eligible {
					t.Errorf("pid %d: eligible want=%v have=%v", tc.proc.pid, tc.eligible, have)
				}
			}
			if have := badness(&args, &m, procs[3]); have != 500000 {
				t.Errorf("pid 400: badness want=500000 have=%d", have)
			}
			if v := find_largest_process_with(&args, &m); v.pid != 400 || v.vmRssKiB != 0 {
				t.Errorf("victim want=400 with 0 KiB, have=%d with %d KiB", v.pid, v.vmRssKiB)
			}
		})
	}
}

// gVisor's VmRSS counts every page of each range it has mapped, touched or
// not: anonymous memory in 2 MiB-aligned blocks, and a mapped file in full.
// Counting the smaps Anonymous total instead, a process that has mapped much
// but holds little no longer outranks one that really holds its memory.
func Test_is_larger_gvisor_smaps_anonymous(t *testing.T) {
	procs := []mockProcProcess{
		// smallest by smaps Anonymous
		{pid: 100, VmRSSkiB: 600000, smapsAnonKiB: 20000, gvisor: true},                      // 20000
		{pid: 101, VmRSSkiB: 60000, gvisor: true},                                            // 60000
		{pid: 102, oom_score_adj: 100, VmRSSkiB: 300000, smapsAnonKiB: 10000, gvisor: true},  // 110000
		{pid: 103, oom_score_adj: 100, VmRSSkiB: 150000, smapsAnonKiB: 140000, gvisor: true}, // 240000
		// largest
	}
	mockProc(t, procs)
	defer procdir_path("/proc")

	m := meminfo_t(testMemTotalKiB, 0)
	anon := badness_poll_loop_args_t(rssSourceSmapsAnonymous)
	permute_is_larger(t, &anon, &m, procs)
	if have := badness(&anon, &m, procs[2]); have != 110000 {
		t.Errorf("pid 102: badness want=110000 have=%d", have)
	}
	if v := find_largest_process_with(&anon, &m); v.pid != 103 {
		t.Errorf("victim want=103 have=%d", v.pid)
	}

	// By VmRSS: 60000, 250000, 400000, 600000
	vmrss := badness_poll_loop_args_t(rssSourceVmrss)
	permute_is_larger(t, &vmrss, &m, []mockProcProcess{procs[1], procs[3], procs[2], procs[0]})
}

func Test_parse_proc_pid_smaps_anon_path(t *testing.T) {
	vma := func(header string, anonKiB int) string {
		return fmt.Sprintf("%s\nSize:\t2048 kB\nRss:\t2048 kB\nAnonymous:\t%d kB\nAnonHugePages:\t0 kB\n", header, anonKiB)
	}
	// A path of this 16-byte text, 16 KB long, has a read-buffer chunk that
	// starts with "Anonymous:" whatever the (odd) buffer length. It is not a
	// field and must not be counted.
	longPath := "/tmp/" + strings.Repeat("Anonymous: 1 kB/", 1000)
	tcs := []struct {
		name    string
		content string
		ok      bool
		anonKiB int64
	}{
		{"sums every mapping", vma("55d5c1000000-55d5c1400000 rw-p 00000000 00:00 0 [heap]", 1500) +
			vma("7f3a00000000-7f3a00200000 rw-p 00000000 00:00 0", 548) +
			vma("7f3a40000000-7f3a40200000 r-xp 00000000 00:31 99 /usr/bin/claude", 0), true, 2048},
		{"long header line", vma("7f3a00000000-7f3a00200000 r--p 00000000 00:31 99 "+longPath, 7) +
			vma("7f3a40000000-7f3a40200000 rw-p 00000000 00:00 0", 5), true, 12},
		{"no mappings", "", true, 0},
		{"garbage", "Anonymous:\tlots kB\n", false, 0},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			path := t.TempDir() + "/smaps"
			writeFile(t, path, tc.content)
			ok, have := parse_proc_pid_smaps_anon_path(path)
			if ok != tc.ok || (ok && have != tc.anonKiB) {
				t.Errorf("want ok=%v %d KiB, have ok=%v %d KiB", tc.ok, tc.anonKiB, ok, have)
			}
		})
	}
	if ok, _ := parse_proc_pid_smaps_anon_path(t.TempDir() + "/missing"); ok {
		t.Error("a missing file parsed")
	}
}

// The host's figures replace the sandbox's only when they show less headroom,
// and only while they are fresh and well-formed.
func Test_apply_host_meminfo(t *testing.T) {
	const now = 1790000000
	host := func(total, avail, ts int64) string {
		return fmt.Sprintf("MemTotal:       %d kB\nMemAvailable:   %d kB\nTimestamp:      %d\n", total, avail, ts)
	}
	tcs := []struct {
		name    string
		buf     string
		want    hostMeminfoResult
		percent float64
	}{
		{"lower", host(1000000, 80000, now), hostMeminfoApplied, 8},
		{"higher", host(1000000, 600000, now), hostMeminfoNotLower, 50},
		{"equal", host(1000000, 500000, now), hostMeminfoNotLower, 50},
		{"just fresh", host(1000000, 80000, now-hostMeminfoMaxAgeSec), hostMeminfoApplied, 8},
		{"old", host(1000000, 80000, now-hostMeminfoMaxAgeSec-1), hostMeminfoStale, 50},
		{"future", host(1000000, 80000, now+hostMeminfoMaxAgeSec+1), hostMeminfoStale, 50},
		{"no timestamp", "MemTotal: 1000000 kB\nMemAvailable: 80000 kB\n", hostMeminfoInvalid, 50},
		{"no MemAvailable", "MemTotal: 1000000 kB\nTimestamp: 1790000000\n", hostMeminfoInvalid, 50},
		{"avail above total", host(1000000, 1000001, now), hostMeminfoInvalid, 50},
		{"zero total", host(0, 0, now), hostMeminfoInvalid, 50},
		{"empty", "", hostMeminfoInvalid, 50},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			m := sandboxMeminfo(1000000, 450000, 900000)
			res := apply_host_meminfo(&m, tc.buf, now)
			if res != tc.want {
				t.Errorf("result want=%s have=%s", host_meminfo_result_name(tc.want), host_meminfo_result_name(res))
			}
			if float64(m.MemAvailablePercent) != tc.percent {
				t.Errorf("MemAvailablePercent want=%v have=%v", tc.percent, m.MemAvailablePercent)
			}
			if bool(m.host_limited) != (tc.want == hostMeminfoApplied) {
				t.Errorf("host_limited=%v", m.host_limited)
			}
			if m.MemTotalKiB != 1000000 {
				t.Errorf("MemTotalKiB changed to %d", m.MemTotalKiB)
			}
			if tc.want == hostMeminfoApplied && (m.MemAvailableKiB != 80000 || m.UserMemTotalKiB != 1000000) {
				t.Errorf("have avail=%d of %d KiB, want the host's 80000 of 1000000", m.MemAvailableKiB, m.UserMemTotalKiB)
			}
		})
	}
}

// The startup self-check picks upstream_fallback when an input of the badness
// cannot be read. Otherwise it picks where the badness reads resident memory
// from: a Linux status has RssAnon, and VmRSS is what the kernel counts.
// gVisor's has none, and the smaps Anonymous total is counted instead, as long
// as earlyoom can read its own smaps.
func Test_select_ordering(t *testing.T) {
	self := os.Getpid()
	tcs := []struct {
		name          string
		self          mockProcProcess
		m             _Ctype_meminfo_t
		want          _Ctype_ordering_t
		wantRssSource _Ctype_rss_source_t
	}{
		{"Linux status", mockProcProcess{pid: self, VmRSSkiB: 1000}, meminfo_t(testMemTotalKiB, 0), orderingKernelBadness, rssSourceVmrss},
		{"gVisor status", mockProcProcess{pid: self, VmRSSkiB: 1000, gvisor: true}, meminfo_t(testMemTotalKiB, 0), orderingKernelBadness, rssSourceSmapsAnonymous},
		{"gVisor status, no smaps", mockProcProcess{pid: self, VmRSSkiB: 1000, gvisor: true, noSmaps: true}, meminfo_t(testMemTotalKiB, 0), orderingKernelBadness, rssSourceVmrss},
		{"unreadable adj", mockProcProcess{pid: self, VmRSSkiB: 1000, noAdj: true}, meminfo_t(testMemTotalKiB, 0), orderingUpstreamFallback, 0},
		{"no VmRSS", mockProcProcess{pid: self, noMm: true}, meminfo_t(testMemTotalKiB, 0), orderingUpstreamFallback, 0},
		{"no MemTotal", mockProcProcess{pid: self, VmRSSkiB: 1000}, meminfo_t(0, 0), orderingUpstreamFallback, 0},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			mockProc(t, []mockProcProcess{tc.self})
			defer procdir_path("/proc")
			m := tc.m
			have, haveRssSource := select_ordering(&m)
			if have != tc.want {
				t.Errorf("want=%s have=%s", ordering_name(tc.want), ordering_name(have))
			}
			if have == orderingKernelBadness && haveRssSource != tc.wantRssSource {
				t.Errorf("rss source: want=%s have=%s", rss_source_name(tc.wantRssSource), rss_source_name(haveRssSource))
			}
		})
	}
}

// The upstream orderings are upstream's is_larger() unchanged, so these are
// upstream's tests.
func Test_is_larger(t *testing.T) {
	procs := []mockProcProcess{
		// smallest
		{pid: 100, oom_score: 100, VmRSSkiB: 1234},
		{pid: 101, oom_score: 100, VmRSSkiB: 1238},
		{pid: 102, oom_score: 101, VmRSSkiB: 4},
		{pid: 103, oom_score: 102, VmRSSkiB: 4},
		{pid: 104, oom_score: 103, VmRSSkiB: 0, num_threads: 2}, // zombie main thread
		// largest
	}

	mockProc(t, procs)
	defer procdir_path("/proc")
	t.Logf("procdir_path=%q", procdir_path(""))

	args := poll_loop_args_t(orderingUpstreamFallback)
	m := meminfo_t(testMemTotalKiB, 0)
	permute_is_larger(t, &args, &m, procs)
}

func Test_is_larger_by_rss(t *testing.T) {
	procs := []mockProcProcess{
		// smallest
		{pid: 100, oom_score: 100, VmRSSkiB: 4},
		{pid: 101, oom_score: 100, VmRSSkiB: 8},
		{pid: 102, oom_score: 101, VmRSSkiB: 8},
		{pid: 103, oom_score: 99, VmRSSkiB: 12},
		{pid: 104, oom_score: 102, VmRSSkiB: 0, num_threads: 2}, // zombie main thread
		{pid: 105, oom_score: 102, VmRSSkiB: 12},
		// largest
	}

	mockProc(t, procs)
	defer procdir_path("/proc")
	t.Logf("procdir_path=%q", procdir_path(""))

	args := poll_loop_args_t(orderingSortByRss)
	m := meminfo_t(testMemTotalKiB, 0)
	permute_is_larger(t, &args, &m, procs)
}

// The -N hook gets the victim's adj, RSS and the ordering in its environment,
// and the badness when that is what chose the victim.
func Test_notify_ext_environment(t *testing.T) {
	victim := victimInfo{pid: 4242, oomScoreAdj: 900, badnessKiB: 920000, vmRssKiB: 20000}
	common := []string{
		"EARLYOOM_PID=4242\n",
		"EARLYOOM_NAME=pytest\n",
		"EARLYOOM_OOM_SCORE_ADJ=900\n",
		"EARLYOOM_VMRSS_KIB=20000\n",
	}
	tcs := []struct {
		ordering _Ctype_ordering_t
		want     []string
		absent   []string
	}{
		{orderingKernelBadness, []string{"EARLYOOM_BADNESS_KIB=920000\n", "EARLYOOM_ORDERING=kernel_badness\n"}, nil},
		{orderingUpstreamFallback, []string{"EARLYOOM_ORDERING=upstream_fallback\n"}, []string{"EARLYOOM_BADNESS_KIB="}},
	}
	for i, tc := range tcs {
		if i > 0 {
			// --dryrun runs the hook at most once per second.
			time.Sleep(1100 * time.Millisecond)
		}
		t.Run(ordering_name(tc.ordering), func(t *testing.T) {
			dir := t.TempDir()
			out := dir + "/env"
			script := dir + "/hook.sh"
			writeFile(t, script, "#!/bin/sh\nenv > "+out+".tmp && mv "+out+".tmp "+out+"\n")
			if err := os.Chmod(script, 0755); err != nil {
				t.Fatal(err)
			}

			kill_process_dryrun_notify(tc.ordering, script, victim, "pytest")

			var content []byte
			for i := 0; i < 100; i++ {
				var err error
				content, err = ioutil.ReadFile(out)
				if err == nil {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			env := string(content)
			for _, want := range append(common, tc.want...) {
				if !strings.Contains(env, want) {
					t.Errorf("hook environment lacks %q:\n%s", want, env)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(env, absent) {
					t.Errorf("hook environment has %q:\n%s", absent, env)
				}
			}
		})
	}
}

func Test_parse_proc_pid_status_buf(t *testing.T) {
	tcs := []struct {
		buf    string
		ok     bool
		hasRss bool
		rss    int64
		swap   int64
		pte    int64
		// Linux prints RssAnon, gVisor does not
		rssAnon bool
	}{
		{"Name:\tbash\nVmRSS:\t  8240 kB\nRssAnon:\t  6120 kB\nVmPTE:\t    64 kB\nVmSwap:\t    12 kB\n", true, true, 8240, 12, 64, true},
		// gVisor: no VmSwap, no VmPTE
		{"Name:\tbash\nVmRSS:\t8240 kB\n", true, true, 8240, 0, 0, false},
		// kernel thread: no Vm* lines at all
		{"Name:\tkthreadd\nState:\tS (sleeping)\nThreads:\t1\n", true, false, 0, 0, 0, false},
		// a process named like a field must not match
		{"Name:\tVmRSS: 99 kB\nVmRSS:\t7 kB\n", true, true, 7, 0, 0, false},
		{"Name:\tbash\nVmRSS:\tgarbage\n", false, false, 0, 0, 0, false},
		{"", true, false, 0, 0, 0, false},
	}
	for _, tc := range tcs {
		ok, have := parse_proc_pid_status_buf(tc.buf)
		if ok != tc.ok {
			t.Errorf("%q: ok want=%v have=%v", tc.buf, tc.ok, ok)
			continue
		}
		if !ok {
			continue
		}
		if bool(have.has_VmRSS) != tc.hasRss || int64(have.VmRSSkiB) != tc.rss ||
			int64(have.VmSwapkiB) != tc.swap || int64(have.VmPTEkiB) != tc.pte ||
			bool(have.has_RssAnon) != tc.rssAnon {
			t.Errorf("%q: have=%#v", tc.buf, have)
		}
	}
}

func Test_status_has_mm(t *testing.T) {
	tcs := []struct {
		buf   string
		hasMm bool
	}{
		{"Name:\tbash\nVmSize:\t20480 kB\nVmRSS:\t8240 kB\nThreads:\t1\n", true},
		// Linux kernel thread or zombie: no Vm* lines
		{"Name:\tkthreadd\nState:\tS (sleeping)\nThreads:\t1\n", false},
		// gVisor zombie, or a task still exiting: every Vm* line reads 0
		{"Name:\tpulseaudio\nState:\tZ (zombie)\nVmSize:\t0 kB\nVmRSS:\t0 kB\nVmData:\t0 kB\nThreads:\t1\n", false},
		// A live task whose pages are all swapped out still has a VmSize
		{"Name:\tidle\nVmSize:\t20480 kB\nVmRSS:\t0 kB\n", true},
	}
	for _, tc := range tcs {
		if have := status_has_mm(tc.buf); have != tc.hasMm {
			t.Errorf("%q: want=%v have=%v", tc.buf, tc.hasMm, have)
		}
	}
}

func Test_parse_proc_pid_status_self(t *testing.T) {
	ok, have := parse_proc_pid_status(os.Getpid())
	if !ok || !bool(have.has_VmRSS) || have.VmRSSkiB <= 0 {
		t.Errorf("ok=%v have=%#v", ok, have)
	}
}

func Benchmark_parse_meminfo(b *testing.B) {
	enable_debug(false)

	for n := 0; n < b.N; n++ {
		parse_meminfo()
	}
}

func Benchmark_kill_process(b *testing.B) {
	enable_debug(false)

	for n := 0; n < b.N; n++ {
		kill_process()
	}
}

func Benchmark_find_largest_process(b *testing.B) {
	enable_debug(false)

	for n := 0; n < b.N; n++ {
		find_largest_process()
	}
}

func Benchmark_get_oom_score(b *testing.B) {
	enable_debug(false)

	pid := os.Getpid()
	for n := 0; n < b.N; n++ {
		get_oom_score(pid)
	}
}

func Benchmark_get_oom_score_adj(b *testing.B) {
	enable_debug(false)

	pid := os.Getpid()
	for n := 0; n < b.N; n++ {
		var out int
		get_oom_score_adj(pid, &out)
	}
}

func Benchmark_get_cmdline(b *testing.B) {
	enable_debug(false)

	pid := os.Getpid()
	for n := 0; n < b.N; n++ {
		res, comm := get_cmdline(pid)
		if len(comm) == 0 {
			b.Fatalf("empty process cmdline %q", comm)
		}
		if res != 0 {
			b.Fatalf("error %d", res)
		}
	}
}

func Benchmark_parse_proc_pid_stat(b *testing.B) {
	enable_debug(false)

	pid := os.Getpid()
	for n := 0; n < b.N; n++ {
		res, out := parse_proc_pid_stat(pid)
		if out.num_threads == 0 {
			b.Fatalf("no threads???")
		}
		if !res {
			b.Fatal("failed")
		}
	}
}
