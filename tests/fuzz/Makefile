# Fuzz + regression targets for libinjector's input parsers.
#
# The ELF and /proc parsers consume data that an untrusted or compromised
# target process effectively controls (its own libc image and /proc entries),
# so they are fuzzed with libFuzzer under ASan+UBSan.
#
#   make fuzz          # build the fuzzers and run a short fuzzing session
#   make regress       # replay tests/fuzz/crashes/ - must stay crash-free
#   make fuzz-long     # longer session (FUZZ_SECONDS override)
#
# clang with libFuzzer is REQUIRED, and nothing here ever "skips": without it
# every target fails with exit 1. A silently-skipped fuzz regression looks
# exactly like a passing one in CI, which is how a reintroduced memory-safety
# bug would stay invisible. Set CLANG=... to point at another clang.

CLANG ?= clang
CC ?= cc
SRC_DIR := ../../src/linux
INCLUDES := -I../../include -I$(SRC_DIR)
SAN := -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all
FUZZ_CFLAGS := -g -O1 $(SAN) -fno-omit-frame-pointer $(INCLUDES)
LIB_SRCS := $(wildcard $(SRC_DIR)/*.c) $(SRC_DIR)/shellcode.S
FUZZ_SECONDS ?= 60
JOBS ?= 8
# Floor for how many ELF reproducers `regress` must actually replay. It used to
# be implicit in prose ("4 reproducers are expected") while the only real check
# was `elf_n -eq 0`, so deleting three of the four crashers kept CI green.
# Override on the command line when crashes/ is restructured deliberately:
#   make regress ELF_MIN_REPRODUCERS=1
# Valid values: ONE integer in 0-16, and never more than the number of
# crashes/elf__*.bin files present. Both conditions are enforced at PARSE time
# (see the validation block below), in addition to the runtime check in the
# `regress` recipe, so a bad floor aborts make with an explanation instead of
# reaching `[ $$elf_n -lt $(ELF_MIN_REPRODUCERS) ]`: there a non-integer makes
# test exit 2, the `if` goes false, and the floor silently "passes" - which is
# exactly the false green this guard exists to prevent.
ELF_MIN_REPRODUCERS ?= 4
# Same floor for the /proc parser. It was 0 for a long time - honestly reported
# as a gap rather than dressed up as a pass - until fuzzing the widened harness
# found the zero-length-buffer write in proc__read_comm(), so there is now one
# reproducer and the floor follows it. Same two parse-time gates as above.
PROC_MIN_REPRODUCERS ?= 1
# Reproducers are named <target>__<detector>__<site>__<function>.bin so that
# each one is replayed by the fuzzer that actually covers that entry point.
# Only <target> is load-bearing here - the dispatch reads nothing else. What the
# other three fields mean (and why <detector> is `canary` rather than an ASan
# report type for the proc__* reproducer) is documented in tests/fuzz/README.md;
# keep the two in sync if the convention ever changes.
# Anything in crashes/ matching neither pattern is a bug - a prefix typo or a
# duplicate check-in - and would sit there forever without ever being replayed,
# so `regress` refuses to run at all when it sees one. That check is only as good
# as the scan feeding it, so the scan must see EVERY entry: $(wildcard) is
# glob(3) without GLOB_PERIOD, so a bare `crashes/*` skips dotfiles and a
# `.DS_Store` or an AppleDouble `._elf__*.bin` would match neither prefix list NOR
# the stray list - the exact silent drop this guard exists to prevent, on a tree
# that is edited on macOS and rsynced to Linux. `crashes/.*` puts them back; the
# two directory entries that pattern also matches are removed by name.
ELF_CRASHES := $(wildcard crashes/elf__*.bin)
PROC_CRASHES := $(wildcard crashes/proc__*.bin)
ALL_CRASHES := $(filter-out crashes/. crashes/..,$(wildcard crashes/* crashes/.*))
STRAY_CRASHES := $(filter-out $(ELF_CRASHES) $(PROC_CRASHES),$(ALL_CRASHES))

# --- MIN_WHITELIST: the accepted range for BOTH *_MIN_REPRODUCERS floors ----
# Hand-written ASCENDING integer whitelist. $(sort) must not be used to compare
# these values: it orders lexicographically, so "10" would sort before "4" and
# any range check built on it would be wrong for two-digit floors. Membership in
# this list is the only comparison make can do without a shell, so the list is
# shared by the ELF and the PROC validation blocks below: make cannot evaluate a
# numeric range test such as "0 <= x <= 16", it can only ask whether x is one of
# these words. The whitelist therefore IS the accepted range - each block's
# $(error) spells out what that rejects.
#
# If crashes/ ever holds more than 16 reproducers, EXTEND THIS LIST first. Both
# reachability gates compute their allowed floors with
# $(wordlist 1,$(words x <crashes>),$(MIN_WHITELIST)), which truncates at the end
# of the list, so a legitimate floor of 17 or 20 is unreachable - and would be
# reported as an invalid value - until the whitelist grows to cover it.
MIN_WHITELIST := 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16

# --- parse-time validation of ELF_MIN_REPRODUCERS (ELF floor only) ----------
ELF_MIN_REQ := $(strip $(ELF_MIN_REPRODUCERS))
ELF_MIN_MATCH := $(filter $(ELF_MIN_REQ),$(MIN_WHITELIST))
ELF_MIN_VALID :=
# Two tests, both needed: $(words ...)==1 rejects a multi-word value such as
# "4 5", which $(filter) would otherwise echo straight back as "4 5"; the
# equality rejects anything outside the whitelist - non-numbers, negatives,
# "abc", and glob metacharacters like '%' or '*', which $(filter) would expand
# into the whole whitelist.
ifeq ($(words $(ELF_MIN_MATCH)),1)
ifeq ($(ELF_MIN_MATCH),$(ELF_MIN_REQ))
ELF_MIN_VALID := yes
endif
endif
ifneq ($(ELF_MIN_VALID),yes)
$(error ELF_MIN_REPRODUCERS='$(ELF_MIN_REPRODUCERS)' is not an accepted floor. It must be exactly ONE word appearing in MIN_WHITELIST ($(MIN_WHITELIST)). make cannot compare numbers, so whitelist membership IS the test - there is no numeric range check behind this message. That one test rejects: a non-integer ('abc', '4.5', '', a negative, a glob such as '%' or '*'); a multi-word value such as '4 5'; AND an integer above the top of the whitelist - 17 is a perfectly good integer but is out of range until MIN_WHITELIST is extended. If crashes/ now holds more than 16 elf__*.bin reproducers, extend MIN_WHITELIST rather than working around this gate: the $$(wordlist ...) in the reachability check below truncates at the end of that list)
endif
# Second gate: the floor must actually be reachable. A floor above the number of
# files crashes/ holds can never be satisfied, so every run would fail and the
# failure would read like an ELF parser regression instead of like the missing
# corpus it is. The first $(words x $(ELF_CRASHES)) entries of the ascending
# whitelist are exactly the values <= the file count - one sentinel word "x"
# gives the +1, so no $(shell) arithmetic is needed. If crashes/ ever holds more
# than 16 reproducers the wordlist just yields the whole whitelist.
ELF_CRASH_N := $(words $(ELF_CRASHES))
ELF_MIN_ALLOWED := $(wordlist 1,$(words x $(ELF_CRASHES)),$(MIN_WHITELIST))
ifeq ($(filter $(ELF_MIN_REQ),$(ELF_MIN_ALLOWED)),)
$(error ELF_MIN_REPRODUCERS=$(ELF_MIN_REQ) demands at least $(ELF_MIN_REQ) ELF reproducers, but crashes/ holds only $(ELF_CRASH_N) elf__*.bin files - no run could ever satisfy that floor. Either restore the missing reproducers, or explicitly lower ELF_MIN_REPRODUCERS to $(ELF_CRASH_N) and state in the commit message why the ELF parser regression is allowed to shrink)
endif
# --- end of ELF_MIN_REPRODUCERS validation ---------------------------------

# --- parse-time validation of PROC_MIN_REPRODUCERS (same two gates) ----------
PROC_MIN_REQ := $(strip $(PROC_MIN_REPRODUCERS))
PROC_MIN_MATCH := $(filter $(PROC_MIN_REQ),$(MIN_WHITELIST))
PROC_MIN_VALID :=
ifeq ($(words $(PROC_MIN_MATCH)),1)
ifeq ($(PROC_MIN_MATCH),$(PROC_MIN_REQ))
PROC_MIN_VALID := yes
endif
endif
ifneq ($(PROC_MIN_VALID),yes)
$(error PROC_MIN_REPRODUCERS='$(PROC_MIN_REPRODUCERS)' is not an accepted floor. It must be exactly ONE word appearing in MIN_WHITELIST ($(MIN_WHITELIST)). make cannot compare numbers, so whitelist membership IS the test - there is no numeric range check behind this message. That one test rejects: a non-integer ('abc', '4.5', '', a negative, a glob such as '%' or '*'); a multi-word value such as '4 5'; AND an integer above the top of the whitelist - 17 is a perfectly good integer but is out of range until MIN_WHITELIST is extended. If crashes/ now holds more than 16 proc__*.bin reproducers, extend MIN_WHITELIST rather than working around this gate: the $$(wordlist ...) in the reachability check below truncates at the end of that list)
endif
PROC_CRASH_N := $(words $(PROC_CRASHES))
PROC_MIN_ALLOWED := $(wordlist 1,$(words x $(PROC_CRASHES)),$(MIN_WHITELIST))
ifeq ($(filter $(PROC_MIN_REQ),$(PROC_MIN_ALLOWED)),)
$(error PROC_MIN_REPRODUCERS=$(PROC_MIN_REQ) demands at least $(PROC_MIN_REQ) proc reproducers, but crashes/ holds only $(PROC_CRASH_N) proc__*.bin files - no run could ever satisfy that floor. Either restore the missing reproducers, or explicitly lower PROC_MIN_REPRODUCERS to $(PROC_CRASH_N) and state in the commit message why the /proc parser regression is allowed to shrink)
endif
# --- end of PROC_MIN_REPRODUCERS validation ---------------------------------

.PHONY: all fuzz fuzz-long regress clean have-clang .fuzz-warn

all: regress

have-clang:
	@command -v $(CLANG) >/dev/null 2>&1 || { \
	  echo "ERROR: clang with libFuzzer is required (set CLANG=...)" >&2; \
	  echo "ERROR: '$(CLANG)' is not in PATH, so the fuzzers cannot be built and" >&2; \
	  echo "ERROR: the crash corpus cannot be replayed. Failing rather than" >&2; \
	  echo "ERROR: skipping: a skipped fuzz regression is indistinguishable" >&2; \
	  echo "ERROR: from a passing one." >&2; \
	  exit 1; }

fuzz_elf: have-clang fuzz_elf.c $(LIB_SRCS)
	$(CLANG) $(FUZZ_CFLAGS) -o $@ fuzz_elf.c $(LIB_SRCS) -ldl

fuzz_proc: have-clang fuzz_proc.c $(LIB_SRCS)
	$(CLANG) $(FUZZ_CFLAGS) -o $@ fuzz_proc.c $(LIB_SRCS) -ldl

# Replay every saved reproducer with the fuzzer that owns it, counting the two
# targets separately so a vacuous one cannot hide behind the other's total. Any
# sanitizer hit is a regression.
#
# A reproducer only counts towards its target's total when the run satisfies
# BOTH positive criteria, in addition to tripping no sanitizer:
#   1. the fuzzer exits 0; and
#   2. its output contains libFuzzer's "Executed <that exact file> in <N> ms"
#      line, which is printed only after the input has really been fed to the
#      target - and which echoes the path, so a run against some other input
#      cannot satisfy it.
# Criterion 2 is what stops a vacuous pass from being counted as a clean replay.
# The blacklist grep alone cannot distinguish "the parser handled this input
# safely" from "the fuzzer never ran at all": a missing or unbuildable binary
# exits 127 with a shell error, and an input that vanished between make's
# parse-time $(wildcard) and the run exits 1 with 'ERROR: The required directory
# "..." does not exist' (both observed against clang 18.1.3 on Ubuntu x86_64).
# Neither message matches 'ERROR: AddressSanitizer|runtime error|ERROR:
# libFuzzer', so both used to be reported as "clean" and both used to satisfy
# the floors below - exactly the vacuous pass tests/fuzz/README.md forbids.
# Note the marker is NOT the 'INFO: Running 1 inputs' / '#1 INITED' pair printed
# by the real fuzzing loop: in single-input replay mode libFuzzer prints
# '<binary>: Running 1 inputs 1 time(s) each.' then 'Running: <file>' then
# 'Executed <file> in <N> ms'. A marker copied from the libFuzzer docs would
# have failed every clean replay, so this one was read off the runner image.
#
# Three independent checks then keep the replay honest: the number that replayed
# cleanly must equal the number of files make saw in crashes/ when it read this
# makefile (catches drift between the wildcard and the dispatch, i.e. a
# reproducer that is silently never replayed), and each per-target count must be
# >= its floor (catches reproducers being deleted, which used to pass as long as
# one file was left). Both floors are PROC_MIN_REPRODUCERS / ELF_MIN_REPRODUCERS
# and both are validated at parse time. A count can also never be "the files are
# there but misnamed": the guard above rejects any file that is neither
# elf__*.bin nor proc__*.bin before anything is replayed.
#
# A FOURTH check guards what a clean-looking run actually verified, and it has TWO
# tiers because the harness reports two different kinds of "checked less than the
# documented contract" (see the FAILURE POLICY block at the top of fuzz_proc.c and
# tests/fuzz/README.md). Collapsing them is what made this paragraph wrong once:
#
#   FUZZ_PROC_DEGRADED - the ENVIRONMENT could not support the comm oracle at all:
#     /proc/<pid>/comm was unreadable, or a name just set with prctl did not read
#     back. proc__read_comm's must-succeed and exact-content expectations are
#     dropped for the whole run. Such a replay satisfies both positive criteria
#     above and trips no sanitizer, so this target used to exit 0 in a container
#     without a readable /proc having asserted none of the comm contract - a
#     vacuous pass, which is what tests/fuzz/README.md forbids. A DEGRADED line in
#     a replay's captured output therefore FAILS that replay ("DEGRADED:"), is not
#     counted towards the floor, and ends in "fuzz regression FAILED".
#
#   FUZZ_PROC_NOTE - THIS INPUT made the harness skip some read_link iterations
#     because symlink(2) refused the target (EINVAL / ENAMETOOLONG). Real lost
#     coverage, but input-shaped rather than a hole in the machine, and the rest
#     of the iteration still ran. A NOTE-only replay is NOT a failure: it prints
#     "clean:", counts towards the floor, and its NOTE lines are echoed with their
#     count. Failing on them would redden `regress` forever the first time a
#     long-path reproducer is checked in, with no defect behind it.
#
# A harness abort() is classified by its label, too: FUZZ_PROC_ENV (the machine
# failed) is reported as "ENVIRONMENT FAILURE" and FUZZ_PROC_INVARIANT (the code
# under test broke its contract) as "REGRESSION". BOTH fail the run - the split
# only decides which message you get, so an unwritable TMPDIR is never mistaken
# for a parser defect and never checked in as a bogus reproducer.
# The blacklist grep and the two positive criteria are unchanged; all of this only
# adds conditions to runs that would otherwise have been counted clean.
regress: fuzz_elf fuzz_proc
	@if [ -n "$(STRAY_CRASHES)" ]; then \
	  echo "ERROR: crashes/ holds files that no fuzzer would ever replay:" >&2; \
	  for f in $(STRAY_CRASHES); do echo "         $$f" >&2; done; \
	  echo "       Every reproducer must be elf__*.bin (replayed by ./fuzz_elf)" >&2; \
	  echo "       or proc__*.bin (replayed by ./fuzz_proc). A misnamed prefix or a" >&2; \
	  echo "       duplicate check-in would otherwise never be replayed again." >&2; \
	  echo "       Dotfiles are scanned too: a bare crashes/* wildcard hides them" >&2; \
	  echo "       and this tree is edited on macOS, so a .DS_Store or an ._*" >&2; \
	  echo "       AppleDouble file would otherwise sit here never replayed." >&2; \
	  exit 1; \
	fi
	@fail=0; n=0; elf_n=0; proc_n=0; \
	  elf_expected=$(words $(ELF_CRASHES)); \
	  proc_expected=$(words $(PROC_CRASHES)); \
	replay() { \
	  bin=$$1; shift; \
	  n=0; \
	  for f in "$$@"; do \
	    out=$$(ASAN_OPTIONS=detect_leaks=0 "$$bin" "$$f" 2>&1); \
	    rc=$$?; \
	    san=0; \
	    if echo "$$out" | grep -qE 'ERROR: AddressSanitizer|runtime error'; then san=1; fi; \
	    labels=$$(echo "$$out" | grep -m3 -E 'FUZZ_PROC_ENV|FUZZ_PROC_INVARIANT|FUZZ_PROC_DEGRADED'); \
	    if [ $$san -eq 0 ] && echo "$$labels" | grep -qF 'FUZZ_PROC_ENV'; then \
	      echo "ENVIRONMENT FAILURE (not a regression of the code under test): $$f" >&2; \
	      echo "       the harness aborted with FUZZ_PROC_ENV and NO sanitizer" >&2; \
	      echo "       report fired, so the machine could not support this replay -" >&2; \
	      echo "       an unwritable TMPDIR, a failed allocation, a refused prctl." >&2; \
	      echo "       The parser is not implicated and this file must NOT be" >&2; \
	      echo "       checked in as a reproducer. It still fails the run: an" >&2; \
	      echo "       environment that cannot replay the corpus proves nothing," >&2; \
	      echo "       which is the same vacuous-pass shape as a clean-looking" >&2; \
	      echo "       DEGRADED replay. Fix the machine, then re-run. Its reason:" >&2; \
	      printf '%s\n' "$$labels" | sed 's/^/         /' >&2; \
	      fail=1; \
	    elif [ $$san -ne 0 ] || echo "$$out" | grep -qE 'ERROR: AddressSanitizer|runtime error|ERROR: libFuzzer'; then \
	      echo "REGRESSION: $$f"; \
	      echo "$$out" | grep -m2 -E 'ERROR: AddressSanitizer|runtime error|FUZZ_PROC_ENV|FUZZ_PROC_INVARIANT|FUZZ_PROC_DEGRADED'; \
	      fail=1; \
	    elif [ $$rc -ne 0 ]; then \
	      echo "NOT REPLAYED: $$f" >&2; \
	      echo "       failed criterion 1 of 2: exit status $$rc, expected 0. A run" >&2; \
	      echo "       that did not exit cleanly is no evidence the parser ever saw" >&2; \
	      echo "       this input, so it must not count towards the floor. Tail:" >&2; \
	      echo "$$out" | tail -3 | sed 's/^/         /' >&2; \
	      fail=1; \
	    elif ! echo "$$out" | grep -qF -- "Executed $$f in"; then \
	      echo "NOT REPLAYED: $$f" >&2; \
	      echo "       failed criterion 2 of 2: libFuzzer's positive marker" >&2; \
	      echo "       'Executed $$f in' is absent from the output, so nothing" >&2; \
	      echo "       proves THIS input reached the target even though the exit" >&2; \
	      echo "       status was 0 - which is exactly what a binary that never" >&2; \
	      echo "       started, or an input libFuzzer refused to load, looks like." >&2; \
	      echo "       No sanitizer error is not proof of a clean replay. Tail:" >&2; \
	      echo "$$out" | tail -3 | sed 's/^/         /' >&2; \
	      fail=1; \
	    else \
	      deg=$$(echo "$$out" | grep -m3 -F 'FUZZ_PROC_DEGRADED'); \
	      if [ -n "$$deg" ]; then \
	        echo "DEGRADED: $$f" >&2; \
	        echo "       the run satisfied both positive criteria and tripped no" >&2; \
	        echo "       sanitizer, but the harness reported that the ENVIRONMENT" >&2; \
	        echo "       could not support the comm oracle, so it verified LESS" >&2; \
	        echo "       than the documented contract. Its report:" >&2; \
	        echo "$$deg" | sed 's/^/         /' >&2; \
	        echo "       Run in a container without a readable /proc this target" >&2; \
	        echo "       used to exit 0 having asserted none of proc__read_comm's" >&2; \
	        echo "       must-succeed or exact-content contract, so a degraded run" >&2; \
	        echo "       is a failure here and does not count towards the floor." >&2; \
	        echo "       Fix the environment; do not weaken this gate." >&2; \
	        fail=1; \
	      else \
	        notes=$$(echo "$$out" | grep -c -F 'FUZZ_PROC_NOTE'); \
	        if [ "$$notes" -gt 0 ]; then \
	          echo "  clean: $$f ($$notes informational NOTE line(s) - input-dependent" ; \
	          echo "         symlink skips, not an environment failure; echoed below)"; \
	          echo "$$out" | grep -F 'FUZZ_PROC_NOTE' | tail -3 | sed 's/^/         /'; \
	        else \
	          echo "  clean: $$f"; \
	        fi; \
	        n=$$((n+1)); \
	      fi; \
	    fi; \
	  done; \
	}; \
	replay ./fuzz_elf $(ELF_CRASHES); elf_n=$$n; \
	replay ./fuzz_proc $(PROC_CRASHES); proc_n=$$n; \
	echo "elf: $$elf_n replayed cleanly, proc: $$proc_n replayed cleanly (expected: $$elf_expected / $$proc_expected)"; \
	if [ $$elf_n -ne $$elf_expected ]; then \
	  echo "ERROR: elf: only $$elf_n reproducer(s) replayed cleanly, but make" >&2; \
	  echo "       saw $$elf_expected crashes/elf__*.bin file(s) when it read this" >&2; \
	  echo "       makefile. A run counts only if it exits 0, prints the positive" >&2; \
	  echo "       marker and trips no sanitizer, so either the glob and the" >&2; \
	  echo "       dispatch disagree (a reproducer was never replayed) or one of" >&2; \
	  echo "       the per-file diagnostics above failed." >&2; \
	  fail=1; \
	fi; \
	if [ $$proc_n -ne $$proc_expected ]; then \
	  echo "ERROR: proc: only $$proc_n reproducer(s) replayed cleanly, but" >&2; \
	  echo "       make saw $$proc_expected crashes/proc__*.bin file(s) when it" >&2; \
	  echo "       read this makefile. A run counts only if it exits 0, prints" >&2; \
	  echo "       the positive marker and trips no sanitizer, so either the glob" >&2; \
	  echo "       and the dispatch disagree (a reproducer was never replayed) or" >&2; \
	  echo "       one of the per-file diagnostics above failed." >&2; \
	  fail=1; \
	fi; \
	if [ $$elf_n -lt $(ELF_MIN_REPRODUCERS) ]; then \
	  echo "ERROR: elf: crashes/ currently holds only $$elf_n reproducer(s)," >&2; \
	  echo "       but at least $(ELF_MIN_REPRODUCERS) must be replayed - below that the" >&2; \
	  echo "       ELF parser regression is vacuous. Deleting reproducers used to" >&2; \
	  echo "       keep this target green (only elf_n == 0 was checked), so the" >&2; \
	  echo "       floor is now explicit. If the reduction is deliberate, run:" >&2; \
	  echo "       make regress ELF_MIN_REPRODUCERS=$$elf_n" >&2; \
	  fail=1; \
	fi; \
	if [ $$proc_n -lt $(PROC_MIN_REPRODUCERS) ]; then \
	  echo "ERROR: proc: crashes/ currently holds only $$proc_n reproducer(s)," >&2; \
	  echo "       but at least $(PROC_MIN_REPRODUCERS) must be replayed - below that the" >&2; \
	  echo "       /proc parser regression is vacuous and the parser is covered only" >&2; \
	  echo "       by the seed corpus 'make fuzz' builds. If the reduction is" >&2; \
	  echo "       deliberate, run: make regress PROC_MIN_REPRODUCERS=$$proc_n" >&2; \
	  fail=1; \
	fi; \
	if [ $$fail -ne 0 ]; then echo "fuzz regression FAILED"; exit 1; fi; \
	echo "fuzz regression OK (elf: $$elf_n clean, proc: $$proc_n clean)"

# The ELF fuzzer needs a real libc image to start from, and libc.so.6 does not
# live at one fixed path: probe the usual Debian/Ubuntu, Fedora/SUSE/Alpine and
# toolchain locations instead of hardcoding one and swallowing the failure.
fuzz: fuzz_elf fuzz_proc
	@mkdir -p corpus/elf corpus/proc work
	@if [ -f corpus/proc/seed_maps ]; then \
	  echo "seed corpus: keeping the existing corpus/proc/seed_maps"; \
	else \
	  echo "seed corpus: /proc/self/maps -> corpus/proc/seed_maps"; \
	  cp /proc/self/maps corpus/proc/seed_maps || { \
	    echo "ERROR: cannot copy /proc/self/maps to corpus/proc/seed_maps, so" >&2; \
	    echo "ERROR: corpus/proc would be EMPTY and fuzz_proc would start from" >&2; \
	    echo "ERROR: scratch instead of a realistic /proc/PID/maps image." >&2; \
	    echo "ERROR: drop a maps file at corpus/proc/seed_maps to seed it." >&2; \
	    exit 1; }; \
	fi
	@libc=""; \
	for c in /lib/x86_64-linux-gnu/libc.so.6 /usr/lib/x86_64-linux-gnu/libc.so.6 \
	         /lib64/libc.so.6 /usr/lib64/libc.so.6 /lib/libc.so.6 /usr/lib/libc.so.6 \
	         $$($(CC) -print-file-name=libc.so.6 2>/dev/null); do \
	  if [ -n "$$c" ] && [ -f "$$c" ]; then libc="$$c"; break; fi; \
	done; \
	if [ -z "$$libc" ]; then \
	  echo "WARNING: no libc.so.6 found - corpus/elf will be EMPTY and fuzz_elf" >&2; \
	  echo "WARNING: will start from scratch instead of a realistic ELF image." >&2; \
	  echo "WARNING: looked in /lib/x86_64-linux-gnu, /usr/lib/x86_64-linux-gnu," >&2; \
	  echo "WARNING: /lib64, /usr/lib64, /lib, /usr/lib and" >&2; \
	  echo "WARNING: '$$(CC) -print-file-name=libc.so.6'. Drop a libc image at" >&2; \
	  echo "WARNING: corpus/elf/seed_libc to seed it manually." >&2; \
	elif [ -f corpus/elf/seed_libc ]; then \
	  echo "seed corpus: keeping the existing corpus/elf/seed_libc ($$libc available)"; \
	else \
	  echo "seed corpus: $$libc -> corpus/elf/seed_libc"; \
	  cp "$$libc" corpus/elf/seed_libc || { \
	    echo "ERROR: cannot copy $$libc to corpus/elf/seed_libc" >&2; exit 1; }; \
	fi
	cd work && ../fuzz_proc ../corpus/proc -max_total_time=$(FUZZ_SECONDS) \
	  -jobs=$(JOBS) -workers=$(JOBS) -max_len=4096 -artifact_prefix=proc-crash- \
	  > proc.log 2>&1 || { echo "fuzz_proc found a crash:"; grep -m5 -E 'ERROR|runtime error|FUZZ_PROC_ENV|FUZZ_PROC_INVARIANT|FUZZ_PROC_DEGRADED' proc.log; exit 1; }
	cd work && ../fuzz_elf ../corpus/elf -max_total_time=$(FUZZ_SECONDS) \
	  -jobs=$(JOBS) -workers=$(JOBS) -artifact_prefix=elf-crash- \
	  > elf.log 2>&1 || { echo "fuzz_elf found a crash:"; grep -m5 -E 'ERROR|runtime error|FUZZ_PROC_ENV|FUZZ_PROC_INVARIANT|FUZZ_PROC_DEGRADED' elf.log; exit 1; }
	@# Surface what the harness itself reported instead of leaving it in a log
	@# nobody reads: work/proc.log and work/elf.log were written by the two runs
	@# above and never opened again on success, so a degraded comm oracle or a
	@# million symlink iterations skipped for ENAMETOOLONG looked exactly like a
	@# clean campaign. The markers are treated differently, on purpose:
	@#   FUZZ_PROC_DEGRADED (the environment could not test comm at all) gets a
	@#     real make-level warning, because this campaign verified less than it
	@#     claims and `regress` would refuse to pass in the same state. It also
	@#     decides the FINAL line below: a degraded campaign must not end on an
	@#     affirmative "fuzzing OK", because CI shows the last line and the exit
	@#     status, and the status here is 0 by design (warn, do not fail: a
	@#     missing /proc is the machine's property, and a red fuzz step that is
	@#     red on every container run gets ignored).
	@#   FUZZ_PROC_NOTE (this input's symlink was too long, so that iteration was
	@#     skipped) is only echoed with its count. Any campaign that fuzzes long
	@#     paths produces these by the thousand; warning on them would put a
	@#     permanent red flag on every run and teach people to skip past it.
	@#   FUZZ_PROC_COVERAGE (per-entry-point call counts) is echoed for the same
	@#     reason the NOTE lines are: it is the only proof in the log that all
	@#     three entry points were reached at all. Informational, never a gate.
	@noted=0; deg=0; \
	for log in work/proc.log work/elf.log; do \
	  [ -f "$$log" ] || continue; \
	  hits=$$(grep -F 'FUZZ_PROC_NOTE' "$$log" | tail -5); \
	  if [ -n "$$hits" ]; then \
	    echo "--- informational FUZZ_PROC_NOTE from $$log (last 5 of $$(grep -c -F 'FUZZ_PROC_NOTE' "$$log")) ---"; \
	    printf '%s\n' "$$hits"; \
	    noted=$$((noted+1)); \
	  fi; \
	  chits=$$(grep -F 'FUZZ_PROC_COVERAGE' "$$log" | tail -2); \
	  if [ -n "$$chits" ]; then \
	    echo "--- informational FUZZ_PROC_COVERAGE from $$log (last 2 of $$(grep -c -F 'FUZZ_PROC_COVERAGE' "$$log")) ---"; \
	    printf '%s\n' "$$chits"; \
	  fi; \
	  dhits=$$(grep -F 'FUZZ_PROC_DEGRADED' "$$log" | tail -5); \
	  if [ -n "$$dhits" ]; then \
	    echo "--- FUZZ_PROC_DEGRADED from $$log ---"; \
	    printf '%s\n' "$$dhits"; \
	    deg=$$((deg+1)); \
	  fi; \
	done; \
	if [ $$deg -ne 0 ]; then \
	  echo "WARNING: the harness reported a DEGRADED comm oracle in $$deg of" >&2; \
	  echo "WARNING: the 2 logs above, so this campaign did NOT verify the" >&2; \
	  echo "WARNING: whole proc__read_comm contract. 'make regress' refuses" >&2; \
	  echo "WARNING: to pass in this state." >&2; \
	  $(MAKE) --no-print-directory .fuzz-warn; \
	fi; \
	if [ $$noted -ne 0 ]; then \
	  echo "informational: $$noted of the 2 campaign logs reported skipped coverage (the FUZZ_PROC_NOTE lines above; not a warning)"; \
	fi; \
	if [ $$deg -ne 0 ]; then \
	  echo "fuzzing finished (DEGRADED: comm contract NOT verified this run)"; \
	else \
	  echo "fuzzing OK ($(FUZZ_SECONDS)s per target, no new crashes)"; \
	fi

fuzz-long:
	$(MAKE) fuzz FUZZ_SECONDS=600 JOBS=16

# Invoked by `fuzz` above when a campaign log holds FUZZ_PROC_DEGRADED lines (and
# only then - `deg` counts DEGRADED logs, never FUZZ_PROC_NOTE ones, which are
# echoed with their count and warn nothing), so the message arrives as a real
# make-level warning ("Makefile:NN: ...") rather than as one more line of shell
# output that scrolls past in CI. Hidden and never run directly: it re-parses this
# makefile, warns, and does nothing.
.fuzz-warn:
	@: $(warning WARNING: the fuzzing harness printed FUZZ_PROC_DEGRADED, echoed above: the comm oracle could not be calibrated in this environment, so proc__read_comm's must-succeed and exact-content contract was NOT verified this run - the memory-safety and n==0/-1 assertions still were. 'make regress' fails outright in this state. Treat this campaign as partial coverage, not as a clean one; informational FUZZ_PROC_NOTE skip lines are counted separately and are not a warning - see tests/fuzz/README.md)

clean:
	$(RM) fuzz_elf fuzz_proc
	$(RM) -r work
