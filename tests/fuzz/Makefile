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
# Reproducers are named <target>__<sanitizer>__<site>__<function>.bin so that
# each one is replayed by the fuzzer that actually covers that entry point.
# Anything in crashes/ matching neither pattern is a bug - a prefix typo or a
# duplicate check-in - and would sit there forever without ever being replayed,
# so `regress` refuses to run at all when it sees one.
ELF_CRASHES := $(wildcard crashes/elf__*.bin)
PROC_CRASHES := $(wildcard crashes/proc__*.bin)
ALL_CRASHES := $(wildcard crashes/*)
STRAY_CRASHES := $(filter-out $(ELF_CRASHES) $(PROC_CRASHES),$(ALL_CRASHES))

# --- parse-time validation of ELF_MIN_REPRODUCERS ---------------------------
# Hand-written ASCENDING integer whitelist. $(sort) must not be used to compare
# these values: it orders lexicographically, so "10" would sort before "4" and
# any range check built on it would be wrong for two-digit floors. Membership in
# this list is the only comparison make can do without a shell.
ELF_MIN_WHITELIST := 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16
ELF_MIN_REQ := $(strip $(ELF_MIN_REPRODUCERS))
ELF_MIN_MATCH := $(filter $(ELF_MIN_REQ),$(ELF_MIN_WHITELIST))
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
$(error ELF_MIN_REPRODUCERS must be an integer 0-16, got '$(ELF_MIN_REPRODUCERS)')
endif
# Second gate: the floor must actually be reachable. A floor above the number of
# files crashes/ holds can never be satisfied, so every run would fail and the
# failure would read like an ELF parser regression instead of like the missing
# corpus it is. The first $(words x $(ELF_CRASHES)) entries of the ascending
# whitelist are exactly the values <= the file count - one sentinel word "x"
# gives the +1, so no $(shell) arithmetic is needed. If crashes/ ever holds more
# than 16 reproducers the wordlist just yields the whole whitelist.
ELF_CRASH_N := $(words $(ELF_CRASHES))
ELF_MIN_ALLOWED := $(wordlist 1,$(words x $(ELF_CRASHES)),$(ELF_MIN_WHITELIST))
ifeq ($(filter $(ELF_MIN_REQ),$(ELF_MIN_ALLOWED)),)
$(error ELF_MIN_REPRODUCERS=$(ELF_MIN_REQ) demands at least $(ELF_MIN_REQ) ELF reproducers, but crashes/ holds only $(ELF_CRASH_N) elf__*.bin files - no run could ever satisfy that floor. Either restore the missing reproducers, or explicitly lower ELF_MIN_REPRODUCERS to $(ELF_CRASH_N) and state in the commit message why the ELF parser regression is allowed to shrink)
endif
# --- end of ELF_MIN_REPRODUCERS validation ---------------------------------

.PHONY: all fuzz fuzz-long regress clean have-clang

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
# sanitizer hit is a regression. Two independent checks keep the replay honest:
# the number actually replayed must equal the number of files make saw in
# crashes/ when it read this makefile (catches any drift between the wildcard
# and the dispatch, i.e. a reproducer that is silently never replayed), and the
# elf count must be >= ELF_MIN_REPRODUCERS (catches reproducers being deleted,
# which used to pass as long as one file was left). An empty *proc* corpus is
# still reported honestly as a known gap instead of being dressed up as a
# pass - and it cannot be confused with "the files are there but misnamed",
# because the guard above rejects any file that is not elf__*.bin or
# proc__*.bin before anything is replayed.
regress: fuzz_elf fuzz_proc
	@if [ -n "$(STRAY_CRASHES)" ]; then \
	  echo "ERROR: crashes/ holds files that no fuzzer would ever replay:" >&2; \
	  for f in $(STRAY_CRASHES); do echo "         $$f" >&2; done; \
	  echo "       Every reproducer must be elf__*.bin (replayed by ./fuzz_elf)" >&2; \
	  echo "       or proc__*.bin (replayed by ./fuzz_proc). A misnamed prefix or a" >&2; \
	  echo "       duplicate check-in would otherwise never be replayed again." >&2; \
	  exit 1; \
	fi
	@fail=0; n=0; elf_n=0; proc_n=0; \
	  elf_expected=$(words $(ELF_CRASHES)); \
	  proc_expected=$(words $(PROC_CRASHES)); \
	replay() { \
	  bin=$$1; shift; \
	  n=0; \
	  for f in "$$@"; do \
	    n=$$((n+1)); \
	    out=$$(ASAN_OPTIONS=detect_leaks=0 "$$bin" "$$f" 2>&1); \
	    if echo "$$out" | grep -qE 'ERROR: AddressSanitizer|runtime error|ERROR: libFuzzer'; then \
	      echo "REGRESSION: $$f"; echo "$$out" | grep -m2 -E 'ERROR: AddressSanitizer|runtime error'; \
	      fail=1; \
	    else \
	      echo "  clean: $$f"; \
	    fi; \
	  done; \
	}; \
	replay ./fuzz_elf $(ELF_CRASHES); elf_n=$$n; \
	replay ./fuzz_proc $(PROC_CRASHES); proc_n=$$n; \
	echo "elf: $$elf_n replayed, proc: $$proc_n replayed (expected: $$elf_expected / $$proc_expected)"; \
	if [ $$elf_n -ne $$elf_expected ]; then \
	  echo "ERROR: elf: replayed $$elf_n reproducer(s), but make saw" >&2; \
	  echo "       $$elf_expected crashes/elf__*.bin file(s) when it read this" >&2; \
	  echo "       makefile. The glob and the dispatch disagree, so at least" >&2; \
	  echo "       one reproducer was never replayed." >&2; \
	  fail=1; \
	fi; \
	if [ $$proc_n -ne $$proc_expected ]; then \
	  echo "ERROR: proc: replayed $$proc_n reproducer(s), but make saw" >&2; \
	  echo "       $$proc_expected crashes/proc__*.bin file(s) when it read" >&2; \
	  echo "       this makefile. The glob and the dispatch disagree, so at" >&2; \
	  echo "       least one reproducer was never replayed." >&2; \
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
	if [ $$proc_n -eq 0 ]; then \
	  echo "NOTE:  proc: 0 reproducers - no saved crash exists for the /proc"; \
	  echo "       maps parser yet, so it is covered only by the seed corpus"; \
	  echo "       built by 'make fuzz', not by this replay. Not a failure:"; \
	  echo "       misnamed files are rejected above, so this really is"; \
	  echo "       'none exist' and not 'they exist under a wrong prefix'."; \
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
	  > proc.log 2>&1 || { echo "fuzz_proc found a crash:"; grep -m5 -E 'ERROR|runtime error' proc.log; exit 1; }
	cd work && ../fuzz_elf ../corpus/elf -max_total_time=$(FUZZ_SECONDS) \
	  -jobs=$(JOBS) -workers=$(JOBS) -artifact_prefix=elf-crash- \
	  > elf.log 2>&1 || { echo "fuzz_elf found a crash:"; grep -m5 -E 'ERROR|runtime error' elf.log; exit 1; }
	@echo "fuzzing OK ($(FUZZ_SECONDS)s per target, no new crashes)"

fuzz-long:
	$(MAKE) fuzz FUZZ_SECONDS=600 JOBS=16

clean:
	$(RM) fuzz_elf fuzz_proc
	$(RM) -r work
