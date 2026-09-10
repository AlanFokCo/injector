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
# Requires clang with libFuzzer. Set CLANG=... to point at another clang.

CLANG ?= clang
SRC_DIR := ../../src/linux
INCLUDES := -I../../include -I$(SRC_DIR)
SAN := -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all
FUZZ_CFLAGS := -g -O1 $(SAN) -fno-omit-frame-pointer $(INCLUDES)
LIB_SRCS := $(wildcard $(SRC_DIR)/*.c) $(SRC_DIR)/shellcode.S
FUZZ_SECONDS ?= 60
JOBS ?= 8
# Reproducers are named <target>__<sanitizer>__<site>__<function>.bin so that
# each one is replayed by the fuzzer that actually covers that entry point.
ELF_CRASHES := $(wildcard crashes/elf__*.bin)
PROC_CRASHES := $(wildcard crashes/proc__*.bin)

.PHONY: all fuzz fuzz-long regress clean have-clang

all: regress

have-clang:
	@command -v $(CLANG) >/dev/null 2>&1 || { \
	  echo "clang not found (set CLANG=...); skipping fuzz targets"; exit 77; }

fuzz_elf: have-clang fuzz_elf.c $(LIB_SRCS)
	$(CLANG) $(FUZZ_CFLAGS) -o $@ fuzz_elf.c $(LIB_SRCS) -ldl

fuzz_proc: have-clang fuzz_proc.c $(LIB_SRCS)
	$(CLANG) $(FUZZ_CFLAGS) -o $@ fuzz_proc.c $(LIB_SRCS) -ldl

# Replay every saved reproducer with the fuzzer that owns it. Any sanitizer hit
# is a regression. An empty corpus is treated as a failure, not as success, so a
# bad rename or a missing directory cannot silently make this target vacuous.
regress: fuzz_elf fuzz_proc
	@fail=0; n=0; \
	replay() { \
	  bin=$$1; shift; \
	  for f in $$*; do \
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
	replay ./fuzz_elf $(ELF_CRASHES); \
	replay ./fuzz_proc $(PROC_CRASHES); \
	if [ $$n -eq 0 ]; then \
	  echo "fuzz regression FAILED: no reproducers found in crashes/ (expected elf__*.bin)"; \
	  exit 1; \
	fi; \
	if [ $$fail -ne 0 ]; then echo "fuzz regression FAILED"; exit 1; fi; \
	echo "fuzz regression OK ($$n reproducers clean)"

fuzz: fuzz_elf fuzz_proc
	@mkdir -p corpus/elf corpus/proc work
	@cp -n /proc/self/maps corpus/proc/seed_maps 2>/dev/null || true
	@cp -n /lib/x86_64-linux-gnu/libc.so.6 corpus/elf/seed_libc 2>/dev/null || true
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
