TEST_TARGET_LDFLAGS =
TEST_LIBRARY_LDFLAGS = -shared -fPIC

SRC_DIR = ../src/linux
SO_EXT = so
EXE_EXT =
INJECTOR_STATIC_LIB = libinjector.a
TEST_TARGET_LDFLAGS += -rdynamic

BUILD_TARGETS =

ifneq ($(wildcard /usr/bin/x86_64-linux-gnu-gcc),)
  BUILD_TARGETS += x86_64
  ifneq ($(wildcard /usr/lib/gcc/x86_64-linux-gnu/*/32/libgcc.a),)
    BUILD_TARGETS += i386
  endif
  # There is deliberately NO x32 target here. This project ships x86_64 (LP64)
  # and i386 runtimes only; the x32 ABI is detected and REFUSED by the library
  # (see injector__arch_is_unsupported() in $(SRC_DIR)/elf.c) rather than
  # injected into. Building x32 fixtures would mean shipping a code path that
  # cannot be executed anywhere we can test - execve'ing an x32 binary needs a
  # kernel with CONFIG_X86_X32_ABI, which neither this host nor GitHub's runners
  # has - so every x32 pair in `check` could only ever SKIP, and an untestable
  # path that patches a live process is worse than no path at all. Do not
  # re-add this without a kernel that can actually run the result.
endif

ifneq ($(wildcard /usr/bin/aarch64-linux-gnu-gcc),)
  BUILD_TARGETS += arm64
endif

ifneq ($(wildcard /usr/bin/arm-linux-gnueabihf-gcc),)
  BUILD_TARGETS += armhf
endif

ifneq ($(wildcard /usr/bin/arm-linux-gnueabi-gcc),)
  BUILD_TARGETS += armel
endif

ifneq ($(wildcard /usr/bin/mips-linux-gnu-gcc),)
  BUILD_TARGETS += mips
endif

ifneq ($(wildcard /usr/bin/mipsel-linux-gnu-gcc),)
  BUILD_TARGETS += mipsel
endif

ifneq ($(wildcard /usr/bin/mips64-linux-gnuabi64-gcc),)
  BUILD_TARGETS += mips64
endif

ifneq ($(wildcard /usr/bin/mips64el-linux-gnuabi64-gcc),)
  BUILD_TARGETS += mips64el
endif

ifneq ($(wildcard /usr/bin/mipsisa32r6-linux-gnu-gcc),)
  BUILD_TARGETS += mipsisa32r6
endif

ifneq ($(wildcard /usr/bin/mipsisa32r6el-linux-gnu-gcc),)
  BUILD_TARGETS += mipsisa32r6el
endif

ifneq ($(wildcard /usr/bin/mipsisa64r6-linux-gnuabi64-gcc),)
  BUILD_TARGETS += mipsisa64r6
endif

ifneq ($(wildcard /usr/bin/mipsisa64r6el-linux-gnuabi64-gcc),)
  BUILD_TARGETS += mipsisa64r6el
endif

ifneq ($(wildcard /usr/bin/riscv64-linux-gnu-gcc),)
  BUILD_TARGETS += riscv64
endif

CHECK_TARGETS = \
  "x86_64 x86_64" \
  "x86_64 i386" \
  "i386 i386" \
  "arm64 arm64" \
  "arm64 armhf" \
  "arm64 armel" \
  "armhf armhf" \
  "armhf armel" \
  "armel armhf" \
  "armel armel" \

all:
	SUFFIX= $(MAKE) build

# Every per-arch rule below runs `cd $(SRC_DIR) && $(MAKE) clean && $(MAKE)`
# with that arch's CC, so the archive left behind in $(SRC_DIR) belongs to the
# LAST arch built - i386 on any host where gcc-multilib provides
# /usr/lib/gcc/x86_64-linux-gnu/*/32/libgcc.a, which includes the CI runners.
# Everything that links natively afterwards (`make unit`, `cd cmd && make`, the
# language bindings) then dies with
#   ld: i386:x64-32 architecture of input file `libinjector.a(elf.o)' is
#       incompatible with i386:x86-64 output
# and the failure looks like a broken unit test rather than a stale artifact.
# Rebuild for the host at the end so `make cross` leaves a usable tree.
cross: $(BUILD_TARGETS)
	cd $(SRC_DIR) && $(MAKE) clean && $(MAKE)

x86_64:
	@echo "=============== build: x86_64 ==============="; \
	CC='cc -m64' SUFFIX=-x86_64 $(MAKE) build

i386:
	@echo "=============== build: i386 ==============="; \
	CC='cc -m32' SUFFIX=-i386 $(MAKE) build

arm64:
	@echo "=============== build: arm64 ==============="; \
	CC=aarch64-linux-gnu-gcc SUFFIX=-arm64 $(MAKE) build

armhf:
	@echo "=============== build: armhf ==============="; \
	CC=arm-linux-gnueabihf-gcc SUFFIX=-armhf $(MAKE) build

armel:
	@echo "=============== build: armel ==============="; \
	CC=arm-linux-gnueabi-gcc SUFFIX=-armel $(MAKE) build

mips:
	@echo "=============== build: mips ==============="; \
	CC='mips-linux-gnu-gcc -mabi=32' SUFFIX=-mips32 $(MAKE) build
	CC='mips-linux-gnu-gcc -mabi=n32' SUFFIX=-mipsn32 $(MAKE) build

mipsel:
	@echo "=============== build: mipsel ==============="; \
	CC='mipsel-linux-gnu-gcc -mabi=32' SUFFIX=-mips32el $(MAKE) build
	CC='mipsel-linux-gnu-gcc -mabi=n32' SUFFIX=-mipsn32el $(MAKE) build

mips64:
	@echo "=============== build: mips64 ==============="; \
	CC=mips64-linux-gnuabi64-gcc SUFFIX=-mips64 $(MAKE) build

mips64el:
	@echo "=============== build: mips64el ==============="; \
	CC=mips64el-linux-gnuabi64-gcc SUFFIX=-mips64el $(MAKE) build

mipsisa32r6:
	@echo "=============== build: mipsisa32r6 ==============="; \
	CC='mipsisa32r6-linux-gnu-gcc -mabi=32' SUFFIX=-mipsisa32r6 $(MAKE) build
	CC='mipsisa32r6-linux-gnu-gcc -mabi=n32' SUFFIX=-mipsisan32r6 $(MAKE) build

mipsisa32r6el:
	@echo "=============== build: mipsisa32r6el ==============="; \
	CC='mipsisa32r6el-linux-gnu-gcc -mabi=32' SUFFIX=-mipsisa32r6el $(MAKE) build
	CC='mipsisa32r6el-linux-gnu-gcc -mabi=n32' SUFFIX=-mipsisan32r6el $(MAKE) build

mipsisa64r6:
	@echo "=============== build: mipsisa64r6 ==============="; \
	CC=mipsisa64r6-linux-gnuabi64-gcc SUFFIX=-mipsisa64r6 $(MAKE) build

mipsisa64r6el:
	@echo "=============== build: mipsisa64r6el ==============="; \
	CC=mipsisa64r6el-linux-gnuabi64-gcc SUFFIX=-mipsisa64r6el $(MAKE) build

riscv64:
	@echo "=============== build: riscv64 ==============="; \
	CC=riscv64-linux-gnu-gcc SUFFIX=-riscv64 $(MAKE) build

build: test-prog$(SUFFIX)$(EXE_EXT) test-target$(SUFFIX)$(EXE_EXT) test-library$(SUFFIX).$(SO_EXT) \
       arch-probe$(SUFFIX)$(EXE_EXT)

# A do-nothing binary in the arch we just built for. `check` uses it to tell
# "this host cannot execute that arch" apart from "that test failed", which the
# two other options both get wrong: running the fixture and seeing whether it
# dies is unreliable (test-prog exits 1 on its own for many legitimate reasons),
# and assuming anything that linked will also exec is simply false - every
# cross-compiled arch links fine wherever its toolchain is installed, but
# execve fails with ENOEXEC because the host kernel has no binfmt for it. (x32
# used to be the example here; it is no longer built at all, for the reason
# given at BUILD_TARGETS above.)
#
# It hangs off FORCE so that every `build` recompiles it. A rule with no
# prerequisite is up to date as soon as the file exists, so a tree that switched
# CC would keep the previous arch's probe and `check` would believe it - the
# probe would say "this host can run that arch" about a binary for a different
# one. It is a single line of C; always rebuilding costs nothing.
#
# The limit of that guarantee, stated plainly: FORCE only fires when THIS arch's
# build rule runs. `check` depends on `all`, which rebuilds the unsuffixed probe
# and nothing else, so an arch-probe-<arch> is refreshed only by re-running that
# arch's target (`make cross`, or `make <arch>`). And the probe is trusted purely
# by filename - nothing compares its ELF e_machine against the fixture's - so a
# probe hand-replaced with a binary for some other arch would still be believed.
# Both need a deliberately inconsistent tree; neither can arise from the rules
# in this file.
arch-probe$(SUFFIX)$(EXE_EXT): FORCE
	echo 'int main(void) { return 0; }' | $(CC) $(CFLAGS) -x c - -o $@

FORCE:

test-prog$(SUFFIX)$(EXE_EXT): test-prog.c
	cd $(SRC_DIR) && $(MAKE) clean && $(MAKE)
	$(CC) $(CFLAGS) -o $@ $^ $(SRC_DIR)/$(INJECTOR_STATIC_LIB) $(TEST_PROG_LIBS)

test-target$(SUFFIX)$(EXE_EXT): test-target.c
	$(CC) $(CFLAGS) $(TEST_TARGET_LDFLAGS) -o $@ $^

test-library$(SUFFIX).$(SO_EXT): test-library.c
	$(CC) $(CFLAGS) $(TEST_LIBRARY_LDFLAGS) -o $@ $^

# Every pair listed in CHECK_TARGETS is accounted for: RUN, or SKIP with the
# reason - and the summary prints all three counts (run, skipped, and fixtures
# built for an arch no pair names) on every exit path, including a failing one.
# On the missing-probe path it says so, because that path aborts before the
# unpaired pass and its third count is therefore not final. Skipping silently (the old `if test -x ...; then ... fi`) is what
# let a host that could not execute a single pair report a green `make check`,
# so a run with zero pairs executed is an error.
#
# `check` deliberately does NOT build a missing per-arch probe. Only that arch's
# own build rule knows its CC, so `check` would have to compile the probe with
# the host CC - and a host-arch binary named arch-probe-<arch> is a probe that
# lies, which is worse than no probe at all. Fixtures present without their
# probe mean the tree was built before this rule existed or the probe was
# deleted, so that is a hard error naming the fix instead of a SKIP that quietly
# shrinks the run count and still exits 0.
#
# CHECK_TARGETS covers fewer arches than `make cross` builds (it has no pairs for
# the mips ABIs or riscv64), so fixtures can exist for an arch that is neither
# run nor skipped. Those are counted and reported too: not an error, because
# there is no pair to run, but not silent either. That set is collected in its
# own pass over CHECK_TARGETS first, because a failing pair breaks out of the run
# loop and an accounting that depended on how far that loop got would misreport
# every arch after the failure as unpaired.
#
# The two roles are tracked SEPARATELY. An arch appears in a pair as the injector
# (test-prog-<arch>, the first word) and as the target (test-target-<arch>, the
# second), and those sets need not coincide: with CHECK_TARGETS holding only
# "x86_64 i386", test-prog-i386 would never execute even though i386 is named as
# a target. One shared bag would call that accounted-for and report 0 unpaired -
# the silent green this target exists to prevent.
#
# Only regular files are considered: a clang .dSYM bundle matches test-prog-*
# and is a directory, so `-e` would have reported an unpaired arch named
# "x86_64.dSYM" on a macOS build tree.
#
# `build` makes a third fixture, test-library-<arch>.so, which is not globbed
# here. That is not an escape: all three come from the same rule with the same
# SUFFIX, so a test-library-<arch>.so can only exist alongside a
# test-prog-<arch>, and that one IS reported. Counting the library too would
# name the same arch twice for a fact already stated.
check: all
	@run=0; skipped=0; unpaired=0; st=0; failed=""; paired_inj=" "; paired_tgt=" "; \
	 summary() { echo "check: $$run arch pair(s) run, $$skipped skipped, $$unpaired built fixture(s) with no CHECK_TARGETS pair$$1"; }; \
	 for target_pair in $(CHECK_TARGETS); do \
	   set -- $$target_pair; paired_inj="$$paired_inj$$1 "; paired_tgt="$$paired_tgt$$2 "; \
	 done; \
	 for target_pair in "default default" $(CHECK_TARGETS); do \
	   set -- $$target_pair; prog=$$1; target=$$2; \
	   if test "$$prog" = default; then \
	     tp=test-prog$(EXE_EXT); tt=test-target$(EXE_EXT); targ=""; \
	     ap=arch-probe$(EXE_EXT); at=$$ap; \
	   else \
	     tp=test-prog-$$prog; tt=test-target-$$target; targ=$$target; \
	     ap=arch-probe-$$prog; at=arch-probe-$$target; \
	   fi; \
	   if ! test -x "$$tp" || ! test -x "$$tt"; then \
	     echo "SKIP: $$prog -> $$target (fixtures not built on this host)"; \
	     skipped=$$((skipped+1)); continue; \
	   fi; \
	   if ! test -x "$$ap" || ! test -x "$$at"; then \
	     miss=$$ap; test "$$at" = "$$ap" || miss="$$ap $$at"; \
	     echo "ERROR: $$prog -> $$target has its fixtures but not its arch probe(s)"; \
	     echo "       (missing: $$miss), so 'check' cannot tell 'this host cannot"; \
	     echo "       execute that arch' from 'that test failed'. It will not build"; \
	     echo "       one either: only that arch's build rule knows its CC, and a"; \
	     echo "       host-arch binary named $$ap would probe the wrong architecture."; \
	     echo "       Fix: re-run 'make cross && make all', which builds every probe"; \
	     echo "       with its own arch's CC."; \
	     summary " (partial: aborted before the unpaired-fixture pass)"; exit 1; \
	   fi; \
	   if ! ./"$$ap" >/dev/null 2>&1; then \
	     echo "SKIP: $$prog -> $$target (this host cannot execute $$prog binaries:"; \
	     echo "      $$ap is built for that arch, but execve fails)"; \
	     skipped=$$((skipped+1)); continue; \
	   fi; \
	   if test "$$ap" != "$$at" && ! ./"$$at" >/dev/null 2>&1; then \
	     echo "SKIP: $$prog -> $$target (this host cannot execute $$target binaries:"; \
	     echo "      $$at is built for that arch, but execve fails with ENOEXEC:"; \
	     echo "      the host kernel has no binfmt handler for a cross-compiled arch)"; \
	     skipped=$$((skipped+1)); continue; \
	   fi; \
	   echo "=============== injector: $$prog, target: $$target ==============="; \
	   ./"$$tp" $$targ; st=$$?; run=$$((run+1)); \
	   if [ $$st -ne 0 ]; then failed="$$prog -> $$target"; break; fi; \
	 done; \
	 for f in test-prog-*; do \
	   test -f "$$f" || continue; \
	   a=$${f#test-prog-}; a=$${a%$(EXE_EXT)}; \
	   case "$$paired_inj" in *" $$a "*) continue;; esac; \
	   echo "WARN: test-prog-$$a is built, but no CHECK_TARGETS pair injects FROM"; \
	   echo "      arch '$$a', so that injector binary was never executed above"; \
	   unpaired=$$((unpaired+1)); \
	 done; \
	 for f in test-target-*; do \
	   test -f "$$f" || continue; \
	   a=$${f#test-target-}; a=$${a%$(EXE_EXT)}; \
	   case "$$paired_tgt" in *" $$a "*) continue;; esac; \
	   echo "WARN: test-target-$$a is built, but no CHECK_TARGETS pair injects INTO"; \
	   echo "      arch '$$a', so that target binary was never used above"; \
	   unpaired=$$((unpaired+1)); \
	 done; \
	 summary ""; \
	 if [ -n "$$failed" ]; then echo "FAILED: $$failed exited $$st"; exit $$st; fi; \
	 if [ $$run -eq 0 ]; then \
	   echo "ERROR: not one arch pair executed - 'make check' verified nothing"; \
	   exit 1; \
	 fi

UNIT_TESTS = unit/run
UNIT_OBJS = unit/run.o unit/test_errmsg.o unit/test_opts.o unit/test_elf.o unit/test_proc.o unit/test_init.o unit/test_guards.o unit/test_trampoline.o unit/test_x32_refused.o unit/test_handles.o unit/test_orphan_scan.o

# Number of MU_RUN_TEST registration lines in unit/run.c, pinned so that
# DELETING one is as loud as never adding one. Bump it in the same commit that
# legitimately adds or removes a test; unit/registration-check below says so.
UNIT_RUN_TEST_COUNT = 21

# Nothing else in this file links UNIT_OBJS to the registrations in unit/run.c,
# and that gap is a silent green in both directions. A unit/test_*.c added to
# UNIT_OBJS but never registered still links - its test_* symbol is simply
# unreferenced, and a static archive is only searched for symbols somebody
# needs - so it compiles, gets archived into unit/run, and never executes.
# Deleting a MU_RUN_TEST line does the same thing by omission. Either way the
# suite runs, prints its summary and exits 0.
#
# So `unit` first proves three things and fails the build if any is false:
#   1. every unit/test_*.c on disk has its .o in UNIT_OBJS (a file nobody lists
#      is compiled by nobody);
#   2. every top-level `int test_*(void)` DEFINED in those files is registered
#      with MU_RUN_TEST in unit/run.c - definitions only, so run.c's extern
#      prototypes cannot satisfy the check for a test that has no body here;
#      both greps anchor on a line that STARTS with MU_RUN_TEST( so that a
#      comment in run.c mentioning the macro cannot register a test by
#      accident;
#   3. unit/run.c has exactly $(UNIT_RUN_TEST_COUNT) MU_RUN_TEST lines, which is
#      what makes (2) bite when a registration is removed rather than merely
#      never added.
# This is a prerequisite of `unit`, not a step inside its recipe, so a failure
# here stops the build before the test binary is executed and reported on. It is
# phony: it re-checks on every run, which is the point, and it costs one grep
# pass over the dozen or so small files in unit/.
.PHONY: unit/registration-check
unit/registration-check:
	@fail=0; seen=0; \
	 for f in unit/test_*.c; do \
	   if ! test -e "$$f"; then \
	     echo "ERROR: no unit/test_*.c found - the registration guard cannot see the suite"; \
	     exit 1; \
	   fi; \
	   seen=$$((seen+1)); o=$${f%.c}.o; \
	   case " $(UNIT_OBJS) " in \
	     *" $$o "*) ;; \
	     *) echo "ERROR: $$f exists but $$o is not in UNIT_OBJS, so nothing compiles it"; \
	        echo "       and no test in it can ever run. Fix: add $$o to UNIT_OBJS."; \
	        fail=1;; \
	   esac; \
	 done; \
	 for sym in $$(grep -h '^int test_[A-Za-z0-9_]*(void)' unit/test_*.c | sed -e 's/^int //' -e 's/(void).*//'); do \
	   grep -q "^[[:space:]]*MU_RUN_TEST($$sym)" unit/run.c || { \
	     echo "ERROR: $$sym is defined in unit/test_*.c but is not registered with"; \
	     echo "       MU_RUN_TEST in unit/run.c, so it links and never executes."; \
	     fail=1; }; \
	 done; \
	 n=$$(grep -c '^[[:space:]]*MU_RUN_TEST(' unit/run.c); \
	 if [ "$$n" != "$(UNIT_RUN_TEST_COUNT)" ]; then \
	   echo "ERROR: unit/run.c has $$n MU_RUN_TEST registration(s), expected $(UNIT_RUN_TEST_COUNT)."; \
	   echo "       Fewer means a test stopped running; more means the pin is stale."; \
	   echo "       Check the registration list, then update UNIT_RUN_TEST_COUNT."; \
	   fail=1; \
	 fi; \
	 if [ $$seen -eq 0 ]; then \
	   echo "ERROR: the glob unit/test_*.c matched nothing - wrong directory?"; fail=1; \
	 fi; \
	 test $$fail -eq 0

unit: unit/registration-check $(UNIT_TESTS) $(UNIT_OBJS)
	@for t in $(UNIT_TESTS); do echo "=== $$t ==="; ./$$t || exit 1; done

# FORCE, not "no prerequisites". A rule whose target file exists and whose
# prerequisite list is empty is permanently up to date, so once
# src/linux/libinjector.a had been built once this recipe never ran again and
# `make -C tests unit` linked whatever archive was already on disk. Measured:
# after editing src/linux/remote_call.c, `make -C tests unit` reported
# "31 run, 0 failed" against the PRE-EDIT library, and only a forced
# `make -C src/linux` made the change take effect - a green suite that had not
# run the code under test. The sub-make has the real dependencies, so let it
# decide every time.
../src/linux/libinjector.a: FORCE
	@cd ../src/linux && $(MAKE)

unit/run: $(UNIT_OBJS) ../src/linux/libinjector.a
	$(CC) $(CFLAGS) -I. -I../include -o $@ $(UNIT_OBJS) ../src/linux/libinjector.a -ldl -pthread

# unit/run.c is the only file in unit/ that does not #include "injector.h" (it
# includes just minunit.h), so it is the only rule here without that header as a
# prerequisite. Every unit/test_*.c does include it. Listing it is not a style
# nit: without it a .o built against an older public header survives an edit to
# include/injector.h, and unit/run then links that stale .o against a freshly
# rebuilt libinjector.a - the suite exercises an ABI the library no longer has
# and still reports green.
unit/run.o: unit/run.c unit/minunit.h
	$(CC) $(CFLAGS) -I. -I../include -c -o $@ unit/run.c

unit/test_errmsg.o: unit/test_errmsg.c unit/minunit.h ../include/injector.h
	$(CC) $(CFLAGS) -I. -I../include -c -o $@ unit/test_errmsg.c

unit/test_opts.o: unit/test_opts.c unit/minunit.h ../include/injector.h
	$(CC) $(CFLAGS) -I. -I../include -c -o $@ unit/test_opts.c

unit/test_elf.o: unit/test_elf.c unit/minunit.h ../include/injector.h
	$(CC) $(CFLAGS) -I. -I../include -c -o $@ unit/test_elf.c

unit/test_proc.o: unit/test_proc.c unit/minunit.h ../src/linux/proc.h ../include/injector.h
	$(CC) $(CFLAGS) -I. -I../include -I../src/linux -c -o $@ unit/test_proc.c

unit/test_init.o: unit/test_init.c unit/minunit.h ../include/injector.h
	$(CC) $(CFLAGS) -I. -I../include -c -o $@ unit/test_init.c

unit/test_guards.o: unit/test_guards.c unit/minunit.h ../src/linux/proc.h ../include/injector.h
	$(CC) $(CFLAGS) -I. -I../include -I../src/linux -c -o $@ unit/test_guards.c

unit/test_trampoline.o: unit/test_trampoline.c unit/minunit.h ../src/linux/injector_internal.h ../include/injector.h
	$(CC) $(CFLAGS) -I. -I../include -I../src/linux -c -o $@ unit/test_trampoline.c

# test_handles.c drives the real library against throwaway children it forks
# itself (FP-slot exhaustion, the desync latch) and against a second thread
# (ptrace tracer affinity), hence -pthread. It does NOT include
# injector_internal.h - that used to be listed here as a prerequisite on the
# claim that the test needed it for FP_SLOTS / DESYNC_SLOTS, which was false:
# both constants live in .c files (FP_SLOTS in ptrace.c, DESYNC_SLOTS in
# remote_call.c) and are not in any header, so the test spells its own expected
# values out as FP_SLOTS_EXPECTED (4) / DESYNC_SLOTS_EXPECTED (40). That is
# deliberate - it tests the boundary itself, so a change to either constant
# fails an assertion naming the expected number. The only header from this repo
# that it does include is the public one; the two desync functions it drives
# (injector__handle_mark_desynced / injector__handle_is_desynced) are declared
# in the test file itself, because they too are exported non-static from
# remote_call.c without appearing in any header.
unit/test_handles.o: unit/test_handles.c unit/minunit.h ../include/injector.h
	$(CC) $(CFLAGS) -pthread -I. -I../include -I../src/linux -c -o $@ unit/test_handles.c

unit/test_x32_refused.o: unit/test_x32_refused.c unit/minunit.h ../src/linux/injector_internal.h ../include/injector.h
	$(CC) $(CFLAGS) -I. -I../include -I../src/linux -c -o $@ unit/test_x32_refused.c

# test_orphan_scan.c drives injector__nonstop_orphan_kill(), which injector.c
# exports non-static for exactly this harness, so it needs injector_internal.h
# (for injector_t and the arch types) and the -I../src/linux that goes with it;
# injector.h reaches it through injector_internal.h, and is listed here as well
# because it is a real dependency of that include chain. It clone()s throwaway
# children but creates no pthreads, so unlike test_handles.o it needs no
# -pthread.
unit/test_orphan_scan.o: unit/test_orphan_scan.c unit/minunit.h ../src/linux/injector_internal.h ../include/injector.h
	$(CC) $(CFLAGS) -I. -I../include -I../src/linux -c -o $@ unit/test_orphan_scan.c

clean:
	$(RM) test-prog$(EXE_EXT) test-prog-* test-target$(EXE_EXT) test-target-* test-library.$(SO_EXT) test-library-*.$(SO_EXT) arch-probe$(EXE_EXT) arch-probe-* $(UNIT_TESTS) $(UNIT_OBJS)

.PHONY: $(BUILD_TARGETS) build check clean unit unit/registration-check FORCE
