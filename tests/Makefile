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
  ifneq ($(wildcard /usr/lib/gcc/x86_64-linux-gnu/*/x32/libgcc.a),)
    BUILD_TARGETS += x32
  endif
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
  "x86_64 x32" \
  "i386 i386" \
  "x32 i386" \
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
# LAST arch built - x32 on any host where gcc-multilib provides
# /usr/lib/gcc/x86_64-linux-gnu/*/x32/libgcc.a, which includes the CI runners.
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

x32:
	@echo "=============== build: x32 ==============="; \
	CC='cc -mx32' SUFFIX=-x32 $(MAKE) build

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
# and assuming anything that linked will also exec is simply false - an x32
# binary links fine wherever gcc-multilib is installed, but execve fails with
# ENOEXEC on a kernel built without CONFIG_X86_X32_ABI, and every
# cross-compiled arch is in the same boat.
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
	     echo "      $$at is built for that arch, but execve fails - a cross-compiled"; \
	     echo "      arch, or e.g. x32 on a kernel without CONFIG_X86_X32_ABI)"; \
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
UNIT_OBJS = unit/run.o unit/test_errmsg.o unit/test_opts.o unit/test_elf.o unit/test_proc.o unit/test_init.o unit/test_guards.o unit/test_trampoline.o

unit: $(UNIT_TESTS) $(UNIT_OBJS)
	@for t in $(UNIT_TESTS); do echo "=== $$t ==="; ./$$t || exit 1; done

../src/linux/libinjector.a:
	@cd ../src/linux && $(MAKE)

unit/run: $(UNIT_OBJS) ../src/linux/libinjector.a
	$(CC) $(CFLAGS) -I. -I../include -o $@ $(UNIT_OBJS) ../src/linux/libinjector.a -ldl

unit/run.o: unit/run.c unit/minunit.h
	$(CC) $(CFLAGS) -I. -I../include -c -o $@ unit/run.c

unit/test_errmsg.o: unit/test_errmsg.c unit/minunit.h
	$(CC) $(CFLAGS) -I. -I../include -c -o $@ unit/test_errmsg.c

unit/test_opts.o: unit/test_opts.c unit/minunit.h
	$(CC) $(CFLAGS) -I. -I../include -c -o $@ unit/test_opts.c

unit/test_elf.o: unit/test_elf.c unit/minunit.h
	$(CC) $(CFLAGS) -I. -I../include -c -o $@ unit/test_elf.c

unit/test_proc.o: unit/test_proc.c unit/minunit.h ../src/linux/proc.h
	$(CC) $(CFLAGS) -I. -I../include -I../src/linux -c -o $@ unit/test_proc.c

unit/test_init.o: unit/test_init.c unit/minunit.h
	$(CC) $(CFLAGS) -I. -I../include -c -o $@ unit/test_init.c

unit/test_guards.o: unit/test_guards.c unit/minunit.h ../src/linux/proc.h
	$(CC) $(CFLAGS) -I. -I../include -I../src/linux -c -o $@ unit/test_guards.c

unit/test_trampoline.o: unit/test_trampoline.c unit/minunit.h ../src/linux/injector_internal.h
	$(CC) $(CFLAGS) -I. -I../include -I../src/linux -c -o $@ unit/test_trampoline.c

clean:
	$(RM) test-prog$(EXE_EXT) test-prog-* test-target$(EXE_EXT) test-target-* test-library.$(SO_EXT) test-library-*.$(SO_EXT) arch-probe$(EXE_EXT) arch-probe-* $(UNIT_TESTS) $(UNIT_OBJS)

.PHONY: $(BUILD_TARGETS) build check clean unit FORCE
