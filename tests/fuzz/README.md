# Fuzzing libinjector's parsers

`libinjector` parses data that is ultimately controlled by the *target* process:
the ELF image of its libc (and of the library being injected), and its
`/proc/<pid>/maps` entries. A hostile or merely unusual target can therefore feed
the injector malformed input, so these parsers are fuzzed continuously.

## Targets

| target        | entry points covered |
|---------------|----------------------|
| `fuzz_elf`    | `injector__read_elf_machine`, `injector__elf_load_bias`, `injector__elf_find_symbols` (and the internal `read_elf_ehdr` / `read_elf_shdr` / `read_elf_sym` / `locate_dynsym` helpers) |
| `fuzz_proc`   | all three of `src/linux/proc.h`: `proc__parse_maps_line` (one line, a whole maps file, and the `" (deleted)"` tail variants), `proc__read_link` (through a real symlink the harness recreates each iteration, so arbitrary-length targets reach `readlink()`), and `proc__read_comm` (against this process, whose `comm` the harness sets from the fuzz input). The two functions that take a caller-declared output size are called with that size swept over `0, 1, 2, bufsz-1, bufsz, bufsz+1, SIZE_MAX` plus fuzz-derived values, and the documented contract is asserted on every call - see below. |

`proc__parse_maps_line` is *not* part of that sweep: it has no output-size
parameter, it writes into a caller struct, so it is exercised by shape (single
line / whole file / `" (deleted)"` tail) rather than by size.

### The output-size sweep, precisely

For each swept `n`, and for both `proc__read_link` and `proc__read_comm`:

* `n <= bufsz` gets `malloc(n + 1)`: the callee is handed `n` bytes plus one
  canary byte at index `n`, and the `n` bytes are prefilled with `0xA5`. A write
  at index `n` trips the canary (so it is caught even with ASan off), a write
  further out is an ASan heap-buffer-overflow, and the prefill proves nothing was
  written past the NUL terminator.
* `n > bufsz` (`bufsz + 1`, `SIZE_MAX`, fuzz-derived huge values) gets a static
  buffer wrapped in 16-byte canaries on both sides. Lying about the size is
  the point: both callees must be bounded by the data they read, never by `n`.
* Asserted after every call: the return code is `0` or `-1` and nothing else;
  `rc == 0` implies NUL-termination inside the buffer plus the exact expected
  content or the exact expected truncation; `rc == -1` implies `out[0] == '\0'`
  for `n > 0` and zero writes for `n == 0`.
* Two carve-outs from that content oracle, both for `proc__read_link` only,
  because `readlink(2)` takes an `int` bufsiz while the sweep hands it a `size_t`:
  * `n == 1` passes the syscall a bufsiz of `0`, which POSIX requires to fail with
    `EINVAL`. That is a property of the libc, not of `proc.c`, so the assertion
    accepts either answer - `-1`, or `0` with an empty string - instead of
    demanding `-1` and letting one libc difference bury every real bug behind a
    spurious crash. `tests/unit/test_guards.c` carries the identical relaxation.
  * `n > INT_MAX` - always `SIZE_MAX`, plus the fuzz-derived huge candidates -
    reaches the syscall as the truncated low 32 bits, which may be negative
    (`EINVAL` again) or an arbitrary positive count of which only that many bytes
    are copied. There is no single right answer to compare against, so for those
    sizes the must-succeed/must-fail expectations and the exact-content check
    are skipped entirely (the `int_trunc` branch of `check_out()`).
* Neither carve-out touches memory safety. At every `n`, `SIZE_MAX` included,
  these still assert in full: NUL-termination inside the buffer that was given;
  the canary byte at index `n`; the 16-byte pre/post canaries around the oversized
  static buffer; the `0xA5` prefill past the terminator ("nothing at all written
  after the NUL"); `rc == 0` with `n == 0` being fatal; and `rc == -1` leaving a
  non-empty `out`. Only the *content* oracle steps aside, and only for the sizes
  where its answer is undefined. `proc__read_comm()` has no syscall size argument
  at all, so it keeps the ordinary expectations at every `n`.
* The candidate list lives in a fixed `FP_NCAND`-slot (10) stack array and every
  write goes through a bound check that aborts with `FUZZ_PROC_ENV` rather than
  writing past the end of it. The slot count and the number of candidates emitted
  drifted apart once already - 12 slots, 10 written - and that gap is easy to
  oversize: an 11th and a 12th candidate still land inside a 12-slot array, so
  only a 13th write would have reached past the end of `sweep()`'s frame. It does
  not get that far, because `cand_put()` compares its index against the capacity
  `sweep()` passes down. Adding one `cand_put()` call to a tree whose `FP_NCAND`
  is 10 and replaying the empty input gives an abort in the harness, not a
  sanitizer report:

      $ : > /tmp/empty.bin && ./fuzz_proc /tmp/empty.bin
      Running: /tmp/empty.bin
      FUZZ_PROC_ENV: n_candidates() emitted more values than FP_NCAND slots [sweep]
      ==717344==ERROR: libFuzzer: deadly signal
          #9  ... in fail_env      fuzz_proc.c
          #10 ... in cand_put      fuzz_proc.c
          #11 ... in n_candidates  fuzz_proc.c

  The frame survives, and the `FUZZ_PROC_ENV` label is what keeps the artifact
  libFuzzer drops out of `crashes/`.

### Input layout and clamping

One input drives all three entry points. There is no `FuzzedDataProvider`,
because the harness is C, so the bytes are cut up by hand:

| bytes | meaning |
|-------|---------|
| `data[0]` | mode bitmask: which optional scenarios this input runs |
| `data[1]` | ratio `0..255`: the share of the remaining payload that becomes `A` |
| `data[2..]` | payload, split into `A` \| `B` \| `C` |

`A` is text (maps lines, symlink target bytes, this process' new `comm`), `B` is
numbers (`nhint`, mixed into the `n` sweep and the long-target length) and `C` is
filler cycled into long targets: `A` is `ratio/255` of the payload, `B` half of
what is left, `C` the rest.

Inputs longer than `FP_MAX_INPUT` (16384 bytes) are clamped to their first
16384 bytes instead of being skipped, so an oversized artifact still replays
deterministically. `size == 0`, `size == 1` and huge sizes are all safe: the
segments simply come out empty and the always-on boundary sweeps still run. The
campaigns this Makefile starts pass `-max_len=4096` to `fuzz_proc`, so in practice
the clamp only bites on a hand-supplied artifact.

The content oracle degrades only with the environment, and says so loudly: if
`/proc/<pid>/comm` cannot be read at all (a container without `/proc`), or the
expected `comm` cannot be trusted, the harness prints a `FUZZ_PROC_DEGRADED` line
and drops the *"must succeed" / "must match exactly"* expectations for that run.
Every memory-safety assertion above stays on regardless - a degraded oracle never
turns into a skipped canary check.

A separate and quieter marker, `FUZZ_PROC_NOTE`, reports `read_link` coverage
that `symlink(2)` refused: EINVAL on
an empty or NUL-containing target, ENAMETOOLONG on one at or over `PATH_MAX`.
Those lines come from inside the fuzz loop - as soon as the first skip
happens, then again on each 10x growth of the total, so at most ~8 lines per
worker - and not only from `atexit`, because libFuzzer's unit-timeout path tears
the process down with `_Exit()`, which runs neither `atexit` handlers nor
destructors. A clean exit runs both. That holds in all three modes this Makefile
uses, with and without `-jobs`/`-workers`. The `atexit` copy therefore still runs
on a clean exit and carries the exact final total, e.g.
`FUZZ_PROC_NOTE: 24826 symlink iteration(s) SKIPPED (final), so
proc__read_link() never saw those targets: 0 x EINVAL ... 24826 x ENAMETOOLONG`
(elided; the real line spells both refusals out in full).

The two markers are deliberately not treated alike:

* `FUZZ_PROC_DEGRADED` is **never a pass**. `make regress` fails on it, and
  `make fuzz` / `make fuzz-long` echo it and emit a make-level warning. Before
  that gate existed, a container without a readable `/proc` made both targets
  exit 0 having asserted none of the `comm` contract, with the only evidence
  sitting in a log that no step ever read.
* `FUZZ_PROC_NOTE` is echoed with its count and never fails anything on its own.
  Any campaign that fuzzes long paths produces these by the thousand - one run
  skipped 24826 iterations for ENAMETOOLONG out of 113287 - so warning on them
  would put a permanent red flag on every campaign and teach people to read past
  it. It would also be a trap: the first reproducer checked in carrying a
  long-path mode bit would redden `make regress` forever with no defect behind
  it. Skipped coverage is still counted and printed; it is just not an alarm.

A third marker, `FUZZ_PROC_COVERAGE`, is neither tier - it is a count, printed
once at exit by `cleanup()` next to the final skip summary:

    FUZZ_PROC_COVERAGE: entry-point calls in this process: proc__parse_maps_line=N
    proc__read_link=N proc__read_comm=N (informational - no floor, a zero can be a
    legitimate single-input or heavily-skipped run)

It exists because every other gate in here is a property of calls that *happened*:
a harness that silently stopped reaching `proc__read_link()` would still satisfy
every canary, both floors and both make targets. The counters make that visible in
the log. They are deliberately not a floor - one single-input replay is one
iteration, and an iteration whose mode bits skip the long-target cases makes zero
`proc__read_link()` calls, so `> 0` would redden `make regress` on the checked-in
0-byte reproducer for a reason that is not a defect. A false red in the one target
that has to stay trustworthy is worse than the gap; read the trend, do not gate on
it. `make fuzz` echoes the last two such lines per log. Like the final skip line
it comes from `atexit`, so a worker killed by libFuzzer's `-timeout` path
(`_Exit()`) prints neither.

Both fuzzers are built with `clang -fsanitize=fuzzer,address,undefined
-fno-sanitize-recover=all`, so any memory error or undefined behaviour is fatal.

## Usage

`clang` with libFuzzer support is a prerequisite for every target below, not an
optional extra. Each one depends on `have-clang`, which fails the run when
`$(CLANG)` is not in `PATH`; it does not skip, because a skipped fuzz regression
is indistinguishable from a passing one. That is a change from an earlier
`exit 77`, which read like a skip in the recipe's own output while make still
treated the non-zero status as an error and went red with a bare `Error 77`. Set
`CLANG=` to something else if `clang` is not the name you want.

```sh
cd tests/fuzz
make              # the default goal is `all`, which is `regress`
make regress      # replay crashes/ - must stay clean (used by CI)
make fuzz         # 60s per target, 8 parallel workers
make fuzz-long    # `$(MAKE) fuzz FUZZ_SECONDS=600 JOBS=16`
make clean        # remove fuzz_elf, fuzz_proc and work/
```

Three variables carry the defaults, all with `?=`, so the environment sets them
too: `FUZZ_SECONDS` (60), `JOBS` (8) and `CLANG` (clang).

`make fuzz` also seeds the corpora before it starts. `corpus/elf/seed_libc` is a
copy of the host's `libc.so.6`, looked for in `/lib/x86_64-linux-gnu`,
`/usr/lib/x86_64-linux-gnu`, `/lib64`, `/usr/lib64`, `/lib`, `/usr/lib` and
`$(CC) -print-file-name=libc.so.6`; an existing `seed_libc` is kept, and finding
no libc at all warns and leaves `corpus/elf` empty rather than failing, so
`fuzz_elf` then starts from scratch instead of a realistic ELF image.
`corpus/proc/seed_maps` is copied from `/proc/self/maps` the same way, except
that a failure to copy it does fail the run.

CI does not run the documented default campaign: `.github/workflows/test.yml`
invokes `make fuzz FUZZ_SECONDS=60 JOBS=4`, which keeps the default duration and
halves the default worker count.

A green `make regress` ends with `fuzz regression OK (elf: N clean, proc: M
clean)`. A green `make fuzz` ends with `fuzzing OK (60s per target, no new
crashes)`; a `FUZZ_PROC_DEGRADED` campaign ends with `fuzzing finished (DEGRADED:
comm contract NOT verified this run)` instead, because the last line is what a
human and a CI log both read and it must never affirm a run that verified less
than it claims. The exit status is `0` in both cases, by design: a machine
without a readable `/proc` is not a parser defect, and a fuzz step that went red
on every container run would be ignored. The warning, not the status, carries the
signal. `make fuzz` in addition echoes, per campaign log, the last two
`FUZZ_PROC_COVERAGE` lines and - only when that log reported skips - the last five
`FUZZ_PROC_NOTE` lines with their total count; when at least one log had skips it
prints one `informational: N of the 2 campaign logs reported skipped coverage (the
FUZZ_PROC_NOTE lines above; not a warning)` line. `WARNING:` lines plus a
make-level warning appear only if some log was `FUZZ_PROC_DEGRADED`.

## `crashes/`

Each file is a *minimal reproducer* for one distinct defect that was found and
fixed. Files are named

    <target>__<detector>__<site>__<function>.bin

If a reproducer ever starts crashing again, `make regress` fails and CI goes red.
What each field means - only the first one is load-bearing for the replay:

* `<target>` is the fuzzer that covers the entry point, and the only field the
  dispatch reads: `elf__*` goes to `fuzz_elf`, `proc__*` to `fuzz_proc`. A file
  matching neither prefix is a hard failure, not a skip.
* `<detector>` is what actually caught the defect. Usually that is a sanitizer
  report type (`heap-buffer-overflow`, `stack-buffer-overflow`,
  `signed_integer`), or `requested` for an absurd allocation the parser asked
  for. It can also be `canary` or `invariant`, meaning one of the harness's own
  checks fired. That distinction is not cosmetic: for the `n == 0` sweep the
  output buffer is `malloc(1)` whose single canary byte *is* index 0, so a
  one-byte write into a buffer the caller declared zero-length lands inside the
  allocation where ASan cannot see it - the canary catches it, `abort()`s, and
  libFuzzer reports the result as a deadly signal. Naming that file
  `heap-buffer-overflow` would have described the defect in production but not
  the report you actually get when you replay it.
* `<site>` is `file_line` in the revision the defect was found in, not in the
  current tree - fixing a bug moves lines. This repository has no tags
  (`git tag -l` is empty), so there is no "tagged revision" to grep;
  `git show <rev>:<path>` prints the file each line number below refers to.
  * the four `elf.c_*` sites are lines of `290afa0` ("feat(cli): add
    `--delivery` ..."), the parent of the fix commit `27f7a69` ("fix(elf):
    reject hostile ELF input instead of overflowing buffers"):
    `git show 290afa0:src/linux/elf.c`. That fix changed 398 lines and deleted 43
    in `elf.c` alone, so at `27f7a69` those same line numbers already hold
    unrelated code (`rv = INJERR_NO_FUNCTION;`, `return INJERR_NO_LIBRARY;`,
    `return NULL;`, `return NULL;`). At HEAD they hold something unrelated again:

        $ git show HEAD:src/linux/elf.c | sed -n '343p;639p;663p;693p'
                }
                if (offset != 0) {
                *p = '\0';
            const char *p = strstr(path, "/rootfs/");

    `src/linux/elf.c` is byte-identical between HEAD and the working tree, so for
    ELF sites this is purely a historical-revision question.
  * `proc.c_70` is the opposite case: it is line 70 of
    `git show 3c156cd:src/linux/proc.c`, where `out[0] = '\0';` still sits inside
    the `fopen()`-failure branch, ahead of any `n == 0` guard. `3c156cd` is the
    revision the reproducer was found at, not the one that introduced the defect -
    it is a docs-only commit, "docs(injector.h): state what injector_list_modules
    does not list", and touches no `.c` file. The fix is `92a5bbc` ("fix(proc):
    guard a zero-length buffer before the fopen failure branch"), whose parent is
    `3c156cd`. So read the defect at `92a5bbc^` and the fix at `92a5bbc`: there
    the guard is `src/linux/proc.c` lines 83-85 and the `out[0] = '\0';` of the
    `fopen()`-failure branch has moved to line 89.
* `<function>` is the entry point, or `unknown` when the report attributed none.

Nothing in here is allowed to pass vacuously. The gates below answer three
different questions: what one replayed file has to prove, what the per-target
counts are checked against, and what may not be sitting in `crashes/`.

What one replayed file has to prove:

* A reproducer only *counts* when its run satisfies two positive criteria on
  top of tripping no sanitizer: the fuzzer must exit 0, and its output must
  contain libFuzzer's `Executed <file> in <N> ms` line. For the checked-in proc
  reproducer that line is
  `Executed crashes/proc__canary__proc.c_70__proc__read_comm.bin in 0 ms`. The
  millisecond count is wall-clock and not stable (the same replay reports 1 ms on
  a loaded host), which is why the gate greps for the `Executed <file> in` prefix
  only and never for a number. That line is printed only after the input really
  reached the target and it echoes the path, so a run against some other file
  cannot satisfy it. "No sanitizer error" on its
  own is not evidence of anything: a missing or unbuildable binary exits 127 with
  a shell error, and an input that vanished between make's parse-time
  `$(wildcard)` and the run exits 1 with
  `ERROR: The required directory "/nonexistent-dir-xyz" does not exist` - neither
  string matches the blacklist grep, so both used to be reported as clean and both
  used to satisfy the floors.
* A replay that satisfies both criteria and trips no sanitizer must also contain
  **no `FUZZ_PROC_DEGRADED`**. If it does, `regress` reports `DEGRADED: <file>`
  with the harness's own text, does not count the file towards the floor, and
  ends in `fuzz regression FAILED` - a gate may not pass on a run that verified
  less than it claims. Plain `FUZZ_PROC_NOTE` skip lines are echoed with their
  count and still let the replay count, for the reason given above.

What the per-target counts are checked against:


* `regress` counts and reports each target separately: the per-target line is
  `elf: N replayed cleanly, proc: M replayed cleanly (expected: N / M)`, and each
  count must equal the number of files make can see (`$(words ...)`), which is
  what catches a glob that stopped matching its dispatch.
* Each count is also checked against a floor - `ELF_MIN_REPRODUCERS` (4) and
  `PROC_MIN_REPRODUCERS` (1) - so deleting reproducers cannot keep the target
  green. Both floors are validated while the Makefile is parsed: a non-integer
  used to reach `[ N -lt abc ]`, which exits 2, which makes the `if` false,
  which passed the guard silently; and a floor above the number of files present
  can never be satisfied, so that is rejected up front with an explanation
  instead of turning every run red. There is a ceiling as well as a floor. make
  cannot compare numbers, so the test is membership in `MIN_WHITELIST`
  (`Makefile`:78), which lists `0` through `16`: a floor of 17 is a perfectly
  good integer and is still rejected by the `$(error)` at `Makefile`:95 and
  `Makefile`:121, which report it as an invalid value rather than as too high.
  Widening `MIN_WHITELIST` is the fix, and it has to come first - the
  reachability check computes its allowed floors with
  `$(wordlist 1,$(words x <crashes>),$(MIN_WHITELIST))`, which truncates at the
  end of that list.
* The proc floor used to be 0 with an explicit `NOTE:` in its place, because no
  defect had ever been found in the `/proc` parsers and the honest thing was to
  say so rather than imply coverage. Widening the harness beyond
  `proc__parse_maps_line` found one immediately (see the table below), so the
  note is gone and the floor is 1.

What may not be sitting in `crashes/`, and how a failure there is labelled:


* A file in `crashes/` that matches *neither* prefix is a hard failure, so a bad
  rename (or a stray artifact committed without one) can never silently drop a
  reproducer out of the replay set. That promise needs the scan to see dotfiles
  too: make's `$(wildcard)` is `glob(3)` without `GLOB_PERIOD`, so a bare
  `crashes/*` skips them and a macOS `.DS_Store` or an AppleDouble `._elf__*.bin`
  - both realistic in a tree edited on macOS and rsynced to Linux - would have
  matched neither prefix list nor the stray list, i.e. exactly the silent drop the
  check exists to prevent. The wildcard is therefore
  `$(filter-out crashes/. crashes/..,$(wildcard crashes/* crashes/.*))`.
* An abort during a replay is classified by its label rather than reported as one
  undifferentiated failure: `FUZZ_PROC_ENV` with no sanitizer report gives
  `ENVIRONMENT FAILURE (not a regression of the code under test): <file>` plus the
  harness' own reason, and `FUZZ_PROC_INVARIANT` (or any sanitizer hit) gives
  `REGRESSION: <file>`. Both labels fail the run. An environment that cannot
  replay the corpus proves nothing, which is the same vacuous pass a
  clean-looking `DEGRADED` replay would be, so the split only decides which
  message you read: an unwritable `TMPDIR` is not mistaken for a parser defect
  and is not checked in as a bogus reproducer.

| reproducer | defect it pins |
|------------|----------------|
| `elf__stack-buffer-overflow__elf.c_639__read_elf_shdr.bin` | `fread()` used the file-controlled `e_shentsize` as the size for a fixed-size stack `Elf_Shdr`, smashing the stack (72 bytes of input). |
| `elf__heap-buffer-overflow__elf.c_663__read_elf_sym.bin` | same pattern with `.dynsym`'s `sh_entsize` into a 24-byte `Elf_Sym`, overflowing the heap symbol array. Produced from a valid `.so` by changing one field. |
| `elf__signed_integer__elf.c_693__unknown.bin` | `e_shstrndx * e_shentsize` (both `uint16_t`) was evaluated in `int` and overflowed, corrupting the section-header seek. |
| `elf__requested__elf.c_343__injector__elf_find_symbols.bin` | `sym_num * sizeof(Elf_Sym)` from unchecked `sh_size`/`sh_entsize` requested an absurd allocation. |
| `proc__canary__proc.c_70__proc__read_comm.bin` | `proc__read_comm()` guarded `n == 0` *after* the `fopen()` failure branch, and that branch writes `out[0] = '\0'` unconditionally - so a caller passing a zero-length buffer still took a one-byte write whenever `/proc/<pid>/comm` could not be opened (a pid that exited, or one it may not read). Only the `n - 1` wrap had been fixed; this is the same bug one branch earlier. The reproducer is the empty input: size 0 makes the harness sweep `n == 0` against a pid whose `comm` cannot be opened. |

Adding a new reproducer: run `make fuzz` (or `make fuzz-long`), take the artifact
libFuzzer drops in `work/` (`proc-crash-*` / `elf-crash-*`, from the
`-artifact_prefix=` each run passes), minimize it, and document it in the table
above. The name carries all four fields - a two-field `elf__<name>.bin`
contradicts the convention and leaves the next reader unable to tell which
detector fired or where:

```sh
# an ELF reproducer
./fuzz_elf work/elf-crash-<hash> -minimize_crash=1 -max_len=65536 \
  -exact_artifact_path=crashes/elf__<detector>__<site>__<function>.bin

# a /proc reproducer (same flags, other binary and prefix)
./fuzz_proc work/proc-crash-<hash> -minimize_crash=1 -max_len=65536 \
  -exact_artifact_path=crashes/proc__<detector>__<site>__<function>.bin
```

Two traps:

* When the minimal reproducer is the empty input, `-minimize_crash=1` is
  meaningless - there is nothing left to shrink, and it will only rewrite the
  same zero bytes. Write the file directly
  (`: > crashes/proc__canary__proc.c_70__proc__read_comm.bin`), then prove it
  really reproduces: `./fuzz_proc crashes/<name>.bin` must crash, and
  `make regress` must go green again once the defect is fixed. Say plainly in the
  table that the reproducer is 0 bytes - otherwise it looks like a truncated
  check-in, and `rsync`/`git` both carry empty files fine, so nothing else will
  tell you.
* Read the `FUZZ_PROC_*` label before naming the file. A harness `abort()` is
  reported by libFuzzer as a deadly signal, so it looks exactly like a crash:
  `FUZZ_PROC_ENV` means the *machine* failed and the artifact
  **must be discarded, not checked in**.

Then raise the matching floor (`ELF_MIN_REPRODUCERS` / `PROC_MIN_REPRODUCERS`) so
the new file cannot be deleted later without the target going red, and run
`make regress`. A floor is accepted only if it is one of the words in
`MIN_WHITELIST` (`Makefile`:78), which currently runs `0` to `16`. If the new
floor would be 17 or more, widen that list first, or the `$(error)` at
`Makefile`:95 and `Makefile`:121 rejects the value as invalid instead of letting
the higher floor take effect.
