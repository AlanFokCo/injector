# Fuzzing libinjector's parsers

`libinjector` parses data that is ultimately controlled by the *target* process:
the ELF image of its libc (and of the library being injected), and its
`/proc/<pid>/maps` entries. A hostile or merely unusual target can therefore feed
the injector malformed input, so these parsers are fuzzed continuously.

## Targets

| target        | entry points covered |
|---------------|----------------------|
| `fuzz_elf`    | `injector__read_elf_machine`, `injector__elf_load_bias`, `injector__elf_find_symbols` (and the internal `read_elf_ehdr` / `read_elf_shdr` / `read_elf_sym` / `locate_dynsym` helpers) |
| `fuzz_proc`   | `proc__parse_maps_line` |

Both are built with `clang -fsanitize=fuzzer,address,undefined
-fno-sanitize-recover=all`, so any memory error or undefined behaviour is fatal.

## Usage

```sh
cd tests/fuzz
make regress      # replay crashes/ - must stay clean (used by CI)
make fuzz         # 60s per target
make fuzz-long    # 600s per target, 16 parallel workers
```

## `crashes/`

Each file is a *minimal reproducer* for one distinct defect that was found and
fixed. Files are named

    <target>__<sanitizer>__<site>__<function>.bin

so that `make regress` feeds each one to the fuzzer that actually covers that
entry point (`elf__*` to `fuzz_elf`, `proc__*` to `fuzz_proc`). If a reproducer
ever starts crashing again, `make regress` fails and CI goes red. Note that
`make regress` also fails when the corpus is *empty*, so a bad rename cannot
silently turn the target into a no-op.

| reproducer | defect it pins |
|------------|----------------|
| `elf__stack-buffer-overflow__elf.c_639__read_elf_shdr.bin` | `fread()` used the file-controlled `e_shentsize` as the size for a fixed-size stack `Elf_Shdr`, smashing the stack (72 bytes of input). |
| `elf__heap-buffer-overflow__elf.c_663__read_elf_sym.bin` | same pattern with `.dynsym`'s `sh_entsize` into a 24-byte `Elf_Sym`, overflowing the heap symbol array. Produced from a valid `.so` by changing one field. |
| `elf__signed_integer__elf.c_693__unknown.bin` | `e_shstrndx * e_shentsize` (both `uint16_t`) was evaluated in `int` and overflowed, corrupting the section-header seek. |
| `elf__requested__elf.c_343__injector__elf_find_symbols.bin` | `sym_num * sizeof(Elf_Sym)` from unchecked `sh_size`/`sh_entsize` requested an absurd allocation. |

Adding a new reproducer: run `make fuzz`, take the artifact libFuzzer writes,
minimize it (`./fuzz_elf <crash> -minimize_crash=1 -max_len=65536
-exact_artifact_path=crashes/elf__<name>.bin`), and document it above.
