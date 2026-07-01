#include "minunit.h"
#include "../src/linux/proc.h"
#include "injector.h"
#include <unistd.h>
#include <string.h>

int test_proc_parse_maps_line_libc(void) {
    const char *line = "7f1234567000-7f1234720000 r-xp 00000000 fe:01 123 /lib/x86_64-linux-gnu/libc.so.6\n";
    proc_map_t m;
    MU_ASSERT(proc__parse_maps_line(line, &m) == 0);
    MU_ASSERT_STR_EQ(m.path, "/lib/x86_64-linux-gnu/libc.so.6");
    MU_ASSERT(m.start == 0x7f1234567000UL);
    MU_ASSERT(m.inode == 123);
    MU_ASSERT(m.deleted == 0);
    return 0;
}

int test_proc_parse_maps_line_deleted(void) {
    const char *line = "7f0000000000-7f0000100000 r--p 00000000 00:05 42 /usr/lib/old.so (deleted)\n";
    proc_map_t m;
    MU_ASSERT(proc__parse_maps_line(line, &m) == 0);
    MU_ASSERT_STR_EQ(m.path, "/usr/lib/old.so");
    MU_ASSERT(m.deleted == 1);
    return 0;
}

int test_proc_parse_maps_line_anon(void) {
    const char *line = "7fff00000000-7fff00001000 rw-p 00000000 00:00 0\n";
    proc_map_t m;
    MU_ASSERT(proc__parse_maps_line(line, &m) == -1);
    return 0;
}

int test_proc_target_info_self(void) {
    injector_target_info_t info;
    MU_ASSERT(injector_target_info(getpid(), &info) == 0);
    MU_ASSERT(info.alive == 1);
    MU_ASSERT(info.arch != NULL && info.arch[0] != '\0');
    MU_ASSERT(info.libc != NULL && info.libc[0] != '\0');
    MU_ASSERT(info.exe[0] != '\0');
    return 0;
}
