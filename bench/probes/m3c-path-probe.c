/* X-11 independent syscall oracle. The helper/test harness prepares argv[1].
 * cc -Wall -Wextra -Werror bench/probes/m3c-path-probe.c -o /tmp/m3c-path-probe
 * /tmp/m3c-path-probe <fixture-root> [--force-absent]
 * Current-runtime + forced fallback are required; minimum OS is decision 24.
 */
#include <AvailabilityMacros.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#ifdef PROBE_ORDER_INTERPOSER
#include <sys/resource.h>
#include <stdlib.h>
static int saw_probe;
static int checked_openat(int base, const char *path, int flags, ...) {
    if (base == 6) {
        struct rlimit n, f, c;
        if (getrlimit(RLIMIT_NOFILE, &n) || n.rlim_cur != 64 ||
            getrlimit(RLIMIT_FSIZE, &f) || f.rlim_cur != 0 ||
            getrlimit(RLIMIT_CPU, &c) || c.rlim_cur != 1) _exit(88);
        saw_probe = 1;
    }
    return openat(base, path, flags, 0);
}
static ssize_t checked_write(int fd, const void *buf, size_t size) {
    if (fd == 1 && size >= 11 && !memcmp(buf, "BNGIPC05", 8) && ((const unsigned char *)buf)[10] == 1) {
        if (!saw_probe || fcntl(6, F_GETFD) >= 0 || errno != EBADF) _exit(89);
    }
    return write(fd, buf, size);
}
__attribute__((used,section("__DATA,__interpose"))) static const struct { const void *replacement; const void *original; }
    check_open = {(const void *)checked_openat, (const void *)openat},
    check_write = {(const void *)checked_write, (const void *)write};
__attribute__((constructor)) static void clean(void) { unsetenv("DYLD_INSERT_LIBRARIES"); }
#else
/* Apple XNU bsd/sys/fcntl.h; definitions alone never grant capabilities. */
#ifndef O_RESOLVE_BENEATH
#define O_RESOLVE_BENEATH 0x00001000
#endif
#ifndef O_UNIQUE
#define O_UNIQUE 0x00002000
#endif
#ifndef O_NOFOLLOW_ANY
#define O_NOFOLLOW_ANY 0x20000000
#endif
struct row { const char *path; int flag; int expected; const char *cap; };
int main(int argc, char **argv) {
    if (argc != 2 && !(argc == 3 && strcmp(argv[2], "--force-absent") == 0)) return 2;
    int absent = argc == 3;
    int root = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) return 2;
    struct utsname host;
    if (uname(&host)) return 2;
    printf("{\"kind\":\"host\",\"kernel\":\"%s\",\"arch\":\"%s\",\"sdk\":%d,\"deployment_target\":%d,\"compiler\":\"%s\",\"forced_absent\":%s,\"minimum_os\":\"deferred-decision-24\"}\n", host.release, host.machine, __MAC_OS_X_VERSION_MAX_ALLOWED, __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__, __clang_version__, absent ? "true" : "false");
    const struct row rows[] = {
        {"value", O_RESOLVE_BENEATH, 0, "beneath"},
        {"dir/../value", O_RESOLVE_BENEATH, 0, "beneath"},
        {"dir/inner", O_RESOLVE_BENEATH, 0, "beneath"},
        {"../outside", O_RESOLVE_BENEATH, ENOTCAPABLE, "beneath"},
        {"/", O_RESOLVE_BENEATH, ENOTCAPABLE, "beneath"},
        {"absolute", O_RESOLVE_BENEATH, ENOTCAPABLE, "beneath"},
        {"escape", O_RESOLVE_BENEATH, ENOTCAPABLE, "beneath"},
        {"dir/up", O_RESOLVE_BENEATH, ENOTCAPABLE, "beneath"},
        {"/dev/fd/0", O_RESOLVE_BENEATH, ENOTCAPABLE, "beneath"},
        {"dir/file", O_NOFOLLOW_ANY, 0, "nofollow_any"},
        {"linkdir/file", O_NOFOLLOW_ANY, ELOOP, "nofollow_any"},
        {"dir/file", O_NOFOLLOW_ANY | O_NOFOLLOW, EINVAL, "nofollow_any"},
        {"value", O_UNIQUE, 0, "unique"},
        {"hard", O_UNIQUE, ENOTCAPABLE, "unique"},
    };
    int caps[3] = {1,1,1};
    for (unsigned i = 0; i < sizeof(rows)/sizeof(rows[0]); ++i) {
        int flag = absent ? (rows[i].flag & O_NOFOLLOW) : rows[i].flag;
        int fd = openat(root, rows[i].path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | flag);
        int observed = fd < 0 ? errno : 0;
        if (fd >= 0) close(fd);
        int which = i < 9 ? 0 : i < 12 ? 1 : 2;
        caps[which] &= observed == rows[i].expected;
        printf("{\"kind\":\"errno\",\"path\":\"%s\",\"cap\":\"%s\",\"flags\":%d,\"errno\":%d,\"expected\":%d}\n", rows[i].path, rows[i].cap, flag, observed, rows[i].expected);
    }
    close(root);
    int slash = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int dev = openat(slash, "dev", O_RDONLY | O_DIRECTORY | O_RESOLVE_BENEATH);
    int mount_errno = dev < 0 ? errno : 0;
    if (dev >= 0) close(dev);
    close(slash);
    printf("{\"kind\":\"result\",\"beneath\":%d,\"nofollow_any\":%d,\"unique\":%d,\"beneath_dev_errno\":%d}\n", caps[0], caps[1], caps[2], mount_errno);
    /* 이것을 실패시키는 것: 음성 errno를 무시하거나 강제 부재를 지원으로 승격하는 것. */
    return (caps[0] != !absent || caps[1] != !absent || caps[2] != !absent || mount_errno != 0);
}

#endif
