/* X-15: the raw openat2 result inside a container under Docker's default
 * seccomp profile. 0 means the Openat2 backend applies; ENOSYS or EPERM
 * means the Stepwise resolver (proved separately by the forced cells). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
    struct open_how how = {
        .flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV,
    };
    long fd = syscall(SYS_openat2, AT_FDCWD, ".", &how, sizeof how);
    int error = fd < 0 ? errno : 0;
    if (fd >= 0) {
        close((int)fd);
    }
    printf("X-15 openat2 errno=%d docker=%s seccomp=default\n", error, argc > 1 ? argv[1] : "unknown");
    return 0;
}
