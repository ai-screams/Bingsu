#define _GNU_SOURCE
/* Product BPF is serialized by the Rust harness, never reimplemented here. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static void require(int yes) { if (!yes) _exit(90); }
static struct stat identity;
/* musl stdio writes with writev, which the filter refuses; print with write(2). */
static void say(const char *text) {
    size_t left = strlen(text);
    while (left > 0) {
        ssize_t n = write(1, text, left);
        require(n > 0);
        text += n;
        left -= (size_t)n;
    }
}
static void unchanged(void) {
    struct stat after;
    char bytes[64];
    int fd = open("sentinel", O_RDONLY | O_CLOEXEC);
    require(fd >= 0 && fstat(fd, &after) == 0);
    ssize_t n = read(fd, bytes, sizeof(bytes));
    require(n == 19 && memcmp(bytes, "unchanged sentinel\n", 19) == 0);
    require(after.st_dev == identity.st_dev && after.st_ino == identity.st_ino &&
            after.st_nlink == identity.st_nlink && after.st_size == identity.st_size);
    require(close(fd) == 0);
}
static void refused(const char *name, long result) {
    require(result == -1 && errno == EPERM);
    unchanged();
    say("X-16 ");
    say(name);
    say(" EPERM unchanged\n");
}
int main(int argc, char **argv) {
#ifdef __GLIBC__
    say("X-16 c_libc=glibc\n");
#else
    say("X-16 c_libc=non-glibc\n");
#endif
    require(argc == 3 && chdir(argv[1]) == 0);
    int fd = open("filter.bpf", O_RDONLY | O_CLOEXEC);
    struct sock_filter program[4096];
    ssize_t size = read(fd, program, sizeof(program));
    require(size > 0 && size % sizeof(program[0]) == 0 && close(fd) == 0);
    struct sock_fprog fp = { .len = (unsigned short)(size / sizeof(program[0])), .filter = program };
    require(stat("sentinel", &identity) == 0);
    int connected = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(connected >= 0);
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = htons((unsigned short)atoi(argv[2])) };
    require(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
    struct rlimit zero = {0, 0};
    require(setrlimit(RLIMIT_FSIZE, &zero) == 0);
    /* Negative control: FSIZE=0 alone still permits truncation of existing data. */
    fd = open("control", O_RDONLY | O_TRUNC);
    struct stat control;
    require(fd >= 0 && fstat(fd, &control) == 0 && control.st_size == 0 && close(fd) == 0);
    require(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    require(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &fp) == 0);
    refused("O_RDONLY|O_TRUNC", open("sentinel", O_RDONLY | O_TRUNC));
    refused("O_WRONLY|O_TRUNC", open("sentinel", O_WRONLY | O_TRUNC));
    refused("unlink", unlink("sentinel"));
    refused("rename", rename("sentinel", "renamed"));
    refused("socket", socket(AF_INET, SOCK_STREAM, 0));
    refused("connect", connect(connected, (struct sockaddr *)&address, sizeof(address)));
    struct rlimit actual;
    require(getrlimit(RLIMIT_FSIZE, &actual) == 0 && actual.rlim_cur == 0 && actual.rlim_max == 0);
    say("X-16 PASS cells=6 fsize=0 control_truncated=1\n");
    return 0;
}
