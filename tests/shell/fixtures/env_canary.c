/* Test-only LD_PRELOAD canary. Its constructor records which bingsu role the
 * dynamic loader loaded it into: a file named after argv[1] ("prompt" or
 * "__refresh-v1") and the pid, in CANARY_DIR (fixed at compile time, so the
 * helper's empty environment cannot hide it). Never installed. */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef CANARY_DIR
#error "compile with -DCANARY_DIR=\"/path\""
#endif

__attribute__((constructor)) static void canary(void) {
    char cmdline[4096];
    int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    ssize_t n = read(fd, cmdline, sizeof(cmdline) - 1);
    close(fd);
    if (n <= 0) return;
    cmdline[n] = 0;
    const char *verb = cmdline + strlen(cmdline) + 1;
    if (verb >= cmdline + n) return;
    if (strcmp(verb, "prompt") && strcmp(verb, "__refresh-v1")) return;
    char path[4096];
    snprintf(path, sizeof(path), "%s/%s-%d", CANARY_DIR, verb, (int)getpid());
    int out = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (out >= 0) close(out);
}
