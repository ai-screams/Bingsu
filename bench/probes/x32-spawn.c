/* Standalone experiment. SDK declarations are not evidence for older OSes.
 * https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/spawn.h */
#define _DARWIN_C_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef POSIX_SPAWN_SETSID
#define POSIX_SPAWN_SETSID 0
#define MISSING_SETSID 1
#else
#define MISSING_SETSID 0
#endif
#ifndef POSIX_SPAWN_CLOEXEC_DEFAULT
#define POSIX_SPAWN_CLOEXEC_DEFAULT 0
#define MISSING_CLOEXEC 1
#else
#define MISSING_CLOEXEC 0
#endif

#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "assertion: %s errno=%d\n", #x, errno); exit(90); } } while (0)
static atomic_int running, opened;
static int ceiling;
struct report { int pid, sid, leaks, high_open; };
static void *race_open(void *unused) {
    (void)unused;
    while (atomic_load(&running)) {
        int fd = open("/dev/null", O_RDONLY); /* deliberately not CLOEXEC */
        if (fd >= 0) { atomic_fetch_add(&opened, 1); close(fd); }
    }
    return NULL;
}
static void child_report(int bound) {
    struct report r = {getpid(), getsid(0), 0, fcntl(1025, F_GETFD) >= 0};
    for (int fd = 4; fd < bound; ++fd) if (fcntl(fd, F_GETFD) >= 0) ++r.leaks;
    if (write(3, &r, sizeof(r)) != sizeof(r)) _exit(92);
    _exit(0);
}
/* Only these two conditions may select the approved fallback. */
static int fallback_for(int missing, int error) { return missing || error == EINVAL; }
static void probe(const char *self, const char *cell, short flags, int missing,
                  int forced_error, int mutate) {
    int p[2]; REQUIRE(pipe(p) == 0);
    REQUIRE(fcntl(p[0], F_SETFD, FD_CLOEXEC) == 0);
    REQUIRE(fcntl(p[1], F_SETFD, FD_CLOEXEC) == 0);
    char bound[32]; snprintf(bound, sizeof(bound), "%d", ceiling);
    char *args[] = {(char *)self, "--child", bound, NULL};
    char *env[] = {NULL};
    posix_spawnattr_t attr;
    posix_spawn_file_actions_t actions;
    REQUIRE(posix_spawnattr_init(&attr) == 0);
    REQUIRE(posix_spawn_file_actions_init(&actions) == 0);
    REQUIRE(posix_spawn_file_actions_adddup2(&actions, p[1], 3) == 0);
    /* SETSID alone tests session semantics, not descriptor isolation.
     * The fallback closes the whole inherited table in the child; enumerating
     * the parent's open descriptors would race with race_open. */
    int error = forced_error;
    pid_t pid = -1;
    struct timeval start, end; REQUIRE(gettimeofday(&start, NULL) == 0);
    if (!missing && !error) {
        error = posix_spawnattr_setflags(&attr, flags);
        if (!error) error = posix_spawn(&pid, self, &actions, &attr, args, env);
    }
    int fallback = fallback_for(missing, error);
    long long close_ns = 0;
    if (fallback) {
        pid = fork(); REQUIRE(pid >= 0);
        if (pid == 0) {
            /* First child operation detaches. Only async-signal-safe calls
             * until exec; no locks, allocator, stdio or parent thread state. */
            if (setsid() < 0 || dup2(p[1], 3) < 0) _exit(93);
            struct timespec before, after;
            if (clock_gettime(CLOCK_MONOTONIC, &before) != 0) _exit(95);
            for (int fd = 4; fd < ceiling; ++fd) close(fd);
            if (clock_gettime(CLOCK_MONOTONIC, &after) != 0) _exit(95);
            close_ns = (after.tv_sec - before.tv_sec) * 1000000000LL + after.tv_nsec - before.tv_nsec;
            if (write(3, &close_ns, sizeof(close_ns)) != sizeof(close_ns)) _exit(96);
            execve(self, args, env);
            _exit(94);
        }
    } else REQUIRE(error == 0);
    REQUIRE(close(p[1]) == 0);
    if (fallback) REQUIRE(read(p[0], &close_ns, sizeof(close_ns)) == sizeof(close_ns) && close_ns > 0);
    struct report r;
    REQUIRE(read(p[0], &r, sizeof(r)) == sizeof(r));
    REQUIRE(close(p[0]) == 0);
    int status; REQUIRE(waitpid(pid, &status, 0) == pid);
    REQUIRE(gettimeofday(&end, NULL) == 0);
    REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    int detached = fallback || (flags & POSIX_SPAWN_SETSID);
    /* 이것을 실패시키는 것: SETSID가 부모 세션을 그대로 물려주는 것. */
    REQUIRE(mutate ? r.sid != r.pid : (detached ? r.sid == r.pid && r.sid != getsid(0) : r.sid == getsid(0)));
    REQUIRE(r.pid == pid);
    if (fallback || (flags & POSIX_SPAWN_CLOEXEC_DEFAULT)) REQUIRE(r.leaks == 0 && r.high_open == 0);
    long us = (end.tv_sec - start.tv_sec) * 1000000L + end.tv_usec - start.tv_usec;
    printf("{\"cell\":\"%s\",\"evidence\":{\"errno\":%d,\"missing\":%d,\"fallback\":%d,\"pid\":%d,\"sid\":%d,\"parent_sid\":%d,\"leaks\":%d,\"high_open\":%d,\"exit\":0,\"elapsed_us\":%ld,\"close_ns\":%lld}}\n",
           cell, error, missing, fallback, r.pid, r.sid, getsid(0), r.leaks, r.high_open, us, close_ns);
    REQUIRE(posix_spawn_file_actions_destroy(&actions) == 0);
    REQUIRE(posix_spawnattr_destroy(&attr) == 0);
}

int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "--child")) child_report(atoi(argv[2]));
    REQUIRE(argc == 1 || (argc == 2 && !strcmp(argv[1], "--mutate-expectation")));
    int maxfiles; size_t n = sizeof(maxfiles);
    REQUIRE(sysctlbyname("kern.maxfilesperproc", &maxfiles, &n, NULL, 0) == 0);
    struct rlimit old, low; REQUIRE(getrlimit(RLIMIT_NOFILE, &old) == 0);
    ceiling = old.rlim_max == RLIM_INFINITY ? maxfiles : (int)old.rlim_max;
    if (ceiling < maxfiles) ceiling = maxfiles;
    REQUIRE(ceiling > 1025 && ceiling < 2000000);
    low = old; if (low.rlim_cur < 1026) { low.rlim_cur = 1026; REQUIRE(setrlimit(RLIMIT_NOFILE, &low) == 0); }
    int base = open("/dev/null", O_RDONLY); REQUIRE(base >= 0);
    REQUIRE(dup2(base, 1025) == 1025); REQUIRE(close(base) == 0);
    low.rlim_cur = 256; REQUIRE(setrlimit(RLIMIT_NOFILE, &low) == 0);
    atomic_store(&running, 1);
    pthread_t thread; REQUIRE(pthread_create(&thread, NULL, race_open, NULL) == 0);
    while (!atomic_load(&opened)) sched_yield();
    REQUIRE(fallback_for(1, 0) && fallback_for(0, EINVAL) && !fallback_for(0, EPERM));
    probe(argv[0], "setsid", POSIX_SPAWN_SETSID, MISSING_SETSID, 0, argc == 2);
    probe(argv[0], "cloexec_default", POSIX_SPAWN_CLOEXEC_DEFAULT, MISSING_CLOEXEC, 0, 0);
    probe(argv[0], "both", POSIX_SPAWN_SETSID | POSIX_SPAWN_CLOEXEC_DEFAULT, MISSING_SETSID || MISSING_CLOEXEC, 0, 0);
    probe(argv[0], "fallback_missing", 0, 1, 0, 0);
    probe(argv[0], "fallback_einval", 0, 0, EINVAL, 0);
    atomic_store(&running, 0); REQUIRE(pthread_join(thread, NULL) == 0);
    REQUIRE(close(1025) == 0 && setrlimit(RLIMIT_NOFILE, &old) == 0);
    printf("{\"cell\":\"race\",\"evidence\":{\"opens\":%d,\"high_fd\":1025,\"soft_limit\":256,\"close_ceiling\":%d,\"other_errno_rejected\":1}}\n", atomic_load(&opened), ceiling);
    return 0;
}
