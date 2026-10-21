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
    if (write(3, &r, sizeof(r)) != sizeof(r)) {
        dprintf(2, "child report write errno=%d\n", errno);
        _exit(92);
    }
    _exit(0);
}
/* Only these two conditions may select the approved fallback. */
static int fallback_for(int missing, int error) { return missing || error == EINVAL; }
/* Read a complete packet, distinguishing EOF from a syscall error. */
static ssize_t read_report(int fd, void *buffer, size_t size, int *error) {
    size_t used = 0;
    while (used < size) {
        ssize_t n = read(fd, (char *)buffer + used, size - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { *error = errno; return -1; }
        if (!n) break;
        used += (size_t)n;
    }
    return (ssize_t)used;
}
static void probe(const char *self, const char *cell, short flags, int missing,
                  int forced_error, int mutate) {
    int p[2] = {-1, -1}, original_writer = -1, setup_error = 0, read_error = 0;
    int error = forced_error, status = -1, wait_error = 0;
    int attr_ready = 0, actions_ready = 0, fallback = 0;
    const char *stage = "complete";
    pid_t pid = -1;
    ssize_t report_bytes = -1, timing_bytes = 0;
    long long close_ns = 0;
    struct report r = {-1, -1, -1, -1};
    struct timeval start = {0}, end;
    posix_spawnattr_t attr;
    posix_spawn_file_actions_t actions;
#define CELL_SYS(x) do { if (!(x)) { setup_error = errno; stage = #x; goto done; } } while (0)
#define CELL_API(x) do { int e_ = (x); if (e_) { setup_error = e_; stage = #x; goto done; } } while (0)
    CELL_SYS(gettimeofday(&start, NULL) == 0);
    CELL_SYS(pipe(p) == 0);
    original_writer = p[1];
    CELL_SYS(fcntl(p[0], F_SETFD, FD_CLOEXEC) == 0);
    CELL_SYS(fcntl(p[1], F_SETFD, FD_CLOEXEC) == 0);
    /* pipe() allocates its two fds separately on Darwin. race_open can free
     * fd 3 between those allocations, giving p={4,3}. dup2(3,3) would keep
     * FD_CLOEXEC, including in spawn file actions, and exec would lose the
     * report channel. Always use distinct source/destination descriptors. */
    if (p[1] == 3) {
        int moved = fcntl(p[1], F_DUPFD_CLOEXEC, 4);
        CELL_SYS(moved >= 0);
        CELL_SYS(close(p[1]) == 0);
        p[1] = moved;
    }
    char bound[32]; snprintf(bound, sizeof(bound), "%d", ceiling);
    char *args[] = {(char *)self, "--child", bound, NULL};
    char *env[] = {NULL};
    CELL_API(posix_spawnattr_init(&attr)); attr_ready = 1;
    CELL_API(posix_spawn_file_actions_init(&actions)); actions_ready = 1;
    CELL_API(posix_spawn_file_actions_adddup2(&actions, p[1], 3));
    if (!missing && !error) {
        error = posix_spawnattr_setflags(&attr, flags);
        if (!error) error = posix_spawn(&pid, self, &actions, &attr, args, env);
    }
    fallback = fallback_for(missing, error);
    if (fallback) {
        pid = fork(); CELL_SYS(pid >= 0);
        if (pid == 0) {
            /* Only async-signal-safe operations between fork and exec. */
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
    }
    CELL_SYS(close(p[1]) == 0); p[1] = -1;
    if (pid > 0) {
        if (fallback) timing_bytes = read_report(p[0], &close_ns, sizeof(close_ns), &read_error);
        report_bytes = read_report(p[0], &r, sizeof(r), &read_error);
        pid_t waited;
        do { waited = waitpid(pid, &status, 0); } while (waited < 0 && errno == EINTR);
        if (waited < 0) wait_error = errno;
    }
done:
    if (p[1] >= 0) close(p[1]);
    if (p[0] >= 0) close(p[0]);
    if (actions_ready) { int e = posix_spawn_file_actions_destroy(&actions); if (e) setup_error = e; }
    if (attr_ready) { int e = posix_spawnattr_destroy(&attr); if (e) setup_error = e; }
    if (gettimeofday(&end, NULL) != 0) { setup_error = errno; stage = "end time"; end = start; }
    int child_exit = status >= 0 && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    int child_signal = status >= 0 && WIFSIGNALED(status) ? WTERMSIG(status) : 0;
    int detached = fallback || (flags & POSIX_SPAWN_SETSID);
    int session_ok = detached ? r.sid == r.pid && r.sid != getsid(0) : r.sid == getsid(0);
    if (mutate) session_ok = r.sid != r.pid;
    int pass = !setup_error && !read_error && !wait_error && (!error || fallback)
        && child_exit == 0 && report_bytes == sizeof(r) && r.pid == pid && session_ok
        && (!fallback || (timing_bytes == sizeof(close_ns) && close_ns > 0))
        && (!(fallback || (flags & POSIX_SPAWN_CLOEXEC_DEFAULT)) || (!r.leaks && !r.high_open));
    long us = (end.tv_sec - start.tv_sec) * 1000000L + end.tv_usec - start.tv_usec;
    printf("{\"cell\":\"%s\",\"evidence\":{\"outcome\":\"%s\",\"stage\":\"%s\",\"setup_errno\":%d,\"errno\":%d,\"missing\":%d,\"fallback\":%d,\"pid\":%d,\"child_pid\":%d,\"sid\":%d,\"parent_sid\":%d,\"leaks\":%d,\"high_open\":%d,\"exit\":%d,\"signal\":%d,\"wait_status\":%d,\"wait_errno\":%d,\"report_bytes\":%zd,\"read_errno\":%d,\"timing_bytes\":%zd,\"pipe_write_fd\":%d,\"elapsed_us\":%ld,\"close_ns\":%lld}}\n",
           cell, pass ? "PASS" : "FAIL", stage, setup_error, error, missing, fallback,
           r.pid, pid, r.sid, getsid(0), r.leaks, r.high_open, child_exit, child_signal,
           status, wait_error, report_bytes, read_error, timing_bytes, original_writer, us, close_ns);
    fflush(stdout);
#undef CELL_SYS
#undef CELL_API
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
    printf("{\"cell\":\"race\",\"evidence\":{\"outcome\":\"PASS\",\"opens\":%d,\"high_fd\":1025,\"soft_limit\":256,\"close_ceiling\":%d,\"other_errno_rejected\":1}}\n", atomic_load(&opened), ceiling);
    return argc == 2 ? 90 : 0;
}
