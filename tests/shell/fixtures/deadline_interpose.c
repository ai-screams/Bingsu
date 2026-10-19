/* N6 fault injection only; never linked into the product. No threads.
 * The real SIGALRM handler still runs; the wrapper records its delivery so the
 * first write can be forced into the check/handler/write race deterministically.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static int mode, writes, armed;
static volatile sig_atomic_t alarms;
static void (*handler)(int);
static ssize_t (*real_write)(int, const void *, size_t);
static int (*real_action)(int, const struct sigaction *, struct sigaction *);
static int (*real_mask)(int, const sigset_t *, sigset_t *);
static int (*real_timer)(int, const struct itimerval *, struct itimerval *);
static int (*real_clock)(clockid_t, struct timespec *);

__attribute__((constructor)) static void init(void) {
    const char *value = getenv("N6_TEST_MODE");
    mode = value ? atoi(value) : 0;
#ifdef __APPLE__
    /* dyld leaves replacee references from this image pointing at originals;
     * RTLD_NEXT lookup, in contrast, would resolve the interposed function. */
    real_write = write;
    real_action = sigaction;
    real_mask = sigprocmask;
    real_timer = setitimer;
    real_clock = clock_gettime;
#else
    real_write = dlsym(RTLD_NEXT, "write");
    real_action = dlsym(RTLD_NEXT, "sigaction");
    real_mask = dlsym(RTLD_NEXT, "sigprocmask");
    real_timer = dlsym(RTLD_NEXT, "setitimer");
    real_clock = dlsym(RTLD_NEXT, "clock_gettime");
#endif
    if (!real_write || !real_action || !real_mask || !real_timer || !real_clock) _exit(90);
}
static void alarm_seen(int signal) {
    alarms = 1;
    handler(signal);
}
static int probe_action(int sig, const struct sigaction *act, struct sigaction *old) {
    if (mode == 10 && act && sig == SIGPIPE) {
        /* Direct-exec fixture: the launcher blocks ALRM across exec solely to
         * make delivery at this old pre-handler window deterministic. */
        struct itimerval inherited;
        sigset_t pending, alarm;
        if (getitimer(ITIMER_REAL, &inherited) || sigpending(&pending)) _exit(92);
        if (!inherited.it_value.tv_sec && !inherited.it_value.tv_usec &&
            !sigismember(&pending, SIGALRM)) _exit(93);
        const char witness[] = "K87 inherited timer at PIPE setup\n";
        real_write(2, witness, sizeof(witness) - 1);
        sigemptyset(&alarm); sigaddset(&alarm, SIGALRM);
        real_mask(SIG_UNBLOCK, &alarm, NULL);
        struct timespec delay = {0, 100000000};
        while (nanosleep(&delay, &delay) && errno == EINTR) {}
    }
    if (act && ((mode == 3 && sig == SIGPIPE) || (mode == 4 && sig == SIGALRM))) {
        errno = EPERM;
        return -1;
    }
    if (act && sig == SIGALRM && mode == 1) {
        struct sigaction wrapper = *act;
        handler = act->sa_handler;
        wrapper.sa_handler = alarm_seen;
        return real_action(sig, &wrapper, old);
    }
    return real_action(sig, act, old);
}
static int probe_mask(int how, const sigset_t *set, sigset_t *old) {
    if (mode == 5 && how == SIG_UNBLOCK && set && sigismember(set, SIGALRM)) {
        errno = EPERM;
        return -1;
    }
    return real_mask(how, set, old);
}
static int probe_timer(int which, const struct itimerval *value, struct itimerval *old) {
    if (mode == 10) return real_timer(which, value, old); /* direct-exec launcher's one-shot */
    if (mode == 6) { errno = EPERM; return -1; }
    if (which != ITIMER_REAL || !value ||
        (mode != 1 && (value->it_interval.tv_sec != 0 || value->it_interval.tv_usec != 1000)) ||
        (value->it_value.tv_sec == 0 && value->it_value.tv_usec == 0)) _exit(91);
    armed = 1;
    return real_timer(which, value, old);
}
static int probe_clock(clockid_t clock, struct timespec *value) {
    if (mode == 7) { errno = EIO; return -1; }
    int result = real_clock(clock, value);
    /* Preparation has consumed the budget. The original entry end must win. */
    if (result == 0 && mode == 8 && armed) value->tv_sec += 1;
    return result;
}
static ssize_t probe_write(int fd, const void *buf, size_t len) {
    if (fd == 1 && ++writes == 1 && mode == 1) {
        while (!alarms) { /* consume the first alarm before entering write */ }
    }
    if (fd == 1 && mode == 2) {
        if (writes == 2 || writes == 4) { errno = EINTR; return -1; }
        if (len > 3) len = 3;
    }
    if (fd == 1 && mode == 9) { errno = EINTR; return -1; }
    return real_write(fd, buf, len);
}

#ifdef __APPLE__
#define INTERPOSE(new, old) \
    __attribute__((used)) static struct { const void *replacement, *replacee; } \
    ip_##old __attribute__((section("__DATA,__interpose"))) = { (const void *)&new, (const void *)&old };
INTERPOSE(probe_write, write)
INTERPOSE(probe_action, sigaction)
INTERPOSE(probe_mask, sigprocmask)
INTERPOSE(probe_timer, setitimer)
INTERPOSE(probe_clock, clock_gettime)
#else
ssize_t write(int fd, const void *p, size_t n) { return probe_write(fd, p, n); }
int sigaction(int s, const struct sigaction *a, struct sigaction *o) { return probe_action(s, a, o); }
int sigprocmask(int h, const sigset_t *s, sigset_t *o) { return probe_mask(h, s, o); }
#ifdef __GLIBC__
#define TIMER_WHICH __itimer_which_t
#else
#define TIMER_WHICH int
#endif
int setitimer(TIMER_WHICH w, const struct itimerval *v, struct itimerval *o) { return probe_timer(w, v, o); }
int clock_gettime(clockid_t c, struct timespec *t) { return probe_clock(c, t); }
#endif
