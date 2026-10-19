/* K87 test-only launcher. exec preserves ITIMER_REAL; fork would not.
 * Blocking across exec controls the reproduction, not a product guarantee. */
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) return 90;
    sigset_t alarm;
    sigemptyset(&alarm);
    sigaddset(&alarm, SIGALRM);
    if (sigprocmask(SIG_BLOCK, &alarm, 0)) return 91;
    struct itimerval timer = {{0, 0}, {0, 20000}};
    if (setitimer(ITIMER_REAL, &timer, 0)) return 92;
    execv(argv[1], argv + 1);
    return 93;
}
