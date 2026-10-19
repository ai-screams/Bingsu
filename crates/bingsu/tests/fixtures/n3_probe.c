/* Test-only executable for the fixed spawn protocols. Never installed. */
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    int collect = argc == 2 && !strcmp(argv[1], "__collect-v1");
    if (!collect && (argc < 2 || strcmp(argv[1], "__refresh-v1"))) return 9;
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit)) return 10;
    int count = 0, unexpected = 0;
    /* The parent fixture opens fd 1025, then may lower BOTH limits to 32.
     * Scanning only the inherited limit would miss precisely that leak. */
    unsigned long scan = limit.rlim_cur < 2048 ? 2048 : limit.rlim_cur;
    for (unsigned long fd = 0; fd < scan; fd++) {
        if (fcntl((int)fd, F_GETFD) >= 0) {
            count++;
            if (fd >= (collect ? 6 : 3)) unexpected++;
        }
    }
    char path[8192] = {0}; int slow = 0;
    for (int i = 2; i < argc; i++) {
        if (!strncmp(argv[i], "--home=", 7)) snprintf(path, sizeof(path), "%s/probe", argv[i]+7);
        if (!strcmp(argv[i], "--log-level=info")) slow = 1;
    }
    int mode = collect ? (fcntl(3, F_GETFL) & O_ACCMODE) : 0;
    struct sigaction action; sigaction(SIGCHLD, NULL, &action);
    sigset_t mask; sigprocmask(SIG_SETMASK, NULL, &mask);
    int signal_ok = action.sa_handler == SIG_DFL && !sigismember(&mask, SIGTERM);
    int environment_ok = getenv("BINGSU_ATTACK") == NULL;
    struct stat request_stat = {0}; if (collect) fstat(3, &request_stat);
    int out = collect ? openat(4,"probe",O_WRONLY|O_CREAT|O_TRUNC,0600) : open(path,O_WRONLY|O_CREAT|O_TRUNC,0600);
    if (out < 0) return 11;
    dprintf(out,"%d %d %d %d %d %d %d\n",count,unexpected,mode,signal_ok,environment_ok,(int)getpid(),(int)request_stat.st_nlink); close(out);
    if (slow || collect) sleep(2);
    return 0;
}
