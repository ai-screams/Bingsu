/* Test-only blocked NSS provider; not linked into the installed binary. */
#include <fcntl.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>
static int stalled_passwd(uid_t uid, struct passwd *pw, char *buf, size_t size,
                          struct passwd **result) {
    (void)uid; (void)pw; (void)buf; (void)size; (void)result;
    const char *path = getenv("N7_NSS_READY");
    if (!path) _exit(90);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0 || write(fd, "entered\n", 8) != 8) _exit(91);
    close(fd);
    for (;;) pause();
}
#ifdef __APPLE__
__attribute__((used)) static struct { const void *replacement, *replacee; }
interposed __attribute__((section("__DATA,__interpose"))) = {
    (const void *)&stalled_passwd, (const void *)&getpwuid_r
};
#else
int getpwuid_r(uid_t uid, struct passwd *pw, char *buf, size_t size, struct passwd **result) {
    return stalled_passwd(uid, pw, buf, size, result);
}
#endif
