/* Only preloaded by the N7 runtime publication fixture, which has no persistent
 * selection record to renew. Any attempted fsync must fail the named parent test. */
#include <unistd.h>
static int unexpected_fsync(int fd) { (void)fd; _exit(93); }
#ifdef __APPLE__
__attribute__((used)) static struct { const void *replacement, *replacee; }
interposed __attribute__((section("__DATA,__interpose"))) = {
    (const void *)&unexpected_fsync, (const void *)&fsync
};
#else
int fsync(int fd) { return unexpected_fsync(fd); }
#endif
