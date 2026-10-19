/* K82 test-only model of an ancestor procfs mount: libc's visible PID is
 * deliberately not the numeric name returned by the mount's self link.
 * No proc path, fd metadata, boot identity or namespace link is intercepted. */
#include <limits.h>
#include <sys/types.h>
#include <unistd.h>

pid_t getpid(void) { return INT_MAX; }
