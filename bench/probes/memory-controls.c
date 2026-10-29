/* Control processes for the whole-prompt RSS measurer (Linux). Each mode has a
 * known peak: the process allocates and touches its memory, then marks the
 * peak with raise(SIGSTOP). prompt-memtrace observes the mark, reads
 * /proc/<pid>/smaps_rollup from outside while the process is stopped, and
 * suppresses the signal. Parents reap their children, as the prompt tree does.
 * Without a tracer the marks are skipped, so a stray run never stops.
 *
 * modes: small | anon64 | file64 PATH | shared64 | bigparent-spawn |
 *        tree3 | mid | leaf | cached-exec */
#define _GNU_SOURCE
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
#define MiB (1024L * 1024L)

static long field_kb(const char *path, const char *key) {
  char line[256]; FILE *f = fopen(path, "r"); if (!f) return -1; long v = -1; size_t n = strlen(key);
  while (fgets(line, sizeof line, f)) if (!strncmp(line, key, n) && line[n] == ':') { v = atol(line + n + 1); break; }
  fclose(f); return v;
}
static void mark(const char *tag) {
  printf("MARK %s pid=%d rss_kb=%ld\n", tag, getpid(), field_kb("/proc/self/smaps_rollup", "Rss"));
  fflush(stdout);
  if (field_kb("/proc/self/status", "TracerPid") > 0) raise(SIGSTOP);
}
static void touch(volatile char *p, long n) { for (long i = 0; i < n; i += 4096) p[i] = 1; }
static char *anon(long n) {
  char *p = mmap(0, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) exit(3);
  touch(p, n); return p;
}
static int spawn_wait(const char *self, const char *mode) {
  char *cargv[] = { (char *)self, (char *)mode, 0 }; pid_t c;
  if (posix_spawn(&c, self, 0, 0, cargv, environ)) return 6;
  int st; if (waitpid(c, &st, 0) != c) return 7;
  return WIFEXITED(st) ? WEXITSTATUS(st) : 8;
}
/* Page-cache residency of this process's own executable and libc mappings. */
static int cached_exec(void) {
  FILE *f = fopen("/proc/self/maps", "r"); if (!f) return 4;
  char line[512]; long resident = 0, total = 0; long page = sysconf(_SC_PAGESIZE);
  unsigned char *vec = malloc(1 << 20);
  while (fgets(line, sizeof line, f)) {
    unsigned long lo, hi; char path[256] = "";
    if (sscanf(line, "%lx-%lx %*s %*s %*s %*s %255s", &lo, &hi, path) < 2 || path[0] != '/') continue;
    if (!strstr(path, "memory-controls") && !strstr(path, "libc.so")) continue;
    long n = (long)(hi - lo) / page; if (n > (1 << 20)) continue;
    if (mincore((void *)lo, hi - lo, vec)) continue;
    for (long i = 0; i < n; i++) resident += vec[i] & 1;
    total += n;
  }
  fclose(f);
  printf("RESIDENT pages=%ld total=%ld\n", resident, total); fflush(stdout);
  mark("cached-exec");
  return 0;
}

int main(int argc, char **argv) {
  const char *m = argc > 1 ? argv[1] : "small";
  if (!strcmp(m, "small")) { mark("small"); return 0; }
  if (!strcmp(m, "anon64")) { anon(64 * MiB); mark("anon64"); return 0; }
  if (!strcmp(m, "file64")) {
    if (argc < 3) return 2;
    int fd = open(argv[2], O_RDONLY); if (fd < 0) return 4;
    volatile char *p = mmap(0, 64 * MiB, PROT_READ, MAP_PRIVATE, fd, 0); if (p == MAP_FAILED) return 5;
    long s = 0; for (long i = 0; i < 64 * MiB; i += 4096) s += p[i];
    mark("file64");
    return (int)(s & 0);
  }
  if (!strcmp(m, "shared64")) {
    char *p = mmap(0, 64 * MiB, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0); if (p == MAP_FAILED) return 3;
    touch(p, 64 * MiB); mark("shared64-parent");
    pid_t c = fork();
    if (c == 0) { volatile long s = 0; for (long i = 0; i < 64 * MiB; i += 4096) s += p[i]; mark("shared64-child"); _exit(0); }
    int st; return waitpid(c, &st, 0) == c ? 0 : 7;
  }
  if (!strcmp(m, "bigparent-spawn")) { anon(256 * MiB); mark("bigparent"); return spawn_wait(argv[0], "small"); }
  if (!strcmp(m, "tree3")) { anon(8 * MiB); mark("tree3-root"); return spawn_wait(argv[0], "mid"); }
  if (!strcmp(m, "mid")) { anon(16 * MiB); mark("tree3-mid"); return spawn_wait(argv[0], "leaf"); }
  if (!strcmp(m, "leaf")) { anon(32 * MiB); mark("tree3-leaf"); return 0; }
  if (!strcmp(m, "cached-exec")) return cached_exec();
  return 2;
}
