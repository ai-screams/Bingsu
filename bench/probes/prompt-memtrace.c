/* Whole-prompt RSS tracer (Linux): runs one command under ptrace and follows
 * every descendant through fork, vfork, clone and exec. Each task's terminal
 * wait4 rusage (ru_maxrss, the kernel's signal->maxrss/cmaxrss) is the
 * measured value; the tracer reaps every tracee first, whoever its parent is.
 * The same event stream is the process list the measurer cross-checks.
 *
 * Independent reference points come from /proc/<pid>/smaps_rollup, a page
 * table walk that does not read the rss_stat counters, taken while the task is
 * stopped: a new child's first stop (for a vfork child, the shared pre-exec
 * address space), the exec stop, every SIGSTOP the task sends itself (control
 * peak marks, suppressed afterwards) and the exit stop.
 *
 * usage: prompt-memtrace OUT.jsonl TIMEOUT_MS cmd...
 * Exit: the command's status; 3 when the timeout killed the tree. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAXT 4096
struct task { int used, pid, started; };
static struct task T[MAXT];
static FILE *out;
static long seq;

static volatile sig_atomic_t expired;
static void on_alarm(int sig) { (void)sig; expired = 1; }
static long now_ns(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec * 1000000000L + ts.tv_nsec; }

static struct task *find(int pid, int create) {
  for (int i = 0; i < MAXT; i++) if (T[i].used && T[i].pid == pid) return &T[i];
  if (!create) return 0;
  for (int i = 0; i < MAXT; i++) if (!T[i].used) { T[i].used = 1; T[i].pid = pid; T[i].started = 0; return &T[i]; }
  return 0;
}
static int live(void) { int n = 0; for (int i = 0; i < MAXT; i++) n += T[i].used; return n; }

static long field_kb(const char *path, const char *key) {
  char line[256]; FILE *f = fopen(path, "r"); if (!f) return -1; long v = -1; size_t n = strlen(key);
  while (fgets(line, sizeof line, f)) if (!strncmp(line, key, n) && line[n] == ':') { v = atol(line + n + 1); break; }
  fclose(f); return v;
}
static long status_kb(int pid, const char *key) { char p[64]; snprintf(p, sizeof p, "/proc/%d/status", pid); return field_kb(p, key); }
static long rollup_kb(int pid, const char *key) { char p[64]; snprintf(p, sizeof p, "/proc/%d/smaps_rollup", pid); return field_kb(p, key); }

static void json_str(const char *s, size_t n) {
  fputc('"', out);
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c == '"' || c == '\\') fprintf(out, "\\%c", c);
    else if (c < 32 || c > 126) fprintf(out, "\\u%04x", c);
    else fputc(c, out);
  }
  fputc('"', out);
}
static void argv_json(int pid) {
  char path[64], buf[1024]; snprintf(path, sizeof path, "/proc/%d/cmdline", pid);
  FILE *f = fopen(path, "r"); size_t n = 0; if (f) { n = fread(buf, 1, sizeof buf, f); fclose(f); }
  fputc('[', out);
  size_t start = 0; int words = 0;
  for (size_t i = 0; i < n && words < 4; i++) if (!buf[i]) { if (words++) fputc(',', out); json_str(buf + start, i - start); start = i + 1; }
  fputc(']', out);
}
static void exe_json(int pid) {
  char path[64], buf[512]; snprintf(path, sizeof path, "/proc/%d/exe", pid);
  ssize_t n = readlink(path, buf, sizeof buf); json_str(buf, n < 0 ? 0 : (size_t)n);
}
static void head(const char *ev, int pid) { fprintf(out, "{\"seq\":%ld,\"t_ns\":%ld,\"ev\":\"%s\",\"pid\":%d", seq++, now_ns(), ev, pid); }
/* A reference point: page-table Rss plus the fields the obligation checks read. */
static void refpoint(const char *ev, int pid) {
  head(ev, pid);
  fprintf(out, ",\"tgid\":%ld,\"threads\":%ld,\"rollup_rss_kb\":%ld,\"file_pmd_kb\":%ld,\"vmhwm_kb\":%ld,\"vmrss_kb\":%ld}\n",
          status_kb(pid, "Tgid"), status_kb(pid, "Threads"), rollup_kb(pid, "Rss"), rollup_kb(pid, "FilePmdMapped"),
          status_kb(pid, "VmHWM"), status_kb(pid, "VmRSS"));
}

int main(int argc, char **argv) {
  if (argc < 4) { fprintf(stderr, "usage: prompt-memtrace OUT.jsonl TIMEOUT_MS cmd...\n"); return 2; }
  out = fopen(argv[1], "w"); if (!out) return 2;
  long timeout_ms = atol(argv[2]);
  pid_t child = fork();
  if (child < 0) return 2;
  if (child == 0) { ptrace(PTRACE_TRACEME, 0, 0, 0); raise(SIGSTOP); execvp(argv[3], argv + 3); _exit(127); }
  int st; if (waitpid(child, &st, __WALL) != child || !WIFSTOPPED(st)) return 2;
  long opts = PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT | PTRACE_O_EXITKILL;
  if (ptrace(PTRACE_SETOPTIONS, child, 0, opts)) return 2;
  struct task *root = find(child, 1); root->started = 1;
  head("root", child); fprintf(out, ",\"tracer\":%d}\n", getpid());
  /* No SA_RESTART: the alarm interrupts a blocking wait4 at the deadline. */
  struct sigaction sa; memset(&sa, 0, sizeof sa); sa.sa_handler = on_alarm; sigaction(SIGALRM, &sa, 0);
  struct itimerval it = {{0, 0}, {timeout_ms / 1000, (timeout_ms % 1000) * 1000}}; setitimer(ITIMER_REAL, &it, 0);
  ptrace(PTRACE_CONT, child, 0, 0);
  int root_rc = -1, timed_out = 0;
  for (;;) {
    if (!timed_out && expired) {
      timed_out = 1;
      for (int i = 0; i < MAXT; i++) if (T[i].used) kill(T[i].pid, SIGKILL);
    }
    struct rusage ru; memset(&ru, 0, sizeof ru);
    pid_t pid = wait4(-1, &st, __WALL, &ru);
    if (pid < 0) { if (errno == EINTR) continue; break; }
    if (WIFEXITED(st) || WIFSIGNALED(st)) {
      head("reaped", pid);
      fprintf(out, ",\"maxrss_kb\":%ld,\"exited\":%d,\"code\":%d,\"signal\":%d}\n", ru.ru_maxrss,
              WIFEXITED(st), WIFEXITED(st) ? WEXITSTATUS(st) : -1, WIFSIGNALED(st) ? WTERMSIG(st) : 0);
      if (pid == child) root_rc = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
      struct task *t = find(pid, 0); if (t) t->used = 0;
      continue;
    }
    if (!WIFSTOPPED(st)) continue;
    struct task *t = find(pid, 1);
    if (!t) { head("overflow", pid); fputs("}\n", out); ptrace(PTRACE_CONT, pid, 0, 0); continue; }
    int sig = WSTOPSIG(st), ev = st >> 16, inject = 0;
    if (ev == PTRACE_EVENT_FORK || ev == PTRACE_EVENT_VFORK || ev == PTRACE_EVENT_CLONE) {
      unsigned long np = 0; ptrace(PTRACE_GETEVENTMSG, pid, 0, &np);
      find((int)np, 1);
      head("spawn", pid);
      fprintf(out, ",\"child\":%lu,\"kind\":\"%s\",\"parent_tgid\":%ld,\"parent_threads\":%ld}\n", np,
              ev == PTRACE_EVENT_FORK ? "fork" : ev == PTRACE_EVENT_VFORK ? "vfork" : "clone",
              status_kb(pid, "Tgid"), status_kb(pid, "Threads"));
    } else if (ev == PTRACE_EVENT_EXEC) {
      unsigned long former = 0; ptrace(PTRACE_GETEVENTMSG, pid, 0, &former);
      head("exec", pid); fprintf(out, ",\"former\":%lu,\"exe\":", former); exe_json(pid); fputs(",\"argv\":", out); argv_json(pid); fputs("}\n", out);
      refpoint("exec_ref", pid);
    } else if (ev == PTRACE_EVENT_EXIT) {
      refpoint("exit_ref", pid);
    } else if (ev == 0 && sig == SIGSTOP) {
      /* A new task's first stop, or a control's self-sent peak mark. Both are
       * observed and suppressed; the task never enters a group stop. */
      refpoint(t->started ? "mark_ref" : "start_ref", pid);
      t->started = 1;
    } else if (ev == 0 && sig != SIGTRAP) {
      inject = sig;
    }
    t->started = 1;
    ptrace(PTRACE_CONT, pid, 0, inject);
  }
  head("end", getpid());
  fprintf(out, ",\"timed_out\":%d,\"live\":%d,\"errno\":%d}\n", timed_out, live(), errno);
  fclose(out);
  return timed_out ? 3 : root_rc;
}
