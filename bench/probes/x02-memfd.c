#define _GNU_SOURCE
/* Experiment only; no product executor/resolver. UAPI semantics:
 * https://man7.org/linux/man-pages/man2/execveat.2.html
 * https://github.com/torvalds/linux/blob/master/Documentation/userspace-api/mfd_noexec.rst */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/memfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#ifndef MFD_NOEXEC_SEAL
#define MFD_NOEXEC_SEAL 0x0008U
#endif
#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "assertion: %s errno=%d\n", #x, errno); exit(90); } } while (0)
static int fallback_errno;
static int copy_allowed(size_t size) { return size <= 65536; }
static int retry_without_noexec(int error) { return error == EINVAL; }
static int script_fd(const char *bytes, size_t size) {
    if (!copy_allowed(size)) { errno = EFBIG; return -1; }
    int fd = syscall(SYS_memfd_create, "x02-script", MFD_ALLOW_SEALING | MFD_CLOEXEC | MFD_NOEXEC_SEAL);
    if (fd < 0) {
        int error = errno;
        if (!retry_without_noexec(error)) return -1;
        fallback_errno = error;
        fd = syscall(SYS_memfd_create, "x02-script", MFD_ALLOW_SEALING | MFD_CLOEXEC);
    }
    REQUIRE(fd >= 0 && write(fd, bytes, size) == (ssize_t)size);
    int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    REQUIRE(fcntl(fd, F_ADD_SEALS, seals) == 0);
    REQUIRE((fcntl(fd, F_GET_SEALS) & seals) == seals);
    errno = 0; REQUIRE(pwrite(fd, "x", 1, 0) == -1 && errno == EPERM);
    errno = 0; REQUIRE(ftruncate(fd, size + 1) == -1 && errno == EPERM);
    errno = 0; REQUIRE(ftruncate(fd, 0) == -1 && errno == EPERM);
    int result = fcntl(fd, F_DUPFD_CLOEXEC, 10);
    REQUIRE(result >= 10 && close(fd) == 0);
    return result;
}
static int native(int fd) {
    unsigned char magic[4]; struct stat s;
    return fstat(fd, &s) == 0 && S_ISREG(s.st_mode) && s.st_uid == 0 &&
        !(s.st_mode & 0022) && (s.st_mode & 0111) &&
        pread(fd, magic, 4, 0) == 4 && !memcmp(magic, "\177ELF", 4);
}
static int link_target_allowed(const char *target, int trusted_system_chain) {
    return *target && (target[0] == '/' || trusted_system_chain);
}
/* Walk pinned directory fds. Read system symlinks through their O_PATH fd,
 * never by a second path lookup. Relative system links stay beneath root;
 * '..' is deliberately refused. Every component must be root owned. */
/* Fixture injection happens after pinning a symlink, inside the real walk. */
static const char *replace_from, *replace_to;
static int walk(const char *path, int *links, int root, uid_t owner, int trusted) {
    if (path[0] != '/') return -1;
    char todo[PATH_MAX]; if (strlen(path) >= sizeof(todo)) return -1;
    strcpy(todo, path + 1);
    int dir = root < 0 ? open("/", O_PATH | O_DIRECTORY | O_CLOEXEC) : fcntl(root, F_DUPFD_CLOEXEC, 3); REQUIRE(dir >= 0);
    for (int steps = 0; steps < 64; ++steps) {
        char *slash = strchr(todo, '/');
        char rest[PATH_MAX] = "";
        if (slash) { strcpy(rest, slash + 1); *slash = 0; }
        if (!*todo || !strcmp(todo, ".") || !strcmp(todo, "..")) break;
        int fd = openat(dir, todo, O_PATH | O_NOFOLLOW | O_CLOEXEC);
        struct stat s;
        if (fd < 0) break;
        if (fstat(fd, &s) || s.st_uid != owner || (!S_ISLNK(s.st_mode) && (s.st_mode & 0022))) { close(fd); break; }
        if (S_ISLNK(s.st_mode)) {
            char target[PATH_MAX], joined[PATH_MAX];
            ssize_t n = readlinkat(fd, "", target, sizeof(target) - 1);
            if (replace_from) {
                REQUIRE(rename(replace_from, replace_to) == 0);
                replace_from = NULL;
            }
            struct stat current;
            int unchanged = fstatat(dir, todo, &current, AT_SYMLINK_NOFOLLOW) == 0 &&
                current.st_dev == s.st_dev && current.st_ino == s.st_ino;
            close(fd); if (n <= 0 || !unchanged) break;
            target[n] = 0; ++*links;
            if (!link_target_allowed(target, trusted)) break;
            if (snprintf(joined, sizeof(joined), "%s%s%s", target, *rest ? "/" : "", rest) >= (int)sizeof(joined)) break;
            if (target[0] == '/') { owner = 0; trusted = 1; close(dir); dir = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC); REQUIRE(dir >= 0); }
            strcpy(todo, joined + (joined[0] == '/')); continue;
        }
        if (*rest) {
            if (!S_ISDIR(s.st_mode)) { close(fd); break; }
            close(dir); dir = fd; strcpy(todo, rest); continue;
        }
        /* Reopen the pinned inode, then compare identity and ELF bytes. */
        char proc[64]; snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
        int rd = open(proc, O_RDONLY | O_CLOEXEC); struct stat after;
        int good = rd >= 0 && fstat(rd, &after) == 0 && after.st_dev == s.st_dev && after.st_ino == s.st_ino && native(rd);
        close(fd); close(dir);
        if (!good) { if (rd >= 0) close(rd); return -1; }
        return rd;
    }
    close(dir); return -1;
}
static int interpreter_at(const char *path, int root, uid_t owner, int trusted) {
    if (path[0] != '/' || !strcmp(path, "/usr/bin/env") || !strcmp(path, "/bin/env")) return -1;
    int links = 0;
    struct stat s;
    if (root >= 0 && (fstat(root, &s) || s.st_uid != owner || (s.st_mode & 0022))) return -1;
    return walk(path, &links, root, owner, trusted);
}
static int interpreter(const char *path) { return interpreter_at(path, -1, 0, 1); }
static int proc_readable(int fd, const char *base) {
    char path[PATH_MAX]; struct stat before, after;
    if (snprintf(path, sizeof(path), "%s/%d", base, fd) >= (int)sizeof(path)) return 0;
    int copy = open(path, O_RDONLY | O_CLOEXEC);
    if (copy < 0) return 0;
    int good = fstat(fd, &before) == 0 && fstat(copy, &after) == 0 &&
        before.st_dev == after.st_dev && before.st_ino == after.st_ino;
    close(copy); return good;
}
struct result { int exit_code, exec_errno, canaries, leaks, high_fd, soft_limit; };
static int leave_high_fd, high_fd;
/* Enumerate the open set, including descriptors above a lowered soft limit. */
static void close_unlisted(int script, int executable, int errors) {
    DIR *fds = opendir("/proc/self/fd"); REQUIRE(fds != NULL);
    struct dirent *entry;
    while ((entry = readdir(fds))) {
        char *end; long fd = strtol(entry->d_name, &end, 10);
        if (*end || fd < 3 || fd == dirfd(fds) || fd == script || fd == executable || fd == errors) continue;
        if (leave_high_fd && fd == high_fd) continue;
        REQUIRE(close((int)fd) == 0);
    }
    REQUIRE(closedir(fds) == 0);
}
static struct result execute(int interpreter, int script, int clear, int direct) {
    int out[2], errors[2]; REQUIRE(pipe2(out, O_CLOEXEC) == 0 && pipe2(errors, O_CLOEXEC) == 0);
    struct rlimit limits; REQUIRE(getrlimit(RLIMIT_NOFILE, &limits) == 0);
    /* Leave room for fixed fds 100/101 and an fd above the child limit.
     * A low starting soft limit may be raised within the existing hard limit. */
    if (limits.rlim_cur < 104) {
        limits.rlim_cur = limits.rlim_max;
        REQUIRE(setrlimit(RLIMIT_NOFILE, &limits) == 0);
    }
    REQUIRE(limits.rlim_cur >= 104);
    int soft_limit = limits.rlim_cur > 257 ? 256 : (int)limits.rlim_cur - 2;
    /* F_DUPFD picks an unused, inheritable fd within the current limit. */
    high_fd = fcntl(interpreter, F_DUPFD, soft_limit + 1);
    REQUIRE(high_fd > soft_limit);
    pid_t pid = fork(); REQUIRE(pid >= 0);
    if (!pid) {
        REQUIRE(dup2(out[1], 1) == 1);
        int null = open("/dev/null", O_WRONLY | O_CLOEXEC); REQUIRE(null >= 0 && dup2(null, 2) == 2);
        REQUIRE(dup3(interpreter, 100, O_CLOEXEC) == 100);
        /* An unrelated deliberately inheritable fd must be explicitly closed. */
        REQUIRE(dup2(interpreter, 101) == 101);
        limits.rlim_cur = soft_limit; REQUIRE(setrlimit(RLIMIT_NOFILE, &limits) == 0);
        close_unlisted(script, 100, errors[1]);
        if (clear && script >= 0) REQUIRE(fcntl(script, F_SETFD, 0) == 0);
        char path[64]; snprintf(path, sizeof(path), "/proc/self/fd/%d", script);
        char *args[] = {"x02-interpreter", direct ? "-c" : path, direct ? "printf 'CANARY\\n'" : NULL, NULL};
        char *env[] = {NULL};
        syscall(SYS_execveat, 100, "", args, env, AT_EMPTY_PATH);
        int error = errno; _exit(write(errors[1], &error, sizeof(error)) == (ssize_t)sizeof(error) ? 120 : 121);
    }
    REQUIRE(close(high_fd) == 0);
    REQUIRE(close(out[1]) == 0 && close(errors[1]) == 0);
    char output[256]; ssize_t n = 0, got;
    while ((got = read(out[0], output + n, sizeof(output) - 1 - n)) > 0) {
        n += got; REQUIRE(n < (ssize_t)sizeof(output) - 1);
    }
    REQUIRE(got == 0);
    struct result r = {0, 0, 0, -1, high_fd, soft_limit};
    ssize_t e = read(errors[0], &r.exec_errno, sizeof(r.exec_errno)); REQUIRE(e == 0 || e == sizeof(int));
    REQUIRE(close(out[0]) == 0 && close(errors[0]) == 0);
    int status; REQUIRE(waitpid(pid, &status, 0) == pid && WIFEXITED(status)); r.exit_code = WEXITSTATUS(status);
    if (n == 7 && !memcmp(output, "CANARY\n", 7)) r.canaries = 1;
    else if (n > 0) {
        REQUIRE(n < (ssize_t)sizeof(output)); output[n] = 0;
        int used = 0;
        REQUIRE(sscanf(output, "CANARY\nLEAKS:%d\n%n", &r.leaks, &used) == 1 && used == n && r.leaks >= 0);
        r.canaries = 1;
    }
    return r;
}
static void handoff(const char *cell, int interp, const char *script, int mutate) {
    REQUIRE(native(interp) && (fcntl(interp, F_GETFD) & FD_CLOEXEC));
    int fd = script_fd(script, strlen(script)); REQUIRE(fd >= 0);
    REQUIRE(proc_readable(fd, "/proc/self/fd"));
    REQUIRE(!proc_readable(fd, "/proc/x02-unavailable/fd"));
    struct stat mode; REQUIRE(fstat(fd, &mode) == 0);
    if (!fallback_errno) REQUIRE(!(mode.st_mode & 0111));
    int noexec_errno = 0;
    if (!fallback_errno) {
        struct result denied = execute(fd, -1, 0, 1);
        REQUIRE(denied.exec_errno == EACCES && denied.exit_code == 120 && denied.canaries == 0);
        noexec_errno = denied.exec_errno;
    }
    struct result closed = execute(interp, fd, 0, 0), open = execute(interp, fd, 1, 0);
    REQUIRE(closed.exit_code != 0 && closed.exec_errno == 0 && closed.canaries == 0);
    /* 이것을 실패시키는 것: script fd의 CLOEXEC를 끄지 않거나 canary를 두 번 실행하는 것. */
    REQUIRE(fcntl(fd, F_GETFD) & FD_CLOEXEC); /* parent flags unchanged */
    printf("{\"cell\":\"%s\",\"evidence\":{\"closed_exit\":%d,\"closed_canary\":0,\"open_exit\":0,\"open_canary\":1,\"exec_errno\":0,\"leaks\":%d,\"high_fd\":%d,\"soft_limit\":%d,\"seals\":%d,\"fallback_errno\":%d,\"noexec_errno\":%d}}\n", cell, closed.exit_code, open.leaks, open.high_fd, open.soft_limit, fcntl(fd, F_GET_SEALS), fallback_errno, noexec_errno);
    REQUIRE(open.exit_code == 0 && open.exec_errno == 0 && open.canaries == (mutate ? 2 : 1) && open.leaks == 0);
    REQUIRE(close(fd) == 0);
}
int main(int argc, char **argv) {
    /* Start from the worker's known fd set before creating fixture descriptors.
     * Harness capture files/pipes must not become part of the leak fixture. */
    close_unlisted(-1, -1, -1);
    REQUIRE(argc == 1 || argc == 2);
    int mutate = argc == 2 && !strcmp(argv[1], "--mutate-expectation");
    leave_high_fd = argc == 2 && !strcmp(argv[1], "--mutate-fd-close");
    int python_leak = argc == 2 && !strcmp(argv[1], "--mutate-python-fd-close");
    REQUIRE(argc == 1 || mutate || leave_high_fd || python_leak);
    int bash = interpreter("/bin/bash"), python = interpreter("/usr/bin/python3");
    REQUIRE(bash >= 0 && python >= 0);
    /* Bash's private script input fd is not always 255 under low RLIMIT_NOFILE.
     * Exempt the script inode, never the deliberately leaked interpreter fd. */
    const char *sh = "leaks=0; script=${BASH_SOURCE[0]##*/}\n"
        "for f in /proc/$$/fd/*; do n=${f##*/}; case $n in 0|1|2) continue;; esac\n"
        "test \"$n\" = \"$script\" && continue\n"
        "if test \"$f\" -ef \"/proc/$$/fd/$script\"; then continue; fi\n"
        "test -L \"$f\" && leaks=$((leaks+1)); done\nprintf 'CANARY\\nLEAKS:%d\\n' \"$leaks\"\n";
    const char *py = "import os\nscript=int(__file__.rsplit('/',1)[1])\nleaks=0\n"
        "for name in os.listdir('/proc/self/fd'):\n fd=int(name)\n"
        " if fd in (0,1,2,script): continue\n"
        " try: os.fstat(fd)\n except OSError: continue\n leaks+=1\n"
        "print('CANARY\\nLEAKS:%d' % leaks)\n";
    handoff("bash_handoff", bash, sh, mutate);
    leave_high_fd = python_leak;
    handoff("python_handoff", python, py, 0);
    struct result rd = execute(bash, -1, 0, 1); REQUIRE(rd.exit_code == 0 && rd.canaries == 1 && rd.exec_errno == 0);
    int opath = open("/bin/bash", O_PATH | O_CLOEXEC); REQUIRE(opath >= 0);
    char byte; errno = 0; REQUIRE(read(opath, &byte, 1) == -1 && errno == EBADF);
    struct result op = execute(opath, -1, 0, 1); REQUIRE(op.exit_code == 0 && op.canaries == 1 && op.exec_errno == 0);
    puts("{\"cell\":\"native_modes\",\"evidence\":{\"rdonly_exit\":0,\"opath_exit\":0,\"opath_read_errno\":9,\"canaries\":2}}");
    /* Disk-backed shebang boundary remains executable even with memfd_noexec=2. */
    char name[] = "/tmp/x02-shebang-XXXXXX";
    int temp = mkstemp(name); REQUIRE(temp >= 0);
    const char *shebang = "#!/bin/bash\nprintf 'CANARY\\n'\n";
    REQUIRE(write(temp, shebang, strlen(shebang)) == (ssize_t)strlen(shebang) && fchmod(temp, 0700) == 0 && close(temp) == 0);
    int script = open(name, O_RDONLY | O_CLOEXEC); REQUIRE(script >= 0 && unlink(name) == 0);
    struct result boundary = execute(script, -1, 0, 1);
    REQUIRE(boundary.exec_errno == ENOENT && boundary.exit_code == 120 && boundary.canaries == 0);
    REQUIRE(!native(script)); /* nested shebang cannot be a native interpreter */
    puts("{\"cell\":\"shebang_boundary\",\"evidence\":{\"exec_errno\":2,\"canary\":0,\"nested_rejected\":1}}");
    char *large = malloc(65537); REQUIRE(large != NULL); memset(large, '#', 65537);
    int limit = script_fd(large, 65536); REQUIRE(limit >= 0 && close(limit) == 0);
    errno = 0; REQUIRE(script_fd(large, 65537) == -1 && errno == EFBIG); free(large);
    REQUIRE(retry_without_noexec(EINVAL) && !retry_without_noexec(EPERM) && !retry_without_noexec(ENOSYS));
    printf("{\"cell\":\"size_and_noexec\",\"evidence\":{\"accepted_bytes\":65536,\"rejected_bytes\":65537,\"fallback_errno\":%d,\"other_errno_rejected\":1}}\n", fallback_errno);
    int walk_links = 0, shell = walk("/bin/sh", &walk_links, -1, 0, 1); REQUIRE(shell >= 0);
    struct stat bin_link, bin_dir, usr_bin;
    REQUIRE(lstat("/bin", &bin_link) == 0 && S_ISLNK(bin_link.st_mode));
    REQUIRE(stat("/bin", &bin_dir) == 0 && stat("/usr/bin", &usr_bin) == 0 &&
            bin_dir.st_dev == usr_bin.st_dev && bin_dir.st_ino == usr_bin.st_ino);
    struct result merged = execute(shell, -1, 0, 1); REQUIRE(merged.exit_code == 0 && merged.canaries == 1);
    printf("{\"cell\":\"system_walk\",\"evidence\":{\"links\":%d,\"merged_usr\":1,\"native\":1,\"exit\":0,\"canary\":1}}\n", walk_links);
    int ignored = 0;
    REQUIRE(walk("bin/sh", &ignored, -1, 0, 1) == -1 && walk("/usr/bin/env/../sh", &ignored, -1, 0, 1) == -1);
    REQUIRE(interpreter("/usr/bin/env") == -1 && interpreter("bin/bash") == -1);
    char fixture[] = "/tmp/x02-links-XXXXXX"; REQUIRE(mkdtemp(fixture) != NULL);
    char link[PATH_MAX], replacement[PATH_MAX];
    REQUIRE(snprintf(link, sizeof(link), "%s/link", fixture) < (int)sizeof(link));
    REQUIRE(snprintf(replacement, sizeof(replacement), "%s/replacement", fixture) < (int)sizeof(replacement));
    REQUIRE(symlink("/bin/bash", link) == 0);
    /* Pin a fixture root so /tmp permissions cannot reject every fixture first.
     * The same resolver checks its owner/mode; absolute targets rejoin system /. */
    int root = open(fixture, O_PATH | O_DIRECTORY | O_CLOEXEC); REQUIRE(root >= 0);
    int control = interpreter_at("/link", root, getuid(), 0); REQUIRE(control >= 0 && close(control) == 0);
    REQUIRE(symlink("/bin/sh", replacement) == 0);
    replace_from = replacement; replace_to = link;
    REQUIRE(interpreter_at("/link", root, getuid(), 0) == -1 && replace_from == NULL);
    REQUIRE(unlink(link) == 0 && symlink("bin/bash", link) == 0);
    /* A valid relative target: refusal must come from link policy, not ENOENT. */
    char bin[PATH_MAX]; REQUIRE(snprintf(bin, sizeof(bin), "%s/bin", fixture) < (int)sizeof(bin));
    REQUIRE(symlink("/bin", bin) == 0);
    REQUIRE(interpreter_at("/link", root, getuid(), 0) == -1);
    control = interpreter_at("/link", root, getuid(), 1); REQUIRE(control >= 0 && close(control) == 0);
    REQUIRE(unlink(link) == 0 && symlink("/bin/bash", link) == 0);
    control = interpreter_at("/link", root, getuid(), 0); REQUIRE(control >= 0 && close(control) == 0);
    REQUIRE(chmod(fixture, 0777) == 0 && interpreter_at("/link", root, getuid(), 0) == -1);
    REQUIRE(close(root) == 0 && unlink(bin) == 0 && unlink(link) == 0 && rmdir(fixture) == 0);
    puts("{\"cell\":\"refusals\",\"evidence\":{\"relative\":1,\"relative_link\":1,\"env\":1,\"proc_missing\":1,\"replaced_link\":1,\"writable_chain\":1,\"writable_control\":1,\"relative_control\":1,\"replacement_control\":1}}");
    REQUIRE(close(shell) == 0 && close(script) == 0 && close(opath) == 0 && close(bash) == 0 && close(python) == 0);
    return 0;
}
