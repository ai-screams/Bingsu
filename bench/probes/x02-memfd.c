#define _GNU_SOURCE
/* Experiment only; no product executor/resolver. UAPI semantics:
 * https://man7.org/linux/man-pages/man2/execveat.2.html
 * https://github.com/torvalds/linux/blob/master/Documentation/userspace-api/mfd_noexec.rst */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/memfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
static int walk(const char *path, int *links) {
    if (path[0] != '/') return -1;
    char todo[PATH_MAX]; if (strlen(path) >= sizeof(todo)) return -1;
    strcpy(todo, path + 1);
    int dir = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC); REQUIRE(dir >= 0);
    for (int steps = 0; steps < 64; ++steps) {
        char *slash = strchr(todo, '/');
        char rest[PATH_MAX] = "";
        if (slash) { strcpy(rest, slash + 1); *slash = 0; }
        if (!*todo || !strcmp(todo, ".") || !strcmp(todo, "..")) break;
        int fd = openat(dir, todo, O_PATH | O_NOFOLLOW | O_CLOEXEC);
        struct stat s;
        if (fd < 0) break;
        if (fstat(fd, &s) || s.st_uid != 0 || (!S_ISLNK(s.st_mode) && (s.st_mode & 0022))) { close(fd); break; }
        if (S_ISLNK(s.st_mode)) {
            char target[PATH_MAX], joined[PATH_MAX];
            ssize_t n = readlinkat(fd, "", target, sizeof(target) - 1);
            close(fd); if (n <= 0) break;
            target[n] = 0; ++*links;
            if (!link_target_allowed(target, 1)) break;
            if (snprintf(joined, sizeof(joined), "%s%s%s", target, *rest ? "/" : "", rest) >= (int)sizeof(joined)) break;
            if (target[0] == '/') { close(dir); dir = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC); REQUIRE(dir >= 0); }
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
static int interpreter(const char *path) {
    if (path[0] != '/' || !strcmp(path, "/usr/bin/env") || !strcmp(path, "/bin/env")) return -1;
    int links = 0; return walk(path, &links);
}
static int proc_readable(int fd, const char *base) {
    char path[PATH_MAX]; struct stat before, after;
    if (snprintf(path, sizeof(path), "%s/%d", base, fd) >= (int)sizeof(path)) return 0;
    int copy = open(path, O_RDONLY | O_CLOEXEC);
    if (copy < 0) return 0;
    int good = fstat(fd, &before) == 0 && fstat(copy, &after) == 0 &&
        before.st_dev == after.st_dev && before.st_ino == after.st_ino;
    close(copy); return good;
}
static int same_link(const char *path, const struct stat *before) {
    struct stat after;
    return lstat(path, &after) == 0 && S_ISLNK(after.st_mode) &&
        before->st_dev == after.st_dev && before->st_ino == after.st_ino;
}
struct result { int exit_code, exec_errno, canaries; };
static struct result execute(int interpreter, int script, int clear, int direct) {
    int out[2], errors[2]; REQUIRE(pipe2(out, O_CLOEXEC) == 0 && pipe2(errors, O_CLOEXEC) == 0);
    long bound = sysconf(_SC_OPEN_MAX); REQUIRE(bound > 102 && bound < 4000000);
    pid_t pid = fork(); REQUIRE(pid >= 0);
    if (!pid) {
        REQUIRE(dup2(out[1], 1) == 1);
        int null = open("/dev/null", O_WRONLY | O_CLOEXEC); REQUIRE(null >= 0 && dup2(null, 2) == 2);
        REQUIRE(dup3(interpreter, 100, O_CLOEXEC) == 100);
        /* An unrelated deliberately inheritable fd must be explicitly closed. */
        REQUIRE(dup2(interpreter, 101) == 101);
        for (int fd = 3; fd < bound; ++fd)
            if (fd != script && fd != 100 && fd != errors[1]) close(fd);
        if (clear && script >= 0) REQUIRE(fcntl(script, F_SETFD, 0) == 0);
        char path[64]; snprintf(path, sizeof(path), "/proc/self/fd/%d", script);
        char *args[] = {"x02-interpreter", direct ? "-c" : path, direct ? "printf 'CANARY\\n'" : NULL, NULL};
        char *env[] = {NULL};
        syscall(SYS_execveat, 100, "", args, env, AT_EMPTY_PATH);
        int error = errno; (void)write(errors[1], &error, sizeof(error)); _exit(120);
    }
    REQUIRE(close(out[1]) == 0 && close(errors[1]) == 0);
    char output[256]; ssize_t n = read(out[0], output, sizeof(output)); REQUIRE(n >= 0);
    struct result r = {0, 0, 0};
    ssize_t e = read(errors[0], &r.exec_errno, sizeof(r.exec_errno)); REQUIRE(e == 0 || e == sizeof(int));
    REQUIRE(close(out[0]) == 0 && close(errors[0]) == 0);
    int status; REQUIRE(waitpid(pid, &status, 0) == pid && WIFEXITED(status)); r.exit_code = WEXITSTATUS(status);
    if (n == 7 && !memcmp(output, "CANARY\n", 7)) r.canaries = 1;
    else REQUIRE(n == 0);
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
    REQUIRE(open.exit_code == 0 && open.exec_errno == 0 && open.canaries == (mutate ? 2 : 1));
    REQUIRE(fcntl(fd, F_GETFD) & FD_CLOEXEC); /* parent flags unchanged */
    printf("{\"cell\":\"%s\",\"evidence\":{\"closed_exit\":%d,\"closed_canary\":0,\"open_exit\":0,\"open_canary\":1,\"exec_errno\":0,\"leaks\":0,\"seals\":%d,\"fallback_errno\":%d,\"noexec_errno\":%d}}\n", cell, closed.exit_code, fcntl(fd, F_GET_SEALS), fallback_errno, noexec_errno);
    REQUIRE(close(fd) == 0);
}
int main(int argc, char **argv) {
    REQUIRE(argc == 1 || (argc == 2 && !strcmp(argv[1], "--mutate-expectation")));
    int bash = interpreter("/bin/bash"), python = interpreter("/usr/bin/python3");
    REQUIRE(bash >= 0 && python >= 0);
    const char *sh = "test ! -e /proc/self/fd/100 && test ! -e /proc/self/fd/101 && printf 'CANARY\\n'\n";
    const char *py = "import os\nassert not os.path.exists('/proc/self/fd/100')\nassert not os.path.exists('/proc/self/fd/101')\nprint('CANARY')\n";
    handoff("bash_handoff", bash, sh, argc == 2); handoff("python_handoff", python, py, 0);
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
    int walk_links = 0, shell = walk("/bin/sh", &walk_links); REQUIRE(shell >= 0);
    struct stat bin_link, bin_dir, usr_bin;
    REQUIRE(lstat("/bin", &bin_link) == 0 && S_ISLNK(bin_link.st_mode));
    REQUIRE(stat("/bin", &bin_dir) == 0 && stat("/usr/bin", &usr_bin) == 0 &&
            bin_dir.st_dev == usr_bin.st_dev && bin_dir.st_ino == usr_bin.st_ino);
    struct result merged = execute(shell, -1, 0, 1); REQUIRE(merged.exit_code == 0 && merged.canaries == 1);
    printf("{\"cell\":\"system_walk\",\"evidence\":{\"links\":%d,\"merged_usr\":1,\"native\":1,\"exit\":0,\"canary\":1}}\n", walk_links);
    int ignored = 0;
    REQUIRE(walk("bin/sh", &ignored) == -1 && walk("/usr/bin/env/../sh", &ignored) == -1);
    REQUIRE(interpreter("/usr/bin/env") == -1 && interpreter("bin/bash") == -1);
    char fixture[] = "/tmp/x02-links-XXXXXX"; REQUIRE(mkdtemp(fixture) != NULL);
    char link[PATH_MAX], replacement[PATH_MAX];
    REQUIRE(snprintf(link, sizeof(link), "%s/link", fixture) < (int)sizeof(link));
    REQUIRE(snprintf(replacement, sizeof(replacement), "%s/replacement", fixture) < (int)sizeof(replacement));
    REQUIRE(symlink("/bin/bash", link) == 0);
    struct stat before; REQUIRE(lstat(link, &before) == 0 && same_link(link, &before));
    REQUIRE(symlink("/bin/sh", replacement) == 0 && rename(replacement, link) == 0);
    REQUIRE(!same_link(link, &before));
    REQUIRE(unlink(link) == 0 && symlink("bin/bash", link) == 0);
    char target[PATH_MAX]; ssize_t target_size = readlink(link, target, sizeof(target) - 1);
    REQUIRE(target_size > 0); target[target_size] = 0;
    REQUIRE(!link_target_allowed(target, 0));
    REQUIRE(chmod(fixture, 0777) == 0 && walk(link, &ignored) == -1);
    REQUIRE(unlink(link) == 0 && rmdir(fixture) == 0);
    puts("{\"cell\":\"refusals\",\"evidence\":{\"relative\":1,\"relative_link\":1,\"env\":1,\"proc_missing\":1,\"replaced_link\":1,\"writable_chain\":1}}");
    REQUIRE(close(shell) == 0 && close(script) == 0 && close(opath) == 0 && close(bash) == 0 && close(python) == 0);
    return 0;
}
