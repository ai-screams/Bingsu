/* Test-only interposition detector. Never linked into a product binary. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#ifdef __APPLE__
#include <sys/attr.h>
#endif
#include <sys/types.h>
#ifdef __APPLE__
#include <sys/mount.h>
#else
#include <sys/vfs.h>
#endif
#include <unistd.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif
static int armed, permitted;
static unsigned long calls;
void bingsu_io_arm(int active) { armed = active; permitted = 0; calls = 0; }
void bingsu_io_permit(int active) { permitted = active; }
unsigned long bingsu_io_calls(void) { return calls; }
static void detect(void) { if (armed) { if (!permitted) _exit(86); ++calls; } }
#ifdef __APPLE__
#define REAL(name) name
#define DECL_REAL(ret,name,args)
#define REPLACE(name) __attribute__((used,section("__DATA,__interpose"))) static const struct { const void *replacement; const void *original; } interpose_##name = { (const void *)detect_##name, (const void *)name };
#define WRAP(ret,name,args,pass) static ret detect_##name args { detect(); return REAL(name) pass; } REPLACE(name)
#else
#define REAL(name) real_##name
#define DECL_REAL(ret,name,args) static ret (*real_##name) args; if (!real_##name) *(void **)(&real_##name) = dlsym(RTLD_NEXT, #name);
#define REPLACE(name)
#define WRAP(ret,name,args,pass) ret name args { DECL_REAL(ret,name,args) detect(); return REAL(name) pass; }
#endif
WRAP(ssize_t,read,(int fd, void *buf, size_t n),(fd,buf,n))
WRAP(ssize_t,pread,(int fd, void *buf, size_t n, off_t off),(fd,buf,n,off))
WRAP(int,stat,(const char *path, struct stat *out),(path,out))
WRAP(int,lstat,(const char *path, struct stat *out),(path,out))
WRAP(int,fstat,(int fd, struct stat *out),(fd,out))
#ifdef __APPLE__
WRAP(int,getattrlistbulk,(int fd, struct attrlist *attrs, void *buffer, size_t size, uint64_t options),(fd,attrs,buffer,size,options))
#endif
WRAP(int,fstatat,(int fd, const char *path, struct stat *out, int flags),(fd,path,out,flags))
WRAP(int,fstatfs,(int fd, struct statfs *out),(fd,out))
WRAP(int,statfs,(const char *path, struct statfs *out),(path,out))
#if defined(__GLIBC__)
WRAP(int,fstat64,(int fd, struct stat64 *out),(fd,out))
WRAP(int,stat64,(const char *path, struct stat64 *out),(path,out))
WRAP(int,lstat64,(const char *path, struct stat64 *out),(path,out))
WRAP(int,fstatat64,(int fd, const char *path, struct stat64 *out, int flags),(fd,path,out,flags))
WRAP(ssize_t,pread64,(int fd, void *buf, size_t n, off64_t off),(fd,buf,n,off))
#endif
WRAP(ssize_t,readlink,(const char *path, char *buf, size_t n),(path,buf,n))
WRAP(ssize_t,readlinkat,(int fd, const char *path, char *buf, size_t n),(fd,path,buf,n))
WRAP(DIR *,opendir,(const char *path),(path))
WRAP(DIR *,fdopendir,(int fd),(fd))
WRAP(struct dirent *,readdir,(DIR *dir),(dir))
WRAP(FILE *,fopen,(const char *path, const char *mode),(path,mode))
#ifdef __APPLE__
extern ssize_t __getdirentries64(int, char *, size_t, off_t *);
WRAP(ssize_t,__getdirentries64,(int fd, char *buf, size_t n, off_t *base),(fd,buf,n,base))
#define EXPORTED(name) detect_##name
#else
#define EXPORTED(name) name
#endif
static int mode_arg(int flags) {
#ifdef O_TMPFILE
    if ((flags & O_TMPFILE) == O_TMPFILE) return 1;
#endif
    return flags & O_CREAT;
}
int EXPORTED(open)(const char *path, int flags, ...) {
    int mode = 0; if (mode_arg(flags)) { va_list ap; va_start(ap,flags); mode=va_arg(ap,int); va_end(ap); }
    DECL_REAL(int,open,(const char *,int,...)) detect(); return REAL(open)(path,flags,mode);
} REPLACE(open)
int EXPORTED(openat)(int fd, const char *path, int flags, ...) {
    int mode = 0; if (mode_arg(flags)) { va_list ap; va_start(ap,flags); mode=va_arg(ap,int); va_end(ap); }
    DECL_REAL(int,openat,(int,const char *,int,...)) detect(); return REAL(openat)(fd,path,flags,mode);
} REPLACE(openat)
#if defined(__GLIBC__)
/* Rust's File::open on linux-gnu calls open64/openat64, not open/openat.
 * 이것을 실패시키는 것: 이 두 hook을 지우면 Linux에서 history_never_contacts_remote의
 * graph 모드가 경로 검사(87)보다 일반 read 검사(86)에 먼저 걸린다. */
int open64(const char *path, int flags, ...) {
    int mode = 0;
    if (mode_arg(flags)) {
        va_list ap;
        va_start(ap,flags);
        mode=va_arg(ap,int);
        va_end(ap);
    }
    DECL_REAL(int,open64,(const char *,int,...)) detect();
    return REAL(open64)(path,flags,mode);
}
int openat64(int fd, const char *path, int flags, ...) {
    int mode = 0;
    if (mode_arg(flags)) {
        va_list ap;
        va_start(ap,flags);
        mode=va_arg(ap,int);
        va_end(ap);
    }
    DECL_REAL(int,openat64,(int,const char *,int,...)) detect();
    return REAL(openat64)(fd,path,flags,mode);
}
#endif
void *EXPORTED(mmap)(void *addr, size_t n, int prot, int flags, int fd, off_t off) {
    DECL_REAL(void *,mmap,(void *,size_t,int,int,int,off_t))
    if (fd != -1)
        detect();
    return REAL(mmap)(addr,n,prot,flags,fd,off);
} REPLACE(mmap)
#ifdef __linux__
/* libc syscall() is variadic: the Linux ABI always has six argument registers.
 * This detector forwards them unchanged; it is not a confinement mechanism. */
long syscall(long number, ...) {
    DECL_REAL(long,syscall,(long,...))
    va_list ap; va_start(ap,number); unsigned long a[6];
    for (int i=0;i<6;++i)
        a[i]=va_arg(ap,unsigned long);
    va_end(ap);
    switch(number) {
        case SYS_openat: case SYS_openat2: case SYS_read: case SYS_pread64:
        case SYS_newfstatat: case SYS_fstat: case SYS_statx: case SYS_getdents64:
        case SYS_readlinkat: detect(); break;
        default: break;
    }
    return REAL(syscall)(number,a[0],a[1],a[2],a[3],a[4],a[5]);
}
#endif
