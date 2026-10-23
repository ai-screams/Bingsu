/* C4 syscall floor, same 190 x 100 generated tree as the Rust release bench.
 * Usage: cc -O3 bench/worktree-stat-floor.c -o /tmp/stat-floor
 *        /tmp/stat-floor ROOT bulk|stat [rounds]
 * This intentionally omits adapter/meter/identity checks: never product code. */
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/attr.h>
#endif
static uint64_t now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (uint64_t)t.tv_sec*1000000000+t.tv_nsec; }
static int cmp(const void *a, const void *b) { uint64_t x=*(const uint64_t*)a,y=*(const uint64_t*)b; return (x>y)-(x<y); }
int main(int argc, char **argv) {
    if (argc<3) return 2;
    int rounds=argc>3?atoi(argv[3]):200, dirs[190];
    if(rounds<1 || rounds>10000) return 2;
    uint64_t *samples=calloc((size_t)rounds,sizeof(*samples));
    char leaves[100][8];
    for(int i=0;i<100;i++) snprintf(leaves[i],sizeof(leaves[i]),"f%03d",i);
    for(int i=0;i<190;i++) { char path[4096]; snprintf(path,sizeof(path),"%s/d%03d",argv[1],i); dirs[i]=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC); if(dirs[i]<0) {perror("open");return 1;} }
    size_t calls=0;
    for(int run=0;run<=rounds;run++) {
        calls=0;
        /* Reset all held OFDs outside the timed section, so the number really
         * is the bulk-only floor; Rust includes fresh safe opens/checks. */
        for(int i=0;i<190;i++) if(lseek(dirs[i],0,SEEK_SET)<0)return 1;
        uint64_t start=now();
        for(int i=0;i<190;i++) {
#ifdef __APPLE__
            if(!strcmp(argv[2],"bulk")) {
                struct attrlist attrs={.bitmapcount=ATTR_BIT_MAP_COUNT,
                    .commonattr=ATTR_CMN_RETURNED_ATTRS|ATTR_CMN_NAME|ATTR_CMN_ERROR|ATTR_CMN_DEVID|ATTR_CMN_OBJTYPE|ATTR_CMN_FILEID|ATTR_CMN_MODTIME|ATTR_CMN_CHGTIME|ATTR_CMN_OWNERID|ATTR_CMN_GRPID|ATTR_CMN_ACCESSMASK,
                    .dirattr=ATTR_DIR_DATALENGTH,.fileattr=ATTR_FILE_DATALENGTH};
                _Alignas(8) unsigned char buffer[8192];
                int count, total=0;
                do { count=getattrlistbulk(dirs[i],&attrs,buffer,sizeof(buffer),FSOPT_NOFOLLOW); calls++; if(count<0) {perror("bulk"); return 1;} total+=count; } while(count);
                if(total!=100)return 1;
            } else
#endif
            { for(int j=0;j<100;j++) { struct stat st; calls++; if(fstatat(dirs[i],leaves[j],&st,AT_SYMLINK_NOFOLLOW)<0 || st.st_size!=1)return 1; } }
        }
        uint64_t elapsed=now()-start;
        if(run) samples[run-1]=elapsed;
        else printf("FLOOR_FIRST_NS %llu\n",(unsigned long long)elapsed);
    }
    qsort(samples,(size_t)rounds,sizeof(*samples),cmp);
    printf("FLOOR %s n=%d p50_ns=%llu p95_ns=%llu calls=%zu\n",argv[2],rounds,(unsigned long long)samples[(rounds-1)/2],(unsigned long long)samples[(rounds*95+99)/100-1],calls);
    for(int i=0;i<190;i++)close(dirs[i]);
    free(samples);
    return 0;
}
