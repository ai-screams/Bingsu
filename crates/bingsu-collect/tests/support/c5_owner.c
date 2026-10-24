/* Test-only uid mismatch at the real owner comparison, never linked in product. */
#include <sys/types.h>
#include <unistd.h>
static unsigned target_call;
static unsigned calls;
void bingsu_c5_owner(unsigned nth) {
    target_call = nth;
    calls = 0;
}
static uid_t observed_euid(void) {
    ++calls;
    return getuid() + (target_call == 0 || calls == target_call);
}
#ifdef __APPLE__
static uid_t foreign_euid(void) {
    return observed_euid();
}
__attribute__((used, section("__DATA,__interpose")))
static const struct { const void *replacement; const void *original; } owner = {
    (const void *)foreign_euid, (const void *)geteuid
};
#else
uid_t geteuid(void) {
    return observed_euid();
}
#endif
