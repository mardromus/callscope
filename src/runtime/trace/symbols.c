/* Address -> function name resolution for the tracer.
 *
 * dladdr() finds exported symbols (build apps with -rdynamic). Static
 * functions fall back to "module+0xoffset", which `addr2line` can resolve
 * offline. Results are cached per thread in a small direct-mapped table so the
 * hot path rarely calls dladdr. */
#define _GNU_SOURCE
#include "symbols.h"

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CACHE_SIZE 1024
#define NAME_MAX_LEN 120

typedef struct {
    void *addr;
    char name[NAME_MAX_LEN];
} sym_slot;

static __thread sym_slot t_cache[CACHE_SIZE];

static const char *CS_NOINSTR basename_of(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

const char *cs_sym_name(void *addr) {
    size_t h = (((uintptr_t)addr) >> 4) & (CACHE_SIZE - 1);
    sym_slot *s = &t_cache[h];
    if (s->addr == addr && s->name[0]) return s->name;

    Dl_info info;
    memset(&info, 0, sizeof info);
    if (dladdr(addr, &info) && info.dli_sname && info.dli_saddr == addr) {
        snprintf(s->name, sizeof s->name, "%s", info.dli_sname);
    } else if (info.dli_fname && info.dli_fbase) {
        snprintf(s->name, sizeof s->name, "%s+0x%lx", basename_of(info.dli_fname),
                 (unsigned long)((uintptr_t)addr - (uintptr_t)info.dli_fbase));
    } else {
        snprintf(s->name, sizeof s->name, "0x%lx", (unsigned long)(uintptr_t)addr);
    }
    s->addr = addr;
    return s->name;
}
