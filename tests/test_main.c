/* Test runner: runs every registered test, optionally filtered by substring. */
#include "cstest.h"

#include <stdlib.h>

#define CS_MAX_TESTS 512

typedef struct {
    const char *name;
    const char *file;
    cs_test_fn fn;
} cs_test_case;

static cs_test_case g_tests[CS_MAX_TESTS];
static int g_ntests;

void cs_test_register(const char *name, const char *file, cs_test_fn fn) {
    if (g_ntests < CS_MAX_TESTS) g_tests[g_ntests++] = (cs_test_case){name, file, fn};
}

static int cmp_case(const void *a, const void *b) {
    const cs_test_case *x = a, *y = b;
    int c = strcmp(x->file, y->file);
    return c ? c : strcmp(x->name, y->name);
}

int main(int argc, char **argv) {
    const char *filter = argc > 1 ? argv[1] : NULL;
    qsort(g_tests, (size_t)g_ntests, sizeof(g_tests[0]), cmp_case);
    int run = 0, failed = 0;
    for (int i = 0; i < g_ntests; i++) {
        if (filter && !strstr(g_tests[i].name, filter)) continue;
        int f = 0;
        g_tests[i].fn(&f);
        run++;
        if (f) {
            failed++;
            printf("  FAIL  %s\n", g_tests[i].name);
        } else {
            printf("  ok    %s\n", g_tests[i].name);
        }
    }
    printf("\n%d tests, %d passed, %d failed\n", run, run - failed, failed);
    return failed ? 1 : 0;
}
