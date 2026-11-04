/* cstest.h - a tiny self-registering unit test harness (no dependencies).
 *
 *   CS_TEST(strbuf_appends) {
 *       CS_ASSERT_EQ_INT(1 + 1, 2);
 *   }
 *
 * Tests register themselves through a constructor, so adding a new test file
 * to tests/ is enough for it to run. */
#ifndef CALLSCOPE_CSTEST_H
#define CALLSCOPE_CSTEST_H

#include <stdio.h>
#include <string.h>

typedef void (*cs_test_fn)(int *failed);

void cs_test_register(const char *name, const char *file, cs_test_fn fn);

#define CS_TEST(name)                                                                              \
    static void cs_test_##name(int *cs_failed__);                                                  \
    __attribute__((constructor)) static void cs_test_reg_##name(void) {                            \
        cs_test_register(#name, __FILE__, cs_test_##name);                                         \
    }                                                                                              \
    static void cs_test_##name(int *cs_failed__)

#define CS_FAIL_(fmt, ...)                                                                         \
    do {                                                                                           \
        fprintf(stderr, "    %s:%d: " fmt "\n", __FILE__, __LINE__, __VA_ARGS__);                  \
        *cs_failed__ = 1;                                                                          \
        return;                                                                                    \
    } while (0)

#define CS_ASSERT(cond)                                                                            \
    do {                                                                                           \
        if (!(cond)) CS_FAIL_("assertion failed: %s", #cond);                                      \
    } while (0)

#define CS_ASSERT_EQ_INT(a, b)                                                                     \
    do {                                                                                           \
        long long a__ = (long long)(a), b__ = (long long)(b);                                      \
        if (a__ != b__) CS_FAIL_("%s == %s (%lld != %lld)", #a, #b, a__, b__);                     \
    } while (0)

#define CS_ASSERT_EQ_STR(a, b)                                                                     \
    do {                                                                                           \
        const char *a__ = (a), *b__ = (b);                                                         \
        if (!a__ || !b__ || strcmp(a__, b__) != 0)                                                 \
            CS_FAIL_("%s == %s (\"%s\" != \"%s\")", #a, #b, a__ ? a__ : "(null)",                  \
                     b__ ? b__ : "(null)");                                                        \
    } while (0)

#define CS_ASSERT_NEAR(a, b, eps)                                                                  \
    do {                                                                                           \
        double a__ = (double)(a), b__ = (double)(b);                                               \
        if (a__ - b__ > (eps) || b__ - a__ > (eps))                                                \
            CS_FAIL_("%s ~= %s (%g vs %g)", #a, #b, a__, b__);                                     \
    } while (0)

/* Path of the tests/data directory, injected by CMake. */
#ifndef CS_TEST_DATA_DIR
#define CS_TEST_DATA_DIR "tests/data"
#endif

#endif
