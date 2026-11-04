/* strbuf.h - growable string buffer used across callscope. */
#ifndef CALLSCOPE_STRBUF_H
#define CALLSCOPE_STRBUF_H

#include <stdarg.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cs_strbuf {
    char *data; /* always NUL-terminated once anything was appended */
    size_t len;
    size_t cap;
} cs_strbuf;

void cs_sb_init(cs_strbuf *sb);
void cs_sb_free(cs_strbuf *sb);
void cs_sb_clear(cs_strbuf *sb);
int cs_sb_reserve(cs_strbuf *sb, size_t extra);
int cs_sb_append(cs_strbuf *sb, const char *s);
int cs_sb_appendn(cs_strbuf *sb, const char *s, size_t n);
int cs_sb_appendc(cs_strbuf *sb, char c);
int cs_sb_appendf(cs_strbuf *sb, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
int cs_sb_vappendf(cs_strbuf *sb, const char *fmt, va_list ap);
/* Append s with HTML special characters escaped. */
int cs_sb_append_html(cs_strbuf *sb, const char *s);
/* Return the buffer (or "" if empty). Never NULL. */
const char *cs_sb_cstr(const cs_strbuf *sb);
/* Hand ownership of the heap buffer to the caller and reset sb. */
char *cs_sb_steal(cs_strbuf *sb);

#ifdef __cplusplus
}
#endif
#endif
