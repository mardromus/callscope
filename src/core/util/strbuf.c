#include "callscope/strbuf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void cs_sb_init(cs_strbuf *sb) {
    sb->data = NULL;
    sb->len = 0;
    sb->cap = 0;
}

void cs_sb_free(cs_strbuf *sb) {
    free(sb->data);
    cs_sb_init(sb);
}

void cs_sb_clear(cs_strbuf *sb) {
    sb->len = 0;
    if (sb->data) sb->data[0] = '\0';
}

int cs_sb_reserve(cs_strbuf *sb, size_t extra) {
    size_t need = sb->len + extra + 1;
    if (need <= sb->cap) return 0;
    size_t cap = sb->cap ? sb->cap : 64;
    while (cap < need) cap *= 2;
    char *p = realloc(sb->data, cap);
    if (!p) return -1;
    sb->data = p;
    sb->cap = cap;
    return 0;
}

int cs_sb_appendn(cs_strbuf *sb, const char *s, size_t n) {
    if (cs_sb_reserve(sb, n) != 0) return -1;
    memcpy(sb->data + sb->len, s, n);
    sb->len += n;
    sb->data[sb->len] = '\0';
    return 0;
}

int cs_sb_append(cs_strbuf *sb, const char *s) {
    if (!s) return 0;
    return cs_sb_appendn(sb, s, strlen(s));
}

int cs_sb_appendc(cs_strbuf *sb, char c) { return cs_sb_appendn(sb, &c, 1); }

int cs_sb_vappendf(cs_strbuf *sb, const char *fmt, va_list ap) {
    va_list cp;
    va_copy(cp, ap);
    int n = vsnprintf(NULL, 0, fmt, cp);
    va_end(cp);
    if (n < 0) return -1;
    if (cs_sb_reserve(sb, (size_t)n) != 0) return -1;
    vsnprintf(sb->data + sb->len, (size_t)n + 1, fmt, ap);
    sb->len += (size_t)n;
    return 0;
}

int cs_sb_appendf(cs_strbuf *sb, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int rc = cs_sb_vappendf(sb, fmt, ap);
    va_end(ap);
    return rc;
}

int cs_sb_append_html(cs_strbuf *sb, const char *s) {
    if (!s) return 0;
    for (; *s; s++) {
        int rc;
        switch (*s) {
        case '&': rc = cs_sb_append(sb, "&amp;"); break;
        case '<': rc = cs_sb_append(sb, "&lt;"); break;
        case '>': rc = cs_sb_append(sb, "&gt;"); break;
        case '"': rc = cs_sb_append(sb, "&quot;"); break;
        case '\'': rc = cs_sb_append(sb, "&#39;"); break;
        default: rc = cs_sb_appendc(sb, *s); break;
        }
        if (rc != 0) return rc;
    }
    return 0;
}

const char *cs_sb_cstr(const cs_strbuf *sb) { return sb->data ? sb->data : ""; }

char *cs_sb_steal(cs_strbuf *sb) {
    char *p = sb->data;
    if (!p) {
        p = malloc(1);
        if (p) p[0] = '\0';
    }
    cs_sb_init(sb);
    return p;
}
