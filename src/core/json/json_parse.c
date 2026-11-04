/* Recursive-descent JSON parser producing a cs_json DOM. */
#include "callscope/json.h"

#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CS_JSON_MAX_NEST 128

typedef struct {
    const char *p, *end;
    int line;
    char *err;
    size_t errlen;
    int failed;
    int depth;
} parser;

static void fail(parser *ps, const char *msg) {
    if (ps->failed) return;
    ps->failed = 1;
    if (ps->err && ps->errlen) snprintf(ps->err, ps->errlen, "line %d: %s", ps->line, msg);
}

static void skip_ws(parser *ps) {
    while (ps->p < ps->end) {
        char c = *ps->p;
        if (c == '\n') ps->line++;
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
            ps->p++;
        else
            break;
    }
}

static cs_json *new_val(cs_json_type t) {
    cs_json *v = calloc(1, sizeof(*v));
    if (v) v->type = t;
    return v;
}

static int add_item(cs_json *c, char *key, cs_json *item) {
    if (c->len == c->cap) {
        size_t ncap = c->cap ? c->cap * 2 : 4;
        cs_json **ni = realloc(c->items, ncap * sizeof(*ni));
        if (!ni) return -1;
        c->items = ni;
        if (c->type == CS_JSON_OBJ) {
            char **nk = realloc(c->keys, ncap * sizeof(*nk));
            if (!nk) return -1;
            c->keys = nk;
        }
        c->cap = ncap;
    }
    if (c->type == CS_JSON_OBJ) c->keys[c->len] = key;
    c->items[c->len++] = item;
    return 0;
}

static void put_utf8(cs_strbuf *sb, unsigned cp) {
    char b[4];
    if (cp < 0x80) {
        cs_sb_appendc(sb, (char)cp);
    } else if (cp < 0x800) {
        b[0] = (char)(0xC0 | (cp >> 6));
        b[1] = (char)(0x80 | (cp & 0x3F));
        cs_sb_appendn(sb, b, 2);
    } else if (cp < 0x10000) {
        b[0] = (char)(0xE0 | (cp >> 12));
        b[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        b[2] = (char)(0x80 | (cp & 0x3F));
        cs_sb_appendn(sb, b, 3);
    } else {
        b[0] = (char)(0xF0 | (cp >> 18));
        b[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
        b[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
        b[3] = (char)(0x80 | (cp & 0x3F));
        cs_sb_appendn(sb, b, 4);
    }
}

static int hex4(parser *ps, unsigned *out) {
    if (ps->end - ps->p < 4) return -1;
    unsigned v = 0;
    for (int i = 0; i < 4; i++) {
        char c = ps->p[i];
        v <<= 4;
        if (c >= '0' && c <= '9')
            v |= (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f')
            v |= (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            v |= (unsigned)(c - 'A' + 10);
        else
            return -1;
    }
    ps->p += 4;
    *out = v;
    return 0;
}

static char *parse_string_raw(parser *ps) {
    if (ps->p >= ps->end || *ps->p != '"') {
        fail(ps, "expected string");
        return NULL;
    }
    ps->p++;
    cs_strbuf sb;
    cs_sb_init(&sb);
    while (ps->p < ps->end && *ps->p != '"') {
        char c = *ps->p++;
        if (c == '\\') {
            if (ps->p >= ps->end) break;
            char e = *ps->p++;
            switch (e) {
            case '"': cs_sb_appendc(&sb, '"'); break;
            case '\\': cs_sb_appendc(&sb, '\\'); break;
            case '/': cs_sb_appendc(&sb, '/'); break;
            case 'b': cs_sb_appendc(&sb, '\b'); break;
            case 'f': cs_sb_appendc(&sb, '\f'); break;
            case 'n': cs_sb_appendc(&sb, '\n'); break;
            case 'r': cs_sb_appendc(&sb, '\r'); break;
            case 't': cs_sb_appendc(&sb, '\t'); break;
            case 'u': {
                unsigned cp;
                if (hex4(ps, &cp) != 0) {
                    fail(ps, "bad \\u escape");
                    cs_sb_free(&sb);
                    return NULL;
                }
                if (cp >= 0xD800 && cp <= 0xDBFF && ps->end - ps->p >= 6 && ps->p[0] == '\\' &&
                    ps->p[1] == 'u') {
                    unsigned lo;
                    ps->p += 2;
                    if (hex4(ps, &lo) == 0 && lo >= 0xDC00 && lo <= 0xDFFF)
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                }
                put_utf8(&sb, cp);
                break;
            }
            default:
                fail(ps, "bad escape");
                cs_sb_free(&sb);
                return NULL;
            }
        } else {
            if (c == '\n') ps->line++;
            cs_sb_appendc(&sb, c);
        }
    }
    if (ps->p >= ps->end) {
        fail(ps, "unterminated string");
        cs_sb_free(&sb);
        return NULL;
    }
    ps->p++; /* closing quote */
    return cs_sb_steal(&sb);
}

static cs_json *parse_value(parser *ps);

static cs_json *parse_number(parser *ps) {
    const char *start = ps->p;
    int is_int = 1;
    if (ps->p < ps->end && (*ps->p == '-' || *ps->p == '+')) ps->p++;
    while (ps->p < ps->end) {
        char c = *ps->p;
        if (c >= '0' && c <= '9') {
            ps->p++;
        } else if (c == '.' || c == 'e' || c == 'E' || c == '-' || c == '+') {
            is_int = 0;
            ps->p++;
        } else {
            break;
        }
    }
    size_t n = (size_t)(ps->p - start);
    if (n == 0 || n > 63) {
        fail(ps, "bad number");
        return NULL;
    }
    char buf[64];
    memcpy(buf, start, n);
    buf[n] = '\0';
    cs_json *v = new_val(CS_JSON_NUM);
    if (!v) return NULL;
    char *endp;
    v->num = strtod(buf, &endp);
    if (*endp != '\0') {
        free(v);
        fail(ps, "bad number");
        return NULL;
    }
    if (is_int) {
        errno = 0;
        long long ll = strtoll(buf, &endp, 10);
        if (errno == 0 && *endp == '\0') {
            v->is_int = 1;
            v->i = ll;
        }
    } else if (isfinite(v->num) && v->num == floor(v->num) && fabs(v->num) < 9e15) {
        v->is_int = 1;
        v->i = (int64_t)v->num;
    }
    return v;
}

static int match_lit(parser *ps, const char *lit) {
    size_t n = strlen(lit);
    if ((size_t)(ps->end - ps->p) >= n && memcmp(ps->p, lit, n) == 0) {
        ps->p += n;
        return 1;
    }
    return 0;
}

static cs_json *parse_container(parser *ps, int is_obj) {
    if (++ps->depth > CS_JSON_MAX_NEST) {
        fail(ps, "nesting too deep");
        return NULL;
    }
    ps->p++; /* [ or { */
    cs_json *c = new_val(is_obj ? CS_JSON_OBJ : CS_JSON_ARR);
    if (!c) return NULL;
    char close = is_obj ? '}' : ']';
    skip_ws(ps);
    if (ps->p < ps->end && *ps->p == close) {
        ps->p++;
        ps->depth--;
        return c;
    }
    for (;;) {
        char *key = NULL;
        skip_ws(ps);
        if (is_obj) {
            key = parse_string_raw(ps);
            if (!key) goto bad;
            skip_ws(ps);
            if (ps->p >= ps->end || *ps->p != ':') {
                free(key);
                fail(ps, "expected ':'");
                goto bad;
            }
            ps->p++;
        }
        cs_json *item = parse_value(ps);
        if (!item || add_item(c, key, item) != 0) {
            free(key);
            cs_json_free(item);
            goto bad;
        }
        skip_ws(ps);
        if (ps->p < ps->end && *ps->p == ',') {
            ps->p++;
            continue;
        }
        if (ps->p < ps->end && *ps->p == close) {
            ps->p++;
            break;
        }
        fail(ps, is_obj ? "expected ',' or '}'" : "expected ',' or ']'");
        goto bad;
    }
    ps->depth--;
    return c;
bad:
    cs_json_free(c);
    return NULL;
}

static cs_json *parse_value(parser *ps) {
    skip_ws(ps);
    if (ps->p >= ps->end) {
        fail(ps, "unexpected end of input");
        return NULL;
    }
    char c = *ps->p;
    if (c == '{') return parse_container(ps, 1);
    if (c == '[') return parse_container(ps, 0);
    if (c == '"') {
        char *s = parse_string_raw(ps);
        if (!s) return NULL;
        cs_json *v = new_val(CS_JSON_STR);
        if (!v) {
            free(s);
            return NULL;
        }
        v->str = s;
        return v;
    }
    if (c == '-' || (c >= '0' && c <= '9')) return parse_number(ps);
    if (match_lit(ps, "true")) {
        cs_json *v = new_val(CS_JSON_BOOL);
        if (v) v->b = 1;
        return v;
    }
    if (match_lit(ps, "false")) return new_val(CS_JSON_BOOL);
    if (match_lit(ps, "null")) return new_val(CS_JSON_NULL);
    fail(ps, "unexpected character");
    return NULL;
}

cs_json *cs_json_parse(const char *text, size_t len, char *err, size_t errlen) {
    if (!text) return NULL;
    if (len == (size_t)-1) len = strlen(text);
    parser ps = {text, text + len, 1, err, errlen, 0, 0};
    if (err && errlen) err[0] = '\0';
    cs_json *v = parse_value(&ps);
    if (!v) return NULL;
    skip_ws(&ps);
    if (ps.p != ps.end) {
        fail(&ps, "trailing characters after value");
        cs_json_free(v);
        return NULL;
    }
    return v;
}

void cs_json_free(cs_json *v) {
    if (!v) return;
    for (size_t i = 0; i < v->len; i++) {
        cs_json_free(v->items[i]);
        if (v->keys) free(v->keys[i]);
    }
    free(v->items);
    free(v->keys);
    free(v->str);
    free(v);
}

cs_json *cs_json_get(const cs_json *obj, const char *key) {
    if (!obj || obj->type != CS_JSON_OBJ) return NULL;
    for (size_t i = 0; i < obj->len; i++)
        if (strcmp(obj->keys[i], key) == 0) return obj->items[i];
    return NULL;
}

cs_json *cs_json_at(const cs_json *arr, size_t i) {
    if (!arr || (arr->type != CS_JSON_ARR && arr->type != CS_JSON_OBJ) || i >= arr->len)
        return NULL;
    return arr->items[i];
}

size_t cs_json_len(const cs_json *v) {
    return (v && (v->type == CS_JSON_ARR || v->type == CS_JSON_OBJ)) ? v->len : 0;
}

cs_json *cs_json_path(const cs_json *root, const char *path) {
    const cs_json *cur = root;
    char seg[128];
    while (cur && *path) {
        size_t n = strcspn(path, ".");
        if (n >= sizeof seg) return NULL;
        memcpy(seg, path, n);
        seg[n] = '\0';
        path += n;
        if (*path == '.') path++;
        if (cur->type == CS_JSON_ARR) {
            char *endp;
            long idx = strtol(seg, &endp, 10);
            if (*endp || idx < 0) return NULL;
            cur = cs_json_at(cur, (size_t)idx);
        } else {
            cur = cs_json_get(cur, seg);
        }
    }
    return (cs_json *)cur;
}

const char *cs_json_as_str(const cs_json *v, const char *dflt) {
    return (v && v->type == CS_JSON_STR) ? v->str : dflt;
}

double cs_json_as_num(const cs_json *v, double dflt) {
    return (v && v->type == CS_JSON_NUM) ? v->num : dflt;
}

int64_t cs_json_as_i64(const cs_json *v, int64_t dflt) {
    if (!v || v->type != CS_JSON_NUM) return dflt;
    return v->is_int ? v->i : (int64_t)v->num;
}

int cs_json_as_bool(const cs_json *v, int dflt) {
    if (!v) return dflt;
    if (v->type == CS_JSON_BOOL) return v->b;
    if (v->type == CS_JSON_NUM) return v->num != 0;
    return dflt;
}
