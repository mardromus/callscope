/* JSON serializer and streaming writer. */
#include "callscope/json.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

int cs_json_append_str(cs_strbuf *out, const char *s) {
    if (!s) return cs_sb_append(out, "null");
    cs_sb_appendc(out, '"');
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
        case '"': cs_sb_append(out, "\\\""); break;
        case '\\': cs_sb_append(out, "\\\\"); break;
        case '\n': cs_sb_append(out, "\\n"); break;
        case '\r': cs_sb_append(out, "\\r"); break;
        case '\t': cs_sb_append(out, "\\t"); break;
        case '\b': cs_sb_append(out, "\\b"); break;
        case '\f': cs_sb_append(out, "\\f"); break;
        default:
            if (*p < 0x20)
                cs_sb_appendf(out, "\\u%04x", *p);
            else
                cs_sb_appendc(out, (char)*p);
        }
    }
    return cs_sb_appendc(out, '"');
}

static void append_num(cs_strbuf *out, double v) {
    if (!isfinite(v)) {
        cs_sb_append(out, "null");
        return;
    }
    if (v == floor(v) && fabs(v) < 9e15)
        cs_sb_appendf(out, "%lld", (long long)v);
    else
        cs_sb_appendf(out, "%.6g", v);
}

int cs_json_serialize(const cs_json *v, cs_strbuf *out) {
    if (!v) return cs_sb_append(out, "null");
    switch (v->type) {
    case CS_JSON_NULL: return cs_sb_append(out, "null");
    case CS_JSON_BOOL: return cs_sb_append(out, v->b ? "true" : "false");
    case CS_JSON_NUM:
        if (v->is_int)
            cs_sb_appendf(out, "%lld", (long long)v->i);
        else
            append_num(out, v->num);
        return 0;
    case CS_JSON_STR: return cs_json_append_str(out, v->str);
    case CS_JSON_ARR:
        cs_sb_appendc(out, '[');
        for (size_t i = 0; i < v->len; i++) {
            if (i) cs_sb_appendc(out, ',');
            cs_json_serialize(v->items[i], out);
        }
        return cs_sb_appendc(out, ']');
    case CS_JSON_OBJ:
        cs_sb_appendc(out, '{');
        for (size_t i = 0; i < v->len; i++) {
            if (i) cs_sb_appendc(out, ',');
            cs_json_append_str(out, v->keys[i]);
            cs_sb_appendc(out, ':');
            cs_json_serialize(v->items[i], out);
        }
        return cs_sb_appendc(out, '}');
    }
    return -1;
}

/* ---- streaming writer ---------------------------------------------------- */

void cs_jw_init(cs_jw *w, cs_strbuf *out) {
    memset(w, 0, sizeof(*w));
    w->out = out;
    w->first[0] = 1;
}

static void before_value(cs_jw *w) {
    if (w->after_key) {
        w->after_key = 0;
        return;
    }
    if (!w->first[w->depth]) cs_sb_appendc(w->out, ',');
    w->first[w->depth] = 0;
}

static void push(cs_jw *w, char c) {
    before_value(w);
    cs_sb_appendc(w->out, c);
    if (w->depth < CS_JW_MAX_DEPTH - 1) w->depth++;
    w->first[w->depth] = 1;
}

static void pop(cs_jw *w, char c) {
    cs_sb_appendc(w->out, c);
    if (w->depth > 0) w->depth--;
}

void cs_jw_obj_begin(cs_jw *w) { push(w, '{'); }
void cs_jw_obj_end(cs_jw *w) { pop(w, '}'); }
void cs_jw_arr_begin(cs_jw *w) { push(w, '['); }
void cs_jw_arr_end(cs_jw *w) { pop(w, ']'); }

void cs_jw_key(cs_jw *w, const char *key) {
    before_value(w);
    cs_json_append_str(w->out, key);
    cs_sb_appendc(w->out, ':');
    w->after_key = 1;
}

void cs_jw_str(cs_jw *w, const char *s) {
    before_value(w);
    cs_json_append_str(w->out, s);
}

void cs_jw_i64(cs_jw *w, int64_t v) {
    before_value(w);
    cs_sb_appendf(w->out, "%lld", (long long)v);
}

void cs_jw_num(cs_jw *w, double v) {
    before_value(w);
    append_num(w->out, v);
}

void cs_jw_bool(cs_jw *w, int v) {
    before_value(w);
    cs_sb_append(w->out, v ? "true" : "false");
}

void cs_jw_null(cs_jw *w) {
    before_value(w);
    cs_sb_append(w->out, "null");
}

void cs_jw_raw(cs_jw *w, const char *json) {
    before_value(w);
    cs_sb_append(w->out, json ? json : "null");
}

void cs_jw_kv_str(cs_jw *w, const char *k, const char *v) {
    cs_jw_key(w, k);
    cs_jw_str(w, v);
}

void cs_jw_kv_i64(cs_jw *w, const char *k, int64_t v) {
    cs_jw_key(w, k);
    cs_jw_i64(w, v);
}

void cs_jw_kv_num(cs_jw *w, const char *k, double v) {
    cs_jw_key(w, k);
    cs_jw_num(w, v);
}

void cs_jw_kv_bool(cs_jw *w, const char *k, int v) {
    cs_jw_key(w, k);
    cs_jw_bool(w, v);
}
