/* json.h - small JSON DOM parser, serializer and streaming writer.
 *
 * Integers are kept exactly as int64 (event timestamps are nanoseconds since
 * the epoch, which do not fit in a double without losing precision). */
#ifndef CALLSCOPE_JSON_H
#define CALLSCOPE_JSON_H

#include <stddef.h>
#include <stdint.h>

#include "callscope/strbuf.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CS_JSON_NULL,
    CS_JSON_BOOL,
    CS_JSON_NUM,
    CS_JSON_STR,
    CS_JSON_ARR,
    CS_JSON_OBJ
} cs_json_type;

typedef struct cs_json cs_json;
struct cs_json {
    cs_json_type type;
    int is_int; /* number had no fraction/exponent and fits in int64 */
    int64_t i;
    double num;
    int b;
    char *str;   /* CS_JSON_STR */
    cs_json **items; /* CS_JSON_ARR / CS_JSON_OBJ values */
    char **keys;     /* CS_JSON_OBJ keys (parallel to items) */
    size_t len, cap;
};

/* Parse text (len may be (size_t)-1 for NUL-terminated). Returns NULL on error
 * and writes a message such as "line 3: expected ':'" into err. */
cs_json *cs_json_parse(const char *text, size_t len, char *err, size_t errlen);
void cs_json_free(cs_json *v);

cs_json *cs_json_get(const cs_json *obj, const char *key);
cs_json *cs_json_at(const cs_json *arr, size_t i);
size_t cs_json_len(const cs_json *v);
/* Dotted path lookup, numbers index arrays: "choices.0.message.content". */
cs_json *cs_json_path(const cs_json *root, const char *path);

const char *cs_json_as_str(const cs_json *v, const char *dflt);
double cs_json_as_num(const cs_json *v, double dflt);
int64_t cs_json_as_i64(const cs_json *v, int64_t dflt);
int cs_json_as_bool(const cs_json *v, int dflt);

/* Serialize a DOM value back to compact JSON. */
int cs_json_serialize(const cs_json *v, cs_strbuf *out);
/* Append s as a quoted, escaped JSON string. */
int cs_json_append_str(cs_strbuf *out, const char *s);

/* ---- streaming writer ------------------------------------------------- */
#define CS_JW_MAX_DEPTH 64
typedef struct cs_jw {
    cs_strbuf *out;
    int depth;
    unsigned char first[CS_JW_MAX_DEPTH];
    int after_key;
} cs_jw;

void cs_jw_init(cs_jw *w, cs_strbuf *out);
void cs_jw_obj_begin(cs_jw *w);
void cs_jw_obj_end(cs_jw *w);
void cs_jw_arr_begin(cs_jw *w);
void cs_jw_arr_end(cs_jw *w);
void cs_jw_key(cs_jw *w, const char *key);
void cs_jw_str(cs_jw *w, const char *s); /* NULL writes null */
void cs_jw_i64(cs_jw *w, int64_t v);
void cs_jw_num(cs_jw *w, double v);
void cs_jw_bool(cs_jw *w, int v);
void cs_jw_null(cs_jw *w);
void cs_jw_raw(cs_jw *w, const char *json); /* pre-serialized value */

void cs_jw_kv_str(cs_jw *w, const char *k, const char *v);
void cs_jw_kv_i64(cs_jw *w, const char *k, int64_t v);
void cs_jw_kv_num(cs_jw *w, const char *k, double v);
void cs_jw_kv_bool(cs_jw *w, const char *k, int v);

#ifdef __cplusplus
}
#endif
#endif
