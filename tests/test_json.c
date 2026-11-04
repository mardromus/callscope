#include "cstest.h"

#include "callscope/json.h"

CS_TEST(json_parses_nested_document) {
    const char *doc = "{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\"hi\\nthere\","
                      "\"tool_calls\":[{\"id\":\"c1\",\"function\":{\"name\":\"get_stack\"}}]}}],"
                      "\"usage\":{\"total_tokens\":42},\"ok\":true,\"none\":null}";
    char err[128];
    cs_json *v = cs_json_parse(doc, (size_t)-1, err, sizeof err);
    CS_ASSERT(v != NULL);
    CS_ASSERT_EQ_STR(cs_json_as_str(cs_json_path(v, "choices.0.message.content"), NULL),
                     "hi\nthere");
    CS_ASSERT_EQ_STR(
        cs_json_as_str(cs_json_path(v, "choices.0.message.tool_calls.0.function.name"), NULL),
        "get_stack");
    CS_ASSERT_EQ_INT(cs_json_as_i64(cs_json_path(v, "usage.total_tokens"), 0), 42);
    CS_ASSERT_EQ_INT(cs_json_as_bool(cs_json_get(v, "ok"), 0), 1);
    CS_ASSERT(cs_json_get(v, "none")->type == CS_JSON_NULL);
    CS_ASSERT(cs_json_path(v, "choices.5") == NULL);
    cs_json_free(v);
}

CS_TEST(json_keeps_nanosecond_integers_exact) {
    cs_json *v = cs_json_parse("{\"ts\":1793750400123456789}", (size_t)-1, NULL, 0);
    CS_ASSERT(v != NULL);
    cs_json *ts = cs_json_get(v, "ts");
    CS_ASSERT(ts->is_int);
    CS_ASSERT(cs_json_as_i64(ts, 0) == 1793750400123456789LL);
    cs_json_free(v);
}

CS_TEST(json_decodes_unicode_escapes) {
    cs_json *v = cs_json_parse("\"caf\\u00e9 \\ud83d\\ude80\"", (size_t)-1, NULL, 0);
    CS_ASSERT(v != NULL);
    CS_ASSERT_EQ_STR(v->str, "caf\xc3\xa9 \xf0\x9f\x9a\x80");
    cs_json_free(v);
}

CS_TEST(json_reports_errors_with_line) {
    char err[128];
    CS_ASSERT(cs_json_parse("{\n\"a\" 1}", (size_t)-1, err, sizeof err) == NULL);
    CS_ASSERT_EQ_STR(err, "line 2: expected ':'");
    CS_ASSERT(cs_json_parse("[1,2", (size_t)-1, err, sizeof err) == NULL);
    CS_ASSERT(cs_json_parse("{} extra", (size_t)-1, err, sizeof err) == NULL);
    CS_ASSERT(cs_json_parse("", (size_t)-1, err, sizeof err) == NULL);
}

CS_TEST(json_roundtrips_through_serializer) {
    const char *doc = "{\"a\":[1,2.5,\"x\\\"y\"],\"b\":{\"c\":false,\"d\":null},\"e\":-7}";
    cs_json *v = cs_json_parse(doc, (size_t)-1, NULL, 0);
    CS_ASSERT(v != NULL);
    cs_strbuf sb;
    cs_sb_init(&sb);
    cs_json_serialize(v, &sb);
    CS_ASSERT_EQ_STR(cs_sb_cstr(&sb), doc);
    cs_sb_free(&sb);
    cs_json_free(v);
}

CS_TEST(json_writer_builds_valid_output) {
    cs_strbuf sb;
    cs_sb_init(&sb);
    cs_jw w;
    cs_jw_init(&w, &sb);
    cs_jw_obj_begin(&w);
    cs_jw_kv_str(&w, "name", "tab\there");
    cs_jw_kv_i64(&w, "count", 3);
    cs_jw_key(&w, "items");
    cs_jw_arr_begin(&w);
    cs_jw_i64(&w, 1);
    cs_jw_obj_begin(&w);
    cs_jw_kv_bool(&w, "ok", 1);
    cs_jw_obj_end(&w);
    cs_jw_null(&w);
    cs_jw_arr_end(&w);
    cs_jw_kv_num(&w, "ratio", 0.25);
    cs_jw_obj_end(&w);
    CS_ASSERT_EQ_STR(cs_sb_cstr(&sb),
                     "{\"name\":\"tab\\there\",\"count\":3,\"items\":[1,{\"ok\":true},null],"
                     "\"ratio\":0.25}");
    cs_json *back = cs_json_parse(sb.data, sb.len, NULL, 0);
    CS_ASSERT(back != NULL);
    cs_json_free(back);
    cs_sb_free(&sb);
}
