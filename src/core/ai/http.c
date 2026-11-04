#include "callscope/http.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef CALLSCOPE_HAVE_CURL
#include <curl/curl.h>

static size_t on_data(char *ptr, size_t size, size_t nmemb, void *userdata) {
    cs_strbuf *sb = userdata;
    size_t n = size * nmemb;
    return cs_sb_appendn(sb, ptr, n) == 0 ? n : 0;
}

const char *cs_http_backend(void) { return "libcurl"; }

int cs_http_post_json(void *ctx, const char *url, const char *api_key, const char *body,
                      int timeout_s, cs_strbuf *resp, long *status, char *err, size_t errlen) {
    (void)ctx;
    static int initialised;
    if (!initialised) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        initialised = 1;
    }
    CURL *c = curl_easy_init();
    if (!c) {
        snprintf(err, errlen, "curl_easy_init failed");
        return -1;
    }
    struct curl_slist *hdr = NULL;
    hdr = curl_slist_append(hdr, "Content-Type: application/json");
    hdr = curl_slist_append(hdr, "Accept: application/json");
    char auth[320];
    if (api_key && *api_key) {
        snprintf(auth, sizeof auth, "Authorization: Bearer %s", api_key);
        hdr = curl_slist_append(hdr, auth);
    }
    const char *ca = getenv("CURL_CA_BUNDLE");
    if (!ca) ca = getenv("SSL_CERT_FILE");
    if (ca && *ca) curl_easy_setopt(c, CURLOPT_CAINFO, ca);
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdr);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, on_data);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, (long)(timeout_s > 0 ? timeout_s : 60));
    curl_easy_setopt(c, CURLOPT_USERAGENT, "callscope/1.0");
    CURLcode rc = curl_easy_perform(c);
    if (rc != CURLE_OK) {
        snprintf(err, errlen, "HTTP request failed: %s", curl_easy_strerror(rc));
        curl_slist_free_all(hdr);
        curl_easy_cleanup(c);
        return -1;
    }
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, status);
    curl_slist_free_all(hdr);
    curl_easy_cleanup(c);
    memset(auth, 0, sizeof auth);
    return 0;
}

#else /* curl CLI fallback */

const char *cs_http_backend(void) { return "curl-cli"; }

static int write_temp(char *path_tmpl, const char *data) {
    int fd = mkstemp(path_tmpl);
    if (fd < 0) return -1;
    size_t n = strlen(data);
    ssize_t w = write(fd, data, n);
    close(fd);
    return w == (ssize_t)n ? 0 : -1;
}

int cs_http_post_json(void *ctx, const char *url, const char *api_key, const char *body,
                      int timeout_s, cs_strbuf *resp, long *status, char *err, size_t errlen) {
    (void)ctx;
    char body_path[] = "/tmp/callscope-body-XXXXXX";
    char hdr_path[] = "/tmp/callscope-hdr-XXXXXX";
    char headers[512];
    snprintf(headers, sizeof headers,
             "Content-Type: application/json\nAccept: application/json\n%s%s%s",
             (api_key && *api_key) ? "Authorization: Bearer " : "",
             (api_key && *api_key) ? api_key : "", (api_key && *api_key) ? "\n" : "");
    if (write_temp(body_path, body) != 0 || write_temp(hdr_path, headers) != 0) {
        snprintf(err, errlen, "cannot write temporary files: %s", strerror(errno));
        unlink(body_path);
        return -1;
    }
    memset(headers, 0, sizeof headers);
    char cmd[1024];
    snprintf(cmd, sizeof cmd,
             "curl -sS -X POST --max-time %d -H @%s --data-binary @%s -w '\\n%%{http_code}' '%s'",
             timeout_s > 0 ? timeout_s : 60, hdr_path, body_path, url);
    FILE *p = popen(cmd, "r");
    if (!p) {
        snprintf(err, errlen, "cannot run curl: %s", strerror(errno));
        unlink(body_path);
        unlink(hdr_path);
        return -1;
    }
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, p)) > 0) cs_sb_appendn(resp, buf, n);
    int rc = pclose(p);
    unlink(body_path);
    unlink(hdr_path);
    if (rc != 0 && resp->len == 0) {
        snprintf(err, errlen, "curl exited with status %d", rc);
        return -1;
    }
    /* last line is the HTTP status code */
    char *nl = resp->data ? strrchr(resp->data, '\n') : NULL;
    if (!nl) {
        snprintf(err, errlen, "unexpected curl output");
        return -1;
    }
    *status = strtol(nl + 1, NULL, 10);
    *nl = '\0';
    resp->len = (size_t)(nl - resp->data);
    return 0;
}
#endif
