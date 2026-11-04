/* http.h - minimal HTTPS POST used by the AI client.
 *
 * Built with libcurl when available (CALLSCOPE_HAVE_CURL); otherwise it shells
 * out to the `curl` command line tool, passing the API key through a private
 * temporary header file so it never appears in the process list. */
#ifndef CALLSCOPE_HTTP_H
#define CALLSCOPE_HTTP_H

#include "callscope/strbuf.h"

#ifdef __cplusplus
extern "C" {
#endif

/* POST a JSON body. On success returns 0 and sets *status / resp.
 * api_key may be NULL or "" (no Authorization header). */
int cs_http_post_json(void *ctx, const char *url, const char *api_key, const char *body,
                      int timeout_s, cs_strbuf *resp, long *status, char *err, size_t errlen);

/* Which backend this build uses: "libcurl" or "curl-cli". */
const char *cs_http_backend(void);

#ifdef __cplusplus
}
#endif
#endif
