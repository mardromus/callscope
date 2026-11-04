#ifndef CALLSCOPE_REPORT_INTERNAL_H
#define CALLSCOPE_REPORT_INTERNAL_H

#include "callscope/report.h"

/* Aggregated flame graph (icicle, root at top) of every call path. */
void cs_svg_flamegraph(cs_strbuf *out, const cs_analysis *a, int width, const char *highlight_fn);
/* Per-thread timeline: shallow call bars plus network / error / crash markers. */
void cs_svg_timeline(cs_strbuf *out, const cs_analysis *a, int width);
/* Stable pleasant colour for a function name. */
void cs_color_for(const char *name, char *out, size_t n);

#endif
