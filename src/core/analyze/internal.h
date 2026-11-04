/* Internal helpers shared by the detectors. Not part of the public API. */
#ifndef CALLSCOPE_ANALYZE_INTERNAL_H
#define CALLSCOPE_ANALYZE_INTERNAL_H

#include "callscope/analyze.h"

/* Fill f->stack / f->fn from the frame that was open when event ev_index ran. */
void cs_finding_set_context(const cs_analysis *a, cs_finding *f, size_t ev_index);
/* Same, from a frame index. */
void cs_finding_set_frame(const cs_analysis *a, cs_finding *f, size_t frame);

void cs_detect_function(cs_analysis *a);
void cs_detect_network(cs_analysis *a);
void cs_detect_app(cs_analysis *a);
/* Attribute network time to frames (run before fn stats are built). */
void cs_correlate_net_time(cs_analysis *a);
/* Cross-level findings: run after all other detectors. */
void cs_detect_cross(cs_analysis *a);

#endif
