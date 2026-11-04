/* gen.h - synthetic trace generator.
 *
 * Produces realistic function + network traces of a small "order service"
 * (handle_request -> reserve_inventory -> charge_payment -> write_receipt)
 * with a fault injected according to the scenario. Used for demos, tests and
 * for evaluating the detectors and the RCA engine against a known answer. */
#ifndef CALLSCOPE_GEN_H
#define CALLSCOPE_GEN_H

#include <stdint.h>

#include "callscope/eventlog.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cs_gen_opts {
    const char *scenario; /* see cs_gen_scenarios() */
    int requests;         /* default 40 */
    uint32_t seed;        /* default 42 */
    int64_t start_ns;     /* default: 2026-11-04T09:30:00Z */
    int threads;          /* worker threads, default 2 */
} cs_gen_opts;

typedef struct cs_gen_scenario_info {
    const char *name;
    const char *summary;
    const char *expected_root; /* detector id the RCA should blame */
} cs_gen_scenario_info;

/* NULL-terminated list of scenarios. */
const cs_gen_scenario_info *cs_gen_scenarios(void);
const cs_gen_scenario_info *cs_gen_find(const char *name);

/* Generate events into log (cs_eventlog_finish is called). */
int cs_gen_run(cs_eventlog *log, const cs_gen_opts *opts, char *err, size_t errlen);

#ifdef __cplusplus
}
#endif
#endif
