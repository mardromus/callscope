/* Self-contained HTML report (no external assets) and the JSON report. */
#include <stdio.h>
#include <string.h>

#include "callscope/json.h"
#include "callscope/timeutil.h"
#include "report_internal.h"

static const char *CSS =
    ":root{--bg:#f5f6fa;--card:#fff;--ink:#161a23;--muted:#667085;--line:#e4e7ef;"
    "--accent:#6d28d9;--accent-soft:#f1ebff;--crit:#b42318;--high:#d92d20;--med:#dc6803;"
    "--low:#0e7490;--info:#667085;--net:#0d9488;--ok:#067647}"
    "*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);"
    "font:15px/1.55 ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,sans-serif}"
    "code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}"
    ".wrap{max-width:1180px;margin:0 auto;padding:32px 24px 64px}"
    "header{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;"
    "margin-bottom:22px}.brand{font-weight:800;font-size:26px;letter-spacing:-.02em}"
    ".brand span{color:var(--accent)}.src{color:var(--muted);font-size:13px}"
    ".card{background:var(--card);border:1px solid var(--line);border-radius:14px;"
    "padding:22px 24px;margin-bottom:18px;box-shadow:0 1px 2px rgba(16,24,40,.04)}"
    "h2{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);"
    "margin:0 0 14px}"
    ".verdict{border:1px solid #d9ccff;background:linear-gradient(180deg,#faf7ff,#fff)}"
    ".verdict .sum{font-size:21px;font-weight:700;line-height:1.35;margin:6px 0 12px}"
    ".meta{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px}"
    ".chip{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border-radius:999px;"
    "font-size:12px;font-weight:600;background:var(--accent-soft);color:var(--accent)}"
    ".chip.ghost{background:#f2f4f7;color:var(--muted)}"
    ".conf{display:inline-flex;align-items:center;gap:8px;font-size:12px;color:var(--muted)}"
    ".bar{width:120px;height:8px;background:#eef0f5;border-radius:99px;overflow:hidden}"
    ".bar i{display:block;height:100%;background:linear-gradient(90deg,#8b5cf6,#6d28d9)}"
    ".chain{display:flex;flex-wrap:wrap;gap:8px;align-items:stretch;margin:16px 0}"
    ".step{flex:1 1 200px;border:1px solid var(--line);border-radius:10px;padding:10px 12px;"
    "background:#fff;font-size:13px}.step b{display:block;font-size:11px;color:var(--muted)}"
    ".step.root{border-color:#b692f6;box-shadow:0 0 0 3px #f1ebff}"
    ".arrow{align-self:center;color:#98a2b3;font-size:18px}"
    ".cols{display:grid;grid-template-columns:1fr 1fr;gap:18px}"
    "ol,ul{margin:6px 0 0;padding-left:20px}li{margin:3px 0}"
    ".tiles{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:18px}"
    ".tile{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}"
    ".tile .v{font-size:22px;font-weight:750}.tile .k{font-size:12px;color:var(--muted)}"
    ".tile.bad .v{color:var(--high)}"
    ".sev{font-size:11px;font-weight:700;padding:2px 8px;border-radius:6px;text-transform:"
    "uppercase;letter-spacing:.04em;white-space:nowrap}"
    ".sev.critical{background:var(--crit);color:#fff}.sev.high{background:#fee4e2;color:var(--high)}"
    ".sev.medium{background:#fef0c7;color:var(--med)}.sev.low{background:#cff9fe;color:var(--low)}"
    ".sev.info{background:#f2f4f7;color:var(--info)}"
    ".finding{border-top:1px solid var(--line);padding:14px 0}.finding:first-of-type{border:0}"
    ".finding .t{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}"
    ".finding .id{font-weight:700;color:var(--muted);font-size:13px}"
    ".finding .ti{font-weight:650}.lvl{font-size:12px;color:var(--muted)}"
    ".where{margin:6px 0;padding:6px 10px;background:#f8f9fc;border-radius:8px;"
    "border:1px solid var(--line);overflow-x:auto;white-space:nowrap}"
    ".detail{color:#344054;margin:4px 0}"
    "details summary{cursor:pointer;color:var(--accent);font-size:13px;margin-top:4px}"
    "pre{background:#0f1320;color:#d6dbea;padding:12px 14px;border-radius:10px;overflow-x:auto;"
    "font-size:12.5px;margin:8px 0 0}"
    "table{width:100%;border-collapse:collapse;font-size:13.5px}"
    "th{text-align:left;font-size:12px;color:var(--muted);font-weight:600;border-bottom:1px solid "
    "var(--line);padding:8px 6px}td{border-bottom:1px solid #f0f2f6;padding:8px 6px}"
    "td.n{text-align:right;font-variant-numeric:tabular-nums}"
    ".mini{height:6px;background:#eef0f5;border-radius:99px;min-width:80px}"
    ".mini i{display:block;height:100%;border-radius:99px;background:#f79009}"
    ".mini i.net{background:var(--net)}"
    "svg text{font:11px ui-monospace,Menlo,Consolas,monospace;fill:#1d2433}"
    "svg.flame .fr rect:first-of-type{stroke:#fff;stroke-width:.5}"
    "svg.flame .fr:hover rect:first-of-type{filter:brightness(.9)}"
    "svg.flame .hot rect:first-of-type{stroke:#6d28d9;stroke-width:2}"
    "svg.flame .netw{fill:var(--net);opacity:.85}"
    "svg .lane{fill:var(--muted);font-weight:600}svg .axis{stroke:var(--line)}"
    "svg .tick{fill:var(--muted)}"
    ".m-fail{fill:var(--high)}.m-slow{fill:#f79009;opacity:.8}.m-net{fill:#99f6e4}"
    ".m-app{fill:#7c3aed}.m-crash{stroke:#101828;stroke-width:2.5;fill:none}"
    ".legend{display:flex;gap:16px;flex-wrap:wrap;font-size:12px;color:var(--muted);margin-top:8px}"
    ".legend i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:5px;"
    "vertical-align:-1px}"
    ".muted{color:var(--muted)}.ok{color:var(--ok);font-weight:700}"
    "footer{color:var(--muted);font-size:12px;text-align:center;margin-top:28px}"
    "@media(max-width:900px){.cols{grid-template-columns:1fr}.tiles{grid-template-columns:"
    "repeat(3,1fr)}}";

static void esc(cs_strbuf *o, const char *s) { cs_sb_append_html(o, s ? s : ""); }

static void tile(cs_strbuf *o, const char *k, const char *v, int bad) {
    cs_sb_appendf(o, "<div class=\"tile%s\"><div class=\"v\">", bad ? " bad" : "");
    esc(o, v);
    cs_sb_append(o, "</div><div class=\"k\">");
    esc(o, k);
    cs_sb_append(o, "</div></div>");
}

static void verdict(cs_strbuf *o, const cs_analysis *a, const cs_rca_result *r) {
    cs_sb_append(o, "<section class=\"card verdict\"><h2>Root cause</h2>");
    cs_sb_append(o, "<div class=\"meta\">");
    cs_sb_append(o, "<span class=\"chip\">");
    esc(o, r->category);
    cs_sb_append(o, "</span><span class=\"chip ghost\">");
    esc(o, r->source);
    cs_sb_appendf(o, "</span><span class=\"conf\">confidence <span class=\"bar\"><i style=\"width:%.0f%%\">"
                     "</i></span> %.0f%%</span>",
                  r->confidence * 100, r->confidence * 100);
    if (r->ai_steps) cs_sb_appendf(o, "<span class=\"chip ghost\">%d agent tool calls</span>", r->ai_steps);
    cs_sb_append(o, "</div><div class=\"sum\">");
    esc(o, r->summary);
    cs_sb_append(o, "</div><p class=\"detail\">");
    esc(o, r->explanation);
    cs_sb_append(o, "</p>");
    if (r->found && r->n_chain) {
        cs_sb_append(o, "<div class=\"chain\">");
        for (size_t i = 0; i < r->n_chain; i++) {
            const cs_finding *f = cs_analysis_finding(a, r->chain[i]);
            if (i) cs_sb_append(o, "<span class=\"arrow\">&rarr;</span>");
            cs_sb_appendf(o, "<div class=\"step%s\"><b>%s &middot; %s</b>", i ? "" : " root",
                          r->chain[i], i ? "effect" : "cause");
            esc(o, f ? f->title : r->chain[i]);
            cs_sb_append(o, "</div>");
        }
        cs_sb_append(o, "</div>");
    }
    cs_sb_append(o, "<div class=\"cols\"><div><h2>How to fix</h2><ol>");
    for (size_t i = 0; i < r->n_fixes; i++) {
        cs_sb_append(o, "<li>");
        esc(o, r->fixes[i]);
        cs_sb_append(o, "</li>");
    }
    if (!r->n_fixes) cs_sb_append(o, "<li class=\"muted\">Nothing to fix.</li>");
    cs_sb_append(o, "</ol></div><div><h2>Check next</h2><ul>");
    for (size_t i = 0; i < r->n_checks; i++) {
        cs_sb_append(o, "<li>");
        esc(o, r->checks[i]);
        cs_sb_append(o, "</li>");
    }
    if (!r->n_checks) cs_sb_append(o, "<li class=\"muted\">-</li>");
    cs_sb_append(o, "</ul></div></div>");
    if (r->notes[0]) {
        cs_sb_append(o, "<p class=\"muted\" style=\"margin-top:12px\">");
        esc(o, r->notes);
        cs_sb_append(o, "</p>");
    }
    cs_sb_append(o, "</section>");
}

static void findings(cs_strbuf *o, const cs_analysis *a) {
    cs_sb_appendf(o, "<section class=\"card\"><h2>Findings (%zu)</h2>", a->findings.len);
    if (!a->findings.len) cs_sb_append(o, "<p class=\"ok\">No problems detected.</p>");
    for (size_t i = 0; i < a->findings.len; i++) {
        const cs_finding *f = cs_vec_at(&a->findings, i);
        cs_sb_appendf(o, "<div class=\"finding\" id=\"%s\"><div class=\"t\"><span class=\"id\">%s</span>"
                         "<span class=\"sev %s\">%s</span><span class=\"ti\">",
                      f->id, f->id, cs_severity_name(f->sev), cs_severity_name(f->sev));
        esc(o, f->title);
        cs_sb_appendf(o, "</span><span class=\"lvl\">%s &middot; %s</span></div>",
                      cs_level_name(f->level), f->detector);
        if (f->stack[0]) {
            cs_sb_append(o, "<div class=\"where mono\">");
            esc(o, f->stack);
            cs_sb_append(o, "</div>");
        }
        cs_sb_append(o, "<p class=\"detail\">");
        esc(o, f->detail);
        cs_sb_append(o, "</p>");
        if (f->n_evidence) {
            cs_sb_appendf(o, "<details><summary>%zu evidence event%s</summary><pre>", f->n_evidence,
                          f->n_evidence == 1 ? "" : "s");
            for (size_t k = 0; k < f->n_evidence; k++) {
                char line[512];
                cs_event_describe(cs_eventlog_at(a->log, f->evidence[k]), line, sizeof line);
                cs_sb_appendf(o, "#%-6zu ", f->evidence[k]);
                esc(o, line);
                cs_sb_append(o, "\n");
            }
            cs_sb_append(o, "</pre></details>");
        }
        cs_sb_append(o, "</div>");
    }
    cs_sb_append(o, "</section>");
}

static void tables(cs_strbuf *o, const cs_analysis *a) {
    char d1[32], d2[32], d3[32];
    cs_sb_append(o, "<div class=\"cols\">");
    cs_sb_append(o, "<section class=\"card\"><h2>Functions by exclusive time</h2>");
    if (!a->fns.stats.len) {
        cs_sb_append(o, "<p class=\"muted\">No function-level events.</p>");
    } else {
        int64_t top = ((const cs_fnstat *)cs_vec_at(&a->fns.stats, 0))->excl_total;
        cs_sb_append(o, "<table><tr><th>function</th><th class=\"n\">calls</th><th class=\"n\">"
                        "excl</th><th class=\"n\">p95</th><th>share / net</th></tr>");
        for (size_t i = 0; i < a->fns.stats.len && i < 14; i++) {
            const cs_fnstat *st = cs_vec_at(&a->fns.stats, i);
            int share = top ? (int)(100 * st->excl_total / top) : 0;
            int net = st->incl_total ? (int)(100 * st->net_wait_total / st->incl_total) : 0;
            cs_sb_append(o, "<tr><td class=\"mono\">");
            esc(o, st->fn);
            cs_sb_appendf(o, "</td><td class=\"n\">%lld</td><td class=\"n\">%s</td><td class=\"n\">%s"
                             "</td><td><div class=\"mini\"><i style=\"width:%d%%\"></i></div>"
                             "<div class=\"mini\" style=\"margin-top:3px\"><i class=\"net\" "
                             "style=\"width:%d%%\"></i></div></td></tr>",
                          (long long)st->calls, cs_fmt_dur(st->excl_total, d1, sizeof d1),
                          cs_fmt_dur(st->p95, d2, sizeof d2), share, net);
        }
        cs_sb_append(o, "</table><div class=\"legend\"><span><i style=\"background:#f79009\"></i>"
                        "exclusive time vs top</span><span><i style=\"background:#0d9488\"></i>"
                        "share waiting on network</span></div>");
    }
    cs_sb_append(o, "</section><section class=\"card\"><h2>Network peers</h2>");
    if (!a->net.peers.len && !a->net.dns.len) {
        cs_sb_append(o, "<p class=\"muted\">No network events.</p>");
    } else {
        cs_sb_append(o, "<table><tr><th>peer</th><th class=\"n\">conn</th><th class=\"n\">fail</th>"
                        "<th>error</th><th class=\"n\">conn max</th><th class=\"n\">io max</th></tr>");
        for (size_t i = 0; i < a->net.peers.len && i < 12; i++) {
            const cs_peerstat *p = cs_vec_at(&a->net.peers, i);
            const char *e = cs_peerstat_top_err(p, NULL);
            cs_sb_append(o, "<tr><td class=\"mono\">");
            esc(o, p->peer);
            cs_sb_appendf(o, "</td><td class=\"n\">%lld</td><td class=\"n\"%s>%lld</td><td class=\"mono\">%s"
                             "</td><td class=\"n\">%s</td><td class=\"n\">%s</td></tr>",
                          (long long)(p->attempts + p->accepts),
                          p->failures ? " style=\"color:var(--high);font-weight:700\"" : "",
                          (long long)p->failures, e ? e : "-",
                          cs_fmt_dur(p->connect_max, d1, sizeof d1), cs_fmt_dur(p->io_max, d2, sizeof d2));
        }
        for (size_t i = 0; i < a->net.dns.len && i < 6; i++) {
            const cs_dnsstat *d = cs_vec_at(&a->net.dns, i);
            cs_sb_append(o, "<tr><td class=\"mono\">dns ");
            esc(o, d->host);
            cs_sb_appendf(o, "</td><td class=\"n\">%lld</td><td class=\"n\"%s>%lld</td><td class=\"mono\">%s"
                             "</td><td class=\"n\">-</td><td class=\"n\">%s</td></tr>",
                          (long long)d->lookups,
                          d->failures ? " style=\"color:var(--high);font-weight:700\"" : "",
                          (long long)d->failures, d->last_err ? d->last_err : "-",
                          cs_fmt_dur(d->max_dur, d3, sizeof d3));
        }
        cs_sb_append(o, "</table>");
    }
    cs_sb_append(o, "</section></div>");
}

int cs_report_html(cs_strbuf *o, const cs_analysis *a, const cs_rca_result *r) {
    char d1[32], ts[40], num[48];
    cs_sb_append(o, "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
                    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                    "<title>callscope report</title><style>");
    cs_sb_append(o, CSS);
    cs_sb_append(o, "</style></head><body><div class=\"wrap\"><header><div><div class=\"brand\">"
                    "call<span>scope</span></div><div class=\"src mono\">");
    esc(o, a->log->source[0] ? a->log->source : "stdin");
    cs_sb_appendf(o, "</div></div><div class=\"src\">trace start %s</div></header>",
                  cs_fmt_ts(a->log->t_min, ts, sizeof ts));

    cs_sb_append(o, "<div class=\"tiles\">");
    snprintf(num, sizeof num, "%zu", cs_eventlog_count(a->log));
    tile(o, "events", num, 0);
    tile(o, "time span", cs_fmt_dur(a->span_ns, d1, sizeof d1), 0);
    snprintf(num, sizeof num, "%zu", a->tree.frames.len);
    tile(o, "function calls", num, 0);
    snprintf(num, sizeof num, "%zu", a->n_net_events);
    tile(o, "network events", num, 0);
    snprintf(num, sizeof num, "%zu", a->findings.len);
    tile(o, "findings", num, a->findings.len > 0);
    tile(o, "outcome", a->crashed ? "crashed" : (a->has_exit && a->exit_code) ? "failed" : "ran", a->crashed);
    cs_sb_append(o, "</div>");

    if (r) verdict(o, a, r);

    cs_sb_append(o, "<section class=\"card\"><h2>Timeline</h2>");
    cs_svg_timeline(o, a, 1120);
    cs_sb_append(o, "<div class=\"legend\"><span><i style=\"background:#f6a04d\"></i>calls (depth "
                    "1-3)</span><span><i style=\"background:#99f6e4\"></i>network call</span>"
                    "<span><i style=\"background:#f79009\"></i>slow network wait</span><span><i "
                    "style=\"background:#d92d20;border-radius:50%\"></i>network failure</span><span>"
                    "<i style=\"background:#7c3aed\"></i>app error</span><span><b>&times;</b> "
                    "crash</span></div></section>");

    const cs_finding *root = (r && r->found) ? cs_analysis_finding(a, r->root_id) : NULL;
    cs_sb_append(o, "<section class=\"card\"><h2>Flame graph &middot; all call paths</h2>");
    cs_svg_flamegraph(o, a, 1120, root ? root->fn : NULL);
    cs_sb_append(o, "<div class=\"legend\"><span>width = total time</span><span><i "
                    "style=\"background:#0d9488\"></i>part spent waiting on network</span><span><i "
                    "style=\"background:#fff;border:2px solid #6d28d9\"></i>root-cause function</span>"
                    "</div></section>");

    findings(o, a);
    tables(o, a);
    cs_sb_append(o, "<footer>Generated by callscope &middot; function-level + network-level call "
                    "analysis with root cause detection</footer></div></body></html>\n");
    return 0;
}

int cs_report_json(cs_strbuf *out, const cs_analysis *a, const cs_rca_result *r) {
    cs_sb_append(out, "{\"evidence\":");
    cs_rca_evidence_json(a, NULL, out);
    cs_sb_append(out, ",\"findings\":[");
    for (size_t i = 0; i < a->findings.len; i++) {
        const cs_finding *f = cs_vec_at(&a->findings, i);
        cs_jw w;
        if (i) cs_sb_appendc(out, ',');
        cs_jw_init(&w, out);
        cs_jw_obj_begin(&w);
        cs_jw_kv_str(&w, "id", f->id);
        cs_jw_kv_str(&w, "detector", f->detector);
        cs_jw_kv_str(&w, "severity", cs_severity_name(f->sev));
        cs_jw_kv_str(&w, "level", cs_level_name(f->level));
        cs_jw_kv_str(&w, "title", f->title);
        cs_jw_kv_str(&w, "detail", f->detail);
        cs_jw_kv_str(&w, "where", f->stack);
        cs_jw_kv_num(&w, "score", f->score);
        cs_jw_obj_end(&w);
    }
    cs_sb_append(out, "]");
    if (r) {
        cs_sb_append(out, ",\"rca\":");
        cs_rca_result_json(r, a, out);
    }
    cs_sb_append(out, "}\n");
    return 0;
}
