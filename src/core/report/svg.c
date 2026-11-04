/* SVG renderers for the HTML report: aggregated flame graph and timeline. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "callscope/hashmap.h"
#include "callscope/timeutil.h"
#include "report_internal.h"

void cs_color_for(const char *name, char *out, size_t n) {
    uint64_t h = cs_hash_str(name ? name : "?");
    int hue = 12 + (int)(h % 34);       /* warm oranges / ambers */
    int sat = 70 + (int)((h >> 8) % 20);
    int light = 58 + (int)((h >> 16) % 14);
    snprintf(out, n, "hsl(%d,%d%%,%d%%)", hue, sat, light);
}

/* ---- flame graph ------------------------------------------------------------ */

typedef struct {
    const char *fn;
    size_t parent, first_child, next_sibling;
    int64_t incl, net_wait, calls, open;
    int depth;
} fnode;

static size_t child_of(cs_vec *nodes, size_t parent, const char *fn) {
    fnode *p = cs_vec_at(nodes, parent);
    for (size_t c = p->first_child; c != CS_NONE; c = ((fnode *)cs_vec_at(nodes, c))->next_sibling)
        if (((fnode *)cs_vec_at(nodes, c))->fn == fn) return c;
    fnode *nn = cs_vec_push_slot(nodes);
    if (!nn) return CS_NONE;
    p = cs_vec_at(nodes, parent); /* may have moved */
    size_t idx = nodes->len - 1;
    nn->fn = fn;
    nn->parent = parent;
    nn->first_child = CS_NONE;
    nn->next_sibling = CS_NONE;
    nn->depth = p->depth + 1;
    /* append to keep chronological order */
    if (p->first_child == CS_NONE) {
        p->first_child = idx;
    } else {
        size_t c = p->first_child;
        while (((fnode *)cs_vec_at(nodes, c))->next_sibling != CS_NONE)
            c = ((fnode *)cs_vec_at(nodes, c))->next_sibling;
        ((fnode *)cs_vec_at(nodes, c))->next_sibling = idx;
    }
    return idx;
}

void cs_svg_flamegraph(cs_strbuf *out, const cs_analysis *a, int width, const char *highlight_fn) {
    const cs_calltree *t = &a->tree;
    if (!t->frames.len) {
        cs_sb_append(out, "<p class=\"muted\">No function-level events in this trace. Build the "
                          "program with <code>-finstrument-functions</code> to see call paths.</p>");
        return;
    }
    cs_vec nodes;
    cs_vec_init(&nodes, sizeof(fnode));
    fnode *root = cs_vec_push_slot(&nodes);
    root->fn = "all threads";
    root->parent = root->first_child = root->next_sibling = CS_NONE;
    root->depth = -1;
    size_t *map = malloc(t->frames.len * sizeof(size_t));
    if (!map) {
        cs_vec_free(&nodes);
        return;
    }
    int64_t total = 0;
    for (size_t i = 0; i < t->frames.len; i++) {
        const cs_frame *f = cs_calltree_frame(t, i);
        size_t parent = f->parent == CS_NONE ? 0 : map[f->parent];
        size_t ni = parent == CS_NONE ? CS_NONE : child_of(&nodes, parent, f->fn);
        map[i] = ni;
        if (ni == CS_NONE) continue;
        fnode *n = cs_vec_at(&nodes, ni);
        n->incl += f->incl;
        n->net_wait += f->net_wait;
        n->calls++;
        n->open += f->open;
        if (f->parent == CS_NONE) total += f->incl;
    }
    free(map);
    ((fnode *)cs_vec_at(&nodes, 0))->incl = total;
    if (total <= 0) total = 1;

    const int row = 21, max_rows = 36;
    int rows = 0;
    for (size_t i = 1; i < nodes.len; i++) {
        int d = ((fnode *)cs_vec_at(&nodes, i))->depth + 1;
        if (d > rows) rows = d;
    }
    if (rows > max_rows) rows = max_rows;
    int height = rows * row + 4;
    cs_sb_appendf(out,
                  "<svg class=\"flame\" viewBox=\"0 0 %d %d\" width=\"100%%\" role=\"img\" "
                  "aria-label=\"Flame graph of all call paths\">",
                  width, height);

    /* iterative DFS carrying x offsets */
    typedef struct {
        size_t node;
        double x;
    } item;
    item *stack = malloc((nodes.len + 1) * sizeof(item));
    size_t sp = 0;
    double x0 = 0;
    for (size_t c = ((fnode *)cs_vec_at(&nodes, 0))->first_child; c != CS_NONE;
         c = ((fnode *)cs_vec_at(&nodes, c))->next_sibling) {
        stack[sp++] = (item){c, x0};
        x0 += (double)((fnode *)cs_vec_at(&nodes, c))->incl / (double)total * width;
    }
    while (sp) {
        item it = stack[--sp];
        const fnode *n = cs_vec_at(&nodes, it.node);
        double w = (double)n->incl / (double)total * width;
        if (w < 0.6 || n->depth >= max_rows) continue;
        double y = n->depth * row;
        char col[40], d1[32];
        cs_color_for(n->fn, col, sizeof col);
        int hot = highlight_fn && strcmp(highlight_fn, n->fn) == 0;
        int pct = n->incl ? (int)(100 * n->net_wait / n->incl) : 0;
        cs_sb_appendf(out, "<g class=\"fr%s\"><title>", hot ? " hot" : "");
        cs_sb_append_html(out, n->fn);
        cs_sb_appendf(out, " - %s across %lld call%s, %d%% waiting on network%s</title>",
                      cs_fmt_dur(n->incl, d1, sizeof d1), (long long)n->calls,
                      n->calls == 1 ? "" : "s", pct, n->open ? ", never returned" : "");
        cs_sb_appendf(out,
                      "<rect x=\"%.2f\" y=\"%.0f\" width=\"%.2f\" height=\"%d\" rx=\"2\" "
                      "fill=\"%s\"/>",
                      it.x, y, w > 1 ? w - 0.5 : w, row - 2, col);
        if (pct > 0 && w > 2)
            cs_sb_appendf(out,
                          "<rect class=\"netw\" x=\"%.2f\" y=\"%.0f\" width=\"%.2f\" height=\"4\"/>",
                          it.x, y + row - 6, (w - 0.5) * pct / 100.0);
        if (w > 36) {
            int chars = (int)(w / 7.2);
            char label[160];
            snprintf(label, sizeof label, "%s", n->fn);
            if ((int)strlen(label) > chars && chars > 2) {
                label[chars - 1] = '\0';
                strcat(label, "\xe2\x80\xa6");
            }
            cs_sb_appendf(out, "<text x=\"%.2f\" y=\"%.0f\">", it.x + 4, y + 14);
            cs_sb_append_html(out, label);
            cs_sb_append(out, "</text>");
        }
        cs_sb_append(out, "</g>");
        double cx = it.x;
        for (size_t c = n->first_child; c != CS_NONE;
             c = ((fnode *)cs_vec_at(&nodes, c))->next_sibling) {
            stack[sp++] = (item){c, cx};
            cx += (double)((fnode *)cs_vec_at(&nodes, c))->incl / (double)total * width;
        }
    }
    free(stack);
    cs_sb_append(out, "</svg>");
    cs_vec_free(&nodes);
}

/* ---- timeline ----------------------------------------------------------------- */

typedef struct {
    int32_t pid, tid;
    int base_depth; /* shallowest depth with frames on this thread */
} lane;

void cs_svg_timeline(cs_strbuf *out, const cs_analysis *a, int width) {
    const cs_eventlog *log = a->log;
    if (!cs_eventlog_count(log)) return;
    lane lanes[10];
    int nl = 0;
    for (size_t i = 0; i < cs_eventlog_count(log) && nl < 10; i++) {
        const cs_event *ev = cs_eventlog_at(log, i);
        int k;
        for (k = 0; k < nl; k++)
            if (lanes[k].pid == ev->pid && lanes[k].tid == ev->tid) break;
        if (k == nl) lanes[nl++] = (lane){ev->pid, ev->tid, 1 << 30};
    }
    for (size_t i = 0; i < a->tree.frames.len; i++) {
        const cs_frame *f = cs_calltree_frame(&a->tree, i);
        for (int k = 0; k < nl; k++)
            if (lanes[k].pid == f->pid && lanes[k].tid == f->tid && f->depth < lanes[k].base_depth)
                lanes[k].base_depth = f->depth;
    }
    const int label_w = 110, sub = 8, sub_rows = 3, mark_h = 16;
    const int lane_h = sub_rows * sub + mark_h + 14;
    int plot_w = width - label_w - 10;
    int height = nl * lane_h + 26;
    int64_t t0 = log->t_min, span = log->t_max - log->t_min;
    if (span <= 0) span = 1;
#define XOF(ts) (label_w + (double)((ts) - t0) / (double)span * plot_w)

    cs_sb_appendf(out, "<svg class=\"timeline\" viewBox=\"0 0 %d %d\" width=\"100%%\" role=\"img\" "
                       "aria-label=\"Timeline per thread\">",
                  width, height);
    for (int k = 0; k < nl; k++) {
        int y = k * lane_h + 4;
        cs_sb_appendf(out, "<text class=\"lane\" x=\"0\" y=\"%d\">tid %d</text>", y + 16, lanes[k].tid);
        cs_sb_appendf(out, "<line class=\"axis\" x1=\"%d\" x2=\"%d\" y1=\"%d\" y2=\"%d\"/>", label_w,
                      width - 10, y + lane_h - 6, y + lane_h - 6);
    }
    /* shallow call bars: base, base+1, base+2 (skipping the base when it spans everything) */
    for (size_t i = 0; i < a->tree.frames.len; i++) {
        const cs_frame *f = cs_calltree_frame(&a->tree, i);
        int k;
        for (k = 0; k < nl; k++)
            if (lanes[k].pid == f->pid && lanes[k].tid == f->tid) break;
        if (k == nl) continue;
        int rel = f->depth - lanes[k].base_depth - 1;
        if (rel < 0 || rel >= sub_rows) continue;
        double x1 = XOF(f->start), x2 = XOF(f->end);
        if (x2 - x1 < 0.4) continue;
        char col[40], d1[32];
        cs_color_for(f->fn, col, sizeof col);
        int y = k * lane_h + 4 + rel * sub;
        cs_sb_appendf(out, "<rect x=\"%.2f\" y=\"%d\" width=\"%.2f\" height=\"%d\" fill=\"%s\">"
                           "<title>",
                      x1, y, x2 - x1, sub - 1, col);
        cs_sb_append_html(out, f->fn);
        cs_sb_appendf(out, " %s%s</title></rect>", cs_fmt_dur(f->incl, d1, sizeof d1),
                      f->open ? " (never returned)" : "");
    }
    /* markers */
    for (size_t i = 0; i < cs_eventlog_count(log); i++) {
        const cs_event *ev = cs_eventlog_at(log, i);
        int k;
        for (k = 0; k < nl; k++)
            if (lanes[k].pid == ev->pid && lanes[k].tid == ev->tid) break;
        if (k == nl) continue;
        int y = k * lane_h + 4 + sub_rows * sub + 3;
        double x = XOF(ev->ts);
        char line[400];
        const char *cls = NULL;
        int slow = cs_event_is_net(ev->kind) && ev->dur >= a->opts.net_slow_ns &&
                   ev->kind != CS_EV_NET_CLOSE;
        int fail = (ev->kind == CS_EV_NET_CONNECT && ev->rc < 0) ||
                   ((ev->kind == CS_EV_NET_SEND || ev->kind == CS_EV_NET_RECV) && ev->rc < 0) ||
                   (ev->kind == CS_EV_NET_DNS && ev->rc != 0);
        if (ev->kind == CS_EV_SIGNAL) cls = "m-crash";
        else if (ev->kind == CS_EV_APP_ERROR) cls = "m-app";
        else if (fail) cls = "m-fail";
        else if (slow) cls = "m-slow";
        else if (cs_event_is_net(ev->kind) && ev->kind != CS_EV_NET_CLOSE) cls = "m-net";
        if (!cls) continue;
        cs_event_describe(ev, line, sizeof line);
        if (slow && !fail) {
            double xs = XOF(ev->ts - ev->dur);
            cs_sb_appendf(out, "<rect class=\"%s\" x=\"%.2f\" y=\"%d\" width=\"%.2f\" height=\"10\">",
                          cls, xs, y, x - xs > 1.5 ? x - xs : 1.5);
        } else if (!strcmp(cls, "m-net")) {
            cs_sb_appendf(out, "<rect class=\"m-net\" x=\"%.2f\" y=\"%d\" width=\"1\" height=\"10\">",
                          x, y);
        } else if (!strcmp(cls, "m-crash")) {
            cs_sb_appendf(out, "<path class=\"m-crash\" d=\"M%.1f %d l10 10 m0 -10 l-10 10\">",
                          x - 5, y);
        } else if (!strcmp(cls, "m-app")) {
            cs_sb_appendf(out, "<path class=\"m-app\" d=\"M%.1f %d l5 5 l-5 5 l-5 -5z\">", x, y);
        } else {
            cs_sb_appendf(out, "<circle class=\"%s\" cx=\"%.1f\" cy=\"%d\" r=\"4\">", cls, x, y + 5);
        }
        cs_sb_append(out, "<title>");
        cs_sb_append_html(out, line);
        cs_sb_append(out, "</title>");
        cs_sb_append(out, (slow && !fail) || !strcmp(cls, "m-net") ? "</rect>"
                          : (!strcmp(cls, "m-crash") || !strcmp(cls, "m-app")) ? "</path>"
                                                                              : "</circle>");
    }
    char d1[32], ts[32];
    cs_sb_appendf(out, "<text class=\"tick\" x=\"%d\" y=\"%d\">%s</text>", label_w, height - 4,
                  cs_fmt_clock(t0, ts, sizeof ts));
    cs_sb_appendf(out, "<text class=\"tick\" x=\"%d\" y=\"%d\" text-anchor=\"end\">+%s</text>",
                  width - 10, height - 4, cs_fmt_dur(span, d1, sizeof d1));
    cs_sb_append(out, "</svg>");
#undef XOF
}
