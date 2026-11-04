/* orderservice - a small instrumented C program for callscope demos.
 *
 * Each request: parse_order -> validate_order -> reserve_inventory (TCP to the
 * inventory service) -> charge_payment (TCP to the payment service, with
 * retries) -> write_receipt. Built with -finstrument-functions and linked with
 * libcallscope_trace, so `callscope record` captures function AND network
 * calls in one trace.
 *
 *   orderservice --inventory 127.0.0.1:9101 --payment 127.0.0.1:9102 \
 *                --requests 10 [--bug-null-reply] [--bug-recursion] */
#include "orderservice.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void sleep_ms(long ms) {
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

order parse_order(int n) {
    static const char *const customers[] = {"asha", "rohan", "meera", "kabir"};
    order o = {1000 + n, 1 + n % 3, 499 + 250 * (n % 5), customers[n % 4]};
    return o;
}

int validate_order(const order *o) {
    return o->qty > 0 && o->amount_cents > 0 && o->customer != NULL;
}

int reserve_inventory(const config *cfg, const order *o) {
    int fd = dial(cfg->inventory);
    if (fd < 0) {
        cs_error("INVENTORY_UNAVAILABLE", "cannot reach inventory for order %d", o->id);
        return -1;
    }
    char req[64], reply[64];
    snprintf(req, sizeof req, "RESERVE %d %d\n", o->id, o->qty);
    ssize_t got = roundtrip(fd, req, reply, sizeof reply);
    close(fd);
    return got > 0 ? 0 : -1;
}

/* The demo bug: on a missing reply this returns NULL and the caller uses it. */
const char *parse_payment_response(const char *reply, ssize_t got) {
    if (got <= 0) return NULL;
    return strncmp(reply, "OK", 2) == 0 ? reply + 3 : NULL;
}

int charge_payment(const config *cfg, const order *o) {
    for (int attempt = 1; attempt <= 3; attempt++) {
        int fd = dial(cfg->payment);
        if (fd < 0) {
            cs_log("warn", "payment connect failed (attempt %d), retrying", attempt);
            sleep_ms(100);
            continue;
        }
        char req[64], reply[64] = "";
        snprintf(req, sizeof req, "CHARGE %d %d\n", o->id, o->amount_cents);
        ssize_t got = roundtrip(fd, req, reply, sizeof reply);
        close(fd);
        const char *txn = parse_payment_response(reply, got);
        if (cfg->bug_null_reply) {
            /* BUG (intentional): txn is NULL when the reply is missing */
            size_t len = strlen(txn);
            return len > 0 ? 0 : -1;
        }
        if (!txn) {
            cs_error("PAYMENT_FAILED", "no valid reply for order %d", o->id);
            return -1;
        }
        return 0;
    }
    cs_error("PAYMENT_UNAVAILABLE", "payment service unreachable after 3 attempts (order %d)",
             o->id);
    return -1;
}

int render_template(const char *tpl, int depth) {
    /* BUG (optional): the include check never terminates for "{{>receipt}}" */
    if (strstr(tpl, "{{>receipt}}")) return render_template(tpl, depth + 1) + 1;
    return (int)strlen(tpl) + depth;
}

int write_receipt(const config *cfg, const order *o) {
    char tpl[128];
    snprintf(tpl, sizeof tpl, "Receipt #%d for %s: %d.%02d%s", o->id, o->customer,
             o->amount_cents / 100, o->amount_cents % 100, cfg->bug_recursion ? " {{>receipt}}" : "");
    return render_template(tpl, 0) > 0 ? 0 : -1;
}

int handle_request(const config *cfg, int n) {
    order o = parse_order(n);
    if (!validate_order(&o)) return -1;
    if (reserve_inventory(cfg, &o) != 0) return -1;
    if (charge_payment(cfg, &o) != 0) return -1;
    return write_receipt(cfg, &o);
}

int main(int argc, char **argv) {
    config cfg = {"127.0.0.1:9101", "127.0.0.1:9102", 10, 0, 0};
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--inventory") && i + 1 < argc) cfg.inventory = argv[++i];
        else if (!strcmp(argv[i], "--payment") && i + 1 < argc) cfg.payment = argv[++i];
        else if (!strcmp(argv[i], "--requests") && i + 1 < argc) cfg.requests = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--bug-null-reply")) cfg.bug_null_reply = 1;
        else if (!strcmp(argv[i], "--bug-recursion")) cfg.bug_recursion = 1;
    }
    int ok = 0;
    for (int n = 0; n < cfg.requests; n++) {
        if (handle_request(&cfg, n) == 0) ok++;
        sleep_ms(20);
    }
    printf("orderservice: %d/%d orders completed\n", ok, cfg.requests);
    return ok == cfg.requests ? 0 : 1;
}
