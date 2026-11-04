#ifndef ORDERSERVICE_H
#define ORDERSERVICE_H

#include <sys/types.h>

#include "callscope/runtime.h"

typedef struct order {
    int id;
    int qty;
    int amount_cents;
    const char *customer;
} order;

typedef struct config {
    const char *inventory; /* host:port */
    const char *payment;   /* host:port */
    int requests;
    int bug_null_reply;    /* crash when the payment reply is missing */
    int bug_recursion;     /* infinite recursion in the receipt renderer */
} config;

int dial(const char *hostport);
ssize_t roundtrip(int fd, const char *req, char *reply, size_t n);

int handle_request(const config *cfg, int n);

#endif
