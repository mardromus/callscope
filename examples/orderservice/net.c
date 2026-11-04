/* Minimal blocking TCP client helpers used by the order service. */
#include "orderservice.h"

#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

int dial(const char *hostport) {
    char host[128], port[16];
    const char *colon = strrchr(hostport, ':');
    if (!colon) return -1;
    snprintf(host, sizeof host, "%.*s", (int)(colon - hostport), hostport);
    snprintf(port, sizeof port, "%s", colon + 1);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0 || !res) {
        cs_error("DNS_FAILURE", "cannot resolve %s", host);
        return -1;
    }
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }
    struct timeval tv = {3, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* Send one request line and read one reply line. Returns bytes read, 0 on
 * EOF, -1 on error. */
ssize_t roundtrip(int fd, const char *req, char *reply, size_t n) {
    if (send(fd, req, strlen(req), 0) < 0) return -1;
    ssize_t got = recv(fd, reply, n - 1, 0);
    if (got >= 0) reply[got] = '\0';
    return got;
}
