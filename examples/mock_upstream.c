/* mock_upstream - a tiny line-protocol TCP server that can misbehave on demand.
 *
 *   mock_upstream --port 9102 --mode ok|slow|reset|close [--delay-ms 1500]
 *
 *   ok     reply "OK <id>\n" to every request line
 *   slow   wait --delay-ms before replying
 *   reset  abort the connection with a TCP RST instead of replying
 *   close  close the connection without replying
 * (for "refused", simply do not start the server) */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static void sleep_ms(long ms) {
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

int main(int argc, char **argv) {
    int port = 9102;
    long delay = 1500;
    const char *mode = "ok";
    for (int i = 1; i + 1 < argc; i += 2) {
        if (!strcmp(argv[i], "--port")) port = atoi(argv[i + 1]);
        else if (!strcmp(argv[i], "--mode")) mode = argv[i + 1];
        else if (!strcmp(argv[i], "--delay-ms")) delay = atol(argv[i + 1]);
    }
    signal(SIGPIPE, SIG_IGN);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr *)&addr, sizeof addr) != 0 || listen(s, 64) != 0) {
        perror("mock_upstream: bind/listen");
        return 1;
    }
    fprintf(stderr, "mock_upstream: listening on 127.0.0.1:%d mode=%s\n", port, mode);
    for (;;) {
        int c = accept(s, NULL, NULL);
        if (c < 0) continue;
        char buf[256];
        ssize_t n = recv(c, buf, sizeof buf - 1, 0);
        if (n <= 0) {
            close(c);
            continue;
        }
        buf[n] = '\0';
        char id[64] = "0";
        sscanf(buf, "%*s %63s", id);
        if (!strcmp(mode, "reset")) {
            struct linger lg = {1, 0}; /* close() now sends RST */
            setsockopt(c, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
            sleep_ms(5);
            close(c);
            continue;
        }
        if (!strcmp(mode, "close")) {
            close(c);
            continue;
        }
        if (!strcmp(mode, "slow")) sleep_ms(delay);
        char reply[96];
        int m = snprintf(reply, sizeof reply, "OK %s\n", id);
        if (send(c, reply, (size_t)m, 0) < 0) perror("mock_upstream: send");
        close(c);
    }
}
