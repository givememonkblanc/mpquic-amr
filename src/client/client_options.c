#include "client_runtime.h"

static int parse_port_arg(const char* s, int* out) {
    char* end = NULL;
    long v;

    if (!s || !*s || !out) return -1;
    v = strtol(s, &end, 10);
    if (end == s || *end != '\0') return -1;
    if (v < 1 || v > 65535) return -1;
    *out = (int)v;
    return 0;
}

int client_options_parse(int argc, char** argv, client_options_t* opts) {
    if (!opts) return -1;

    memset(opts, 0, sizeof(*opts));
    snprintf(opts->server_ip, sizeof(opts->server_ip), "%s", "192.168.0.80");
    snprintf(opts->primary_local_ip, sizeof(opts->primary_local_ip), "%s", "192.168.0.13");
    snprintf(opts->backup_local_ip, sizeof(opts->backup_local_ip), "%s", "172.20.10.3");
    opts->port = 4433;

    if (argc < 3) {
        fprintf(stderr, "usage: %s <server_ip> <primary_local_ip> [port] [backup_local_ip]\n", argv[0]);
        return -1;
    }

    if (argc > 1 && argv[1][0]) {
        snprintf(opts->server_ip, sizeof(opts->server_ip), "%s", argv[1]);
    }
    if (argc > 2 && argv[2][0]) {
        snprintf(opts->primary_local_ip, sizeof(opts->primary_local_ip), "%s", argv[2]);
    }
    if (argc > 3 && argv[3][0] && parse_port_arg(argv[3], &opts->port) != 0) {
        fprintf(stderr, "invalid port: %s\n", argv[3]);
        fprintf(stderr, "usage: %s <server_ip> <primary_local_ip> [port] [backup_local_ip]\n", argv[0]);
        return -1;
    }
    if (argc > 4 && argv[4][0]) {
        snprintf(opts->backup_local_ip, sizeof(opts->backup_local_ip), "%s", argv[4]);
    }

    return 0;
}
