#include "client_runtime.h"

/* Map MPQUIC_SCHED_MODE to a scheduler. Default (unset/unknown) = the proposed
 * RSSI-aware policy. Accepts aliases so scripts can use natural names. */
static scheduler_mode_t parse_sched_mode(const char* s) {
    if (!s || !*s) return scheduler_mode_rssi;
    if (strcmp(s, "pqi") == 0)                                            return scheduler_mode_pqi;
    if (strcmp(s, "rssi") == 0 || strcmp(s, "rssi-aware") == 0)           return scheduler_mode_rssi;
    if (strcmp(s, "default") == 0 || strcmp(s, "minrtt") == 0 ||
        strcmp(s, "min-rtt") == 0)                                        return scheduler_mode_default;
    if (strcmp(s, "spquic") == 0 || strcmp(s, "sp-migration") == 0)       return scheduler_mode_spquic_migration;
    if (strcmp(s, "rr") == 0 || strcmp(s, "round-robin") == 0 ||
        strcmp(s, "roundrobin") == 0)                                     return scheduler_mode_round_robin;
    if (strcmp(s, "ecf") == 0)                                            return scheduler_mode_ecf;
    if (strcmp(s, "blest") == 0)                                          return scheduler_mode_blest;
    if (strcmp(s, "tof") == 0)                                            return scheduler_mode_tof;
    fprintf(stderr, "[WARN] unknown MPQUIC_SCHED_MODE='%s'; using rssi\n", s);
    return scheduler_mode_rssi;
}

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
    opts->scheduler_mode = parse_sched_mode(getenv("MPQUIC_SCHED_MODE"));

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
