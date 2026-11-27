#define _GNU_SOURCE

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define PROTO_MAGIC 0x4D435354U
#define PROTO_VERSION 1U

#define TYPE_HELLO 0U
#define TYPE_DATA 1U
#define TYPE_VERIFY 2U

#define MIN_NODES 2U
#define MAX_NODES 64U
#define MAX_FRAG_PAYLOAD 1400U
#define MAX_FRAGS 512U
#define MAX_BLOCK_SIZE (MAX_FRAG_PAYLOAD * MAX_FRAGS)
#define MIN_BLOCK_SIZE 8U

#define DEFAULT_GROUP "239.10.10.10"
#define DEFAULT_PORT 5000U
#define DEFAULT_NODES 10U
#define DEFAULT_SIZE 2048U
#define DEFAULT_DURATION 30U
#define DEFAULT_WARMUP 100U
#define DEFAULT_TIMEOUT_US 100000U
#define DEFAULT_MAX_RETRIES 3U
#define DEFAULT_TTL 1U

#define MIN_TIMEOUT_US 100U
#define MAX_TIMEOUT_US 10000000U
#define MAX_RETRIES_LIMIT 100U
#define MIN_TTL 1U
#define MAX_TTL 32U
#define MAX_DURATION_S 86400U
#define MAX_WARMUP_ROUNDS 1000000U

#define HELLO_INTERVAL_MS 20
#define HELLO_QUIET_MS 100
#define HELLO_TIMEOUT_MS 10000
#define VERIFY_INTERVAL_MS 50
#define VERIFY_TIMEOUT_MS 5000

#define SOCK_BUF_BYTES (8 * 1024 * 1024)
#define CSV_BUF_BYTES (1024 * 1024)

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t type;
    uint64_t round;
    uint32_t sender_id;
    uint32_t frag_index;
    uint32_t frag_total;
    uint32_t total_len;
    uint32_t payload_len;
    uint32_t crc;
    uint64_t value;
} pkt_hdr_t;
#pragma pack(pop)

_Static_assert(sizeof(pkt_hdr_t) == 48, "pkt_hdr_t must be exactly 48 bytes");

typedef struct {
    uint32_t id;
    uint32_t nodes;
    char group[64];
    uint16_t port;
    char iface[64];
    uint32_t size;
    uint32_t duration;
    uint32_t warmup;
    uint32_t timeout_us;
    uint32_t max_retries;
    uint32_t ttl;
    char csv_path[256];
    bool dump_config;
    bool crash;
} config_t;

typedef enum {
    ROUND_OK = 0,
    ROUND_TIMEOUT_ABANDON = 1,
    ROUND_PEER_AHEAD_ABANDON = 2,
    ROUND_INTERRUPTED = 3
} round_status_t;

typedef struct {
    round_status_t status;
    uint32_t peer_blocks_ok;
    uint64_t peer_ahead_round;
    uint64_t peer_values[MAX_NODES];
    bool peer_seen[MAX_NODES];
    double wait_us;
} round_result_t;

typedef struct {
    double *samples;
    size_t count;
    size_t cap;
    uint64_t under_200us;
    uint64_t ge_200us;
    uint64_t hist[16];
} stats_t;

static const double HIST_BOUNDS_US[15] = {
    20.0, 50.0, 75.0, 100.0, 125.0, 150.0, 175.0, 200.0,
    300.0, 500.0, 1000.0, 2000.0, 5000.0, 10000.0, 50000.0
};

static volatile sig_atomic_t g_stop = 0;

static void handle_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static uint64_t now_ns(void) {
    struct timespec ts;
#ifdef CLOCK_MONOTONIC_RAW
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == 0) {
        return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    }
#endif
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t htonll_u64(uint64_t v) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((uint64_t)htonl((uint32_t)(v & 0xFFFFFFFFULL)) << 32) |
           (uint64_t)htonl((uint32_t)(v >> 32));
#else
    return v;
#endif
}

static uint64_t ntohll_u64(uint64_t v) {
    return htonll_u64(v);
}

static uint32_t crc32_table[256];
static bool crc32_initialized = false;

static void crc32_init(void) {
    if (crc32_initialized) {
        return;
    }
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) {
            c = (c & 1U) ? (0xEDB88320U ^ (c >> 1)) : (c >> 1);
        }
        crc32_table[i] = c;
    }
    crc32_initialized = true;
}

static uint32_t crc32_compute(const uint8_t *data, size_t len) {
    uint32_t c = 0xFFFFFFFFU;
    for (size_t i = 0; i < len; i++) {
        c = crc32_table[(c ^ data[i]) & 0xFFU] ^ (c >> 8);
    }
    return c ^ 0xFFFFFFFFU;
}

static void config_init_defaults(config_t *c) {
    memset(c, 0, sizeof(*c));
    c->id = 0;
    c->nodes = DEFAULT_NODES;
    snprintf(c->group, sizeof(c->group), "%s", DEFAULT_GROUP);
    c->port = DEFAULT_PORT;
    c->iface[0] = '\0';
    c->size = DEFAULT_SIZE;
    c->duration = DEFAULT_DURATION;
    c->warmup = DEFAULT_WARMUP;
    c->timeout_us = DEFAULT_TIMEOUT_US;
    c->max_retries = DEFAULT_MAX_RETRIES;
    c->ttl = DEFAULT_TTL;
    c->csv_path[0] = '\0';
    c->dump_config = false;
    c->crash = false;
}

static int parse_u32_range(const char *s, uint32_t min_v, uint32_t max_v, uint32_t *out) {
    if (!s || *s == '\0') {
        return -1;
    }
    if (*s == '-' || *s == '+' || isspace((unsigned char)*s)) {
        return -1;
    }
    errno = 0;
    char *end = NULL;
    unsigned long long val = strtoull(s, &end, 10);
    if (errno == ERANGE || end == s || *end != '\0') {
        return -1;
    }
    if (val < (unsigned long long)min_v || val > (unsigned long long)max_v) {
        return -1;
    }
    *out = (uint32_t)val;
    return 0;
}

static bool is_valid_multicast_ipv4(const char *ip) {
    struct in_addr addr;
    if (!ip || inet_pton(AF_INET, ip, &addr) != 1) {
        return false;
    }
    uint32_t host_ip = ntohl(addr.s_addr);
    return (host_ip >= 0xE0000000U && host_ip <= 0xEFFFFFFFU);
}

static int apply_config_kv(const char *key, const char *val, config_t *c,
                           const char *source, unsigned long line_no) {
    uint32_t u = 0;
    if (strcmp(key, "id") == 0) {
        if (parse_u32_range(val, 0, MAX_NODES - 1U, &u) != 0) {
            fprintf(stderr, "%s:%lu: invalid 'id' value '%s' (expected 0..%u)\n",
                    source, line_no, val, MAX_NODES - 1U);
            return -1;
        }
        c->id = u;
    } else if (strcmp(key, "nodes") == 0) {
        if (parse_u32_range(val, MIN_NODES, MAX_NODES, &u) != 0) {
            fprintf(stderr, "%s:%lu: invalid 'nodes' value '%s' (expected %u..%u)\n",
                    source, line_no, val, MIN_NODES, MAX_NODES);
            return -1;
        }
        c->nodes = u;
    } else if (strcmp(key, "group") == 0) {
        if (!is_valid_multicast_ipv4(val)) {
            fprintf(stderr, "%s:%lu: invalid multicast IPv4 'group' value '%s'\n",
                    source, line_no, val);
            return -1;
        }
        snprintf(c->group, sizeof(c->group), "%s", val);
    } else if (strcmp(key, "port") == 0) {
        if (parse_u32_range(val, 1U, 65535U, &u) != 0) {
            fprintf(stderr, "%s:%lu: invalid 'port' value '%s' (expected 1..65535)\n",
                    source, line_no, val);
            return -1;
        }
        c->port = (uint16_t)u;
    } else if (strcmp(key, "iface") == 0) {
        if (strlen(val) >= sizeof(c->iface)) {
            fprintf(stderr, "%s:%lu: 'iface' value too long\n", source, line_no);
            return -1;
        }
        snprintf(c->iface, sizeof(c->iface), "%s", val);
    } else if (strcmp(key, "size") == 0) {
        if (parse_u32_range(val, MIN_BLOCK_SIZE, MAX_BLOCK_SIZE, &u) != 0) {
            fprintf(stderr, "%s:%lu: invalid 'size' value '%s' (expected %u..%u)\n",
                    source, line_no, val, MIN_BLOCK_SIZE, MAX_BLOCK_SIZE);
            return -1;
        }
        c->size = u;
    } else if (strcmp(key, "duration") == 0) {
        if (parse_u32_range(val, 1U, MAX_DURATION_S, &u) != 0) {
            fprintf(stderr, "%s:%lu: invalid 'duration' value '%s' (expected 1..%u)\n",
                    source, line_no, val, MAX_DURATION_S);
            return -1;
        }
        c->duration = u;
    } else if (strcmp(key, "warmup") == 0) {
        if (parse_u32_range(val, 0U, MAX_WARMUP_ROUNDS, &u) != 0) {
            fprintf(stderr, "%s:%lu: invalid 'warmup' value '%s' (expected 0..%u)\n",
                    source, line_no, val, MAX_WARMUP_ROUNDS);
            return -1;
        }
        c->warmup = u;
    } else if (strcmp(key, "timeout_us") == 0 || strcmp(key, "timeout-us") == 0) {
        if (parse_u32_range(val, MIN_TIMEOUT_US, MAX_TIMEOUT_US, &u) != 0) {
            fprintf(stderr, "%s:%lu: invalid 'timeout_us' value '%s' (expected %u..%u)\n",
                    source, line_no, val, MIN_TIMEOUT_US, MAX_TIMEOUT_US);
            return -1;
        }
        c->timeout_us = u;
    } else if (strcmp(key, "max_retries") == 0 || strcmp(key, "max-retries") == 0) {
        if (parse_u32_range(val, 0U, MAX_RETRIES_LIMIT, &u) != 0) {
            fprintf(stderr, "%s:%lu: invalid 'max_retries' value '%s' (expected 0..%u)\n",
                    source, line_no, val, MAX_RETRIES_LIMIT);
            return -1;
        }
        c->max_retries = u;
    } else if (strcmp(key, "ttl") == 0) {
        if (parse_u32_range(val, MIN_TTL, MAX_TTL, &u) != 0) {
            fprintf(stderr, "%s:%lu: invalid 'ttl' value '%s' (expected %u..%u)\n",
                    source, line_no, val, MIN_TTL, MAX_TTL);
            return -1;
        }
        c->ttl = u;
    } else if (strcmp(key, "csv") == 0) {
        if (strlen(val) >= sizeof(c->csv_path)) {
            fprintf(stderr, "%s:%lu: 'csv' path too long\n", source, line_no);
            return -1;
        }
        snprintf(c->csv_path, sizeof(c->csv_path), "%s", val);
    } else {
        fprintf(stderr, "%s:%lu: warning: unknown config key '%s' (ignored)\n",
                source, line_no, key);
    }
    return 0;
}

static void print_help(const char *prog) {
    printf(
        "Usage: %s [OPTIONS]\n"
        "\n"
        "Distributed UDP multicast data exchange.\n"
        "\n"
        "Options:\n"
        "  --config FILE       Read options from file (same format as command line)\n"
        "  --dump-config       Print resolved configuration and exit\n"
        "  --id N              Node ID (0..nodes-1, default 0)\n"
        "  --nodes N           Total nodes (2..64, default 10)\n"
        "  --group IP          Multicast IPv4 group (default 239.10.10.10)\n"
        "  --port N            UDP port (1..65535, default 5000)\n"
        "  --iface NAME|IP     Network interface name (e.g. eth0) or IPv4 address\n"
        "  --size BYTES        Block size (8..%u, default 2048)\n"
        "  --duration SEC      Measurement duration in seconds (1..86400, default 30)\n"
        "  --warmup N          Warmup rounds excluded from stats (default 100)\n"
        "  --timeout-us US     Per-round receive timeout in us (100..10000000, default 100000)\n"
        "  --max-retries N     Retries per round before abandon (0..100, default 3)\n"
        "  --ttl N             IP_MULTICAST_TTL (1..32, default 1)\n"
        "  --csv FILE          Output per-round CSV log path\n"
        "  --crash             Crash the program on purpose (for gdb)\n"
        "  --help              Show this help and exit\n",
        prog, MAX_BLOCK_SIZE
    );
}

static void dump_config(const config_t *c) {
    printf("Resolved configuration:\n");
    printf("  id          = %u\n", c->id);
    printf("  nodes       = %u\n", c->nodes);
    printf("  group       = %s\n", c->group);
    printf("  port        = %u\n", (unsigned)c->port);
    printf("  iface       = %s\n", c->iface[0] ? c->iface : "(default)");
    printf("  size        = %u\n", c->size);
    printf("  duration    = %u\n", c->duration);
    printf("  warmup      = %u\n", c->warmup);
    printf("  timeout_us  = %u\n", c->timeout_us);
    printf("  max_retries = %u\n", c->max_retries);
    printf("  ttl         = %u\n", c->ttl);
    printf("  csv         = %s\n", c->csv_path[0] ? c->csv_path : "(none)");
}

static int parse_cli_layer(int argc, char **argv, config_t *c, bool *want_help) {
    enum {
        OPT_ID = 1000,
        OPT_NODES,
        OPT_GROUP,
        OPT_PORT,
        OPT_IFACE,
        OPT_SIZE,
        OPT_DURATION,
        OPT_WARMUP,
        OPT_TIMEOUT_US,
        OPT_MAX_RETRIES,
        OPT_TTL,
        OPT_CSV,
        OPT_CONFIG,
        OPT_DUMP_CONFIG,
        OPT_CRASH,
        OPT_HELP
    };

    static const struct option long_opts[] = {
        {"id", required_argument, NULL, OPT_ID},
        {"nodes", required_argument, NULL, OPT_NODES},
        {"group", required_argument, NULL, OPT_GROUP},
        {"port", required_argument, NULL, OPT_PORT},
        {"iface", required_argument, NULL, OPT_IFACE},
        {"size", required_argument, NULL, OPT_SIZE},
        {"duration", required_argument, NULL, OPT_DURATION},
        {"warmup", required_argument, NULL, OPT_WARMUP},
        {"timeout-us", required_argument, NULL, OPT_TIMEOUT_US},
        {"max-retries", required_argument, NULL, OPT_MAX_RETRIES},
        {"ttl", required_argument, NULL, OPT_TTL},
        {"csv", required_argument, NULL, OPT_CSV},
        {"config", required_argument, NULL, OPT_CONFIG},
        {"dump-config", no_argument, NULL, OPT_DUMP_CONFIG},
        {"crash", no_argument, NULL, OPT_CRASH},
        {"help", no_argument, NULL, OPT_HELP},
        {NULL, 0, NULL, 0}
    };

    optind = 1;
    opterr = 1;
    int opt;
    while ((opt = getopt_long(argc, argv, "h", long_opts, NULL)) != -1) {
        switch (opt) {
        case OPT_ID:
            if (apply_config_kv("id", optarg, c, "cli", 0) != 0) return -1;
            break;
        case OPT_NODES:
            if (apply_config_kv("nodes", optarg, c, "cli", 0) != 0) return -1;
            break;
        case OPT_GROUP:
            if (apply_config_kv("group", optarg, c, "cli", 0) != 0) return -1;
            break;
        case OPT_PORT:
            if (apply_config_kv("port", optarg, c, "cli", 0) != 0) return -1;
            break;
        case OPT_IFACE:
            if (apply_config_kv("iface", optarg, c, "cli", 0) != 0) return -1;
            break;
        case OPT_SIZE:
            if (apply_config_kv("size", optarg, c, "cli", 0) != 0) return -1;
            break;
        case OPT_DURATION:
            if (apply_config_kv("duration", optarg, c, "cli", 0) != 0) return -1;
            break;
        case OPT_WARMUP:
            if (apply_config_kv("warmup", optarg, c, "cli", 0) != 0) return -1;
            break;
        case OPT_TIMEOUT_US:
            if (apply_config_kv("timeout_us", optarg, c, "cli", 0) != 0) return -1;
            break;
        case OPT_MAX_RETRIES:
            if (apply_config_kv("max_retries", optarg, c, "cli", 0) != 0) return -1;
            break;
        case OPT_TTL:
            if (apply_config_kv("ttl", optarg, c, "cli", 0) != 0) return -1;
            break;
        case OPT_CSV:
            if (apply_config_kv("csv", optarg, c, "cli", 0) != 0) return -1;
            break;
        case OPT_CONFIG:
            break;
        case OPT_DUMP_CONFIG:
            c->dump_config = true;
            break;
        case OPT_CRASH:
            c->crash = true;
            break;
        case OPT_HELP:
        case 'h':
            *want_help = true;
            return 0;
        default:
            return -1;
        }
    }

    if (optind < argc) {
        fprintf(stderr, "cli: unexpected positional argument '%s'\n", argv[optind]);
        return -1;
    }

    return 0;
}

static int validate_config(const config_t *c) {
    if (c->nodes < MIN_NODES || c->nodes > MAX_NODES) {
        fprintf(stderr, "config error: nodes=%u out of range [%u..%u]\n",
                c->nodes, MIN_NODES, MAX_NODES);
        return -1;
    }
    if (c->id >= c->nodes) {
        fprintf(stderr, "config error: id=%u must be < nodes=%u\n", c->id, c->nodes);
        return -1;
    }
    if (!is_valid_multicast_ipv4(c->group)) {
        fprintf(stderr, "config error: invalid multicast group '%s'\n", c->group);
        return -1;
    }
    if (c->size < MIN_BLOCK_SIZE || c->size > MAX_BLOCK_SIZE) {
        fprintf(stderr, "config error: size=%u out of range [%u..%u]\n",
                c->size, MIN_BLOCK_SIZE, MAX_BLOCK_SIZE);
        return -1;
    }
    uint32_t frags = (c->size + MAX_FRAG_PAYLOAD - 1U) / MAX_FRAG_PAYLOAD;
    if (frags == 0U || frags > MAX_FRAGS) {
        fprintf(stderr, "config error: fragment count %u exceeds MAX_FRAGS=%u\n",
                frags, MAX_FRAGS);
        return -1;
    }
    return 0;
}

static int load_config(const char *path, config_t *c, bool *want_help) {
    static char text[4096];
    char *args[64];
    int n = 0;

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        perror(path);
        return -1;
    }
    size_t len = fread(text, 1, sizeof(text) - 1, f);
    fclose(f);
    text[len] = '\0';

    args[n++] = "exchange";
    char *tok = strtok(text, " \t\r\n");
    while (tok != NULL && n < 64) {
        args[n++] = tok;
        tok = strtok(NULL, " \t\r\n");
    }

    return parse_cli_layer(n, args, c, want_help);
}

static int parse_args(int argc, char **argv, config_t *c, bool *want_help) {
    *want_help = false;
    config_init_defaults(c);
    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "--config") == 0) {
            if (load_config(argv[i + 1], c, want_help) != 0) {
                return -1;
            }
        }
    }
    if (parse_cli_layer(argc, argv, c, want_help) != 0) {
        return -1;
    }
    if (*want_help) {
        return 0;
    }
    return validate_config(c);
}

static int setup_socket(const config_t *cfg, struct sockaddr_in *mcast_dst) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
        perror("setsockopt(SO_REUSEADDR)");
        close(fd);
        return -1;
    }
#ifdef SO_REUSEPORT
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) < 0) {
        perror("setsockopt(SO_REUSEPORT)");
        close(fd);
        return -1;
    }
#endif

    int buf_sz = SOCK_BUF_BYTES;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf_sz, sizeof(buf_sz)) < 0) {
        fprintf(stderr, "warning: SO_RCVBUF(%d) failed: %s\n", buf_sz, strerror(errno));
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf_sz, sizeof(buf_sz)) < 0) {
        fprintf(stderr, "warning: SO_SNDBUF(%d) failed: %s\n", buf_sz, strerror(errno));
    }

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(cfg->port);
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }

    struct ip_mreqn mreq;
    memset(&mreq, 0, sizeof(mreq));
    if (inet_pton(AF_INET, cfg->group, &mreq.imr_multiaddr) != 1) {
        fprintf(stderr, "setup_socket: invalid group '%s'\n", cfg->group);
        close(fd);
        return -1;
    }

    if (cfg->iface[0] != '\0') {
        struct in_addr if_ip;
        if (inet_pton(AF_INET, cfg->iface, &if_ip) == 1) {
            mreq.imr_address = if_ip;
        } else {
            unsigned int idx = if_nametoindex(cfg->iface);
            if (idx == 0U) {
                fprintf(stderr, "setup_socket: unknown interface '%s'\n", cfg->iface);
                close(fd);
                return -1;
            }
            mreq.imr_ifindex = (int)idx;
        }
    } else {
        mreq.imr_address.s_addr = htonl(INADDR_ANY);
    }

    if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt(IP_ADD_MEMBERSHIP)");
        close(fd);
        return -1;
    }

    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt(IP_MULTICAST_IF)");
        close(fd);
        return -1;
    }

    unsigned char ttl = (unsigned char)cfg->ttl;
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0) {
        perror("setsockopt(IP_MULTICAST_TTL)");
        close(fd);
        return -1;
    }

    unsigned char loop = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) < 0) {
        perror("setsockopt(IP_MULTICAST_LOOP)");
        close(fd);
        return -1;
    }

    memset(mcast_dst, 0, sizeof(*mcast_dst));
    mcast_dst->sin_family = AF_INET;
    mcast_dst->sin_port = htons(cfg->port);
    mcast_dst->sin_addr = mreq.imr_multiaddr;

    return fd;
}

static void encode_header(pkt_hdr_t *wire, uint16_t type, uint64_t round,
                          uint32_t sender_id, uint32_t frag_index,
                          uint32_t frag_total, uint32_t total_len,
                          uint32_t payload_len, uint32_t crc, uint64_t value) {
    wire->magic = htonl(PROTO_MAGIC);
    wire->version = htons(PROTO_VERSION);
    wire->type = htons(type);
    wire->round = htonll_u64(round);
    wire->sender_id = htonl(sender_id);
    wire->frag_index = htonl(frag_index);
    wire->frag_total = htonl(frag_total);
    wire->total_len = htonl(total_len);
    wire->payload_len = htonl(payload_len);
    wire->crc = htonl(crc);
    wire->value = htonll_u64(value);
}

static bool decode_header(const uint8_t *buf, size_t n, pkt_hdr_t *out) {
    if (n < sizeof(pkt_hdr_t)) {
        return false;
    }
    pkt_hdr_t wire;
    memcpy(&wire, buf, sizeof(wire));
    out->magic = ntohl(wire.magic);
    out->version = ntohs(wire.version);
    out->type = ntohs(wire.type);
    out->round = ntohll_u64(wire.round);
    out->sender_id = ntohl(wire.sender_id);
    out->frag_index = ntohl(wire.frag_index);
    out->frag_total = ntohl(wire.frag_total);
    out->total_len = ntohl(wire.total_len);
    out->payload_len = ntohl(wire.payload_len);
    out->crc = ntohl(wire.crc);
    out->value = ntohll_u64(wire.value);

    if (out->magic != PROTO_MAGIC || out->version != PROTO_VERSION) {
        return false;
    }
    if (sizeof(pkt_hdr_t) + out->payload_len > n) {
        return false;
    }
    return true;
}

static int send_hello(int fd, const struct sockaddr_in *dst, const config_t *cfg) {
    pkt_hdr_t pkt;
    encode_header(&pkt, TYPE_HELLO, 0, cfg->id, 0, 1, 0, 0, 0, 0);
    ssize_t s = sendto(fd, &pkt, sizeof(pkt), 0,
                       (const struct sockaddr *)dst, sizeof(*dst));
    return (s == (ssize_t)sizeof(pkt)) ? 0 : -1;
}

static int send_verify(int fd, const struct sockaddr_in *dst, const config_t *cfg,
                       uint64_t final_round, uint64_t final_value) {
    pkt_hdr_t pkt;
    encode_header(&pkt, TYPE_VERIFY, final_round, cfg->id, 0, 1, 0, 0, 0, final_value);
    ssize_t s = sendto(fd, &pkt, sizeof(pkt), 0,
                       (const struct sockaddr *)dst, sizeof(*dst));
    return (s == (ssize_t)sizeof(pkt)) ? 0 : -1;
}

static void encode_value_in_block(uint8_t *block, uint64_t value) {
    uint64_t net_v = htonll_u64(value);
    memcpy(block, &net_v, sizeof(net_v));
}

static int send_data(int fd, const struct sockaddr_in *dst, const config_t *cfg,
                     uint64_t round, uint64_t value,
                     const uint8_t *block, const uint32_t *frag_crcs,
                     uint32_t frag_total, double *send_us_out) {
    uint8_t pkt_buf[sizeof(pkt_hdr_t) + MAX_FRAG_PAYLOAD];
    uint64_t t0 = now_ns();

    for (uint32_t fi = 0; fi < frag_total; fi++) {
        uint32_t offset = fi * MAX_FRAG_PAYLOAD;
        uint32_t plen = cfg->size - offset;
        if (plen > MAX_FRAG_PAYLOAD) {
            plen = MAX_FRAG_PAYLOAD;
        }
        pkt_hdr_t hdr;
        encode_header(&hdr, TYPE_DATA, round, cfg->id, fi, frag_total,
                      cfg->size, plen, frag_crcs[fi], value);
        memcpy(pkt_buf, &hdr, sizeof(hdr));
        memcpy(pkt_buf + sizeof(hdr), block + offset, plen);

        ssize_t sent = sendto(fd, pkt_buf, sizeof(hdr) + plen, 0,
                              (const struct sockaddr *)dst, sizeof(*dst));
        if (sent != (ssize_t)(sizeof(hdr) + plen)) {
            return -1;
        }
    }

    uint64_t t1 = now_ns();
    if (send_us_out) {
        *send_us_out = (double)(t1 - t0) / 1000.0;
    }
    return 0;
}

static round_result_t receive_for_round(int fd, const config_t *cfg,
                                        uint64_t target_round,
                                        uint32_t expected_frags) {
    round_result_t res;
    memset(&res, 0, sizeof(res));
    res.status = ROUND_TIMEOUT_ABANDON;

    uint8_t frag_bitmap[MAX_NODES][MAX_FRAGS / 8U];
    uint32_t frag_count[MAX_NODES];
    memset(frag_bitmap, 0, sizeof(frag_bitmap));
    memset(frag_count, 0, sizeof(frag_count));

    uint32_t expected_peers = cfg->nodes - 1U;
    uint8_t rx_buf[sizeof(pkt_hdr_t) + MAX_FRAG_PAYLOAD + 64U];

    uint64_t t_start = now_ns();
    uint64_t deadline = t_start + (uint64_t)cfg->timeout_us * 1000ULL;

    while (!g_stop) {
        uint64_t now = now_ns();
        if (now >= deadline) {
            res.status = ROUND_TIMEOUT_ABANDON;
            break;
        }

        uint64_t rem_ns = deadline - now;
        struct timespec ts;
        ts.tv_sec = (time_t)(rem_ns / 1000000000ULL);
        ts.tv_nsec = (long)(rem_ns % 1000000000ULL);

        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        int pr = ppoll(&pfd, 1, &ts, NULL);
        if (pr < 0) {
            if (errno == EINTR) {
                if (g_stop) {
                    res.status = ROUND_INTERRUPTED;
                    break;
                }
                continue;
            }
            res.status = ROUND_TIMEOUT_ABANDON;
            break;
        }
        if (pr == 0) {
            res.status = ROUND_TIMEOUT_ABANDON;
            break;
        }

        ssize_t n = recvfrom(fd, rx_buf, sizeof(rx_buf), MSG_DONTWAIT, NULL, NULL);
        if (n <= 0) {
            continue;
        }

        pkt_hdr_t hdr;
        if (!decode_header(rx_buf, (size_t)n, &hdr)) {
            continue;
        }
        if (hdr.type != TYPE_DATA) {
            continue;
        }
        if (hdr.sender_id >= cfg->nodes || hdr.sender_id == cfg->id) {
            continue;
        }

        if (hdr.round > target_round) {
            res.status = ROUND_PEER_AHEAD_ABANDON;
            res.peer_ahead_round = hdr.round;
            break;
        }
        if (hdr.round < target_round) {
            continue;
        }
        if (hdr.frag_total != expected_frags || hdr.frag_index >= expected_frags ||
            hdr.total_len != cfg->size) {
            continue;
        }

        uint32_t calc_crc = crc32_compute(rx_buf + sizeof(pkt_hdr_t), hdr.payload_len);
        if (calc_crc != hdr.crc) {
            continue;
        }

        uint32_t pid = hdr.sender_id;
        uint32_t byte_idx = hdr.frag_index / 8U;
        uint8_t bit_mask = (uint8_t)(1U << (hdr.frag_index % 8U));
        if ((frag_bitmap[pid][byte_idx] & bit_mask) == 0U) {
            frag_bitmap[pid][byte_idx] |= bit_mask;
            frag_count[pid]++;
            if (hdr.frag_index == 0U) {
                res.peer_values[pid] = hdr.value;
            }
            if (frag_count[pid] == expected_frags && !res.peer_seen[pid]) {
                res.peer_seen[pid] = true;
                res.peer_blocks_ok++;
            }
        }

        if (res.peer_blocks_ok == expected_peers) {
            res.status = ROUND_OK;
            break;
        }
    }

    if (g_stop && res.status != ROUND_OK) {
        res.status = ROUND_INTERRUPTED;
    }

    res.wait_us = (double)(now_ns() - t_start) / 1000.0;
    return res;
}

static int startup_handshake(int fd, const struct sockaddr_in *dst, const config_t *cfg) {
    bool seen[MAX_NODES];
    memset(seen, 0, sizeof(seen));
    seen[cfg->id] = true;
    uint32_t seen_count = 1U;

    uint64_t t_start = now_ns();
    uint64_t deadline = t_start + (uint64_t)HELLO_TIMEOUT_MS * 1000000ULL;
    uint64_t last_send = 0;
    uint64_t all_seen_at = 0;
    uint8_t rx_buf[256];

    fprintf(stderr, "[node %u] HELLO handshake: waiting for %u nodes on %s:%u...\n",
            cfg->id, cfg->nodes, cfg->group, (unsigned)cfg->port);

    while (!g_stop) {
        uint64_t now = now_ns();
        if (now >= deadline) {
            fprintf(stderr, "[node %u] HELLO timeout: saw %u/%u nodes\n",
                    cfg->id, seen_count, cfg->nodes);
            return -1;
        }
        if (seen_count == cfg->nodes && all_seen_at > 0 &&
            (now - all_seen_at) >= (uint64_t)HELLO_QUIET_MS * 1000000ULL) {
            fprintf(stderr, "[node %u] HELLO complete: all %u nodes ready.\n",
                    cfg->id, cfg->nodes);
            return 0;
        }

        if (last_send == 0 || (now - last_send) >= (uint64_t)HELLO_INTERVAL_MS * 1000000ULL) {
            (void)send_hello(fd, dst, cfg);
            last_send = now;
        }

        struct timespec ts = {0, 10000000L};
        struct pollfd pfd = {fd, POLLIN, 0};
        int pr = ppoll(&pfd, 1, &ts, NULL);
        if (pr > 0) {
            ssize_t n = recvfrom(fd, rx_buf, sizeof(rx_buf), MSG_DONTWAIT, NULL, NULL);
            if (n > 0) {
                pkt_hdr_t hdr;
                if (decode_header(rx_buf, (size_t)n, &hdr) &&
                    hdr.type == TYPE_HELLO && hdr.sender_id < cfg->nodes) {
                    if (!seen[hdr.sender_id]) {
                        seen[hdr.sender_id] = true;
                        seen_count++;
                        if (seen_count == cfg->nodes) {
                            all_seen_at = now_ns();
                            (void)send_hello(fd, dst, cfg);
                        }
                    }
                }
            }
        }
    }
    return -1;
}

static uint64_t compute_round(uint64_t my_value, const round_result_t *rr,
                              const config_t *cfg) {
    uint64_t max_val = my_value;
    bool all_equal = true;

    for (uint32_t i = 0; i < cfg->nodes; i++) {
        if (i == cfg->id) {
            continue;
        }
        if (!rr->peer_seen[i]) {
            all_equal = false;
            continue;
        }
        if (rr->peer_values[i] > max_val) {
            max_val = rr->peer_values[i];
        }
        if (rr->peer_values[i] != my_value) {
            all_equal = false;
        }
    }

    uint64_t new_val = max_val;
    if (all_equal && rr->peer_blocks_ok == cfg->nodes - 1U) {
        new_val += 1ULL;
    }
    return new_val;
}

static int run_verification(int fd, const struct sockaddr_in *dst, const config_t *cfg,
                            uint64_t final_round, uint64_t final_value) {
    bool seen[MAX_NODES];
    uint64_t vals[MAX_NODES];
    memset(seen, 0, sizeof(seen));
    memset(vals, 0, sizeof(vals));
    seen[cfg->id] = true;
    vals[cfg->id] = final_value;
    uint32_t seen_count = 1U;

    uint64_t t_start = now_ns();
    uint64_t deadline = t_start + (uint64_t)VERIFY_TIMEOUT_MS * 1000000ULL;
    uint64_t last_send = 0;
    uint64_t all_seen_at = 0;
    uint8_t rx_buf[256];

    while (now_ns() < deadline) {
        uint64_t now = now_ns();
        if (seen_count == cfg->nodes && all_seen_at > 0 &&
            (now - all_seen_at) >= 150000000ULL) {
            break;
        }
        if (last_send == 0 || (now - last_send) >= (uint64_t)VERIFY_INTERVAL_MS * 1000000ULL) {
            (void)send_verify(fd, dst, cfg, final_round, final_value);
            last_send = now;
        }

        struct timespec ts = {0, 10000000L};
        struct pollfd pfd = {fd, POLLIN, 0};
        if (ppoll(&pfd, 1, &ts, NULL) > 0) {
            ssize_t n = recvfrom(fd, rx_buf, sizeof(rx_buf), MSG_DONTWAIT, NULL, NULL);
            if (n > 0) {
                pkt_hdr_t hdr;
                if (decode_header(rx_buf, (size_t)n, &hdr) &&
                    hdr.type == TYPE_VERIFY && hdr.sender_id < cfg->nodes) {
                    if (!seen[hdr.sender_id]) {
                        seen[hdr.sender_id] = true;
                        vals[hdr.sender_id] = hdr.value;
                        seen_count++;
                        if (seen_count == cfg->nodes) {
                            all_seen_at = now_ns();
                            (void)send_verify(fd, dst, cfg, final_round, final_value);
                        }
                    }
                }
            }
        }
    }

    bool match = (seen_count == cfg->nodes);
    for (uint32_t i = 0; i < cfg->nodes; i++) {
        if (!seen[i] || vals[i] != final_value) {
            match = false;
        }
    }

    printf("\n=== VERIFY ===\n");
    printf("Node %u final_value=%" PRIu64 " (seen %u/%u nodes): %s\n",
           cfg->id, final_value, seen_count, cfg->nodes, match ? "PASS" : "FAIL");
    if (!match) {
        for (uint32_t i = 0; i < cfg->nodes; i++) {
            if (seen[i]) {
                printf("  peer %u: value=%" PRIu64 "\n", i, vals[i]);
            } else {
                printf("  peer %u: MISSING\n", i);
            }
        }
    }
    return match ? 0 : 1;
}

static void stats_init(stats_t *st) {
    memset(st, 0, sizeof(*st));
}

static void stats_free(stats_t *st) {
    free(st->samples);
    st->samples = NULL;
    st->count = 0;
    st->cap = 0;
}

static void stats_add(stats_t *st, double v_us) {
    if (st->count == st->cap) {
        size_t new_cap = (st->cap == 0) ? 4096U : st->cap * 2U;
        double *nb = (double *)realloc(st->samples, new_cap * sizeof(double));
        if (!nb) {
            return;
        }
        st->samples = nb;
        st->cap = new_cap;
    }
    st->samples[st->count++] = v_us;

    if (v_us < 200.0) {
        st->under_200us++;
    } else {
        st->ge_200us++;
    }

    size_t b = 15U;
    for (size_t i = 0; i < 15U; i++) {
        if (v_us < HIST_BOUNDS_US[i]) {
            b = i;
            break;
        }
    }
    st->hist[b]++;
}

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

static double percentile(const double *sorted, size_t n, double p) {
    if (n == 0) return 0.0;
    double idx = (p / 100.0) * (double)(n - 1U);
    size_t lo = (size_t)idx;
    size_t hi = (lo + 1U < n) ? (lo + 1U) : lo;
    double frac = idx - (double)lo;
    return sorted[lo] * (1.0 - frac) + sorted[hi] * frac;
}

static void stats_print(const stats_t *st, const config_t *cfg) {
    printf("\n=== EXCHANGE LATENCY STATS (node=%u, nodes=%u, size=%u B) ===\n",
           cfg->id, cfg->nodes, cfg->size);
    if (st->count == 0) {
        printf("No measured rounds.\n");
        return;
    }

    double *sorted = (double *)malloc(st->count * sizeof(double));
    if (!sorted) {
        return;
    }
    memcpy(sorted, st->samples, st->count * sizeof(double));
    qsort(sorted, st->count, sizeof(double), cmp_double);

    double sum = 0.0;
    for (size_t i = 0; i < st->count; i++) {
        sum += sorted[i];
    }
    double mean = sum / (double)st->count;
    double var_sum = 0.0;
    for (size_t i = 0; i < st->count; i++) {
        double d = sorted[i] - mean;
        var_sum += d * d;
    }
    double stddev = sqrt(var_sum / (double)st->count);
    double pct_under = 100.0 * (double)st->under_200us / (double)st->count;

    printf("n=%zu  min=%.2f us  mean=%.2f us  p50=%.2f us  p90=%.2f us  "
           "p95=%.2f us  p99=%.2f us  p99.9=%.2f us  max=%.2f us  stddev=%.2f us\n",
           st->count, sorted[0], mean,
           percentile(sorted, st->count, 50.0),
           percentile(sorted, st->count, 90.0),
           percentile(sorted, st->count, 95.0),
           percentile(sorted, st->count, 99.0),
           percentile(sorted, st->count, 99.9),
           sorted[st->count - 1U], stddev);
    printf("target <200us: %.3f%% (count>=200us: %" PRIu64 ")\n",
           pct_under, st->ge_200us);

    printf("\nHistogram (exchange_us):\n");
    double prev = 0.0;
    for (size_t i = 0; i < 15U; i++) {
        printf("  [%7.0f .. %7.0f) us : %" PRIu64 "\n",
               prev, HIST_BOUNDS_US[i], st->hist[i]);
        prev = HIST_BOUNDS_US[i];
    }
    printf("  [%7.0f ..     inf) us : %" PRIu64 "\n", prev, st->hist[15]);

    free(sorted);
}

static void crash_program(void) {
    volatile int *p = NULL;
    printf("crash test: writing to NULL pointer\n");
    fflush(stdout);
    *p = 42;
}

int main(int argc, char **argv) {
    config_t cfg;
    bool want_help = false;

    if (parse_args(argc, argv, &cfg, &want_help) != 0) {
        fprintf(stderr, "Use --help for usage.\n");
        return 1;
    }
    if (want_help) {
        print_help(argv[0]);
        return 0;
    }
    if (cfg.dump_config) {
        dump_config(&cfg);
        return 0;
    }
    if (cfg.crash) {
        crash_program();
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    crc32_init();

    struct sockaddr_in mcast_dst;
    int fd = setup_socket(&cfg, &mcast_dst);
    if (fd < 0) {
        return 1;
    }

    FILE *csv_fp = NULL;
    char *csv_buf = NULL;
    if (cfg.csv_path[0] != '\0') {
        csv_fp = fopen(cfg.csv_path, "w");
        if (!csv_fp) {
            perror("fopen(csv)");
            close(fd);
            return 1;
        }
        csv_buf = (char *)malloc(CSV_BUF_BYTES);
        if (csv_buf) {
            setvbuf(csv_fp, csv_buf, _IOFBF, CSV_BUF_BYTES);
        }
        fprintf(csv_fp,
                "node_id,round,prepare_us,send_us,exchange_us,wait_us,"
                "compute_us,peer_blocks,retries,status\n");
    }

    uint8_t *block = (uint8_t *)malloc(cfg.size);
    uint32_t frag_total = (cfg.size + MAX_FRAG_PAYLOAD - 1U) / MAX_FRAG_PAYLOAD;
    uint32_t *frag_crcs = (uint32_t *)calloc(frag_total, sizeof(uint32_t));
    if (!block || !frag_crcs) {
        fprintf(stderr, "Out of memory\n");
        free(block);
        free(frag_crcs);
        if (csv_fp) fclose(csv_fp);
        free(csv_buf);
        close(fd);
        return 1;
    }

    for (uint32_t i = 0; i < cfg.size; i++) {
        block[i] = (uint8_t)((i + cfg.id) & 0xFFU);
    }
    for (uint32_t fi = 1; fi < frag_total; fi++) {
        uint32_t offset = fi * MAX_FRAG_PAYLOAD;
        uint32_t plen = cfg.size - offset;
        if (plen > MAX_FRAG_PAYLOAD) plen = MAX_FRAG_PAYLOAD;
        frag_crcs[fi] = crc32_compute(block + offset, plen);
    }

    if (startup_handshake(fd, &mcast_dst, &cfg) != 0) {
        free(block);
        free(frag_crcs);
        if (csv_fp) fclose(csv_fp);
        free(csv_buf);
        close(fd);
        return 1;
    }

    stats_t st;
    stats_init(&st);

    uint64_t my_value = 0;
    uint64_t round = 0;
    uint64_t t_end = now_ns() + (uint64_t)cfg.duration * 1000000000ULL;
    uint64_t measured_rounds = 0;
    uint32_t frag0_len = (cfg.size < MAX_FRAG_PAYLOAD) ? cfg.size : MAX_FRAG_PAYLOAD;

    while (!g_stop && now_ns() < t_end) {
        uint64_t t_prep0 = now_ns();
        encode_value_in_block(block, my_value);
        frag_crcs[0] = crc32_compute(block, frag0_len);
        uint64_t t_prep1 = now_ns();
        double prepare_us = (double)(t_prep1 - t_prep0) / 1000.0;

        double send_us_total = 0.0;
        double wait_us_total = 0.0;
        uint32_t retries = 0;
        round_result_t rr;
        memset(&rr, 0, sizeof(rr));

        for (uint32_t attempt = 0; attempt <= cfg.max_retries; attempt++) {
            double s_us = 0.0;
            if (send_data(fd, &mcast_dst, &cfg, round, my_value,
                          block, frag_crcs, frag_total, &s_us) != 0) {
                fprintf(stderr, "[node %u] round %" PRIu64 ": send_data failed: %s\n",
                        cfg.id, round, strerror(errno));
            }
            send_us_total += s_us;

            rr = receive_for_round(fd, &cfg, round, frag_total);
            wait_us_total += rr.wait_us;

            if (rr.status == ROUND_OK || rr.status == ROUND_PEER_AHEAD_ABANDON ||
                rr.status == ROUND_INTERRUPTED) {
                break;
            }
            if (attempt < cfg.max_retries) {
                retries++;
            }
        }

        if (rr.status == ROUND_INTERRUPTED) {
            break;
        }

        double exchange_us = prepare_us + send_us_total + wait_us_total;

        uint64_t t_comp0 = now_ns();
        if (rr.status == ROUND_OK) {
            my_value = compute_round(my_value, &rr, &cfg);
        }
        uint64_t t_comp1 = now_ns();
        double compute_us = (double)(t_comp1 - t_comp0) / 1000.0;

        if (rr.status == ROUND_TIMEOUT_ABANDON) {
            fprintf(stderr, "[node %u] round %" PRIu64
                    ": timeout_abandon after %u retries (got %u/%u peers)\n",
                    cfg.id, round, retries, rr.peer_blocks_ok, cfg.nodes - 1U);
        } else if (rr.status == ROUND_PEER_AHEAD_ABANDON) {
            fprintf(stderr, "[node %u] round %" PRIu64
                    ": peer_ahead_abandon -> jumping to round %" PRIu64 "\n",
                    cfg.id, round, rr.peer_ahead_round);
        }

        if (round >= cfg.warmup && rr.status == ROUND_OK) {
            stats_add(&st, exchange_us);
            measured_rounds++;
        }

        if (csv_fp) {
            fprintf(csv_fp, "%u,%" PRIu64 ",%.3f,%.3f,%.3f,%.3f,%.3f,%u,%u,%d\n",
                    cfg.id, round, prepare_us, send_us_total, exchange_us,
                    wait_us_total, compute_us, rr.peer_blocks_ok, retries,
                    (int)rr.status);
        }

        if (rr.status == ROUND_PEER_AHEAD_ABANDON && rr.peer_ahead_round > round) {
            round = rr.peer_ahead_round;
        } else {
            round++;
        }
    }

    stats_print(&st, &cfg);
    printf("Total rounds=%" PRIu64 ", measured_ok=%" PRIu64 "\n", round, measured_rounds);

    int verify_rc = run_verification(fd, &mcast_dst, &cfg, round, my_value);

    stats_free(&st);
    free(block);
    free(frag_crcs);
    if (csv_fp) fclose(csv_fp);
    free(csv_buf);
    close(fd);

    return verify_rc;
}
