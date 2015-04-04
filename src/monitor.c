#define _GNU_SOURCE

#include<stdlib.h>
#include<string.h>
#include<stdio.h>
#include<stdint.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<arpa/inet.h>
#include<linux/if_ether.h>
#include<glib.h>
#include<time.h>

#include "lookup.h"
#include "monitor.h"
#include "queue.h"

#define DEFAULT_TIMEOUT 240

#define PROTO_TCP 6
#define ETH_HEADER(x) ((struct ethhdr *) (x))
#define IP_HEADER(x) ((struct iphdr *) ((x) + sizeof(struct ethhdr)))
#define TCP_HEADER(x) ((struct tcphdr *) ((x) + sizeof(struct ethhdr) + sizeof(struct iphdr)))

#define SESSION_TO_KEY(x) GINT_TO_POINTER((x)->source > (x)->dest ? \
        (uint64_t) ((((uint64_t) (x)->dest) << 32) | (uint64_t) (x)->source) : \
        (uint64_t) ((((uint64_t) (x)->source) << 32) | (uint64_t) (x)->dest))

typedef enum connection_state_t {
    CONNECTION_STATE_UNKNOWN,
    CONNECTION_STATE_SYN_SENT,
    CONNECTION_STATE_SYN_RECEIVED,
    CONNECTION_STATE_ESTABLISHED,
    CONNECTION_STATE_FIN_WAIT_1,
    CONNECTION_STATE_FIN_WAIT_2,
    CONNECTION_STATE_LAST_ACK,
    CONNECTION_STATE_CLOSED,
    CONNECTION_STATE_SIZE
} connection_state_t;

const char* connection_state[] = { "STATE_UNKNOWN",
    "SYN_SENT",
    "SYN_RECEIVED",
    "ESTABLISHED",
    "FIN_WAIT_1",
    "FIN_WAIT_2",
    "LAST_ACK",
    "CONNECTION_STATE_CLOSED" };

struct monitor_t {
    GHashTable *connections;
    GHashTable *hosts;
    GQueue *timeout_list;
    lookup_t *ip_lookup;
    pthread_t *thread;
    pthread_mutex_t *req_lock;
    struct my_queue *in_que;
};

typedef struct session_t {
    uint32_t source;
    uint32_t dest;
    uint16_t sport;
    uint16_t dport;
    connection_state_t state;
    time_t last_update;
    uint64_t packets;
    uint32_t bytes;
} session_t;

//SESSION RELATED
static session_t* _session_create(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport);
static void _session_destroy(void *to_free);
static int _session_compare(const void* a, const void* b);
static void _session_print(void* data, void* unused);

//MONITOR RELATED
static session_t* _monitor_get_session(monitor_t* monitor, const session_t* to_find);
static void _monitor_add_host(monitor_t* monitor, uint32_t addr);
static int _monitor_new_session(monitor_t* monitor, const session_t* new_session);
static void _monitor_remove_session(monitor_t* monitor, const session_t* to_remove);
static void _monitor_update_session(monitor_t* monitor, const session_t* to_update);
static void* _monitor_process_queue(void * arg);

static void _session_destroy(void *to_free)
{
    free(to_free);
}

static void _sessions_destroy(void *to_free)
{
    g_list_free_full((GList *)to_free, free);
}

static session_t* _session_create(uint32_t saddr,
                                  uint32_t daddr,
                                  uint16_t sport,
                                  uint16_t dport)
{
    session_t *new = malloc(sizeof(session_t));

    *new = (session_t) { .source = saddr,
                         .dest = daddr,
                         .sport = sport,
                         .dport = dport,
                         .bytes = 0 };
    return new;
}


static int _session_compare(const void* a, const void* b)
{
    const session_t *_a = a;
    const session_t *_b = b;

    return !((_a->sport == _b->sport && _a->dport == _b->dport) ||
            (_a->dport == _b->sport && _a->sport == _b->dport));
}

static session_t* _get_session(GList* conn,
                               const session_t* to_find)
{
    if (!conn) return NULL;
    GList *found = g_list_find_custom(conn,
                                      to_find,
                                      _session_compare);
    return !found ? NULL : (session_t *) found->data;
}

monitor_t* monitor_init(void)
{
    monitor_t *new = malloc(sizeof(monitor_t));
    new->connections = g_hash_table_new_full(g_direct_hash,
                                             g_direct_equal,
                                             NULL,
                                             NULL);
    new->hosts = g_hash_table_new_full(g_direct_hash,
                                       g_direct_equal,
                                       NULL,
                                       free);
    new->ip_lookup = lookup_init(DB_PATH);
    new->in_que = new_queue();
    new->req_lock = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init( new->req_lock, NULL);
    new->thread = malloc(sizeof(pthread_t));
    pthread_create(new->thread, NULL, _monitor_process_queue, new);
    new->timeout_list = g_queue_new();
    return new;
}

int monitor_host_exist(monitor_t* monitor, uint32_t addr)
{
    return g_hash_table_lookup_extended(monitor->hosts,
                                        GINT_TO_POINTER(addr),
                                        NULL,
                                        NULL);
}

void _host_print_info(void *key, void* value, void* host_str)
{
    char **h = host_str;
    char *tmp = NULL;

    uint32_t addr = GPOINTER_TO_INT(key);
    loc_t *location = value;

    asprintf(&tmp, "%s%s:\n"
             "Latitude  - %f\n"
             "Longitude - %f\n"
             "Country   - %s\n",
             *h ? *h : "",
             inet_ntoa(*(struct in_addr*)&addr),
             location->latitude,
             location->longitude,
             location->country);
    free(*h);
    *h = tmp;
}

static char *monitor_print_hosts(monitor_t* monitor)
{
    char* host_str = NULL;
    g_hash_table_foreach(monitor->hosts,
                         _host_print_info,
                         &host_str);
    return host_str;
}

static void _session_print(void* data, void* session_str)
{
    if (!data) return;

    char **s = session_str;
    char *tmp = NULL;
    session_t *session = data;

    char* source = strdup(inet_ntoa(*(struct in_addr*)&session->source));
    char* dest = strdup(inet_ntoa(*(struct in_addr*)&session->dest));

    printf("%s<%s> %s:%u => %s:%u(%lu => %u)\n",
            *s ? *s : "",
            connection_state[session->state],
            source,
            ntohs(session->sport),
            dest,
            ntohs(session->dport),
            session->packets,
            session->bytes);
    free(source);
    free(dest);
    free(*s);
    *s = tmp;
}

static void _sessions_print(void* k, void* d, void* session_str)
{
    g_list_foreach((GList*) d, _session_print, session_str);
}

static char *monitor_print_sessions(monitor_t* monitor)
{
    char* session_str = NULL;
    g_hash_table_foreach(monitor->connections,
                         _sessions_print,
                         &session_str);
    return session_str;
}

static void _monitor_add_host(monitor_t* monitor, uint32_t addr)
{
    if (monitor_host_exist(monitor, addr)) return;

    struct loc_t *host_location = lookup_ip_location(monitor->ip_lookup,
                                                     addr);
    if (!host_location) return;
    g_hash_table_insert(monitor->hosts,
                        GINT_TO_POINTER(addr),
                        host_location);
}

static int _monitor_new_session(monitor_t* monitor, const session_t* new_session)
{
    if (!monitor || !new_session) return -1;

    pthread_mutex_lock(monitor->req_lock);
    GList *sessions = g_hash_table_lookup(monitor->connections,
                                          SESSION_TO_KEY(new_session));

    session_t *sess = _session_create(new_session->source,
                                      new_session->dest,
                                      new_session->sport,
                                      new_session->dport);
    sessions = g_list_prepend(sessions, sess);
    g_hash_table_insert(monitor->connections,
                        SESSION_TO_KEY(sess),
                        sessions);
    //collapse?
    _monitor_add_host(monitor, sess->source);
    _monitor_add_host(monitor, sess->dest);

    pthread_mutex_unlock(monitor->req_lock);
    return 0;
}

static void _monitor_remove_session(monitor_t* monitor, const session_t* to_remove)
{
    if (!monitor || !to_remove) return;
    //We make a copy in case the to_remove pointer is the actual pointer in
    //memory... YIKES.  Ponder on how we should rearchitect to avoid this.
    session_t _to_remove = *to_remove;
    pthread_mutex_lock(monitor->req_lock);
    GList *sessions = g_hash_table_lookup(monitor->connections,
                                          SESSION_TO_KEY(&_to_remove));
    session_t* found = _get_session(sessions, &_to_remove);
    if (!found) return;
    sessions = g_list_remove(sessions, found);
    _session_destroy(found);
    if (!g_list_length(sessions)) {
        g_list_free(sessions);
        g_hash_table_remove(monitor->connections,
                            SESSION_TO_KEY(&_to_remove));
    }
    else {
        g_hash_table_insert(monitor->connections,
                            SESSION_TO_KEY(&_to_remove),
                            sessions);
    }
    pthread_mutex_unlock(monitor->req_lock);
}

static void _monitor_update_session(monitor_t* monitor, const session_t* to_update)
{
    session_t *sess = _monitor_get_session(monitor, to_update);
    if (!sess) return;
    pthread_mutex_lock(monitor->req_lock);
    sess->bytes += to_update->bytes;
    sess->packets++;
    pthread_mutex_unlock(monitor->req_lock);
}

static session_t* _monitor_get_session(monitor_t* monitor, const session_t* to_find)
{
    if (!monitor || !to_find) return NULL;

    session_t* result = NULL;

    pthread_mutex_lock(monitor->req_lock);
    GList *conns = g_hash_table_lookup(monitor->connections,
                                       SESSION_TO_KEY(to_find));
    result = _get_session(conns, to_find);
    pthread_mutex_unlock(monitor->req_lock);
    return result;
}

static int _compare_timeouts(const void* a, const void* b, void* unused)
{
    const session_t* _a = a;
    const session_t* _b = b;

    if (_a->last_update < _b->last_update) return -1;
    else if (_a->last_update == _b->last_update) return 0;
    return 1;
}

static void _monitor_update_timeout(monitor_t* monitor, session_t* session)
{
    if (!monitor || !session) return;

    time_t now = time(NULL);

    g_queue_remove(monitor->timeout_list, session);
    session->last_update = now;
    g_queue_insert_sorted(monitor->timeout_list, session, _compare_timeouts, NULL);
}

static void _monitor_timeout_sessions(monitor_t* monitor)
{
    time_t now = time(NULL);
    session_t* next = NULL;

    while (next = g_queue_peek_head(monitor->timeout_list)) {
        if (next->last_update + DEFAULT_TIMEOUT < now) {
            next = g_queue_pop_head(monitor->timeout_list);
            _monitor_remove_session(monitor, next);
        }
        else break;
    }
}

static void *_monitor_process_queue(void* arg)
{
    monitor_t *monitor = arg;

    while (1) {
        u_char* packet = my_queue_pop_timed(monitor->in_que, 5);
        struct ethhdr *eth = ETH_HEADER(packet);
        struct iphdr *ip = IP_HEADER(packet);
        struct tcphdr *tcp = TCP_HEADER(packet);

        if (packet &&
            ntohs(eth->h_proto) == ETH_P_IP &&
            ip->protocol == PROTO_TCP)
        {
            uint32_t data_size = ntohs(ip->tot_len) - (ip->ihl * 4) - (tcp->doff * 4);
            struct session_t session = (session_t) { .source = ip->saddr,
                                                     .dest = ip->daddr,
                                                     .sport = tcp->source,
                                                     .dport = tcp->dest,
                                                     .bytes = data_size };
            //Can optimiize this
            session_t *sess = _monitor_get_session(monitor, &session);
            if (!sess) {
                if (_monitor_new_session(monitor, &session)) {
                    continue;
                }
                sess = _monitor_get_session(monitor, &session);
            }

            _monitor_update_timeout(monitor, sess);
            //Right now we just close the connection on unexpected response.
            //Should more effort be put into identifying and reporting what caused
            //the closed connection????
            switch (sess->state) {
                case CONNECTION_STATE_SYN_SENT:
                    if (tcp->syn && tcp->ack) {
                        sess->state = CONNECTION_STATE_SYN_RECEIVED;
                    }
                    else {
                        sess->state = CONNECTION_STATE_CLOSED;
                    }
                    break;
                case CONNECTION_STATE_SYN_RECEIVED:
                    if (tcp->ack && !(tcp->syn || tcp->fin || tcp->rst)) {
                        sess->state = CONNECTION_STATE_ESTABLISHED;
                    }
                    else {
                        sess->state = CONNECTION_STATE_CLOSED;
                    }
                    break;
                case CONNECTION_STATE_ESTABLISHED:
                    if (tcp->fin) {
                        sess->state = CONNECTION_STATE_FIN_WAIT_1;
                    }
                    if (tcp->rst) {
                        sess->state = CONNECTION_STATE_CLOSED;
                    }
                    else {
                        _monitor_update_session(monitor, &session);
                    }
                    break;
                case CONNECTION_STATE_FIN_WAIT_1:
                    if (!tcp->fin && tcp->ack) {
                        sess->state = CONNECTION_STATE_FIN_WAIT_2;
                    }
                    else if (tcp->fin && tcp->ack) {
                        sess->state = CONNECTION_STATE_LAST_ACK;
                    }
                    else {
                        sess->state = CONNECTION_STATE_CLOSED;
                    }
                    break;
                case CONNECTION_STATE_FIN_WAIT_2:
                    if (tcp->fin) {
                        sess->state = CONNECTION_STATE_LAST_ACK;
                    }
                    else {
                        sess->state = CONNECTION_STATE_CLOSED;
                    }
                    break;
                case CONNECTION_STATE_LAST_ACK:
                    if (tcp->ack) {
                        sess->state = CONNECTION_STATE_CLOSED;
                    }
                    //fallthrough intentional
                case CONNECTION_STATE_CLOSED:
                    break;
                case CONNECTION_STATE_UNKNOWN:
                    //fallthrough intentional
                default:
                    if (tcp->syn && tcp->ack) {
                        sess->state = CONNECTION_STATE_SYN_RECEIVED;
                    }
                    else if (tcp->syn) {
                        sess->state = CONNECTION_STATE_SYN_SENT;
                    }
                    else if (tcp->fin) {
                        sess->state = CONNECTION_STATE_FIN_WAIT_1;
                    }
                    else if (tcp->rst) {
                        sess->state = CONNECTION_STATE_CLOSED;
                    }
                    else {
                        sess->state = CONNECTION_STATE_ESTABLISHED;
                    }
            }
        }
        _monitor_timeout_sessions(monitor);
        free(packet);
    }
    pthread_exit((void *) 0);
}

static request_t* _process_request(monitor_t* monitor, request_type r)
{
    request_t* response = malloc(sizeof(request_t));
    response->req = r;

    switch (r) {
        case REQUEST_TYPE_HOST_TABLE_STR:
            response->response = monitor_print_hosts(monitor);
            break;
        case REQUEST_TYPE_HOST_TABLE_JSON:
            break;
        case REQUEST_TYPE_CONNECTION_TABLE_STR:
            response->response = monitor_print_sessions(monitor);
            break;
        case REQUEST_TYPE_CONNECTION_TABLE_JSON:
            break;
        default:
            break;
    }
    return response;
}

request_t* monitor_data_request(monitor_t* monitor, request_type r)
{
    if (!monitor) return NULL;
    return _process_request(monitor, r);
}

void monitor_process_packet(monitor_t* monitor, const u_char* packet, int len) {
    if (!packet || !monitor || !len) return;
    u_char* copy = malloc(len);
    memcpy(copy, packet, len);
    my_queue_push(monitor->in_que, copy);
}
