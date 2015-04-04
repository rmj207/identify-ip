#include<glib/glib.h>
#ifndef __MONITOR__
#define __MONITOR__

struct monitor_t;
typedef struct monitor_t monitor_t;

typedef enum request_type {
    REQUEST_TYPE_HOST_TABLE_STR,
    REQUEST_TYPE_HOST_TABLE_JSON,
    REQUEST_TYPE_CONNECTION_TABLE_STR,
    REQUEST_TYPE_CONNECTION_TABLE_JSON
} request_type;

typedef struct request_t {
    request_type req;
    void *response;
} request_t;


monitor_t* monitor_init(void);
void monitor_process_packet(monitor_t* monitor, const u_char *packet, int len);
request_t* monitor_data_request(monitor_t* monitor, request_type r);
#endif
