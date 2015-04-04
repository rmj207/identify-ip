#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>

#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>

#include <maxminddb.h>

#include "lookup.h"

struct lookup_t {
    MMDB_s *geo_database;
};

static loc_t* _get_location_info(MMDB_lookup_result_s *const result)
{
    struct loc_t *location = NULL;
    MMDB_entry_data_s entry_data;
    char *country = NULL;
    double lat, lon;
    int r = 0;

    r = MMDB_get_value(&result->entry, &entry_data, "location",
                                                    "latitude",
                                                    NULL);
    if (MMDB_SUCCESS != r) goto cleanup;
    if (entry_data.has_data) {
        lat = entry_data.double_value;
    }
    r = MMDB_get_value(&result->entry, &entry_data, "location",
                                                    "longitude",
                                                    NULL);
    if (MMDB_SUCCESS != r) goto cleanup;
    if (entry_data.has_data) {
        lon = entry_data.double_value;
    }
    r = MMDB_get_value(&result->entry, &entry_data, "country",
                                                    "names",
                                                    "en",
                                                    NULL);
    if (MMDB_SUCCESS != r) goto cleanup;
    if (entry_data.has_data) {
        country = strndup(entry_data.utf8_string, entry_data.data_size);
    }

    location = malloc(sizeof(loc_t));
    *location = (struct loc_t) { .latitude = lat,
                                 .longitude = lon,
                                 .country = country };
cleanup:
    return location;
}

loc_t* lookup_ip_location(lookup_t* db, uint32_t address)
{
    if (!db || !db->geo_database) return NULL;

    MMDB_lookup_result_s result;
    int gai_error;
    int mmdb_error;

    result = MMDB_lookup_string(db->geo_database,
                                inet_ntoa(*(struct in_addr*)&address),
                                &gai_error,
                                &mmdb_error);

    if (gai_error || MMDB_SUCCESS != mmdb_error) return NULL;

    if (!result.found_entry) return NULL;

    return _get_location_info(&result);
}

lookup_t* lookup_init(char* db_path)
{
    if (!db_path) return NULL;

    lookup_t *new = malloc(sizeof(lookup_t));
    new->geo_database = malloc(sizeof(MMDB_s));

    MMDB_open(db_path, MMDB_MODE_MMAP, new->geo_database);
    return new;
}

void lookup_fin(lookup_t* fin)
{
    MMDB_close(fin->geo_database);
    free(fin->geo_database);
    free(fin);
}
