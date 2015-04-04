#ifndef __LOOKUP_H__
#define __LOOKUP_H__

#define DB_PATH "/tmp/max/GeoLite2-City.mmdb"

struct lookup_t;
typedef struct lookup_t lookup_t;

typedef struct loc_t {
    double latitude;
    double longitude;
    char *country;
} loc_t;

loc_t* lookup_ip_location(lookup_t* db, uint32_t address);
lookup_t* lookup_init(char* db_path);
void lookup_fin(lookup_t* fin);
#endif
