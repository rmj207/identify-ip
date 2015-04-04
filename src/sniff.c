#define _GNU_SOURCE
#include<pcap.h>
#include<string.h>
#include<stdio.h>
#include<stdint.h>
#include<stdlib.h>
#include<unistd.h>

#include "monitor.h"

#define PROTO_TCP 6
#define ETH_HEADER(x) ((struct ethhdr *) (x))
#define IP_HEADER(x) ((struct iphdr *) ((x) + sizeof(struct ethhdr)))
#define TCP_HEADER(x) ((struct tcphdr *) ((x) + sizeof(struct ethhdr) + sizeof(struct iphdr)))

void *print_data(void* m)
{
    monitor_t* monitor = m;
    while (1) {
        request_t *req = monitor_data_request(monitor,  REQUEST_TYPE_HOST_TABLE_STR);
        if (req && req->response) {
            printf("%s", req->response);
        }
        free(req->response);
        free(req);
        sleep(5);
    }
    pthread_exit((void *) 0);
}

int main(int argc, char** argv)
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    uint32_t mask;
    uint32_t net;
    int cont = 1;
    pthread_t thread;

    struct pcap_pkthdr header;
    const u_char *packet;

    monitor_t *monitor = monitor_init();

    if (pcap_lookupnet(argv[1], &net, &mask, errbuf) == - 1) {
        fprintf(stderr, "Couldn't get netmask for device '%s': %s\n", argv[1], errbuf);
        return -1;
    }

    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Couldn't open device '%s': %s\n", argv[1], errbuf);
        return -1;
    }

    pthread_create(&thread, NULL, print_data, monitor);
    while (cont) {
        packet = pcap_next(handle, &header);
        monitor_process_packet(monitor, packet, header.caplen);
    }
    pcap_close(handle);
}

