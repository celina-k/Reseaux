#undef INTERFACE

#define _GNU_SOURCE
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>
#include <search.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include "rfc6234/sha.h"
#define NEIGH_CAPACITY 15
#define MYID 69
#define INITIAL_DATA_CAPACITY 1024
#define INITIAL_SEQNO 1
#define DEFAULT_MESSAGE "<1777"

#ifndef PROJETC_PROJET_H
#define PROJETC_PROJET_H

typedef struct tlv {
    unsigned char type;
    unsigned char length;
    int pad;
    short seqno;
    uint64_t node_id;
    unsigned char hash[16];
    char ip[16];
    short port;
    unsigned char data_len;
    unsigned char* data;
} tlv;	

typedef struct neighbour {
    struct sockaddr_in6* sin;
    int permanent;
    time_t last_package ;
}neighbour;

typedef struct neigh_table {
    neighbour table[NEIGH_CAPACITY];
    int len;
}neigh_table;

typedef struct data {
    uint64_t node_id;
    uint16_t seq;
    unsigned char* d;
    size_t len;
    unsigned char node_hash[16];
} data;

typedef struct data_table {
    int len;
    int capacity;
    unsigned char hash[16];
    data* table;
}data_table;


static void send_network_hash_to_all_neighbours();
static void initialisation(char *node,char *service);
static void send_warning(struct sockaddr_in6 *addr,char *error);
static void send_neigh_request(struct sockaddr_in6 *addr);
extern int(*tlv_processor[10])(unsigned char *current_tlv,tlv table[],int len);
static int warning_processor(unsigned char *current_tlv,tlv table[],int len);
static int node_state_processor(unsigned char *current_tlv,tlv table[],int len);
static int node_state_request_processor(unsigned char *current_tlv,tlv table[],int len);
static int node_hash_processor(unsigned char *current_tlv,tlv table[],int len);
static int network_state_request_processor(unsigned char *current_tlv,tlv table[],int len);
static int network_hash_processor(unsigned char *current_tlv,tlv table[],int len);
static unsigned char *package_builder(tlv table[],unsigned int amount_of_tlv);
static int package_sender(struct sockaddr_in6 *sin6,unsigned char *package);
static int neighbour_processor(unsigned char *current_tlv,tlv table[],int len);
static int neighbour_request_processor(unsigned char *current_tlv,tlv table[],int len);
static int return0(unsigned char *current_tlv,tlv table[],int len);
extern int(*tlv_builder[10])(tlv x,unsigned char *buf);
static int tlv_warning(tlv tlv,unsigned char *buf);
static int tlv_node_state(tlv tlv,unsigned char *buf);
static int tlv_node_state_request(tlv tlv,unsigned char *buf);
static int tlv_node_hash(tlv tlv,unsigned char *buf);
static int tlv_network_state_request(tlv tlv,unsigned char *buf);
static int tlv_network_hash(tlv tlv,unsigned char *buf);
static int tlv_neighbour(tlv tlv,unsigned char *buf);
static int tlv_neighbour_request(tlv tlv,unsigned char *buf);
static int tlv_pad_n(tlv tlv,unsigned char *buf);
static int header_builder(unsigned char *header,unsigned short length);
static unsigned char *network_hash();
static void insertData(data d);
static long getData(uint64_t id);
static char *paquet_ok(unsigned char *reply,size_t len);
static int getneighbour(struct sockaddr_in6 *sin6);
static int add_neighbour(struct sockaddr_in6 *addr,int permanent);
static int creation_socket();
static int s;
static int ourdata_index;
static neigh_table neighTable;
static data_table dataTable;
static time_t lastping;
static int updated_our_data ;
static int updated_our_network ;
static int converged;
#endif