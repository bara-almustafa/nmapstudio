/* model.h - normalized Nmap result objects */
#ifndef NS_MODEL_H
#define NS_MODEL_H

#include "util.h"

typedef struct {
    char *id;
    char *output;
} NseScript;

typedef struct {
    char        proto[8];      /* tcp / udp / sctp */
    int         portid;
    char        state[16];     /* open / closed / filtered ... */
    char       *reason;
    char       *service;       /* http, ssh ... */
    char       *product;
    char       *version;
    char       *extrainfo;
    char       *tunnel;        /* ssl ... */
    int         conf;          /* service detection confidence 0-10 */
    NseScript  *scripts;
    int         nscripts;
} Port;

typedef struct {
    int   ttl;
    char *ip;
    char *host;
    double rtt;
} Hop;

typedef struct {
    char  *ip;
    char  *addrtype;
    char  *mac;
    char  *vendor;
    char  *hostname;
    char   state[16];          /* up / down */
    char  *reason;
    char  *os;                 /* best OS guess name */
    int    osaccuracy;
    Port  *ports;
    int    nports;
    Hop   *hops;
    int    nhops;
    double distance;
} Host;

Host *host_new(void);
void  host_free(Host *h);
Port      *host_add_port(Host *h);
Hop       *host_add_hop(Host *h);
NseScript *port_add_script(Port *p);

/* serialize one host to JSON (object). `scan_id` tags which run it belongs to. */
char *host_to_json(const Host *h, int scan_id);

/* helper: set a char* field, freeing old */
void  set_str(char **dst, const char *v);

#endif
