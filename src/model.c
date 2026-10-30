#include "model.h"
#include <stdlib.h>
#include <string.h>

void set_str(char **dst, const char *v) {
    free(*dst);
    *dst = v ? xstrdup(v) : NULL;
}

Host *host_new(void) {
    Host *h = xmalloc(sizeof *h);
    memset(h, 0, sizeof *h);
    return h;
}

Port *host_add_port(Host *h) {
    h->ports = xrealloc(h->ports, (h->nports + 1) * sizeof *h->ports);
    Port *p = &h->ports[h->nports++];
    memset(p, 0, sizeof *p);
    p->conf = -1;
    return p;
}

Hop *host_add_hop(Host *h) {
    h->hops = xrealloc(h->hops, (h->nhops + 1) * sizeof *h->hops);
    Hop *hp = &h->hops[h->nhops++];
    memset(hp, 0, sizeof *hp);
    return hp;
}

NseScript *port_add_script(Port *p) {
    p->scripts = xrealloc(p->scripts, (p->nscripts + 1) * sizeof *p->scripts);
    NseScript *s = &p->scripts[p->nscripts++];
    memset(s, 0, sizeof *s);
    return s;
}

void host_free(Host *h) {
    if (!h) return;
    free(h->ip); free(h->addrtype); free(h->mac); free(h->vendor);
    free(h->hostname); free(h->reason); free(h->os);
    for (int i = 0; i < h->nports; i++) {
        Port *p = &h->ports[i];
        free(p->reason); free(p->service); free(p->product); free(p->version);
        free(p->extrainfo); free(p->tunnel);
        for (int j = 0; j < p->nscripts; j++) { free(p->scripts[j].id); free(p->scripts[j].output); }
        free(p->scripts);
    }
    free(h->ports);
    for (int i = 0; i < h->nhops; i++) { free(h->hops[i].ip); free(h->hops[i].host); }
    free(h->hops);
    free(h);
}

static void json_kv_str(strbuf *s, const char *k, const char *v, int comma) {
    if (comma) sb_putc(s, ',');
    sb_json_str(s, k); sb_putc(s, ':'); sb_json_str(s, v);
}

char *host_to_json(const Host *h, int scan_id) {
    strbuf s; sb_init(&s);
    sb_putc(&s, '{');
    sb_printf(&s, "\"type\":\"host\",\"scan\":%d", scan_id);
    json_kv_str(&s, "ip", h->ip ? h->ip : "", 1);
    json_kv_str(&s, "addrtype", h->addrtype, 1);
    json_kv_str(&s, "mac", h->mac, 1);
    json_kv_str(&s, "vendor", h->vendor, 1);
    json_kv_str(&s, "hostname", h->hostname, 1);
    json_kv_str(&s, "state", h->state, 1);
    json_kv_str(&s, "reason", h->reason, 1);
    json_kv_str(&s, "os", h->os, 1);
    sb_printf(&s, ",\"osaccuracy\":%d", h->osaccuracy);
    sb_printf(&s, ",\"distance\":%g", h->distance);

    sb_puts(&s, ",\"ports\":[");
    for (int i = 0; i < h->nports; i++) {
        const Port *p = &h->ports[i];
        if (i) sb_putc(&s, ',');
        sb_putc(&s, '{');
        sb_printf(&s, "\"port\":%d", p->portid);
        json_kv_str(&s, "proto", p->proto, 1);
        json_kv_str(&s, "state", p->state, 1);
        json_kv_str(&s, "reason", p->reason, 1);
        json_kv_str(&s, "service", p->service, 1);
        json_kv_str(&s, "product", p->product, 1);
        json_kv_str(&s, "version", p->version, 1);
        json_kv_str(&s, "extrainfo", p->extrainfo, 1);
        json_kv_str(&s, "tunnel", p->tunnel, 1);
        sb_printf(&s, ",\"conf\":%d", p->conf);
        sb_puts(&s, ",\"scripts\":[");
        for (int j = 0; j < p->nscripts; j++) {
            if (j) sb_putc(&s, ',');
            sb_putc(&s, '{');
            json_kv_str(&s, "id", p->scripts[j].id, 0);
            json_kv_str(&s, "output", p->scripts[j].output, 1);
            sb_putc(&s, '}');
        }
        sb_puts(&s, "]}");
    }
    sb_putc(&s, ']');

    sb_puts(&s, ",\"hops\":[");
    for (int i = 0; i < h->nhops; i++) {
        const Hop *hp = &h->hops[i];
        if (i) sb_putc(&s, ',');
        sb_putc(&s, '{');
        sb_printf(&s, "\"ttl\":%d,\"rtt\":%g", hp->ttl, hp->rtt);
        json_kv_str(&s, "ip", hp->ip, 1);
        json_kv_str(&s, "host", hp->host, 1);
        sb_putc(&s, '}');
    }
    sb_puts(&s, "]}");
    return sb_detach(&s);
}
