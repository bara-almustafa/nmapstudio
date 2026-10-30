#include "scan.h"
#include "xml.h"
#include "model.h"
#include "db.h"
#include "platform.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

struct Scan {
    char        *nmap_path;
    char        *db_path;
    char        *targets;
    char        *args;
    int          run_id;
    scan_emit_fn emit;
    void        *ud;

    ns_proc     *proc;
    ns_thread    thread;
    volatile int running;
    volatile int stop_req;

    /* parse state */
    xml_parser   xp;
    sqlite3     *db;
    Host        *cur_host;
    Port        *cur_port;
    int          in_hostscript;
    int          up, down;
    double       elapsed;
    char        *summary;
    strbuf       raw;
};

static void emit_str(struct Scan *s, char *json) { s->emit(s->ud, json); }

static void emit_log(struct Scan *s, const char *level, const char *msg) {
    strbuf b; sb_init(&b);
    sb_puts(&b, "{\"type\":\"log\",\"level\":");
    sb_json_str(&b, level);
    sb_puts(&b, ",\"msg\":");
    sb_json_str(&b, msg);
    sb_putc(&b, '}');
    emit_str(s, sb_detach(&b));
}

/* ---------- XML callbacks ---------- */
static void on_open(void *ud, const char *name, const xml_attr_t *a, int na, int self) {
    struct Scan *s = ud;
    (void)self;

    if (!strcmp(name, "host")) {
        if (s->cur_host) host_free(s->cur_host);
        s->cur_host = host_new();
        s->cur_port = NULL;
        s->in_hostscript = 0;
    } else if (!s->cur_host) {
        if (!strcmp(name, "taskprogress")) {
            const char *pct = xml_get(a, na, "percent");
            const char *etc = xml_get(a, na, "etc");
            const char *task = xml_get(a, na, "task");
            strbuf b; sb_init(&b);
            sb_puts(&b, "{\"type\":\"progress\",\"percent\":");
            sb_printf(&b, "%g", pct ? atof(pct) : 0.0);
            sb_puts(&b, ",\"task\":"); sb_json_str(&b, task ? task : "");
            sb_puts(&b, ",\"etc\":");  sb_json_str(&b, etc ? etc : "");
            sb_putc(&b, '}');
            emit_str(s, sb_detach(&b));
        } else if (!strcmp(name, "finished")) {
            const char *el = xml_get(a, na, "elapsed");
            const char *sm = xml_get(a, na, "summary");
            if (el) s->elapsed = atof(el);
            if (sm) set_str(&s->summary, sm);
        }
        return;
    } else {
        /* inside a host */
        Host *h = s->cur_host;
        if (!strcmp(name, "status")) {
            const char *st = xml_get(a, na, "state");
            const char *rs = xml_get(a, na, "reason");
            if (st) { strncpy(h->state, st, sizeof h->state - 1); }
            if (rs) set_str(&h->reason, rs);
        } else if (!strcmp(name, "address")) {
            const char *addr = xml_get(a, na, "addr");
            const char *t = xml_get(a, na, "addrtype");
            if (t && !strcmp(t, "mac")) {
                set_str(&h->mac, addr);
                set_str(&h->vendor, xml_get(a, na, "vendor"));
            } else if (addr && !h->ip) {
                set_str(&h->ip, addr);
                set_str(&h->addrtype, t);
            }
        } else if (!strcmp(name, "hostname")) {
            if (!h->hostname) set_str(&h->hostname, xml_get(a, na, "name"));
        } else if (!strcmp(name, "port")) {
            Port *p = host_add_port(h);
            const char *proto = xml_get(a, na, "protocol");
            const char *pid = xml_get(a, na, "portid");
            if (proto) strncpy(p->proto, proto, sizeof p->proto - 1);
            if (pid) p->portid = atoi(pid);
            s->cur_port = p;
        } else if (!strcmp(name, "state") && s->cur_port) {
            const char *st = xml_get(a, na, "state");
            const char *rs = xml_get(a, na, "reason");
            if (st) strncpy(s->cur_port->state, st, sizeof s->cur_port->state - 1);
            if (rs) set_str(&s->cur_port->reason, rs);
        } else if (!strcmp(name, "service") && s->cur_port) {
            Port *p = s->cur_port;
            set_str(&p->service,   xml_get(a, na, "name"));
            set_str(&p->product,   xml_get(a, na, "product"));
            set_str(&p->version,   xml_get(a, na, "version"));
            set_str(&p->extrainfo, xml_get(a, na, "extrainfo"));
            set_str(&p->tunnel,    xml_get(a, na, "tunnel"));
            const char *cf = xml_get(a, na, "conf");
            if (cf) p->conf = atoi(cf);
        } else if (!strcmp(name, "hostscript")) {
            s->in_hostscript = 1;
        } else if (!strcmp(name, "script") && s->cur_port && !s->in_hostscript) {
            NseScript *ns = port_add_script(s->cur_port);
            ns->id     = xstrdup(xml_get(a, na, "id") ? xml_get(a, na, "id") : "");
            ns->output = xstrdup(xml_get(a, na, "output") ? xml_get(a, na, "output") : "");
        } else if (!strcmp(name, "osmatch")) {
            const char *nm = xml_get(a, na, "name");
            const char *ac = xml_get(a, na, "accuracy");
            int acc = ac ? atoi(ac) : 0;
            if (nm && acc >= h->osaccuracy) { set_str(&h->os, nm); h->osaccuracy = acc; }
        } else if (!strcmp(name, "distance")) {
            const char *v = xml_get(a, na, "value");
            if (v) h->distance = atof(v);
        } else if (!strcmp(name, "hop")) {
            Hop *hp = host_add_hop(h);
            const char *ttl = xml_get(a, na, "ttl");
            const char *ip  = xml_get(a, na, "ipaddr");
            const char *rtt = xml_get(a, na, "rtt");
            const char *hn  = xml_get(a, na, "host");
            if (ttl) hp->ttl = atoi(ttl);
            if (rtt) hp->rtt = atof(rtt);
            set_str(&hp->ip, ip);
            set_str(&hp->host, hn);
        }
    }
}

static void on_close(void *ud, const char *name) {
    struct Scan *s = ud;
    if (!strcmp(name, "port")) {
        s->cur_port = NULL;
    } else if (!strcmp(name, "hostscript")) {
        s->in_hostscript = 0;
    } else if (!strcmp(name, "host")) {
        Host *h = s->cur_host;
        if (h) {
            if (!strcmp(h->state, "up")) s->up++; else s->down++;
            emit_str(s, host_to_json(h, s->run_id));
            if (s->db) db_insert_host(s->db, s->run_id, h);
            host_free(h);
            s->cur_host = NULL;
            s->cur_port = NULL;
        }
    }
}

/* ---------- argv splitting ---------- */
char **argv_split(const char *str, int *argc_out) {
    int cap = 8, n = 0;
    char **argv = xmalloc(cap * sizeof *argv);
    const char *p = str;
    strbuf cur; sb_init(&cur);
    int have = 0;
    while (*p) {
        if (isspace((unsigned char)*p)) {
            if (have) {
                if (n + 1 >= cap) { cap *= 2; argv = xrealloc(argv, cap * sizeof *argv); }
                argv[n++] = sb_detach(&cur); sb_init(&cur); have = 0;
            }
            p++;
            continue;
        }
        if (*p == '"' || *p == '\'') {
            char q = *p++;
            while (*p && *p != q) sb_putc(&cur, *p++);
            if (*p == q) p++;
            have = 1;
        } else {
            sb_putc(&cur, *p++);
            have = 1;
        }
    }
    if (have) {
        if (n + 1 >= cap) { cap *= 2; argv = xrealloc(argv, cap * sizeof *argv); }
        argv[n++] = sb_detach(&cur);
    } else {
        sb_free(&cur);
    }
    argv[n] = NULL;
    if (argc_out) *argc_out = n;
    return argv;
}
void argv_free(char **argv) {
    if (!argv) return;
    for (int i = 0; argv[i]; i++) free(argv[i]);
    free(argv);
}

/* ---------- worker thread ---------- */
static void *scan_worker(void *arg) {
    struct Scan *s = arg;

    /* build argv: nmap -oX - --stats-every 1s <args...> <targets...> */
    int uargc = 0, targc = 0;
    char **uargv = argv_split(s->args ? s->args : "", &uargc);
    char **targv = argv_split(s->targets ? s->targets : "", &targc);

    int cap = uargc + targc + 8;
    char **argv = xmalloc(cap * sizeof *argv);
    int k = 0;
    argv[k++] = xstrdup(s->nmap_path);
    argv[k++] = xstrdup("-oX");
    argv[k++] = xstrdup("-");
    argv[k++] = xstrdup("--stats-every");
    argv[k++] = xstrdup("2s");
    for (int i = 0; i < uargc; i++) argv[k++] = xstrdup(uargv[i]);
    for (int i = 0; i < targc; i++) argv[k++] = xstrdup(targv[i]);
    argv[k] = NULL;
    argv_free(uargv); argv_free(targv);

    /* echo the command we are about to run */
    {
        strbuf c; sb_init(&c);
        for (int i = 0; argv[i]; i++) { if (i) sb_putc(&c, ' '); sb_puts(&c, argv[i]); }
        emit_log(s, "cmd", c.buf);
        sb_free(&c);
    }

    char err[256] = {0};
    s->proc = ns_proc_spawn(argv, err, sizeof err);
    argv_free(argv);
    if (!s->proc) {
        emit_log(s, "error", err[0] ? err : "failed to launch nmap");
        strbuf d; sb_init(&d);
        sb_printf(&d, "{\"type\":\"done\",\"scan\":%d,\"ok\":false}", s->run_id);
        emit_str(s, sb_detach(&d));
        s->running = 0;
        return NULL;
    }

    s->db = db_open(s->db_path);
    xml_init(&s->xp, on_open, on_close, s);

    char buf[8192];
    for (;;) {
        if (s->stop_req) { ns_proc_kill(s->proc); }
        long r = ns_proc_read(s->proc, buf, sizeof buf);
        if (r <= 0) break;
        sb_putn(&s->raw, buf, (size_t)r);
        xml_feed(&s->xp, buf, (size_t)r);
    }
    ns_proc_wait(s->proc);

    if (s->db) {
        db_finish_run(s->db, s->run_id, s->elapsed,
                      s->summary ? s->summary : "", s->up, s->down,
                      s->stop_req ? "stopped" : "done", s->raw.buf);
    }

    /* final done event */
    strbuf d; sb_init(&d);
    sb_printf(&d, "{\"type\":\"done\",\"scan\":%d,\"ok\":true,\"up\":%d,\"down\":%d,\"elapsed\":%g,\"summary\":",
              s->run_id, s->up, s->down, s->elapsed);
    sb_json_str(&d, s->summary ? s->summary : "");
    sb_putc(&d, '}');
    emit_str(s, sb_detach(&d));

    xml_free(&s->xp);
    if (s->db) { db_close(s->db); s->db = NULL; }
    s->running = 0;
    return NULL;
}

Scan *scan_start(const char *nmap_path, const char *db_path, int run_id,
                 const char *targets, const char *args,
                 scan_emit_fn emit, void *ud, char *errbuf, size_t errsz) {
    if (!targets || !*targets) { if (errbuf) snprintf(errbuf, errsz, "no targets"); return NULL; }
    Scan *s = xmalloc(sizeof *s);
    memset(s, 0, sizeof *s);
    s->nmap_path = xstrdup(nmap_path && *nmap_path ? nmap_path : "nmap");
    s->db_path = xstrdup(db_path);
    s->targets = xstrdup(targets);
    s->args = xstrdup(args ? args : "");
    s->run_id = run_id;
    s->emit = emit;
    s->ud = ud;
    s->running = 1;
    sb_init(&s->raw);
    if (ns_thread_start(&s->thread, scan_worker, s) != 0) {
        if (errbuf) snprintf(errbuf, errsz, "failed to start worker thread");
        sb_free(&s->raw);
        free(s->nmap_path); free(s->db_path); free(s->targets); free(s->args);
        free(s);
        return NULL;
    }
    return s;
}

int  scan_running(Scan *s) { return s && s->running; }
void scan_stop(Scan *s)    { if (s) s->stop_req = 1; }

void scan_join_free(Scan *s) {
    if (!s) return;
    ns_thread_join(s->thread);
    if (s->proc) ns_proc_free(s->proc);
    free(s->summary);
    sb_free(&s->raw);
    free(s->nmap_path); free(s->db_path); free(s->targets); free(s->args);
    free(s);
}
