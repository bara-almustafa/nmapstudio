#include "db.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static const char *SCHEMA =
 "PRAGMA journal_mode=WAL;"
 "CREATE TABLE IF NOT EXISTS scan_runs("
 " id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, args TEXT, targets TEXT,"
 " started INTEGER DEFAULT (strftime('%s','now')), finished INTEGER,"
 " elapsed REAL, summary TEXT, up INTEGER DEFAULT 0, down INTEGER DEFAULT 0,"
 " status TEXT DEFAULT 'running', raw_xml TEXT);"
 "CREATE TABLE IF NOT EXISTS hosts("
 " id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER, ip TEXT, hostname TEXT,"
 " state TEXT, os TEXT, distance REAL);"
 "CREATE TABLE IF NOT EXISTS ports("
 " id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER, ip TEXT, proto TEXT,"
 " portid INTEGER, state TEXT, service TEXT, product TEXT, version TEXT, extrainfo TEXT);"
 "CREATE INDEX IF NOT EXISTS idx_ports_scan ON ports(scan_id);"
 "CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);"
 "CREATE INDEX IF NOT EXISTS idx_ports_ip ON ports(ip);";

sqlite3 *db_open(const char *path) {
    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) {
        fprintf(stderr, "db open failed: %s\n", sqlite3_errmsg(db));
        if (db) sqlite3_close(db);
        return NULL;
    }
    sqlite3_busy_timeout(db, 5000);
    char *err = NULL;
    if (sqlite3_exec(db, SCHEMA, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "db schema: %s\n", err ? err : "?");
        sqlite3_free(err);
    }
    return db;
}
void db_close(sqlite3 *db) { if (db) sqlite3_close(db); }

int db_create_run(sqlite3 *db, const char *name, const char *args, const char *targets) {
    sqlite3_stmt *st;
    const char *sql = "INSERT INTO scan_runs(name,args,targets) VALUES(?,?,?)";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, name ? name : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, args ? args : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, targets ? targets : "", -1, SQLITE_TRANSIENT);
    int id = -1;
    if (sqlite3_step(st) == SQLITE_DONE) id = (int)sqlite3_last_insert_rowid(db);
    sqlite3_finalize(st);
    return id;
}

void db_finish_run(sqlite3 *db, int run_id, double elapsed, const char *summary,
                   int up, int down, const char *status, const char *raw_xml) {
    sqlite3_stmt *st;
    const char *sql = "UPDATE scan_runs SET finished=strftime('%s','now'),elapsed=?,"
                      "summary=?,up=?,down=?,status=?,raw_xml=? WHERE id=?";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return;
    sqlite3_bind_double(st, 1, elapsed);
    sqlite3_bind_text(st, 2, summary ? summary : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, up);
    sqlite3_bind_int(st, 4, down);
    sqlite3_bind_text(st, 5, status ? status : "done", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, raw_xml ? raw_xml : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 7, run_id);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

void db_insert_host(sqlite3 *db, int run_id, const Host *h) {
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db,
        "INSERT INTO hosts(scan_id,ip,hostname,state,os,distance) VALUES(?,?,?,?,?,?)",
        -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int(st, 1, run_id);
        sqlite3_bind_text(st, 2, h->ip ? h->ip : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, h->hostname ? h->hostname : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, h->state, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, h->os ? h->os : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_double(st, 6, h->distance);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
    const char *psql = "INSERT INTO ports(scan_id,ip,proto,portid,state,service,product,version,extrainfo)"
                       " VALUES(?,?,?,?,?,?,?,?,?)";
    for (int i = 0; i < h->nports; i++) {
        const Port *p = &h->ports[i];
        if (sqlite3_prepare_v2(db, psql, -1, &st, NULL) != SQLITE_OK) continue;
        sqlite3_bind_int(st, 1, run_id);
        sqlite3_bind_text(st, 2, h->ip ? h->ip : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, p->proto, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 4, p->portid);
        sqlite3_bind_text(st, 5, p->state, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, p->service ? p->service : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, p->product ? p->product : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 8, p->version ? p->version : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, p->extrainfo ? p->extrainfo : "", -1, SQLITE_TRANSIENT);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
}

static const char *col_text(sqlite3_stmt *st, int i) {
    const char *t = (const char *)sqlite3_column_text(st, i);
    return t ? t : "";
}

char *db_runs_json(sqlite3 *db) {
    strbuf s; sb_init(&s);
    sb_puts(&s, "{\"type\":\"history\",\"runs\":[");
    sqlite3_stmt *st;
    const char *sql = "SELECT id,name,targets,args,started,finished,elapsed,summary,up,down,status"
                      " FROM scan_runs ORDER BY id DESC LIMIT 500";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        int first = 1;
        while (sqlite3_step(st) == SQLITE_ROW) {
            if (!first) sb_putc(&s, ',');
            first = 0;
            sb_putc(&s, '{');
            sb_printf(&s, "\"id\":%d", sqlite3_column_int(st, 0));
            sb_puts(&s, ",\"name\":");   sb_json_str(&s, col_text(st,1));
            sb_puts(&s, ",\"targets\":");sb_json_str(&s, col_text(st,2));
            sb_puts(&s, ",\"args\":");   sb_json_str(&s, col_text(st,3));
            sb_printf(&s, ",\"started\":%lld",  (long long)sqlite3_column_int64(st,4));
            sb_printf(&s, ",\"finished\":%lld", (long long)sqlite3_column_int64(st,5));
            sb_printf(&s, ",\"elapsed\":%g",    sqlite3_column_double(st,6));
            sb_puts(&s, ",\"summary\":"); sb_json_str(&s, col_text(st,7));
            sb_printf(&s, ",\"up\":%d,\"down\":%d", sqlite3_column_int(st,8), sqlite3_column_int(st,9));
            sb_puts(&s, ",\"status\":"); sb_json_str(&s, col_text(st,10));
            sb_putc(&s, '}');
        }
        sqlite3_finalize(st);
    }
    sb_puts(&s, "]}");
    return sb_detach(&s);
}

void db_replay_emit(sqlite3 *db, int run_id, emit_fn emit, void *ud) {
    { strbuf b; sb_init(&b); sb_printf(&b, "{\"type\":\"replay_begin\",\"scan\":%d}", run_id); emit(ud, sb_detach(&b)); }

    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db,
        "SELECT ip,hostname,state,os,distance FROM hosts WHERE scan_id=? ORDER BY id",
        -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int(st, 1, run_id);
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *ip = col_text(st, 0);
            strbuf s; sb_init(&s);
            sb_printf(&s, "{\"type\":\"host\",\"scan\":%d", run_id);
            sb_puts(&s, ",\"ip\":");       sb_json_str(&s, ip);
            sb_puts(&s, ",\"hostname\":");sb_json_str(&s, col_text(st,1));
            sb_puts(&s, ",\"state\":");   sb_json_str(&s, col_text(st,2));
            sb_puts(&s, ",\"os\":");      sb_json_str(&s, col_text(st,3));
            sb_printf(&s, ",\"distance\":%g", sqlite3_column_double(st,4));
            sb_puts(&s, ",\"ports\":[");
            sqlite3_stmt *ps;
            if (sqlite3_prepare_v2(db,
                "SELECT proto,portid,state,service,product,version,extrainfo"
                " FROM ports WHERE scan_id=? AND ip=? ORDER BY portid",
                -1, &ps, NULL) == SQLITE_OK) {
                sqlite3_bind_int(ps, 1, run_id);
                sqlite3_bind_text(ps, 2, ip, -1, SQLITE_TRANSIENT);
                int pf = 1;
                while (sqlite3_step(ps) == SQLITE_ROW) {
                    if (!pf) sb_putc(&s, ',');
                    pf = 0;
                    sb_putc(&s, '{');
                    sb_puts(&s, "\"proto\":"); sb_json_str(&s, col_text(ps,0));
                    sb_printf(&s, ",\"port\":%d", sqlite3_column_int(ps,1));
                    sb_puts(&s, ",\"state\":");  sb_json_str(&s, col_text(ps,2));
                    sb_puts(&s, ",\"service\":");sb_json_str(&s, col_text(ps,3));
                    sb_puts(&s, ",\"product\":");sb_json_str(&s, col_text(ps,4));
                    sb_puts(&s, ",\"version\":");sb_json_str(&s, col_text(ps,5));
                    sb_puts(&s, ",\"extrainfo\":");sb_json_str(&s, col_text(ps,6));
                    sb_puts(&s, ",\"scripts\":[]}");
                }
                sqlite3_finalize(ps);
            }
            sb_puts(&s, "],\"hops\":[]}");
            emit(ud, sb_detach(&s));
        }
        sqlite3_finalize(st);
    }

    { strbuf b; sb_init(&b); sb_printf(&b, "{\"type\":\"replay_end\",\"scan\":%d}", run_id); emit(ud, sb_detach(&b)); }
}

/* ---- diff: compares open ports between two runs ---- */
typedef struct { char *ip, *proto, *svc, *ver; int port; } PRow;

static PRow *load_open(sqlite3 *db, int run, int *count) {
    PRow *rows = NULL; int n = 0, cap = 0;
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db,
        "SELECT ip,proto,portid,service,version FROM ports"
        " WHERE scan_id=? AND state='open' ORDER BY ip,proto,portid",
        -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int(st, 1, run);
        while (sqlite3_step(st) == SQLITE_ROW) {
            if (n == cap) { cap = cap ? cap*2 : 32; rows = xrealloc(rows, cap*sizeof *rows); }
            rows[n].ip    = xstrdup(col_text(st,0));
            rows[n].proto = xstrdup(col_text(st,1));
            rows[n].port  = sqlite3_column_int(st,2);
            rows[n].svc   = xstrdup(col_text(st,3));
            rows[n].ver   = xstrdup(col_text(st,4));
            n++;
        }
        sqlite3_finalize(st);
    }
    *count = n;
    return rows;
}
static int prow_cmp(const PRow *a, const PRow *b) {
    int c = strcmp(a->ip, b->ip); if (c) return c;
    c = strcmp(a->proto, b->proto); if (c) return c;
    return a->port - b->port;
}
static void emit_prow(strbuf *s, const PRow *r) {
    sb_putc(s, '{');
    sb_puts(s, "\"ip\":");      sb_json_str(s, r->ip);
    sb_puts(s, ",\"proto\":");  sb_json_str(s, r->proto);
    sb_printf(s, ",\"port\":%d", r->port);
    sb_puts(s, ",\"service\":");sb_json_str(s, r->svc);
    sb_puts(s, ",\"version\":");sb_json_str(s, r->ver);
    sb_putc(s, '}');
}
static void free_rows(PRow *r, int n) {
    for (int i = 0; i < n; i++) { free(r[i].ip); free(r[i].proto); free(r[i].svc); free(r[i].ver); }
    free(r);
}

char *db_diff_json(sqlite3 *db, int a, int b) {
    int na, nb;
    PRow *ra = load_open(db, a, &na);
    PRow *rb = load_open(db, b, &nb);
    strbuf s; sb_init(&s);
    sb_printf(&s, "{\"type\":\"diff\",\"a\":%d,\"b\":%d,\"added\":[", a, b);
    /* merge-join */
    int i = 0, j = 0, firstAdd = 1;
    while (i < na && j < nb) {
        int c = prow_cmp(&ra[i], &rb[j]);
        if (c < 0) i++;                 /* only in A -> removed, later */
        else if (c > 0) { if (!firstAdd) sb_putc(&s, ','); firstAdd = 0; emit_prow(&s, &rb[j]); j++; }
        else { i++; j++; }
    }
    for (; j < nb; j++) { if (!firstAdd) sb_putc(&s, ','); firstAdd = 0; emit_prow(&s, &rb[j]); }

    sb_puts(&s, "],\"removed\":[");
    i = 0; j = 0; int firstRem = 1;
    while (i < na && j < nb) {
        int c = prow_cmp(&ra[i], &rb[j]);
        if (c < 0) { if (!firstRem) sb_putc(&s, ','); firstRem = 0; emit_prow(&s, &ra[i]); i++; }
        else if (c > 0) j++;
        else { i++; j++; }
    }
    for (; i < na; i++) { if (!firstRem) sb_putc(&s, ','); firstRem = 0; emit_prow(&s, &ra[i]); }

    sb_puts(&s, "],\"changed\":[");
    i = 0; j = 0; int firstChg = 1;
    while (i < na && j < nb) {
        int c = prow_cmp(&ra[i], &rb[j]);
        if (c < 0) i++;
        else if (c > 0) j++;
        else {
            if (strcmp(ra[i].svc, rb[j].svc) != 0 || strcmp(ra[i].ver, rb[j].ver) != 0) {
                if (!firstChg) sb_putc(&s, ',');
                firstChg = 0;
                sb_putc(&s, '{');
                sb_puts(&s, "\"ip\":");     sb_json_str(&s, rb[j].ip);
                sb_puts(&s, ",\"proto\":"); sb_json_str(&s, rb[j].proto);
                sb_printf(&s, ",\"port\":%d", rb[j].port);
                sb_puts(&s, ",\"from\":");  sb_json_str(&s, ra[i].svc && *ra[i].svc ? ra[i].svc : ra[i].ver);
                sb_puts(&s, ",\"to\":");    sb_json_str(&s, rb[j].svc && *rb[j].svc ? rb[j].svc : rb[j].ver);
                sb_puts(&s, ",\"fromver\":");sb_json_str(&s, ra[i].ver);
                sb_puts(&s, ",\"tover\":"); sb_json_str(&s, rb[j].ver);
                sb_putc(&s, '}');
            }
            i++; j++;
        }
    }
    sb_puts(&s, "]}");
    free_rows(ra, na); free_rows(rb, nb);
    return sb_detach(&s);
}

char *db_inventory_json(sqlite3 *db) {
    strbuf s; sb_init(&s);
    sb_puts(&s, "{\"type\":\"inventory\",\"hosts\":[");
    sqlite3_stmt *st;
    const char *sql =
      "SELECT ip, MAX(hostname), MAX(os), COUNT(DISTINCT scan_id), MAX(scan_id)"
      " FROM hosts WHERE ip<>'' GROUP BY ip ORDER BY ip";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        int first = 1;
        while (sqlite3_step(st) == SQLITE_ROW) {
            if (!first) sb_putc(&s, ',');
            first = 0;
            sb_putc(&s, '{');
            sb_puts(&s, "\"ip\":");       sb_json_str(&s, col_text(st,0));
            sb_puts(&s, ",\"hostname\":");sb_json_str(&s, col_text(st,1));
            sb_puts(&s, ",\"os\":");      sb_json_str(&s, col_text(st,2));
            sb_printf(&s, ",\"seen\":%d,\"lastscan\":%d",
                      sqlite3_column_int(st,3), sqlite3_column_int(st,4));
            sb_putc(&s, '}');
        }
        sqlite3_finalize(st);
    }
    sb_puts(&s, "]}");
    return sb_detach(&s);
}
